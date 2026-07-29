#!/usr/bin/env python3
"""Match pinned GitHub Action releases against a reviewed advisory snapshot."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


INVENTORY_SCHEMA = "psb-github-action-inventory/v1"
SNAPSHOT_SCHEMA = "psb-github-actions-advisory-snapshot/v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GHSA_RE = re.compile(r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
VERSION_RE = re.compile(r"^v?(?P<major>0|[1-9][0-9]*)(?:\.(?P<minor>0|[1-9][0-9]*))?(?:\.(?P<patch>0|[1-9][0-9]*))?$")
COMPARATOR_RE = re.compile(r"^(?P<operator>>=|<=|>|<|=)?\s*(?P<version>v?[0-9]+(?:\.[0-9]+){0,2})$")


class VerificationError(ValueError):
    """Input could not be evaluated safely."""


def load_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} is unavailable")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is unreadable or malformed") from error


def parse_version(value: Any, label: str) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise VerificationError(f"{label} must be a stable semantic version")
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise VerificationError(f"{label} must be a stable semantic version")
    return (
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
    )


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise VerificationError(f"{label} is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise VerificationError(f"{label} must use UTC")
    return parsed


def load_inventory(path: Path) -> list[dict[str, str]]:
    raw = load_json(path, "Action inventory")
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "actions"}
        or raw.get("schema_version") != INVENTORY_SCHEMA
        or not isinstance(raw.get("actions"), list)
        or not raw["actions"]
    ):
        raise VerificationError("Action inventory fields are malformed")
    actions: list[dict[str, str]] = []
    identities: set[tuple[str, str, str]] = set()
    for index, action in enumerate(raw["actions"]):
        label = f"actions[{index}]"
        if (
            not isinstance(action, dict)
            or set(action) != {"package", "version", "commit_sha", "release_url"}
            or not isinstance(action.get("package"), str)
            or PACKAGE_RE.fullmatch(action["package"]) is None
            or not isinstance(action.get("commit_sha"), str)
            or SHA_RE.fullmatch(action["commit_sha"]) is None
            or not isinstance(action.get("release_url"), str)
            or not action["release_url"].startswith(
                f"https://github.com/{action['package']}/releases/"
            )
        ):
            raise VerificationError(f"{label} fields are malformed")
        parse_version(action.get("version"), f"{label}.version")
        identity = (action["package"].lower(), action["version"], action["commit_sha"])
        if identity in identities:
            raise VerificationError(f"{label} duplicates an inventory entry")
        identities.add(identity)
        actions.append(action)
    return actions


def load_snapshot(path: Path, as_of: datetime, max_age_days: int) -> list[dict[str, Any]]:
    raw = load_json(path, "advisory snapshot")
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "source", "advisories"}
        or raw.get("schema_version") != SNAPSHOT_SCHEMA
        or not isinstance(raw.get("source"), dict)
        or set(raw["source"])
        != {"api_url", "api_version", "ecosystem", "type", "retrieved_at", "complete"}
        or raw["source"].get("api_url") != "https://api.github.com/advisories"
        or raw["source"].get("api_version") != "2022-11-28"
        or raw["source"].get("ecosystem") != "actions"
        or raw["source"].get("type") != "reviewed"
        or raw["source"].get("complete") is not True
        or not isinstance(raw.get("advisories"), list)
    ):
        raise VerificationError("advisory snapshot fields are malformed or incomplete")
    retrieved_at = parse_time(raw["source"].get("retrieved_at"), "source.retrieved_at")
    age_seconds = (as_of - retrieved_at).total_seconds()
    if age_seconds < 0:
        raise VerificationError("advisory snapshot is from the future")
    if age_seconds > max_age_days * 86400:
        raise VerificationError(
            f"advisory snapshot is older than {max_age_days} day(s)"
        )

    advisories: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, advisory in enumerate(raw["advisories"]):
        label = f"advisories[{index}]"
        if (
            not isinstance(advisory, dict)
            or set(advisory)
            != {
                "ghsa_id",
                "html_url",
                "severity",
                "updated_at",
                "withdrawn_at",
                "vulnerabilities",
            }
            or not isinstance(advisory.get("ghsa_id"), str)
            or GHSA_RE.fullmatch(advisory["ghsa_id"]) is None
            or advisory["ghsa_id"] in identifiers
            or not isinstance(advisory.get("html_url"), str)
            or advisory["html_url"]
            != f"https://github.com/advisories/{advisory['ghsa_id']}"
            or advisory.get("severity") not in {"unknown", "low", "medium", "high", "critical"}
            or not isinstance(advisory.get("vulnerabilities"), list)
        ):
            raise VerificationError(f"{label} fields are malformed")
        parse_time(advisory.get("updated_at"), f"{label}.updated_at")
        if advisory.get("withdrawn_at") is not None:
            parse_time(advisory["withdrawn_at"], f"{label}.withdrawn_at")
        for vulnerability_index, vulnerability in enumerate(advisory["vulnerabilities"]):
            vulnerability_label = f"{label}.vulnerabilities[{vulnerability_index}]"
            if (
                not isinstance(vulnerability, dict)
                or set(vulnerability)
                != {
                    "ecosystem",
                    "package",
                    "vulnerable_version_range",
                    "patched_versions",
                }
                or vulnerability.get("ecosystem") != "actions"
                or not isinstance(vulnerability.get("package"), str)
                or PACKAGE_RE.fullmatch(vulnerability["package"]) is None
                or not isinstance(vulnerability.get("vulnerable_version_range"), str)
                or not vulnerability["vulnerable_version_range"]
                or (
                    vulnerability.get("patched_versions") is not None
                    and not isinstance(vulnerability["patched_versions"], str)
                )
            ):
                raise VerificationError(f"{vulnerability_label} is malformed")
        identifiers.add(advisory["ghsa_id"])
        advisories.append(advisory)
    return advisories


def comparator_matches(version: tuple[int, int, int], comparator: str) -> bool:
    match = COMPARATOR_RE.fullmatch(comparator.strip())
    if match is None:
        raise VerificationError(
            f"unsupported advisory version comparator {comparator!r}"
        )
    target = parse_version(match.group("version"), "advisory comparator")
    operator = match.group("operator") or "="
    return {
        "=": version == target,
        ">": version > target,
        ">=": version >= target,
        "<": version < target,
        "<=": version <= target,
    }[operator]


def range_matches(version: tuple[int, int, int], expression: str) -> bool:
    alternatives = [alternative.strip() for alternative in expression.split("||")]
    if not alternatives or any(not alternative for alternative in alternatives):
        raise VerificationError("advisory version range is malformed")
    for alternative in alternatives:
        comparators = [item.strip() for item in alternative.split(",")]
        if any(not comparator for comparator in comparators):
            raise VerificationError("advisory version range is malformed")
        if all(comparator_matches(version, comparator) for comparator in comparators):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--as-of", required=True, help="RFC3339 UTC timestamp")
    parser.add_argument("--max-age-days", type=int, default=7)
    args = parser.parse_args()
    try:
        if args.max_age_days < 1:
            raise VerificationError("max-age-days must be positive")
        as_of = parse_time(args.as_of, "as-of")
        actions = load_inventory(args.inventory)
        advisories = load_snapshot(
            args.snapshot,
            as_of=as_of,
            max_age_days=args.max_age_days,
        )
        active = [advisory for advisory in advisories if advisory["withdrawn_at"] is None]
        findings = 0
        for action in actions:
            matches: list[str] = []
            version = parse_version(action["version"], "inventory version")
            for advisory in active:
                for vulnerability in advisory["vulnerabilities"]:
                    if (
                        vulnerability["package"].lower() == action["package"].lower()
                        and range_matches(
                            version, vulnerability["vulnerable_version_range"]
                        )
                    ):
                        matches.append(advisory["ghsa_id"])
                        break
            identity = (
                f"{action['package']}@{action['version']} "
                f"sha={action['commit_sha'][:12]}"
            )
            if matches:
                print(
                    f"FAIL {identity} affected_by={','.join(sorted(matches))}"
                )
                findings += 1
            else:
                print(f"PASS {identity} no reviewed advisory match")
    except (OSError, VerificationError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    if findings:
        print(
            f"REJECTED {findings} vulnerable Action release(s) "
            f"from {len(actions)} inventory item(s)"
        )
        return 1
    print(
        f"ACCEPTED {len(actions)} Action release(s) checked against "
        f"{len(active)} active reviewed advisory record(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
