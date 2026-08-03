#!/usr/bin/env python3
"""Review only the dependency graph delta and fail closed on missing evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SEVERITY = {"unknown": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


class ReviewError(RuntimeError):
    """The dependency decision cannot be evaluated."""

    def __init__(self, message: str, check_id: str = "DCR-009") -> None:
        super().__init__(message)
        self.check_id = check_id


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError(f"cannot load {label}") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be a JSON object")
    return value


def parse_time(value: Any, label: str, check_id: str = "DCR-009") -> datetime:
    if not isinstance(value, str):
        raise ReviewError(f"{label} must be an RFC3339 timestamp", check_id)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReviewError(f"{label} must be an RFC3339 timestamp", check_id) from error
    if parsed.tzinfo is None:
        raise ReviewError(f"{label} must include a timezone", check_id)
    return parsed


def require_text(value: dict[str, Any], key: str, label: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise ReviewError(f"{label}.{key} must be non-empty text")
    return result


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReviewError(f"{label} must be an exact SHA-256")
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema") != "psb-dependency-review-policy/1.0":
        raise ReviewError("unsupported dependency review policy schema")
    require_digest(policy.get("policy_bundle_sha256"), "policy.policy_bundle_sha256")
    threshold = policy.get("vulnerability_threshold")
    if threshold not in SEVERITY or threshold == "unknown":
        raise ReviewError("policy vulnerability threshold is invalid")
    for field in (
        "allowed_registries",
        "allowed_repository_prefixes",
        "denied_licenses",
    ):
        values = policy.get(field)
        if not isinstance(values, list) or not values or not all(
            isinstance(item, str) and item for item in values
        ):
            raise ReviewError(f"policy.{field} must be a non-empty string list")
    if policy.get("require_verified_provenance") is not True:
        raise ReviewError("policy must require verified provenance", "DCR-006")
    if policy.get("minimum_non_author_approvals") != 1:
        raise ReviewError("policy must require one non-author approval", "DCR-007")
    maximum_age = policy.get("maximum_advisory_age_seconds")
    exception_age = policy.get("maximum_exception_age_seconds")
    if (
        not isinstance(maximum_age, int)
        or isinstance(maximum_age, bool)
        or maximum_age <= 0
        or not isinstance(exception_age, int)
        or isinstance(exception_age, bool)
        or exception_age <= 0
    ):
        raise ReviewError("policy age limits must be positive integers")


def validate_lock(lock: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    if lock.get("schema") != "psb-normalized-dependency-lock/1.0":
        raise ReviewError(f"unsupported {label} schema", "DCR-001")
    require_digest(lock.get("graph_sha256"), f"{label}.graph_sha256")
    revision = lock.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise ReviewError(f"{label}.revision must be a full commit SHA", "DCR-001")
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise ReviewError(f"{label}.packages must be a list", "DCR-001")
    by_name: dict[str, dict[str, Any]] = {}
    purls: set[str] = set()
    for index, package in enumerate(packages):
        package_label = f"{label}.packages[{index}]"
        if not isinstance(package, dict):
            raise ReviewError(f"{package_label} must be an object", "DCR-001")
        name = require_text(package, "name", package_label)
        purl = require_text(package, "purl", package_label)
        version = require_text(package, "version", package_label)
        if purl != f"pkg:generic/{name}@{version}":
            raise ReviewError(
                f"{package_label}.purl does not match name and exact version",
                "DCR-003",
            )
        if name in by_name or purl in purls:
            raise ReviewError(f"{label} contains duplicate package identity", "DCR-001")
        if package.get("scope") not in {"runtime", "development"}:
            raise ReviewError(f"{package_label}.scope is invalid", "DCR-002")
        if package.get("direct") not in {True, False}:
            raise ReviewError(f"{package_label}.direct must be boolean", "DCR-002")
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list) or not all(
            isinstance(item, str) and item for item in dependencies
        ):
            raise ReviewError(f"{package_label}.dependencies must be a string list", "DCR-002")
        source = package.get("source")
        provenance = package.get("provenance")
        if not isinstance(source, dict) or not isinstance(provenance, dict):
            raise ReviewError(f"{package_label} source and provenance are required")
        for key in ("registry", "repository", "commit"):
            require_text(source, key, f"{package_label}.source")
        require_text(package, "license", package_label)
        by_name[name] = package
        purls.add(purl)
    for package in packages:
        missing = set(package["dependencies"]) - set(by_name)
        if missing:
            raise ReviewError(
                f"{label} dependency edge references missing package", "DCR-002"
            )
    return by_name


def source_identity(package: dict[str, Any]) -> tuple[str, str, str]:
    source = package["source"]
    return source["registry"], source["repository"], source["commit"]


def change_ids(
    base: dict[str, dict[str, Any]], proposed: dict[str, dict[str, Any]]
) -> tuple[list[str], set[str]]:
    changes: list[str] = []
    impacted: set[str] = set()
    for name in sorted(set(base) | set(proposed)):
        before = base.get(name)
        after = proposed.get(name)
        if before is None and after is not None:
            changes.append(f"package:add:{after['purl']}")
            impacted.add(name)
            continue
        if after is None and before is not None:
            changes.append(f"package:remove:{before['purl']}")
            continue
        assert before is not None and after is not None
        if before["version"] != after["version"]:
            changes.append(
                f"version:{name}:{before['version']}->{after['version']}"
            )
            impacted.add(name)
        elif any(
            before[field] != after[field]
            for field in ("scope", "direct", "license", "provenance")
        ):
            changes.append(f"metadata:{name}:{after['purl']}")
            impacted.add(name)
        if source_identity(before) != source_identity(after):
            changes.append(f"source:{name}:{after['purl']}")
            impacted.add(name)
    base_edges = {
        (name, dependency) for name, package in base.items() for dependency in package["dependencies"]
    }
    proposed_edges = {
        (name, dependency)
        for name, package in proposed.items()
        for dependency in package["dependencies"]
    }
    for parent, dependency in sorted(proposed_edges - base_edges):
        changes.append(
            f"edge:add:{proposed[parent]['purl']}->{proposed[dependency]['purl']}"
        )
        impacted.add(parent)
        impacted.add(dependency)
    for parent, dependency in sorted(base_edges - proposed_edges):
        changes.append(f"edge:remove:{base[parent]['purl']}->{base[dependency]['purl']}")
    return changes, impacted


def validate_advisories(
    snapshot: dict[str, Any], policy: dict[str, Any], as_of: datetime
) -> list[dict[str, Any]]:
    if snapshot.get("schema") != "psb-dependency-advisory-snapshot/1.0":
        raise ReviewError("unsupported advisory snapshot schema", "DCR-004")
    if snapshot.get("complete") is not True or snapshot.get("status") != "complete":
        raise ReviewError("advisory snapshot is incomplete", "DCR-004")
    require_digest(snapshot.get("snapshot_sha256"), "advisory.snapshot_sha256")
    generated = parse_time(snapshot.get("generated_at"), "advisory.generated_at", "DCR-004")
    maximum_age = timedelta(seconds=policy["maximum_advisory_age_seconds"])
    if generated > as_of or as_of - generated > maximum_age:
        raise ReviewError("advisory snapshot is stale or from the future", "DCR-004")
    advisories = snapshot.get("advisories")
    if not isinstance(advisories, list):
        raise ReviewError("advisory list is malformed", "DCR-004")
    for advisory in advisories:
        if (
            not isinstance(advisory, dict)
            or not isinstance(advisory.get("id"), str)
            or not isinstance(advisory.get("purl"), str)
            or advisory.get("severity") not in SEVERITY
        ):
            raise ReviewError("advisory record is malformed", "DCR-004")
    return advisories


def finding(check: str, target: str, reason: str) -> tuple[str, str, str, str]:
    return check, f"{check}:{target}", target, reason


def validate_exceptions(
    review: dict[str, Any], policy: dict[str, Any], as_of: datetime
) -> tuple[set[str], list[tuple[str, str, str, str]]]:
    exceptions = review.get("exceptions")
    if not isinstance(exceptions, list):
        raise ReviewError("review.exceptions must be a list", "DCR-008")
    accepted: set[str] = set()
    findings: list[tuple[str, str, str, str]] = []
    for index, exception in enumerate(exceptions):
        target = f"exception-{index + 1}"
        if not isinstance(exception, dict):
            findings.append(finding("DCR-008", target, "malformed-exception"))
            continue
        finding_key = exception.get("finding_key")
        owner = exception.get("owner")
        approver = exception.get("approver")
        justification = exception.get("justification")
        try:
            created = parse_time(exception.get("created_at"), "exception.created_at", "DCR-008")
            expires = parse_time(exception.get("expires_at"), "exception.expires_at", "DCR-008")
        except ReviewError:
            findings.append(finding("DCR-008", target, "invalid-exception-time"))
            continue
        if (
            not isinstance(finding_key, str)
            or "*" in finding_key
            or not isinstance(owner, str)
            or not owner
            or not isinstance(approver, str)
            or not approver
            or approver == owner
            or not isinstance(justification, str)
            or len(justification) < 20
            or created > as_of
            or expires <= as_of
            or expires - created > timedelta(seconds=policy["maximum_exception_age_seconds"])
        ):
            findings.append(finding("DCR-008", target, "broad-unowned-or-expired"))
            continue
        accepted.add(finding_key)
    return accepted, findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--base-lock", type=Path, required=True)
    parser.add_argument("--proposed-lock", type=Path, required=True)
    parser.add_argument("--advisories", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()

    try:
        as_of = parse_time(args.as_of, "--as-of")
        policy = load_json(args.policy, "policy")
        base_lock = load_json(args.base_lock, "base lock")
        proposed_lock = load_json(args.proposed_lock, "proposed lock")
        review = load_json(args.review, "review")
        snapshot = load_json(args.advisories, "advisory snapshot")
        validate_policy(policy)
        base = validate_lock(base_lock, "base lock")
        proposed = validate_lock(proposed_lock, "proposed lock")
        changes, impacted = change_ids(base, proposed)
        if not changes:
            raise ReviewError("dependency review contains no graph change", "DCR-001")
        advisories = validate_advisories(snapshot, policy, as_of)
        if review.get("schema") != "psb-dependency-change-review/1.0":
            raise ReviewError("unsupported review schema", "DCR-007")
        if (
            review.get("base_revision") != base_lock["revision"]
            or review.get("head_revision") != proposed_lock["revision"]
            or review.get("base_graph_sha256") != base_lock["graph_sha256"]
            or review.get("head_graph_sha256") != proposed_lock["graph_sha256"]
            or review.get("policy_bundle_sha256") != policy["policy_bundle_sha256"]
        ):
            raise ReviewError("review is not bound to exact base head and policy", "DCR-001")
        if review.get("advisory_snapshot_sha256") != snapshot["snapshot_sha256"]:
            raise ReviewError(
                "review is not bound to exact advisory snapshot", "DCR-004"
            )
        approved = review.get("approved_change_ids")
        if (
            not isinstance(approved, list)
            or not all(isinstance(item, str) and item for item in approved)
            or len(approved) != len(set(approved))
            or set(approved) != set(changes)
        ):
            raise ReviewError("reviewed dependency delta is incomplete", "DCR-007")

        findings: list[tuple[str, str, str, str]] = []
        if (
            review.get("author") == review.get("reviewer")
            or review.get("reviewer_role") != "dependency-reviewer"
            or review.get("approval_count") != 1
        ):
            findings.append(finding("DCR-007", "review", "non-author-approval-missing"))

        for name in sorted(impacted):
            package = proposed[name]
            purl = package["purl"]
            registry, repository, commit = source_identity(package)
            if (
                registry not in policy["allowed_registries"]
                or not any(
                    repository.startswith(prefix)
                    for prefix in policy["allowed_repository_prefixes"]
                )
                or not REVISION_RE.fullmatch(commit)
            ):
                findings.append(finding("DCR-003", purl, "unapproved-or-mutable-source"))
            if package["license"] in policy["denied_licenses"]:
                findings.append(finding("DCR-005", purl, "denied-license"))
            provenance = package["provenance"]
            if (
                provenance.get("status") != "verified"
                or provenance.get("subject_purl") != purl
                or not SHA256_RE.fullmatch(str(provenance.get("statement_sha256", "")))
            ):
                findings.append(finding("DCR-006", purl, "provenance-gap"))
            for advisory in advisories:
                if (
                    advisory["purl"] == purl
                    and SEVERITY[advisory["severity"]]
                    >= SEVERITY[policy["vulnerability_threshold"]]
                ):
                    findings.append(
                        finding("DCR-004", purl, f"advisory-{advisory['id']}")
                    )

        accepted_exceptions, exception_findings = validate_exceptions(review, policy, as_of)
        findings.extend(exception_findings)
        finding_keys = {item[1] for item in findings}
        for unused in sorted(accepted_exceptions - finding_keys):
            findings.append(finding("DCR-008", unused, "exception-target-not-present"))
        remaining = [item for item in findings if item[1] not in accepted_exceptions]
    except ReviewError as error:
        print(f"ERROR {error.check_id} dependency review unavailable: {error}")
        print("RESULT ERROR; dependency change is not approved")
        return 2

    for check_id, _, target, reason in remaining:
        print(f"BLOCK {check_id} target={target} reason={reason}")
    if remaining:
        print(f"RESULT BLOCKED {len(remaining)} finding(s)")
        return 1

    print(f"PASS DCR-001 exact base and head graph delta contains {len(changes)} change(s)")
    print("PASS DCR-002 direct transitive and edge context preserved")
    print("PASS DCR-003 exact version and approved immutable source verified")
    print("PASS DCR-004 fresh complete advisory snapshot has no threshold finding")
    print("PASS DCR-005 changed dependency licenses satisfy policy")
    print("PASS DCR-006 changed dependency provenance is verified and subject-bound")
    print("PASS DCR-007 exact delta has one non-author dependency reviewer approval")
    print("PASS DCR-008 no invalid or unexpired dependency exception remains")
    print("PASS DCR-009 policy and advisory evaluation completed")
    print("RESULT ACCEPTED dependency change review passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
