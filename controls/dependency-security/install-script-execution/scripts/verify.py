#!/usr/bin/env python3
"""Verify repository-owned dependency install execution controls."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REFERENCE_MAXIMUM_APPROVAL_HOURS = 720
EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z-]+)+(?:\+[0-9A-Za-z.-]+)?$")
PACKAGE_RE = re.compile(r"^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$", re.IGNORECASE)
SHA256_RE = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}(?:\s|$)")


class InputError(ValueError):
    """Raised when input cannot be parsed and no reliable verdict is possible."""


@dataclass(frozen=True)
class Approval:
    ecosystem: str
    package: str
    version: str
    owner: str
    approved_by: str
    justification: str
    created_at: datetime
    expires_at: datetime


def read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InputError(f"cannot read {label} {path}: {error}") from error


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path, label))
    except json.JSONDecodeError as error:
        raise InputError(f"cannot parse {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InputError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise InputError(f"{label} must use UTC")
    return parsed


def text_field(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label} must be non-empty text")
    return value.strip()


def parse_bool(value: str, label: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise InputError(f"{label} must be true or false")


def load_policy(path: Path, as_of: datetime) -> tuple[list[Approval], list[str]]:
    policy = load_json(path, "policy")
    findings: list[str] = []
    if policy.get("default_action") != "deny":
        findings.append("policy.default_action must be deny")

    maximum = policy.get("maximum_approval_hours")
    if not isinstance(maximum, int) or maximum <= 0:
        raise InputError("policy.maximum_approval_hours must be a positive integer")
    if maximum > REFERENCE_MAXIMUM_APPROVAL_HOURS:
        findings.append(
            "policy.maximum_approval_hours exceeds reference maximum "
            f"{REFERENCE_MAXIMUM_APPROVAL_HOURS}"
        )
    effective_maximum = min(maximum, REFERENCE_MAXIMUM_APPROVAL_HOURS)

    raw_approvals = policy.get("approvals")
    if not isinstance(raw_approvals, list):
        raise InputError("policy.approvals must be a list")
    approvals: list[Approval] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_approvals):
        label = f"policy.approvals[{index}]"
        if not isinstance(raw, dict):
            raise InputError(f"{label} must be an object")
        ecosystem = text_field(raw.get("ecosystem"), f"{label}.ecosystem")
        package = text_field(raw.get("package"), f"{label}.package")
        version = text_field(raw.get("version"), f"{label}.version")
        if ecosystem not in {"npm", "pnpm", "bun"}:
            findings.append(f"{label}.ecosystem is not supported: {ecosystem}")
        if not PACKAGE_RE.fullmatch(package):
            findings.append(f"{label}.package must be an exact package name")
        if not EXACT_VERSION_RE.fullmatch(version):
            findings.append(f"{label}.version must be an exact version")
        key = (ecosystem, package, version)
        if key in seen:
            findings.append(f"{label} duplicates {ecosystem}:{package}@{version}")
        seen.add(key)

        owner = text_field(raw.get("owner"), f"{label}.owner")
        approved_by = text_field(raw.get("approved_by"), f"{label}.approved_by")
        justification = text_field(
            raw.get("justification"), f"{label}.justification"
        )
        created_at = parse_timestamp(raw.get("created_at"), f"{label}.created_at")
        expires_at = parse_timestamp(raw.get("expires_at"), f"{label}.expires_at")
        if owner == approved_by:
            findings.append(f"{ecosystem}:{package}@{version} owner and approver must differ")
        if len(justification) < 20:
            findings.append(f"{ecosystem}:{package}@{version} justification is too short")
        if expires_at <= created_at:
            findings.append(f"{ecosystem}:{package}@{version} has invalid approval period")
        elif expires_at - created_at > timedelta(hours=effective_maximum):
            findings.append(
                f"{ecosystem}:{package}@{version} approval exceeds "
                f"{effective_maximum} hours"
            )
        if not (created_at <= as_of < expires_at):
            findings.append(f"{ecosystem}:{package}@{version} approval is not active")
        approvals.append(
            Approval(
                ecosystem,
                package,
                version,
                owner,
                approved_by,
                justification,
                created_at,
                expires_at,
            )
        )
    return approvals, findings


def parse_npmrc(path: Path) -> dict[str, str]:
    settings: dict[str, str] = {}
    for number, raw_line in enumerate(read_text(path, "npm config").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            raise InputError(f"npm config line {number} must be key=value")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key or key in settings:
            raise InputError(f"npm config line {number} has empty or duplicate key")
        settings[key] = value
    return settings


def verify_npm(profile: Path) -> list[str]:
    settings = parse_npmrc(profile / "npm" / ".npmrc")
    findings: list[str] = []
    try:
        ignore_scripts = parse_bool(settings["ignore-scripts"], "npm ignore-scripts")
    except KeyError as error:
        raise InputError("npm config missing ignore-scripts") from error
    if not ignore_scripts:
        findings.append("npm ignore-scripts must be true")
    if "dangerously-allow-all-scripts" in settings and parse_bool(
        settings["dangerously-allow-all-scripts"],
        "npm dangerously-allow-all-scripts",
    ):
        findings.append("npm dangerously-allow-all-scripts must not be true")
    return findings


def parse_pnpm(path: Path) -> tuple[dict[str, bool], dict[str, bool]]:
    root: dict[str, bool] = {}
    allow_builds: dict[str, bool] = {}
    section: str | None = None
    for number, raw_line in enumerate(read_text(path, "pnpm config").splitlines(), 1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line or ":" not in raw_line:
            raise InputError(f"pnpm config line {number} is not supported YAML")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        key, value = (part.strip() for part in raw_line.strip().split(":", 1))
        if indent == 0:
            if value == "":
                section = key
                continue
            section = None
            if key in root:
                raise InputError(f"pnpm config line {number} duplicates {key}")
            root[key] = parse_bool(value, f"pnpm {key}")
        elif indent == 2 and section == "allowBuilds":
            if not key or key in allow_builds:
                raise InputError(f"pnpm config line {number} has invalid allowBuilds key")
            allow_builds[key] = parse_bool(value, f"pnpm allowBuilds.{key}")
        else:
            raise InputError(f"pnpm config line {number} has unsupported structure")
    return root, allow_builds


def split_package_selector(selector: str) -> tuple[str, str] | None:
    if selector.startswith("@"):
        slash = selector.find("/")
        split_at = selector.rfind("@")
        if slash < 0 or split_at <= slash:
            return None
    else:
        split_at = selector.rfind("@")
        if split_at <= 0:
            return None
    package, version = selector[:split_at], selector[split_at + 1 :]
    if not PACKAGE_RE.fullmatch(package) or not EXACT_VERSION_RE.fullmatch(version):
        return None
    return package, version


def verify_pnpm(
    profile: Path, approvals: list[Approval]
) -> tuple[list[str], set[tuple[str, str, str]]]:
    root, allow_builds = parse_pnpm(profile / "pnpm" / "pnpm-workspace.yaml")
    findings: list[str] = []
    used: set[tuple[str, str, str]] = set()
    if root.get("strictDepBuilds") is not True:
        findings.append("pnpm strictDepBuilds must be true")
    if root.get("dangerouslyAllowAllBuilds") is not False:
        findings.append("pnpm dangerouslyAllowAllBuilds must be false")
    approval_keys = {
        (approval.ecosystem, approval.package, approval.version) for approval in approvals
    }
    for selector, allowed in allow_builds.items():
        if not allowed:
            continue
        parsed = split_package_selector(selector)
        if parsed is None:
            findings.append(f"pnpm allowBuilds entry must pin exact version: {selector}")
            continue
        package, version = parsed
        key = ("pnpm", package, version)
        if key not in approval_keys:
            findings.append(f"pnpm allowBuilds entry lacks active approval: {selector}")
        else:
            used.add(key)
    return findings, used


def verify_bun(profile: Path) -> list[str]:
    path = profile / "bun" / "bunfig.toml"
    try:
        config = tomllib.loads(read_text(path, "Bun config"))
    except tomllib.TOMLDecodeError as error:
        raise InputError(f"cannot parse Bun config {path}: {error}") from error
    install = config.get("install")
    if not isinstance(install, dict):
        raise InputError("Bun config missing [install] table")
    findings: list[str] = []
    if install.get("ignoreScripts") is not True:
        findings.append("Bun install.ignoreScripts must be true")
    if install.get("exact") is not True:
        findings.append("Bun install.exact must be true")
    if install.get("frozenLockfile") is not True:
        findings.append("Bun install.frozenLockfile must be true")
    return findings


def logical_requirement_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        lines.append(pending)
        pending = ""
    if pending:
        raise InputError("pip requirements ends with an incomplete continuation")
    return lines


def verify_pip(profile: Path) -> list[str]:
    lines = logical_requirement_lines(
        read_text(profile / "pip" / "requirements.txt", "pip requirements")
    )
    findings: list[str] = []
    options = {line.replace(" ", "") for line in lines if line.startswith("-")}
    if "--only-binary=:all:" not in options:
        findings.append("pip requirements must set --only-binary=:all:")
    if "--require-hashes" not in options:
        findings.append("pip requirements must set --require-hashes")
    if any(option.startswith("--no-binary") for option in options):
        findings.append("pip requirements must not enable source distributions")

    requirements = [line for line in lines if not line.startswith("-")]
    if not requirements:
        raise InputError("pip requirements must contain at least one package")
    for requirement in requirements:
        spec = requirement.split()[0]
        if (
            "==" not in spec
            or spec.startswith((".", "/", "git+", "http:", "https:"))
            or any(token in spec for token in ("*", ">=", "<=", "~=", "!=", " @ "))
        ):
            findings.append(f"pip requirement must use an exact version: {spec}")
        if not SHA256_RE.search(requirement):
            findings.append(f"pip requirement must have a SHA-256 hash: {spec}")
    return findings


def verify(policy: Path, profile: Path, as_of: datetime) -> tuple[list[str], int]:
    approvals, findings = load_policy(policy, as_of)
    findings.extend(verify_npm(profile))
    pnpm_findings, used = verify_pnpm(profile, approvals)
    findings.extend(pnpm_findings)
    findings.extend(verify_bun(profile))
    findings.extend(verify_pip(profile))
    for approval in approvals:
        key = (approval.ecosystem, approval.package, approval.version)
        if key not in used:
            findings.append(
                f"approval is unused: {approval.ecosystem}:{approval.package}@{approval.version}"
            )
    return findings, len(used)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify dependency install-time execution policy."
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--profile-dir", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    try:
        as_of = parse_timestamp(args.as_of, "--as-of")
        findings, approved_count = verify(args.policy, args.profile_dir, as_of)
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print(
        "PASS install execution policy: "
        f"4 ecosystem profiles verified, {approved_count} approved script"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
