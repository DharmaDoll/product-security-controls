#!/usr/bin/env python3
"""Validate a complete, integrity-bound register of time-bound exceptions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import MetadataError, discover_controls, parse_yaml_subset  # noqa: E402


EXCEPTION_SCHEMA = "psb-security-exception/v1"
REGISTER_SCHEMA = "psb-security-exception-register/v1"
POLICY_SCHEMA = "psb-security-exception-policy/v1"
EXCEPTION_ID_RE = re.compile(r"^EXC-[0-9]{4}-[0-9]{4}$")
CONTROL_ID_RE = re.compile(r"^PSB-[A-Z]+-[0-9]{3}$")
CHECK_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")
IDENTITY_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
TICKET_RE = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[1-9][0-9]{0,9}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_SCOPE_VALUES = {"*", "all", "any", "global", "default", "/", "."}
FORBIDDEN_KEY_PARTS = {
    "access_key",
    "authorization",
    "credential",
    "password",
    "payload",
    "private_key",
    "request_body",
    "response_body",
    "secret",
    "source_code",
    "token",
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
)
EXCEPTION_FIELDS = {
    "schema",
    "interface_version",
    "id",
    "control_id",
    "check_id",
    "target_type",
    "target_id",
    "environment",
    "owner",
    "risk_reviewer",
    "approved_by",
    "justification",
    "risk_statement",
    "compensating_controls",
    "created_at",
    "expires_at",
    "approval_reference",
    "remediation_ticket",
}
POLICY_FIELDS = {
    "schema",
    "interface_version",
    "max_lifetime_days",
    "expiring_window_days",
    "max_register_age_minutes",
    "min_justification_chars",
    "min_risk_statement_chars",
    "require_independent_approval",
    "require_independent_risk_review",
    "allowed_target_types",
}
REGISTER_FIELDS = {
    "schema",
    "interface_version",
    "source_status",
    "complete",
    "observed_at",
    "entries",
}


class InputError(ValueError):
    """Raised when evidence cannot support a reliable decision."""


@dataclass(frozen=True)
class EvaluatedException:
    exception_id: str
    control_id: str
    check_id: str
    expires_at: datetime | None
    state: str
    issues: tuple[str, ...]


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InputError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} is not a valid RFC 3339 timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise InputError(f"{label} must use UTC")
    return parsed


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    reject_sensitive_content(value, label)
    return value


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    try:
        value = parse_yaml_subset(path)
    except (OSError, UnicodeError, MetadataError) as error:
        raise InputError(f"cannot load {label}: {error}") from error
    reject_sensitive_content(value, label)
    return value


def reject_sensitive_content(value: Any, label: str, key_path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            path = f"{key_path}.{key}" if key_path else str(key)
            if any(part in normalized for part in FORBIDDEN_KEY_PARTS):
                raise InputError(f"{label} contains forbidden sensitive field {path}")
            reject_sensitive_content(child, label, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_content(child, label, f"{key_path}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            raise InputError(f"{label} contains credential-like content in {key_path}")


def require_text(value: Any, label: str, issues: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        issues.append(f"{label} is required")
        return ""
    return value.strip()


def exact_scope(value: Any, label: str, issues: list[str]) -> str:
    text = require_text(value, label, issues)
    if not text:
        return text
    normalized = text.lower()
    if (
        normalized in FORBIDDEN_SCOPE_VALUES
        or any(character in text for character in "*?[]")
        or len(text) > 180
    ):
        issues.append(f"{label} must identify one exact non-wildcard scope")
    return text


def load_policy(path: Path) -> dict[str, Any]:
    policy = load_yaml(path, "exception policy")
    if set(policy) != POLICY_FIELDS:
        raise InputError("policy fields do not match the versioned interface")
    if policy.get("schema") != POLICY_SCHEMA:
        raise InputError(f"policy.schema must be {POLICY_SCHEMA}")
    if policy.get("interface_version") != "1.0":
        raise InputError("policy.interface_version must be 1.0")
    integer_fields = (
        "max_lifetime_days",
        "expiring_window_days",
        "max_register_age_minutes",
        "min_justification_chars",
        "min_risk_statement_chars",
    )
    for field in integer_fields:
        if not isinstance(policy.get(field), int) or policy[field] <= 0:
            raise InputError(f"policy.{field} must be a positive integer")
    if policy["expiring_window_days"] >= policy["max_lifetime_days"]:
        raise InputError("policy.expiring_window_days must be less than max_lifetime_days")
    for field in ("require_independent_approval", "require_independent_risk_review"):
        if policy.get(field) is not True:
            raise InputError(f"policy.{field} must be true")
    target_types = policy.get("allowed_target_types")
    if not isinstance(target_types, list) or not target_types:
        raise InputError("policy.allowed_target_types must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in target_types):
        raise InputError("policy.allowed_target_types entries must be non-empty strings")
    if len(set(target_types)) != len(target_types):
        raise InputError("policy.allowed_target_types must not contain duplicates")
    return policy


def catalog_checks() -> dict[str, set[str]]:
    try:
        controls = discover_controls()
    except (OSError, UnicodeError, MetadataError) as error:
        raise InputError(f"cannot load repository control catalog: {error}") from error
    result: dict[str, set[str]] = {}
    for control in controls:
        control_id = control.get("id")
        checks = control.get("checks")
        if not isinstance(control_id, str) or not isinstance(checks, list):
            continue
        result[control_id] = {
            item["id"]
            for item in checks
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
    return result


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise InputError(f"cannot read registered exception file {path.name}: {error}") from error
    return digest.hexdigest()


def verify_register(
    manifest: dict[str, Any], directory: Path, policy: dict[str, Any], as_of: datetime
) -> list[Path]:
    if set(manifest) != REGISTER_FIELDS:
        raise InputError("register fields do not match the versioned interface")
    if manifest.get("schema") != REGISTER_SCHEMA:
        raise InputError(f"register.schema must be {REGISTER_SCHEMA}")
    if manifest.get("interface_version") != policy["interface_version"]:
        raise InputError("register.interface_version does not match policy")
    if manifest.get("source_status") != "ok":
        raise InputError("exception register source_status is not ok")
    if manifest.get("complete") is not True:
        raise InputError("exception register is not declared complete")
    observed_at = parse_timestamp(manifest.get("observed_at"), "register.observed_at")
    if observed_at > as_of:
        raise InputError("register.observed_at is in the future")
    if as_of - observed_at > timedelta(minutes=policy["max_register_age_minutes"]):
        raise InputError("exception register evidence is stale")

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise InputError("register.entries must be a list")
    declared: dict[str, str] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise InputError(f"register.entries[{index}] must contain only path and sha256")
        name = entry.get("path")
        digest = entry.get("sha256")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name.endswith(".yaml")
        ):
            raise InputError(f"register.entries[{index}].path must be one YAML filename")
        if name in declared:
            raise InputError(f"register contains duplicate path {name}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise InputError(f"register entry {name} has invalid SHA-256")
        declared[name] = digest

    if not directory.is_dir():
        raise InputError("exceptions directory is unavailable")
    actual = {path.name: path for path in directory.iterdir() if path.is_file()}
    if any(not name.endswith(".yaml") for name in actual):
        raise InputError("exceptions directory contains an unregistered non-YAML file")
    symlinks = sorted(name for name, path in actual.items() if path.is_symlink())
    if symlinks:
        raise InputError(f"exception file must not be a symbolic link: {symlinks[0]}")
    missing = sorted(set(declared) - set(actual))
    extra = sorted(set(actual) - set(declared))
    if missing:
        raise InputError(f"registered exception file is missing: {missing[0]}")
    if extra:
        raise InputError(f"exception file is absent from complete register: {extra[0]}")
    for name, expected in sorted(declared.items()):
        if file_sha256(actual[name]) != expected:
            raise InputError(f"registered exception digest mismatch: {name}")
    return [actual[name] for name in sorted(actual)]


def evaluate_exception(
    path: Path,
    value: dict[str, Any],
    policy: dict[str, Any],
    catalog: dict[str, set[str]],
    as_of: datetime,
) -> EvaluatedException:
    issues: list[str] = []
    unknown = sorted(set(value) - EXCEPTION_FIELDS)
    missing = sorted(EXCEPTION_FIELDS - set(value))
    if unknown:
        issues.append(f"unknown field {unknown[0]}")
    if missing:
        issues.append(f"missing required field {missing[0]}")

    raw_id = value.get("id")
    exception_id = raw_id if isinstance(raw_id, str) and EXCEPTION_ID_RE.fullmatch(raw_id) else path.stem
    if not isinstance(raw_id, str) or not EXCEPTION_ID_RE.fullmatch(raw_id):
        issues.append("id must use EXC-YYYY-NNNN format")
    if value.get("schema") != EXCEPTION_SCHEMA:
        issues.append(f"schema must be {EXCEPTION_SCHEMA}")
    if value.get("interface_version") != policy["interface_version"]:
        issues.append("interface_version does not match policy")

    control_id = exact_scope(value.get("control_id"), "control_id", issues)
    check_id = exact_scope(value.get("check_id"), "check_id", issues)
    if control_id and not CONTROL_ID_RE.fullmatch(control_id):
        issues.append("control_id has invalid syntax")
    elif control_id and control_id not in catalog:
        issues.append("control_id is not present in the repository catalog")
    if check_id and not CHECK_ID_RE.fullmatch(check_id):
        issues.append("check_id has invalid syntax")
    elif control_id in catalog and check_id not in catalog[control_id]:
        issues.append("check_id does not belong to control_id")

    target_type = exact_scope(value.get("target_type"), "target_type", issues)
    if target_type and target_type not in set(policy["allowed_target_types"]):
        issues.append("target_type is not allowed by policy")
    exact_scope(value.get("target_id"), "target_id", issues)
    exact_scope(value.get("environment"), "environment", issues)

    identities: dict[str, str] = {}
    for field in ("owner", "risk_reviewer", "approved_by"):
        identity = require_text(value.get(field), field, issues)
        identities[field] = identity
        if identity and not IDENTITY_RE.fullmatch(identity):
            issues.append(f"{field} must be a stable team identity")
    if policy["require_independent_approval"] and identities["owner"] == identities["approved_by"]:
        issues.append("owner and approved_by must differ")
    if policy["require_independent_risk_review"] and len(set(identities.values())) != 3:
        issues.append("owner risk_reviewer and approved_by must be distinct")

    justification = require_text(value.get("justification"), "justification", issues)
    if justification and len(justification) < policy["min_justification_chars"]:
        issues.append("justification is too short")
    risk_statement = require_text(value.get("risk_statement"), "risk_statement", issues)
    if risk_statement and len(risk_statement) < policy["min_risk_statement_chars"]:
        issues.append("risk_statement is too short")

    compensating = value.get("compensating_controls")
    if not isinstance(compensating, list) or not compensating:
        issues.append("compensating_controls must be a non-empty list")
    elif any(not isinstance(item, str) or not item.strip() for item in compensating):
        issues.append("compensating_controls entries must be non-empty text")
    elif len(set(compensating)) != len(compensating):
        issues.append("compensating_controls contains duplicates")

    for field in ("approval_reference", "remediation_ticket"):
        ticket = require_text(value.get(field), field, issues)
        if ticket and not TICKET_RE.fullmatch(ticket):
            issues.append(f"{field} must be an exact ticket identifier")
    if value.get("approval_reference") == value.get("remediation_ticket"):
        issues.append("approval_reference and remediation_ticket must differ")

    created_at: datetime | None = None
    expires_at: datetime | None = None
    for field in ("created_at", "expires_at"):
        try:
            timestamp = parse_timestamp(value.get(field), field)
        except InputError as error:
            issues.append(str(error))
        else:
            if field == "created_at":
                created_at = timestamp
            else:
                expires_at = timestamp
    if created_at and expires_at:
        if expires_at <= created_at:
            issues.append("expires_at must be after created_at")
        elif expires_at - created_at > timedelta(days=policy["max_lifetime_days"]):
            issues.append("exception lifetime exceeds policy maximum")
        if created_at > as_of:
            issues.append("exception is not active yet")

    if issues:
        return EvaluatedException(exception_id, control_id, check_id, expires_at, "INVALID", tuple(issues))
    assert expires_at is not None
    if expires_at <= as_of:
        state = "EXPIRED"
    elif expires_at - as_of <= timedelta(days=policy["expiring_window_days"]):
        state = "EXPIRING"
    else:
        state = "ACTIVE"
    return EvaluatedException(exception_id, control_id, check_id, expires_at, state, ())


def run(args: argparse.Namespace) -> int:
    as_of = parse_timestamp(args.evaluation_time, "evaluation_time")
    policy = load_policy(args.policy)
    manifest = load_json(args.register, "exception register")
    paths = verify_register(manifest, args.exceptions_dir, policy, as_of)
    catalog = catalog_checks()

    evaluated = [
        evaluate_exception(path, load_yaml(path, f"exception {path.name}"), policy, catalog, as_of)
        for path in paths
    ]
    ids = [item.exception_id for item in evaluated]
    duplicates = {item for item in ids if ids.count(item) > 1}
    if duplicates:
        duplicate = sorted(duplicates)[0]
        raise InputError(f"exception register contains duplicate exception id {duplicate}")

    counts = {state: 0 for state in ("ACTIVE", "EXPIRING", "EXPIRED", "INVALID")}
    for item in sorted(evaluated, key=lambda record: record.exception_id):
        counts[item.state] += 1
        if item.state == "INVALID":
            for issue in item.issues:
                print(f"INVALID {item.exception_id}: {issue}")
        else:
            assert item.expires_at is not None
            print(
                f"{item.state} {item.exception_id} control={item.control_id} "
                f"check={item.check_id} expires_at={item.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )

    summary = (
        f"active={counts['ACTIVE']} expiring={counts['EXPIRING']} "
        f"expired={counts['EXPIRED']} invalid={counts['INVALID']}"
    )
    if counts["EXPIRED"] or counts["INVALID"]:
        print(f"FAIL PSB-GOV-002 exception register rejected: {summary}")
        return 1
    print(f"PASS PSB-GOV-002 exception register accepted: {summary}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--register", required=True, type=Path)
    parser.add_argument("--exceptions-dir", required=True, type=Path)
    parser.add_argument("--evaluation-time", required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except InputError as error:
        print(f"ERROR PSB-GOV-002 exception evaluation unavailable: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
