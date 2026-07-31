#!/usr/bin/env python3
"""Verify pinned scanner releases, normalized results, and narrow exceptions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WILDCARD_RE = re.compile(r"[*?\[\]]")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise OSError(f"{label} does not exist: {path}") from error
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {label} {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid {label} JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def text_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def parse_time(value: Any, label: str) -> datetime:
    raw = text_value(value, label)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def sha256_value(value: Any, label: str) -> str:
    raw = text_value(value, label)
    digest = raw.removeprefix("sha256:")
    if SHA256_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def reject(violations: list[str], noun: str) -> int:
    for violation in violations:
        print(f"FAIL {violation}")
    print(f"REJECTED {len(violations)} {noun} violation(s)")
    return 1


def verify_release(policy_path: Path, receipt_path: Path) -> int:
    policy = load_json(policy_path, "policy")
    receipt = load_json(receipt_path, "release receipt")
    if policy.get("schema") != "psb-scanner-policy/v1":
        raise ValueError("unsupported policy schema")
    if receipt.get("schema") != "psb-release-verification-receipt/v1":
        raise ValueError("unsupported release receipt schema")

    expected = mapping(policy.get("tool"), "policy.tool")
    asset = mapping(expected.get("asset"), "policy.tool.asset")
    checksums = mapping(expected.get("checksum_file"), "policy.tool.checksum_file")
    bundle = mapping(expected.get("signature_bundle"), "policy.tool.signature_bundle")
    actual_asset = mapping(receipt.get("asset"), "receipt.asset")
    actual_checksums = mapping(receipt.get("checksum_file"), "receipt.checksum_file")
    actual_bundle = mapping(receipt.get("signature_bundle"), "receipt.signature_bundle")
    verification = mapping(receipt.get("verification"), "receipt.verification")

    for value, label in (
        (asset.get("sha256"), "policy tool asset"),
        (asset.get("extracted_binary_sha256"), "policy extracted scanner binary"),
        (checksums.get("sha256"), "policy checksum file"),
        (bundle.get("sha256"), "policy signature bundle"),
        (actual_asset.get("sha256"), "receipt tool asset"),
        (
            actual_asset.get("extracted_binary_sha256"),
            "receipt extracted scanner binary",
        ),
        (actual_checksums.get("sha256"), "receipt checksum file"),
        (actual_bundle.get("sha256"), "receipt signature bundle"),
    ):
        sha256_value(value, label)

    violations: list[str] = []

    version = text_value(receipt.get("version"), "receipt.version")
    blocked = array(expected.get("blocked_versions"), "policy.tool.blocked_versions")
    if version in blocked:
        violations.append(f"Trivy {version} is in the explicitly blocked release set")

    comparisons = (
        ("tool", expected.get("name"), receipt.get("tool")),
        ("version", expected.get("version"), version),
        ("tag", expected.get("tag"), receipt.get("tag")),
        ("release immutable state", expected.get("release_immutable"), receipt.get("release_immutable")),
        ("asset name", asset.get("name"), actual_asset.get("name")),
        ("asset SHA-256", asset.get("sha256"), actual_asset.get("sha256")),
        (
            "extracted binary SHA-256",
            asset.get("extracted_binary_sha256"),
            actual_asset.get("extracted_binary_sha256"),
        ),
        ("checksum file name", checksums.get("name"), actual_checksums.get("name")),
        ("checksum file SHA-256", checksums.get("sha256"), actual_checksums.get("sha256")),
        ("signature bundle name", bundle.get("name"), actual_bundle.get("name")),
        ("signature bundle SHA-256", bundle.get("sha256"), actual_bundle.get("sha256")),
        (
            "certificate OIDC issuer",
            bundle.get("certificate_oidc_issuer"),
            actual_bundle.get("certificate_oidc_issuer"),
        ),
        (
            "certificate identity",
            bundle.get("certificate_identity"),
            actual_bundle.get("certificate_identity"),
        ),
    )
    for label, wanted, actual in comparisons:
        if actual != wanted:
            violations.append(f"{label} does not match the reviewed release policy")

    if receipt.get("release_immutable") is not True:
        violations.append("release is not recorded as immutable")
    if verification.get("publisher_checksum_verified") is not True:
        violations.append("publisher checksum verification did not succeed")
    if verification.get("sigstore_bundle_verified") is not True:
        violations.append("Sigstore bundle verification did not succeed")
    parse_time(verification.get("verified_at"), "receipt.verification.verified_at")

    if violations:
        return reject(violations, "release integrity")

    print(
        f"PASS Trivy v{version} immutable release, publisher checksum, "
        "and Sigstore identity verified"
    )
    return 0


def verify_artifact(path: Path, expected_sha256: str) -> int:
    expected = sha256_value(expected_sha256, "expected SHA-256")
    try:
        with path.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
    except FileNotFoundError as error:
        raise OSError(f"artifact does not exist: {path}") from error
    except OSError as error:
        raise OSError(f"cannot read artifact {path}: {error}") from error

    if digest != expected:
        return reject(
            [f"artifact SHA-256 mismatch: expected {expected}, got {digest}"],
            "artifact integrity",
        )
    print(f"PASS artifact SHA-256 verified: {digest}")
    return 0


def find_prohibited_key(value: Any, prohibited: set[str], path: str = "$") -> str | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.lower() in prohibited:
                return f"{path}.{key}"
            found = find_prohibited_key(nested, prohibited, f"{path}.{key}")
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            found = find_prohibited_key(nested, prohibited, f"{path}[{index}]")
            if found is not None:
                return found
    return None


def verify_result(policy_path: Path, database_path: Path, result_path: Path) -> int:
    policy = load_json(policy_path, "policy")
    database = load_json(database_path, "database metadata")
    result = load_json(result_path, "scanner result")
    if policy.get("schema") != "psb-scanner-policy/v1":
        raise ValueError("unsupported policy schema")
    if database.get("schema") != "psb-scanner-database/v1":
        raise ValueError("unsupported database metadata schema")
    if result.get("schema") != "psb-scanner-result/v1":
        raise ValueError("unsupported scanner result schema")

    tool_policy = mapping(policy.get("tool"), "policy.tool")
    execution_policy = mapping(policy.get("execution"), "policy.execution")
    evidence_policy = mapping(policy.get("evidence"), "policy.evidence")
    scanner = mapping(result.get("scanner"), "result.scanner")
    result_database = mapping(result.get("database"), "result.database")
    checks_bundle = mapping(result.get("checks_bundle"), "result.checks_bundle")
    execution = mapping(result.get("execution"), "result.execution")
    findings = array(result.get("findings"), "result.findings")

    if execution.get("status") != "completed":
        reason = execution.get("reason", "unknown_error")
        raise ValueError(f"scanner execution did not complete: {reason}")

    if scanner.get("integrity_verified") is not True:
        raise ValueError("scanner result is not bound to verified tool integrity")
    if scanner.get("name") != tool_policy.get("name"):
        raise ValueError("scanner name does not match policy")
    if scanner.get("version") != tool_policy.get("version"):
        raise ValueError("scanner version does not match policy")
    if scanner.get("release_asset_sha256") != mapping(
        tool_policy.get("asset"), "policy.tool.asset"
    ).get("sha256"):
        raise ValueError("scanner release identity does not match policy")

    for field in ("repository", "schema_version", "digest", "fixture"):
        if result_database.get(field) != database.get(field):
            raise ValueError(f"scanner database {field} does not match reviewed metadata")
    sha256_value(database.get("digest"), "database digest")

    if checks_bundle.get("mode") != "embedded":
        raise ValueError("checks bundle mode must be embedded for deterministic fixture mode")
    expected_bundle = f"trivy-v{tool_policy.get('version')}"
    if checks_bundle.get("identity") != expected_bundle:
        raise ValueError("checks bundle identity does not match the pinned Trivy release")
    if execution.get("offline") is not True:
        raise ValueError("ordinary verification must use offline execution")

    target = text_value(execution.get("target"), "result.execution.target")
    if database.get("fixture") is True and not target.startswith("fixtures/"):
        raise ValueError("synthetic fixture database may only be used with fixtures/")

    categories = array(execution.get("categories"), "result.execution.categories")
    supported = set(
        text_value(item, "policy supported category")
        for item in array(
            execution_policy.get("supported_categories"),
            "policy.execution.supported_categories",
        )
    )
    if not categories or any(category not in supported for category in categories):
        raise ValueError("result contains an absent or unsupported scan category")

    allowed_fields = set(
        text_value(item, "allowed finding field")
        for item in array(
            evidence_policy.get("allowed_finding_fields"),
            "policy.evidence.allowed_finding_fields",
        )
    )
    prohibited = set(
        text_value(item, "prohibited evidence field").lower()
        for item in array(
            evidence_policy.get("prohibited_fields"),
            "policy.evidence.prohibited_fields",
        )
    )
    leaked_at = find_prohibited_key(result, prohibited)
    if leaked_at is not None:
        raise ValueError(f"sanitized evidence contains prohibited field {leaked_at}")

    blocking_severities = set(
        text_value(item, "blocking severity")
        for item in array(
            execution_policy.get("blocking_severities"),
            "policy.execution.blocking_severities",
        )
    )
    normalized: list[dict[str, Any]] = []
    for index, raw_finding in enumerate(findings):
        finding = mapping(raw_finding, f"result.findings[{index}]")
        unknown = sorted(set(finding) - allowed_fields)
        missing = sorted(allowed_fields - set(finding))
        if unknown:
            raise ValueError(
                f"result.findings[{index}] contains unapproved fields: {', '.join(unknown)}"
            )
        if missing:
            raise ValueError(
                f"result.findings[{index}] is missing fields: {', '.join(missing)}"
            )
        for field in ("id", "category", "severity", "target"):
            text_value(finding.get(field), f"result.findings[{index}].{field}")
        if finding["category"] not in categories:
            raise ValueError(
                f"result.findings[{index}] category was not included in the scan"
            )
        should_block = finding["severity"] in blocking_severities
        if finding.get("blocking") is not should_block:
            raise ValueError(
                f"result.findings[{index}] blocking state does not match severity policy"
            )
        normalized.append(finding)

    blocking = [finding for finding in normalized if finding["blocking"]]
    if blocking:
        for finding in blocking:
            print(
                "FINDING "
                f"{finding['category']} {finding['id']} {finding['severity']} "
                f"{finding['target']}"
            )
        print(f"BLOCKED {len(blocking)} blocking finding(s)")
        return 1

    if normalized:
        print(
            f"PASS Trivy v{scanner['version']} completed with "
            f"{len(normalized)} advisory finding(s) and 0 blocking findings"
        )
    else:
        print(
            f"CLEAN Trivy v{scanner['version']} completed for "
            f"{execution.get('target_kind', 'target')}: 0 findings"
        )
    return 0


def verify_exception(
    policy_path: Path, exception_path: Path, evaluation_time: datetime
) -> int:
    policy = load_json(policy_path, "policy")
    exception = load_json(exception_path, "exception")
    if exception.get("schema") != "psb-scanner-exception/v1":
        raise ValueError("unsupported exception schema")
    exception_policy = mapping(policy.get("exceptions"), "policy.exceptions")
    required = array(
        exception_policy.get("required_fields"), "policy.exceptions.required_fields"
    )

    violations: list[str] = []
    for raw_field in required:
        field = text_value(raw_field, "required exception field")
        value = exception.get(field)
        if not isinstance(value, str) or not value.strip():
            violations.append(f"exception field {field} is required")

    for field in ("rule_id", "target"):
        value = exception.get(field)
        if isinstance(value, str) and WILDCARD_RE.search(value):
            violations.append(f"exception {field} must be exact and contain no wildcard")

    expiry = parse_time(exception.get("expires_at"), "exception.expires_at")
    if expiry <= evaluation_time:
        violations.append("exception is expired at the evaluation time")
    if exception.get("owner") == exception.get("approved_by"):
        violations.append("exception approver must be independent from the owner")

    if violations:
        return reject(violations, "exception policy")
    print(
        f"PASS narrow exception {exception['id']} accepted until "
        f"{exception['expires_at']}"
    )
    return 0


def verify_comparison(path: Path) -> int:
    document = load_json(path, "secondary scanner decision")
    if document.get("schema") != "psb-secondary-scanner-decision/v1":
        raise ValueError("unsupported secondary scanner decision schema")
    primary = mapping(document.get("primary"), "comparison.primary")
    candidate = mapping(document.get("candidate"), "comparison.candidate")
    sha256_value(candidate.get("sha256"), "candidate distribution SHA-256")
    fixtures = array(document.get("fixtures"), "comparison.fixtures")
    if not fixtures:
        raise ValueError("comparison must contain at least one common fixture")

    violations: list[str] = []
    unique_value = False
    for index, raw_fixture in enumerate(fixtures):
        fixture = mapping(raw_fixture, f"comparison.fixtures[{index}]")
        text_value(fixture.get("id"), f"comparison.fixtures[{index}].id")
        if fixture.get("trivy") not in {"detected", "not-detected"}:
            raise ValueError(f"comparison.fixtures[{index}].trivy is invalid")
        if fixture.get("checkov") not in {"detected", "not-detected"}:
            raise ValueError(f"comparison.fixtures[{index}].checkov is invalid")
        if fixture.get("unique_candidate_value") is True:
            unique_value = True

    decision = document.get("decision")
    if unique_value and decision == "not-adopted":
        violations.append("candidate has unique value but is marked not adopted")
    if not unique_value and decision != "not-adopted":
        violations.append("candidate without unique value must not add a dependency")
    if primary != {"name": "trivy", "version": "0.72.0"}:
        violations.append("primary scanner identity does not match the reviewed slice")
    if candidate.get("name") != "checkov" or candidate.get("version") != "3.3.8":
        violations.append("candidate Checkov identity does not match the reviewed slice")

    if violations:
        return reject(violations, "secondary scanner decision")
    print(
        "PASS Checkov 3.3.8 comparison recorded; candidate not adopted "
        "(no unique first-slice coverage)"
    )
    return 0


def verify_docksec_profile(path: Path) -> int:
    document = load_json(path, "DockSec adapter profile")
    if document.get("schema") != "psb-docksec-adapter-policy/v1":
        raise ValueError("unsupported DockSec adapter profile schema")

    tool = mapping(document.get("tool"), "DockSec profile.tool")
    distribution = mapping(
        tool.get("distribution"), "DockSec profile.tool.distribution"
    )
    adoption = mapping(document.get("adoption"), "DockSec profile.adoption")
    gate = mapping(document.get("gate"), "DockSec profile.gate")
    runtime = mapping(document.get("runtime"), "DockSec profile.runtime")
    evidence = mapping(document.get("evidence"), "DockSec profile.evidence")
    prohibited = set(
        text_value(item, "DockSec prohibited operation")
        for item in array(document.get("prohibited"), "DockSec profile.prohibited")
    )

    violations: list[str] = []
    if tool.get("name") != "docksec" or tool.get("version") != "2026.7.5":
        violations.append("DockSec tool version is not the reviewed release")
    if tool.get("source_commit") != "4ddcb5285f437c0e84a42c748b0f61f56543e344":
        violations.append("DockSec source is not pinned to the reviewed commit")
    if distribution.get("filename") != "docksec-2026.7.5-py3-none-any.whl":
        violations.append("DockSec wheel filename is not exact")
    try:
        digest = sha256_value(
            distribution.get("sha256"), "DockSec distribution SHA-256"
        )
        if digest != "7f8781db7651216556c86c71ab45527bc484801b974ff264fe0ebe7f70a6f5fb":
            violations.append("DockSec wheel SHA-256 is not the reviewed digest")
    except ValueError:
        violations.append("DockSec wheel SHA-256 is not valid")

    unique_value = set(
        text_value(item, "DockSec unique value")
        for item in array(adoption.get("unique_value"), "DockSec adoption.unique_value")
    )
    if adoption.get("role") != "optional-developer-remediation-orchestrator":
        violations.append("DockSec is assigned authoritative scanner ownership")
    if adoption.get("primary_scanner") != "trivy":
        violations.append("DockSec replaces the reviewed primary scanner")
    if adoption.get("replaces_primary_scanner") is not False:
        violations.append("DockSec replacement flag is enabled")
    if unique_value != {
        "contextual-dockerfile-remediation",
        "compose-service-correlation",
    }:
        violations.append("DockSec adoption has no reviewed unique-value boundary")
    if adoption.get("upstream_github_action") != "rejected-by-project-policy":
        violations.append("upstream DockSec Action is accepted despite unsafe bootstrap")

    expected_gate = {
        "mode": "scan-only",
        "network": "offline",
        "output": "json",
        "fail_on": "HIGH",
        "cache": "bypass",
        "decision_source": "structured-scanner-findings",
        "ai_remediation": "optional-non-blocking",
        "exit_mapping": {
            "0": "clean",
            "1": "finding",
            "2": "error",
            "3": "error",
        },
    }
    if gate != expected_gate:
        violations.append("DockSec gate is not deterministic AI-free and fail-closed")

    expected_runtime = {
        "installation": "organization-built-locked-environment",
        "docksec_distribution_integrity": "required",
        "transitive_dependency_lock": "required",
        "external_scanner_integrity": "required",
        "automatic_external_tool_installer": "forbidden",
        "github_action_reference": "full-commit-sha-only",
    }
    if runtime != expected_runtime:
        violations.append("DockSec runtime does not require a locked verified toolchain")

    required_prohibitions = {
        "--no-redact",
        "--ai-only",
        "install-skill",
        "blocking-ai-score",
        "broad-or-unowned-ignore",
    }
    if prohibited != required_prohibitions:
        violations.append("DockSec prohibited-operation set is incomplete")
    if evidence.get("schema") != "psb-docksec-gate-result/v1":
        violations.append("DockSec evidence schema is not reviewed")
    if evidence.get("retain_raw_output") is not False:
        violations.append("raw DockSec output is retained as ordinary gate evidence")
    if evidence.get("retain_ai_output_as_gate_evidence") is not False:
        violations.append("AI output is retained as authoritative gate evidence")
    if evidence.get("target_path") != "basename-only":
        violations.append("DockSec evidence exposes more than the target basename")
    if set(
        text_value(item, "DockSec evidence severity")
        for item in array(
            evidence.get("severity_counts"), "DockSec evidence.severity_counts"
        )
    ) != {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN",
    }:
        violations.append("DockSec evidence severity inventory is incomplete")

    if violations:
        return reject(violations, "DockSec adapter policy")
    print(
        "PASS DockSec 2026.7.5 optional remediation profile is pinned, "
        "AI-non-authoritative, and fail-closed"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    release = subparsers.add_parser("release")
    release.add_argument("policy", type=Path)
    release.add_argument("receipt", type=Path)

    artifact = subparsers.add_parser("artifact")
    artifact.add_argument("path", type=Path)
    artifact.add_argument("expected_sha256")

    result = subparsers.add_parser("result")
    result.add_argument("policy", type=Path)
    result.add_argument("database", type=Path)
    result.add_argument("result", type=Path)

    exception = subparsers.add_parser("exception")
    exception.add_argument("policy", type=Path)
    exception.add_argument("exception", type=Path)
    exception.add_argument("--at", required=True)

    comparison = subparsers.add_parser("comparison")
    comparison.add_argument("decision", type=Path)

    docksec_profile = subparsers.add_parser("docksec-profile")
    docksec_profile.add_argument("profile", type=Path)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "release":
            return verify_release(arguments.policy, arguments.receipt)
        if arguments.command == "artifact":
            return verify_artifact(arguments.path, arguments.expected_sha256)
        if arguments.command == "result":
            return verify_result(arguments.policy, arguments.database, arguments.result)
        if arguments.command == "exception":
            return verify_exception(
                arguments.policy,
                arguments.exception,
                parse_time(arguments.at, "--at"),
            )
        if arguments.command == "comparison":
            return verify_comparison(arguments.decision)
        if arguments.command == "docksec-profile":
            return verify_docksec_profile(arguments.profile)
    except (OSError, ValueError) as error:
        print(f"ERROR {error}")
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
