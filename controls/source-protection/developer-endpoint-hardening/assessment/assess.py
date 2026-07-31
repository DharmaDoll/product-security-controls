#!/usr/bin/env python3
"""Read-only developer endpoint assessment with sanitized evidence."""

from __future__ import annotations

import argparse
import csv
import json
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTROL_ID = "PSB-SOURCE-001"
ASSESSMENT_DIRECTORY = Path(__file__).resolve().parent
CONTROL_DIRECTORY = ASSESSMENT_DIRECTORY.parent
REPOSITORY_ROOT = CONTROL_DIRECTORY.parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
sys.path.insert(0, str(ASSESSMENT_DIRECTORY))

from control_metadata import parse_yaml_subset  # noqa: E402
from adapters import linux  # noqa: E402


STATUSES = ("PASS", "FAIL", "NOT_CHECKED", "ERROR", "N/A")
ALLOWED_SIGNAL_VALUES = {
    "credential_storage": {"approved", "plaintext", "unknown", "error"},
    "pre_commit_secret_scan": {"enabled", "disabled", "unknown", "error"},
    "sensitive_data_file_guard": {"enabled", "disabled", "unknown", "error"},
    "disk_encryption": {"enabled", "disabled", "unknown", "error"},
    "screen_lock": {"enabled", "disabled", "unknown", "error"},
    "automatic_updates": {"enabled", "disabled", "unknown", "error"},
    "local_admin": {"false", "true", "unknown", "error"},
    "docker_socket_exposed": {"false", "true", "unknown", "error"},
    "local_debug_services": {"disabled", "enabled", "unknown", "error"},
    "workspace_mount": {"read-only", "read-write", "unknown", "error"},
}
LOCAL_CHECKS = {
    "DEH-002": {
        "signal": "credential_storage",
        "pass": "approved",
        "fail": "plaintext",
        "pass_code": "credential-helper-approved",
        "fail_code": "credential-helper-plaintext",
        "pass_detail": "an approved credential helper was detected",
        "fail_detail": "Git credential storage is configured for plaintext persistence",
    },
    "DEH-004": {
        "signal": "pre_commit_secret_scan",
        "pass": "enabled",
        "fail": "disabled",
        "pass_code": "repository-hook-enabled",
        "fail_code": "repository-hook-disabled",
        "pass_detail": "a repository-owned pre-commit hook was detected",
        "fail_detail": "the current repository has no active repository-owned pre-commit hook",
    },
    "DEH-010": {
        "signal": "sensitive_data_file_guard",
        "pass": "enabled",
        "fail": "disabled",
        "pass_code": "sensitive-file-guard-enabled",
        "fail_code": "sensitive-file-guard-disabled",
        "pass_detail": "the repository-owned pre-commit hook invokes the sensitive-data guard",
        "fail_detail": "the active pre-commit path does not establish the sensitive-data guard",
    },
    "END-001": {
        "signal": "disk_encryption",
        "pass": "enabled",
        "fail": "disabled",
        "pass_code": "disk-encryption-detected",
        "fail_code": "disk-encryption-not-detected",
        "pass_detail": "the workspace block-device chain includes encryption",
        "fail_detail": "the workspace block-device chain does not include encryption",
    },
    "END-002": {
        "signal": "screen_lock",
        "pass": "enabled",
        "fail": "disabled",
        "pass_code": "screen-lock-enabled",
        "fail_code": "screen-lock-disabled",
        "pass_detail": "GNOME screen locking and a nonzero idle delay are enabled",
        "fail_detail": "GNOME screen locking or its idle delay is disabled",
    },
    "END-003": {
        "signal": "automatic_updates",
        "pass": "enabled",
        "fail": "disabled",
        "pass_code": "automatic-updates-enabled",
        "fail_code": "automatic-updates-disabled",
        "pass_detail": "a supported automatic security-update policy was detected",
        "fail_detail": "the detected automatic-update policy is disabled",
    },
    "END-004": {
        "signal": "local_admin",
        "pass": "false",
        "fail": "true",
        "pass_code": "routine-admin-not-detected",
        "fail_code": "routine-admin-detected",
        "pass_detail": "the current process is not root and has no recognized admin group",
        "fail_detail": "the current process is root or belongs to a recognized admin group",
    },
    "END-006": {
        "signal": "docker_socket_exposed",
        "pass": "false",
        "fail": "true",
        "pass_code": "container-socket-not-exposed",
        "fail_code": "container-socket-exposed",
        "pass_detail": "no writable common container socket or remote Docker endpoint was detected",
        "fail_detail": "a writable container socket or remote Docker endpoint is available",
    },
    "END-007": {
        "signal": "local_debug_services",
        "pass": "disabled",
        "fail": "enabled",
        "pass_code": "known-debug-listener-not-detected",
        "fail_code": "known-debug-listener-detected",
        "pass_detail": "no known debug port was detected on a non-loopback listener",
        "fail_detail": "a known debug port is listening beyond the loopback interface",
    },
    "END-009": {
        "signal": "workspace_mount",
        "pass": "read-only",
        "fail": "read-write",
        "pass_code": "workspace-mount-read-only",
        "fail_code": "workspace-mount-read-write",
        "pass_detail": "the current workspace mount is read only",
        "fail_detail": "the current workspace mount is writable",
    },
}
EXTERNAL_CHECKS = {
    "DEH-001": (
        "external-identity-evidence",
        "credential lifetime requires identity or source-platform evidence",
    ),
    "DEH-003": (
        "external-key-enrollment-evidence",
        "hardware-backed key enrollment requires identity-platform evidence",
    ),
    "DEH-005": (
        "external-repository-evidence",
        "repository-side scanning requires ruleset or platform evidence",
    ),
    "DEH-006": (
        "external-sandbox-evidence",
        "package-install isolation requires managed workspace or sandbox evidence",
    ),
    "DEH-007": (
        "external-dependency-evidence",
        "dependency update enforcement requires repository automation evidence",
    ),
    "DEH-008": (
        "external-egress-evidence",
        "developer egress enforcement requires managed network evidence",
    ),
    "DEH-009": (
        "external-idp-evidence",
        "phishing-resistant authentication requires IdP policy evidence",
    ),
    "DEH-011": (
        "external-dependency-proxy-evidence",
        "managed dependency proxy requires MDM and network enforcement evidence",
    ),
    "END-005": (
        "approved-scanner-evidence",
        "workspace secret absence requires an approved complete scan",
    ),
    "END-008": (
        "external-ai-egress-evidence",
        "AI tool network enforcement requires managed allowlist evidence",
    ),
    "END-010": (
        "external-backup-evidence",
        "backup encryption requires managed backup evidence",
    ),
    "END-011": (
        "external-application-control-evidence",
        "application allowlisting requires managed inventory and enforcement evidence",
    ),
    "END-012": (
        "external-edr-xdr-evidence",
        "EDR or XDR coverage requires managed platform health and response evidence",
    ),
    "END-013": (
        "external-commit-signing-evidence",
        "commit signing requires managed Git and repository ruleset evidence",
    ),
    "END-014": (
        "external-ide-security-evidence",
        "IDE SAST and SCA feedback requires managed editor evidence",
    ),
    "END-015": (
        "external-managed-environment-evidence",
        "high-risk workload isolation requires managed development environment evidence",
    ),
    "END-016": (
        "external-runtime-monitoring-evidence",
        "sandbox restrictions and telemetry require runtime control evidence",
    ),
    "END-017": (
        "external-mdm-evidence",
        "central endpoint enforcement requires MDM or equivalent evidence",
    ),
    "END-018": (
        "external-physical-protection-evidence",
        "physical device protection requires organization policy and response evidence",
    ),
}


def _load_checks() -> list[dict[str, Any]]:
    control = parse_yaml_subset(CONTROL_DIRECTORY / "control.yaml")
    if control.get("id") != CONTROL_ID:
        raise ValueError("assessment control identity mismatch")
    checks = control.get("checks")
    if not isinstance(checks, list):
        raise ValueError("control checks are unavailable")
    check_ids = {check["id"] for check in checks}
    if check_ids != set(LOCAL_CHECKS) | set(EXTERNAL_CHECKS):
        raise ValueError("assessment coverage does not match control checks")
    return checks


def _load_fixture(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load assessment fixture: {error}") from error
    if not isinstance(data, dict) or set(data) != set(ALLOWED_SIGNAL_VALUES):
        raise ValueError("assessment fixture has an unexpected signal set")
    for signal, value in data.items():
        if value not in ALLOWED_SIGNAL_VALUES[signal]:
            raise ValueError(f"assessment fixture has invalid value for {signal}")
    return data


def _local_result(check: dict[str, Any], observations: dict[str, str]) -> dict[str, str]:
    check_id = check["id"]
    specification = LOCAL_CHECKS[check_id]
    signal = specification["signal"]
    value = observations.get(signal, "error")
    full_id = f"{CONTROL_ID}-{check_id}"
    if value == specification["pass"]:
        return {
            "check_id": full_id,
            "title": check["title"],
            "status": "PASS",
            "evidence_code": specification["pass_code"],
            "detail": specification["pass_detail"],
        }
    if value == specification["fail"]:
        return {
            "check_id": full_id,
            "title": check["title"],
            "status": "FAIL",
            "evidence_code": specification["fail_code"],
            "detail": specification["fail_detail"],
        }
    if value == "unknown":
        return {
            "check_id": full_id,
            "title": check["title"],
            "status": "NOT_CHECKED",
            "evidence_code": f"{signal.replace('_', '-')}-unresolved",
            "detail": "the read-only adapter could not establish this state",
        }
    return {
        "check_id": full_id,
        "title": check["title"],
        "status": "ERROR",
        "evidence_code": f"{signal.replace('_', '-')}-error",
        "detail": "the read-only assessment operation failed",
    }


def _external_result(check: dict[str, Any]) -> dict[str, str]:
    evidence_code, detail = EXTERNAL_CHECKS[check["id"]]
    return {
        "check_id": f"{CONTROL_ID}-{check['id']}",
        "title": check["title"],
        "status": "NOT_CHECKED",
        "evidence_code": evidence_code,
        "detail": detail,
    }


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_csv(path: Path, results: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = ["Check ID", "Title", "Status", "Evidence Code", "Detail"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, lineterminator="\n")
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "Check ID": result["check_id"],
                    "Title": result["title"],
                    "Status": result["status"],
                    "Evidence Code": result["evidence_code"],
                    "Detail": result["detail"],
                }
            )


def _exit_code(summary: Counter[str]) -> int:
    if summary["ERROR"]:
        return 2
    if summary["FAIL"]:
        return 1
    if summary["NOT_CHECKED"]:
        return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument(
        "--fixture",
        type=Path,
        help="Use an isolated normalized test fixture; never represents host state.",
    )
    args = parser.parse_args()

    try:
        checks = _load_checks()
        if args.fixture:
            observations = _load_fixture(args.fixture)
            source = "test-fixture"
            detected_platform = "linux"
            scope = "isolated test fixture; no host claim"
        elif platform.system().lower() == "linux":
            observations = linux.collect(args.workspace)
            source = "live"
            detected_platform = "linux"
            scope = "current execution environment and repository; sanitized"
        else:
            observations = {signal: "error" for signal in ALLOWED_SIGNAL_VALUES}
            source = "live"
            detected_platform = "unsupported"
            scope = "current execution environment and repository; sanitized"
        results = [
            _local_result(check, observations)
            if check["id"] in LOCAL_CHECKS
            else _external_result(check)
            for check in checks
        ]
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR assessment setup failed: {error}", file=sys.stderr)
        return 2

    counts = Counter(result["status"] for result in results)
    summary = {status: counts[status] for status in STATUSES}
    document = {
        "schema_version": "1.0",
        "control_id": CONTROL_ID,
        "assessment_kind": "read-only-developer-endpoint",
        "source": source,
        "platform": detected_platform,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "summary": summary,
        "results": results,
    }
    try:
        _write_json(args.json_output, document)
        _write_csv(args.csv_output, results)
    except OSError as error:
        print(f"ERROR cannot write assessment output: {error}", file=sys.stderr)
        return 2

    print(
        f"ASSESSMENT {CONTROL_ID} source={source} platform={detected_platform}"
    )
    for result in results:
        print(
            f"{result['status']} {result['check_id']} "
            f"{result['evidence_code']}: {result['detail']}"
        )
    print(
        "SUMMARY "
        + " ".join(f"{status}={summary[status]}" for status in STATUSES)
    )
    return _exit_code(counts)


if __name__ == "__main__":
    raise SystemExit(main())
