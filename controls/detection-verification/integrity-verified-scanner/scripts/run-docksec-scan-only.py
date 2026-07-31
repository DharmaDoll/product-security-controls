#!/usr/bin/env python3
"""Run the reviewed DockSec scan-only profile and emit sanitized gate evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_ARGUMENTS = [
    "--scan-only",
    "--offline",
    "--fail-on",
    "high",
    "--json",
    "--no-cache",
]
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class AdapterError(ValueError):
    """DockSec could not produce trustworthy gate evidence."""


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must be a JSON object")
    return value


def validate_profile(profile: dict[str, Any]) -> tuple[str, str]:
    if profile.get("schema") != "psb-docksec-adapter-policy/v1":
        raise AdapterError("unsupported DockSec profile schema")
    tool = profile.get("tool")
    gate = profile.get("gate")
    evidence = profile.get("evidence")
    if not isinstance(tool, dict) or not isinstance(gate, dict) or not isinstance(evidence, dict):
        raise AdapterError("DockSec profile is incomplete")
    distribution = tool.get("distribution")
    if not isinstance(distribution, dict):
        raise AdapterError("DockSec distribution policy is missing")
    if gate != {
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
    }:
        raise AdapterError("DockSec gate policy is not the reviewed fail-closed profile")
    if evidence.get("schema") != "psb-docksec-gate-result/v1":
        raise AdapterError("DockSec evidence schema is not reviewed")
    if evidence.get("retain_raw_output") is not False:
        raise AdapterError("raw DockSec output retention is enabled")
    version = tool.get("version")
    digest = distribution.get("sha256")
    if not isinstance(version, str) or not version:
        raise AdapterError("DockSec version is missing")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AdapterError("DockSec distribution SHA-256 is invalid")
    return version, digest


def severity_counts(raw: dict[str, Any]) -> dict[str, int]:
    counts = raw.get("severity_counts")
    if not isinstance(counts, dict):
        raise AdapterError("DockSec JSON has no severity_counts object")
    normalized: dict[str, int] = {}
    for severity in SEVERITIES:
        count = counts.get(severity, 0)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise AdapterError(f"DockSec severity count {severity} is invalid")
        normalized[severity] = count
    unknown_keys = sorted(set(counts) - set(SEVERITIES))
    if unknown_keys:
        raise AdapterError(
            f"DockSec JSON contains unknown severities: {', '.join(unknown_keys)}"
        )
    return normalized


def write_evidence(
    output: Path,
    version: str,
    digest: str,
    target: Path,
    counts: dict[str, int],
    decision: str,
) -> None:
    if output.exists():
        raise AdapterError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence = {
        "schema": "psb-docksec-gate-result/v1",
        "scanner": {
            "name": "docksec",
            "version": version,
            "expected_distribution_sha256": digest,
        },
        "execution": {
            "mode": "scan-only",
            "network": "offline",
            "ai_used": False,
            "cache": "bypass",
            "target": target.name,
            "status": "completed",
        },
        "severity_counts": counts,
        "decision": decision,
    }
    output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docksec", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        profile = load_object(arguments.profile, "DockSec profile")
        version, digest = validate_profile(profile)
        if not arguments.docksec.is_file() or not os.access(arguments.docksec, os.X_OK):
            raise AdapterError("reviewed DockSec executable is unavailable")
        if not arguments.target.is_file():
            raise AdapterError("DockSec target is unavailable")

        version_process = subprocess.run(
            [str(arguments.docksec), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if version_process.returncode != 0:
            raise AdapterError("DockSec version check failed")
        if version_process.stdout.strip() != f"DockSec {version}":
            raise AdapterError("DockSec executable version does not match the profile")

        environment = os.environ.copy()
        for name in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GOOGLE_API_KEY",
            "LLM_PROVIDER",
            "LLM_MODEL",
        ):
            environment.pop(name, None)
        environment["DOCKSEC_USE_CACHE"] = "false"
        environment["NO_COLOR"] = "1"

        process = subprocess.run(
            [str(arguments.docksec), str(arguments.target), *EXPECTED_ARGUMENTS],
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
            env=environment,
        )
        if process.returncode in {2, 3}:
            raise AdapterError(
                f"DockSec execution failed with upstream status {process.returncode}"
            )
        if process.returncode not in {0, 1}:
            raise AdapterError(
                f"DockSec returned unsupported status {process.returncode}"
            )
        try:
            raw = json.loads(process.stdout)
        except json.JSONDecodeError as error:
            raise AdapterError("DockSec stdout is not one JSON object") from error
        if not isinstance(raw, dict):
            raise AdapterError("DockSec stdout JSON must be an object")
        if "ai_analysis" in raw:
            raise AdapterError("DockSec scan-only output unexpectedly contains AI analysis")
        counts = severity_counts(raw)
        blocking = counts["CRITICAL"] + counts["HIGH"]
        if process.returncode == 0 and blocking:
            raise AdapterError("DockSec returned clean with blocking severity counts")
        if process.returncode == 1 and not blocking:
            raise AdapterError("DockSec returned finding without blocking severity counts")
        decision = "finding" if process.returncode == 1 else "clean"
        write_evidence(
            arguments.output,
            version,
            digest,
            arguments.target,
            counts,
            decision,
        )
        if decision == "finding":
            print(f"FINDING DockSec completed with {blocking} blocking finding(s)")
            return 1
        print("CLEAN DockSec completed with 0 blocking findings")
        return 0
    except (AdapterError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
