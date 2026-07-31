#!/usr/bin/env python3
"""Convert selected Trivy JSON fields to secret-safe PSB scanner evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


TRIVY_VERSION = "0.72.0"
RELEASE_SHA256 = "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise OSError(f"{label} does not exist: {path}") from error
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid {label} JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    output = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}[{index}] must be an object")
        output.append(item)
    return output


def required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def normalize(
    raw_path: Path,
    database_path: Path,
    target_kind: str,
    logical_target: str,
    declared_categories: set[str],
    output_path: Path,
) -> None:
    raw = load_object(raw_path, "Trivy result")
    database = load_object(database_path, "database metadata")
    raw_results = records(raw.get("Results"), "Trivy Results")
    findings: list[dict[str, Any]] = []
    detected_categories: set[str] = set()

    for result_index, raw_result in enumerate(raw_results):
        target = required_text(
            raw_result.get("Target"), f"Trivy Results[{result_index}].Target"
        )
        for item in records(
            raw_result.get("Vulnerabilities"),
            f"Trivy Results[{result_index}].Vulnerabilities",
        ):
            category = (
                "sbom-vulnerability"
                if target_kind == "cyclonedx-sbom"
                else "vulnerability"
            )
            severity = required_text(item.get("Severity"), "vulnerability severity")
            detected_categories.add(category)
            findings.append(
                {
                    "id": required_text(
                        item.get("VulnerabilityID"), "vulnerability identifier"
                    ),
                    "category": category,
                    "severity": severity,
                    "target": target,
                    "blocking": severity in BLOCKING_SEVERITIES,
                }
            )

        for item in records(
            raw_result.get("Misconfigurations"),
            f"Trivy Results[{result_index}].Misconfigurations",
        ):
            category = (
                "container-misconfiguration"
                if target_kind == "containerfile"
                else "iac-misconfiguration"
            )
            severity = required_text(item.get("Severity"), "misconfiguration severity")
            detected_categories.add(category)
            findings.append(
                {
                    "id": required_text(item.get("ID"), "misconfiguration identifier"),
                    "category": category,
                    "severity": severity,
                    "target": target,
                    "blocking": severity in BLOCKING_SEVERITIES,
                }
            )

        for item in records(
            raw_result.get("Secrets"), f"Trivy Results[{result_index}].Secrets"
        ):
            severity = required_text(item.get("Severity"), "secret severity")
            detected_categories.add("secret")
            findings.append(
                {
                    "id": required_text(item.get("RuleID"), "secret rule identifier"),
                    "category": "secret",
                    "severity": severity,
                    "target": target,
                    "blocking": severity in BLOCKING_SEVERITIES,
                }
            )

    if not declared_categories:
        raise ValueError("at least one scan category must be declared")
    unexpected = detected_categories - declared_categories
    if unexpected:
        raise ValueError(
            "Trivy result contains undeclared categories: "
            + ", ".join(sorted(unexpected))
        )

    normalized = {
        "schema": "psb-scanner-result/v1",
        "scanner": {
            "name": "trivy",
            "version": TRIVY_VERSION,
            "release_asset_sha256": RELEASE_SHA256,
            "integrity_verified": True,
        },
        "database": {
            field: database.get(field)
            for field in ("repository", "schema_version", "digest", "fixture")
        },
        "checks_bundle": {
            "mode": "embedded",
            "identity": f"trivy-v{TRIVY_VERSION}",
        },
        "execution": {
            "status": "completed",
            "target": logical_target,
            "target_kind": target_kind,
            "offline": True,
            "categories": sorted(declared_categories),
        },
        "findings": findings,
    }
    output_path.write_text(
        json.dumps(normalized, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_result", type=Path)
    parser.add_argument("database_metadata", type=Path)
    parser.add_argument("target_kind")
    parser.add_argument("output", type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--categories", required=True)
    arguments = parser.parse_args()
    try:
        normalize(
            arguments.raw_result,
            arguments.database_metadata,
            arguments.target_kind,
            arguments.target,
            {
                item.strip()
                for item in arguments.categories.split(",")
                if item.strip()
            },
            arguments.output,
        )
    except (OSError, ValueError) as error:
        print(f"ERROR {error}")
        return 2
    print(f"PASS wrote sanitized scanner evidence to {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
