#!/usr/bin/env python3
"""Search SBOM inventory and emit an approved dry-run incident response plan."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SERIAL_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
REQUIRED_ACTIONS = [
    "preserve-evidence",
    "suspend-workflows",
    "revoke-credentials",
    "quarantine-artifacts",
    "pin-safe-version",
    "clean-rebuild",
    "notify-stakeholders",
]


class InputError(ValueError):
    pass


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def validate_runbook(value: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[str] = []
    if value.get("dry_run_default") is not True:
        findings.append("runbook.dry_run_default must be true")
    actions = value.get("actions")
    if not isinstance(actions, list):
        raise InputError("runbook.actions must be a list")
    action_ids = [action.get("id") for action in actions if isinstance(action, dict)]
    if action_ids != REQUIRED_ACTIONS:
        findings.append("runbook actions must use the required evidence-first order")
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise InputError(f"runbook.actions[{index}] must be an object")
        if "command" in action:
            findings.append(f"runbook action {action.get('id')} must not embed a command")
        if action.get("requires_approval") is not True:
            findings.append(f"runbook action {action.get('id')} requires approval")
        owner = action.get("owner")
        if not isinstance(owner, str) or not owner:
            findings.append(f"runbook action {action.get('id')} requires an owner")
    return actions, findings


def validate_sbom(path: Path) -> tuple[dict[str, Any], list[str]]:
    sbom = load_json(path, "SBOM")
    findings: list[str] = []
    if sbom.get("bomFormat") != "CycloneDX":
        findings.append(f"{path.name} bomFormat must be CycloneDX")
    if sbom.get("specVersion") != "1.7":
        findings.append(f"{path.name} specVersion must be 1.7")
    serial = sbom.get("serialNumber")
    if not isinstance(serial, str) or not SERIAL_RE.fullmatch(serial):
        findings.append(f"{path.name} requires a valid unique serialNumber")
    version = sbom.get("version")
    if not isinstance(version, int) or version < 1:
        findings.append(f"{path.name} version must be a positive integer")
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict) or not all(
        isinstance(component.get(field), str) and component.get(field)
        for field in ("name", "version")
    ):
        findings.append(f"{path.name} metadata.component requires name and version")
    compositions = sbom.get("compositions")
    if (
        not isinstance(compositions, list)
        or not compositions
        or not all(
            isinstance(item, dict) and item.get("aggregate") == "complete"
            for item in compositions
        )
    ):
        findings.append(f"{path.name} component inventory must be marked complete")
    components = sbom.get("components")
    if not isinstance(components, list):
        raise InputError(f"{path.name} components must be a list")
    for index, item in enumerate(components):
        if not isinstance(item, dict):
            raise InputError(f"{path.name} components[{index}] must be an object")
        name, item_version, purl = item.get("name"), item.get("version"), item.get("purl")
        if not all(isinstance(field, str) and field for field in (name, item_version, purl)):
            findings.append(
                f"{path.name} component {index} requires exact name version and purl"
            )
        elif "*" in item_version or f"{name}@{item_version}" not in purl:
            findings.append(f"{path.name} component {name} has non-exact identity")
    return sbom, findings


def validate_records(
    value: dict[str, Any], serials: set[str]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records = value.get("records")
    if not isinstance(records, list):
        raise InputError("build-records.records must be a list")
    findings: list[str] = []
    by_serial: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise InputError(f"build record {index} must be an object")
        serial = record.get("sbom_serial")
        if not isinstance(serial, str) or serial in by_serial:
            findings.append(f"build record {index} has invalid or duplicate SBOM serial")
            continue
        by_serial[serial] = record
        for field in ("repository", "build_id", "artifact"):
            if not isinstance(record.get(field), str) or not record[field]:
                findings.append(f"build record {serial} missing {field}")
        if not COMMIT_RE.fullmatch(str(record.get("source_commit", ""))):
            findings.append(f"build record {serial} source_commit must be immutable")
        for field in ("provenance_digest", "log_digest"):
            if not DIGEST_RE.fullmatch(str(record.get(field, ""))):
                findings.append(f"build record {serial} missing valid {field}")
        credentials = record.get("credential_ids")
        if not isinstance(credentials, list) or not all(
            isinstance(item, str) and item and "secret" not in item.lower()
            for item in credentials
        ):
            findings.append(f"build record {serial} credential_ids are invalid")
    missing = sorted(serials - set(by_serial))
    if missing:
        findings.append(f"build records missing SBOM serials: {', '.join(missing)}")
    return by_serial, findings


def run(
    package: str,
    version: str,
    inventory_dir: Path,
    records_path: Path,
    runbook_path: Path,
    dry_run: bool,
) -> tuple[int, list[str]]:
    if not package or not version or "*" in package or "*" in version:
        raise InputError("package and version must be exact non-empty identifiers")
    runbook = load_json(runbook_path, "runbook")
    actions, findings = validate_runbook(runbook)
    if not dry_run:
        findings.append("reference responder only permits --dry-run")

    try:
        paths = sorted(inventory_dir.glob("*.cdx.json"))
    except OSError as error:
        raise InputError(f"cannot enumerate inventory: {error}") from error
    if not paths:
        raise InputError("SBOM inventory is empty or unavailable")
    sboms: list[tuple[Path, dict[str, Any]]] = []
    serials: set[str] = set()
    for path in paths:
        sbom, sbom_findings = validate_sbom(path)
        findings.extend(sbom_findings)
        serial = sbom.get("serialNumber")
        if isinstance(serial, str):
            if serial in serials:
                findings.append(f"duplicate SBOM serialNumber: {serial}")
            serials.add(serial)
        sboms.append((path, sbom))
    records, record_findings = validate_records(
        load_json(records_path, "build records"), serials
    )
    findings.extend(record_findings)
    if findings:
        return 1, [*(f"FAIL {finding}" for finding in findings), f"RESULT rejected with {len(findings)} finding(s)"]

    impacted: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    for path, sbom in sboms:
        if any(
            component.get("name") == package and component.get("version") == version
            for component in sbom["components"]
        ):
            impacted.append((path, sbom, records[sbom["serialNumber"]]))
    if not impacted:
        return 0, [f"CLEAN no inventory matches {package}@{version}"]

    output = [f"DETECTED {package}@{version} in {len(impacted)} product(s)"]
    for path, sbom, record in impacted:
        output.append(
            "AFFECTED "
            f"repository={record['repository']} build={record['build_id']} "
            f"artifact={record['artifact']} sbom={path.name}"
        )
        output.append(
            "EVIDENCE "
            f"provenance={record['provenance_digest']} logs={record['log_digest']} "
            f"credentials={','.join(record['credential_ids'])}"
        )
    for index, action in enumerate(actions, 1):
        output.append(
            f"PLAN {index} {action['id']} owner={action['owner']} approval=required"
        )
    output.append("RESULT dry-run no external actions executed")
    return 1, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--inventory-dir", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--runbook", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        status, output = run(
            args.package,
            args.version,
            args.inventory_dir,
            args.records,
            args.runbook,
            args.dry_run,
        )
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    print("\n".join(output))
    return status


if __name__ == "__main__":
    sys.exit(main())
