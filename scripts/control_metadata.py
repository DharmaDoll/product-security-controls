#!/usr/bin/env python3
"""Shared control discovery and metadata validation helpers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
CONTROL_GLOB = "controls/*/*/control.yaml"

DOMAINS = {
    "secure-design",
    "secure-coding",
    "source-protection",
    "dependency-security",
    "cicd-security",
    "build-security",
    "container-cloud-iac-security",
    "release-integrity",
    "ai-development-security",
    "detection-verification",
    "governance-operations",
}
SECURITY_FUNCTIONS = {"prevent", "detect", "verify", "respond", "govern"}
RELATIONSHIPS = {
    "addresses",
    "supports",
    "detects",
    "mitigates",
    "verifies",
    "evidence-for",
    "related-to",
}
CONFIDENCE_LEVELS = {"low", "medium", "high"}
STATUSES = {"idea", "planned", "prototype", "reference", "adopted", "deprecated"}
EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3", "E4"}
CHECK_ROLES = {
    "developer",
    "repository-admin",
    "ci-platform",
    "build-platform",
    "release-manager",
    "security",
    "incident-response",
    "shared",
}
VERIFICATION_TYPES = {"automated", "manual", "external-evidence", "hybrid"}
MAPPING_STATUSES = {"reviewed", "provisional", "unmapped"}
CONTROL_ID_RE = re.compile(r"^PSB-[A-Z]+-[0-9]{3}$")
CHECK_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")
_INTEGER_RE = re.compile(r"^-?\d+$")


class MetadataError(ValueError):
    """Raised when control metadata cannot be parsed or validated."""


def parse_scalar(value: str) -> Any:
    if value == "":
        return ""
    if value in {"true", "false"}:
        return value == "true"
    if _INTEGER_RE.fullmatch(value):
        return int(value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_yaml_subset(path: Path) -> dict[str, Any]:
    """Parse the deliberately small YAML subset used by control.yaml files."""

    entries = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            indent = len(raw_line.rstrip("\n")) - len(raw_line.rstrip("\n").lstrip(" "))
            entries.append((line_number, indent, raw_line.strip()))

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(entries):
            return {}, index

        is_list = entries[index][2].startswith("- ")
        value: list[Any] | dict[str, Any] = [] if is_list else {}

        while index < len(entries):
            line_number, current_indent, text = entries[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                raise MetadataError(f"{path}:{line_number}: unexpected indentation")

            if is_list:
                if not text.startswith("- "):
                    break
                item_text = text[2:]
                if ": " in item_text:
                    key, scalar = item_text.split(": ", 1)
                    item: dict[str, Any] = {key: parse_scalar(scalar)}
                    index += 1
                    if index < len(entries) and entries[index][1] > current_indent:
                        nested, index = parse_block(index, current_indent + 2)
                        if not isinstance(nested, dict):
                            nested_line = entries[index][0] if index < len(entries) else line_number
                            raise MetadataError(
                                f"{path}:{nested_line}: list mapping fields must be a mapping"
                            )
                        for nested_key, nested_value in nested.items():
                            if nested_key in item:
                                raise MetadataError(
                                    f"{path}:{line_number}: duplicate key {nested_key!r}"
                                )
                            item[nested_key] = nested_value
                    value.append(item)
                elif item_text.endswith(":"):
                    key = item_text[:-1]
                    nested, index = parse_block(index + 1, current_indent + 2)
                    value.append({key: nested})
                else:
                    value.append(parse_scalar(item_text))
                    index += 1
                continue

            if text.startswith("- "):
                break
            if ": " in text:
                key, scalar = text.split(": ", 1)
                if key in value:
                    raise MetadataError(f"{path}:{line_number}: duplicate key {key!r}")
                value[key] = parse_scalar(scalar)
                index += 1
                continue
            if text.endswith(":"):
                key = text[:-1]
                if key in value:
                    raise MetadataError(f"{path}:{line_number}: duplicate key {key!r}")
                nested, index = parse_block(index + 1, current_indent + 2)
                value[key] = nested
                continue
            raise MetadataError(f"{path}:{line_number}: unsupported YAML syntax")

        return value, index

    parsed, next_index = parse_block(0, 0)
    if next_index != len(entries) or not isinstance(parsed, dict):
        raise MetadataError(f"{path}: unsupported YAML document")
    return parsed


def discover_controls() -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    for path in sorted(REPOSITORY_ROOT.glob(CONTROL_GLOB)):
        data = parse_yaml_subset(path)
        data["_path"] = path
        data["_directory"] = path.parent
        controls.append(data)
    return controls


def _require_text(data: dict[str, Any], field: str, errors: list[str], label: str) -> None:
    if not isinstance(data.get(field), str) or not data[field].strip():
        errors.append(f"{label}: {field} must be a non-empty string")


def validate_controls(controls: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen_ids: dict[str, Path] = {}

    if not controls:
        return ["no controls discovered"]

    for control in controls:
        path: Path = control["_path"]
        directory: Path = control["_directory"]
        label = str(path.relative_to(REPOSITORY_ROOT))

        for field in ("id", "title", "domain", "summary", "owner"):
            _require_text(control, field, errors, label)

        control_id = control.get("id")
        if isinstance(control_id, str):
            if not CONTROL_ID_RE.fullmatch(control_id):
                errors.append(f"{label}: invalid control id {control_id!r}")
            if control_id in seen_ids:
                first = seen_ids[control_id].relative_to(REPOSITORY_ROOT)
                errors.append(f"{label}: duplicate control id {control_id} (first in {first})")
            else:
                seen_ids[control_id] = path

        domain = control.get("domain")
        if domain not in DOMAINS:
            errors.append(f"{label}: unsupported domain {domain!r}")
        elif directory.parent.name != domain:
            errors.append(
                f"{label}: domain {domain!r} does not match directory {directory.parent.name!r}"
            )

        functions = control.get("security_functions")
        if not isinstance(functions, list) or not functions:
            errors.append(f"{label}: security_functions must be a non-empty list")
        elif invalid := sorted(set(functions) - SECURITY_FUNCTIONS):
            errors.append(f"{label}: unsupported security_functions: {', '.join(invalid)}")

        threats = control.get("threats")
        if not isinstance(threats, list) or not threats:
            errors.append(f"{label}: threats must be a non-empty list")
        else:
            for index, threat in enumerate(threats):
                if not isinstance(threat, dict):
                    errors.append(f"{label}: threats[{index}] must be a mapping")
                    continue
                for field in ("id", "description"):
                    _require_text(threat, field, errors, f"{label}: threats[{index}]")

        implementations = control.get("implementations")
        if not isinstance(implementations, dict):
            errors.append(f"{label}: implementations must be a mapping")
        else:
            for kind in ("insecure", "secure"):
                entries = implementations.get(kind)
                if not isinstance(entries, list) or not entries:
                    errors.append(f"{label}: implementations.{kind} must be a non-empty list")
                    continue
                for relative in entries:
                    if not isinstance(relative, str) or not (directory / relative).is_file():
                        errors.append(f"{label}: missing implementation file {relative!r}")

        verification = control.get("verification")
        if not isinstance(verification, dict):
            errors.append(f"{label}: verification must be a mapping")
        else:
            for field in ("commands", "expected"):
                if not isinstance(verification.get(field), list) or not verification[field]:
                    errors.append(f"{label}: verification.{field} must be a non-empty list")

        checks = control.get("checks")
        check_ids: set[str] = set()
        mapping_status_by_check: dict[str, str] = {}
        if not isinstance(checks, list) or not checks:
            errors.append(f"{label}: checks must be a non-empty list")
        else:
            for index, check in enumerate(checks):
                check_label = f"{label}: checks[{index}]"
                if not isinstance(check, dict):
                    errors.append(f"{check_label} must be a mapping")
                    continue
                for field in (
                    "id",
                    "title",
                    "required_state",
                    "responsible_role",
                    "mapping_status",
                ):
                    _require_text(check, field, errors, check_label)
                check_id = check.get("id")
                if isinstance(check_id, str):
                    if not CHECK_ID_RE.fullmatch(check_id):
                        errors.append(f"{check_label}: invalid check id {check_id!r}")
                    if check_id in check_ids:
                        errors.append(f"{check_label}: duplicate check id {check_id!r}")
                    check_ids.add(check_id)
                    mapping_status_by_check[check_id] = check.get("mapping_status", "")
                if check.get("responsible_role") not in CHECK_ROLES:
                    errors.append(
                        f"{check_label}: unsupported responsible_role "
                        f"{check.get('responsible_role')!r}"
                    )
                applies_to = check.get("applies_to")
                if not isinstance(applies_to, list) or not applies_to:
                    errors.append(f"{check_label}: applies_to must be a non-empty list")
                elif any(not isinstance(item, str) or not item.strip() for item in applies_to):
                    errors.append(f"{check_label}: applies_to entries must be non-empty strings")
                check_verification = check.get("verification")
                if not isinstance(check_verification, dict):
                    errors.append(f"{check_label}: verification must be a mapping")
                else:
                    for field in ("type", "method", "expected"):
                        _require_text(
                            check_verification,
                            field,
                            errors,
                            f"{check_label}: verification",
                        )
                    if check_verification.get("type") not in VERIFICATION_TYPES:
                        errors.append(
                            f"{check_label}: unsupported verification type "
                            f"{check_verification.get('type')!r}"
                        )
                    evidence = check_verification.get("evidence")
                    if not isinstance(evidence, list) or not evidence:
                        errors.append(
                            f"{check_label}: verification.evidence must be a non-empty list"
                        )
                if check.get("mapping_status") not in MAPPING_STATUSES:
                    errors.append(
                        f"{check_label}: unsupported mapping_status "
                        f"{check.get('mapping_status')!r}"
                    )

        mappings = control.get("mappings")
        mapped_check_ids: set[str] = set()
        if not isinstance(mappings, list) or not mappings:
            errors.append(f"{label}: mappings must be a non-empty list")
        else:
            for index, mapping in enumerate(mappings):
                mapping_label = f"{label}: mappings[{index}]"
                if not isinstance(mapping, dict):
                    errors.append(f"{mapping_label} must be a mapping")
                    continue
                for field in (
                    "framework",
                    "version",
                    "id",
                    "relationship",
                    "confidence",
                    "rationale",
                    "reviewer",
                    "review_date",
                ):
                    _require_text(mapping, field, errors, mapping_label)
                if mapping.get("relationship") not in RELATIONSHIPS:
                    errors.append(
                        f"{mapping_label}: unsupported relationship "
                        f"{mapping.get('relationship')!r}"
                    )
                if mapping.get("confidence") not in CONFIDENCE_LEVELS:
                    errors.append(
                        f"{mapping_label}: unsupported confidence {mapping.get('confidence')!r}"
                    )
                applies_to = mapping.get("applies_to")
                if not isinstance(applies_to, list) or not applies_to:
                    errors.append(f"{mapping_label}: applies_to must be a non-empty list")
                else:
                    for check_id in applies_to:
                        if check_id not in check_ids:
                            errors.append(
                                f"{mapping_label}: unknown check id {check_id!r}"
                            )
                        elif isinstance(check_id, str):
                            mapped_check_ids.add(check_id)

        for check_id, mapping_status in mapping_status_by_check.items():
            if mapping_status in {"reviewed", "provisional"} and check_id not in mapped_check_ids:
                errors.append(
                    f"{label}: check {check_id!r} is {mapping_status} but has no mapping"
                )
            if mapping_status == "unmapped" and check_id in mapped_check_ids:
                errors.append(
                    f"{label}: check {check_id!r} is unmapped but is referenced by a mapping"
                )

        limitations = control.get("limitations")
        if not isinstance(limitations, list) or not limitations:
            errors.append(f"{label}: limitations must be a non-empty list")
        if control.get("status") not in STATUSES:
            errors.append(f"{label}: unsupported status {control.get('status')!r}")
        if control.get("evidence_level") not in EVIDENCE_LEVELS:
            errors.append(
                f"{label}: unsupported evidence_level {control.get('evidence_level')!r}"
            )

        for required in ("README.md", "tests/test.sh"):
            if not (directory / required).is_file():
                errors.append(f"{label}: missing required file {required}")

    return errors


def controls_by_id(controls: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {control["id"]: control for control in controls if isinstance(control.get("id"), str)}
