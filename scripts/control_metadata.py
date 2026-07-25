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
CONTROL_ID_RE = re.compile(r"^PSB-[A-Z]+-[0-9]{3}$")
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
                    while index < len(entries) and entries[index][1] > current_indent:
                        nested_line, nested_indent, nested_text = entries[index]
                        if nested_indent != current_indent + 2 or ": " not in nested_text:
                            raise MetadataError(
                                f"{path}:{nested_line}: unsupported list mapping syntax"
                            )
                        nested_key, nested_scalar = nested_text.split(": ", 1)
                        item[nested_key] = parse_scalar(nested_scalar)
                        index += 1
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
                value[key] = parse_scalar(scalar)
                index += 1
                continue
            if text.endswith(":"):
                key = text[:-1]
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

        mappings = control.get("mappings")
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
