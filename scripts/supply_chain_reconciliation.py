#!/usr/bin/env python3
"""Load and validate the cross-control software supply-chain reconciliation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "psb-supply-chain-integration-reconciliation/v1"
DISPOSITIONS = {"implemented", "planned", "gap", "out-of-scope"}
ROW_ID_RE = re.compile(r"^SCIR-[0-9]{3}$")
CONTROL_ID_RE = re.compile(r"^PSB-[A-Z]+-[0-9]{3}$")
SECTION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){0,2}$")
REQUIRED_ROW_FIELDS = {
    "id",
    "nist_sections",
    "integration_boundary",
    "threat_or_failure",
    "required_connection",
    "disposition",
    "check_refs",
    "planned_control_ids",
    "gap_owner",
    "gap_description",
    "rationale",
    "limitations",
}


class ReconciliationError(ValueError):
    """Raised when the reconciliation source cannot be trusted."""


def _text(row: dict[str, Any], field: str, label: str, errors: list[str]) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label}: {field} must be a non-empty string")
        return ""
    return value.strip()


def validate_reconciliation(
    data: dict[str, Any], controls: list[dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"reconciliation: schema must be {SCHEMA!r}")
    if data.get("profile_id") != "nist-sp-800-204d-integration":
        errors.append("reconciliation: unexpected profile_id")
    _text(data, "title", "reconciliation", errors)
    _text(data, "claim_boundary", "reconciliation", errors)

    source = data.get("source")
    if not isinstance(source, dict):
        errors.append("reconciliation: source must be an object")
    else:
        expected_source = {
            "reference_id": "REF-CICD-012",
            "publication": "NIST SP 800-204D",
            "version": "Final, February 2024",
            "official_url": "https://csrc.nist.gov/pubs/sp/800/204/d/final",
        }
        for field, expected in expected_source.items():
            if source.get(field) != expected:
                errors.append(
                    f"reconciliation: source.{field} must be {expected!r}"
                )

    known_checks = {
        f"{control['id']}-{check['id']}"
        for control in controls
        for check in control["checks"]
    }
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows:
        errors.append("reconciliation: rows must be a non-empty list")
        return errors

    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        label = f"reconciliation row {index}"
        if not isinstance(row, dict):
            errors.append(f"{label}: must be an object")
            continue
        missing = REQUIRED_ROW_FIELDS - set(row)
        extra = set(row) - REQUIRED_ROW_FIELDS
        if missing:
            errors.append(f"{label}: missing fields {sorted(missing)}")
        if extra:
            errors.append(f"{label}: unknown fields {sorted(extra)}")

        row_id = _text(row, "id", label, errors)
        if row_id and not ROW_ID_RE.fullmatch(row_id):
            errors.append(f"{label}: invalid repository row id {row_id!r}")
        if row_id in seen:
            errors.append(f"{label}: duplicate row id {row_id!r}")
        seen.add(row_id)
        for field in (
            "integration_boundary",
            "threat_or_failure",
            "required_connection",
            "rationale",
            "limitations",
        ):
            _text(row, field, label, errors)

        sections = row.get("nist_sections")
        if not isinstance(sections, list) or not sections:
            errors.append(f"{label}: nist_sections must be a non-empty list")
        elif any(not isinstance(item, str) or not SECTION_RE.fullmatch(item) for item in sections):
            errors.append(f"{label}: nist_sections contains an invalid section")

        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            errors.append(f"{label}: invalid disposition {disposition!r}")

        check_refs = row.get("check_refs")
        if not isinstance(check_refs, list) or any(
            not isinstance(item, str) for item in check_refs
        ):
            errors.append(f"{label}: check_refs must be a string list")
            check_refs = []
        else:
            if len(check_refs) != len(set(check_refs)):
                errors.append(f"{label}: check_refs must be unique")
            for reference in check_refs:
                if reference not in known_checks:
                    errors.append(f"{label}: unknown check reference {reference!r}")

        planned = row.get("planned_control_ids")
        if not isinstance(planned, list) or any(
            not isinstance(item, str) or not CONTROL_ID_RE.fullmatch(item)
            for item in planned
        ):
            errors.append(f"{label}: planned_control_ids must contain control IDs")
            planned = []
        elif len(planned) != len(set(planned)):
            errors.append(f"{label}: planned_control_ids must be unique")

        gap_owner = row.get("gap_owner")
        gap_description = row.get("gap_description")
        if not isinstance(gap_owner, str) or not isinstance(gap_description, str):
            errors.append(f"{label}: gap fields must be strings")
            gap_owner = ""
            gap_description = ""

        if disposition == "implemented":
            if not check_refs:
                errors.append(f"{label}: implemented requires exact check_refs")
            if planned or gap_owner or gap_description:
                errors.append(f"{label}: implemented cannot carry plan or gap fields")
        elif disposition == "planned":
            if not planned:
                errors.append(f"{label}: planned requires planned_control_ids")
            if not gap_owner.strip() or not gap_description.strip():
                errors.append(f"{label}: planned requires owner and remaining work")
        elif disposition == "gap":
            if planned:
                errors.append(f"{label}: gap cannot claim a planned control")
            if not gap_owner.strip() or not gap_description.strip():
                errors.append(f"{label}: gap requires owner and description")
        elif disposition == "out-of-scope":
            if check_refs or planned:
                errors.append(f"{label}: out-of-scope cannot claim control evidence")
            if not gap_owner.strip() or not gap_description.strip():
                errors.append(f"{label}: out-of-scope requires boundary owner and reason")

    return errors


def load_reconciliation(
    path: Path, controls: list[dict[str, Any]]
) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReconciliationError(f"cannot load reconciliation: {exc}") from exc
    if not isinstance(data, dict):
        raise ReconciliationError("reconciliation root must be an object")
    errors = validate_reconciliation(data, controls)
    if errors:
        raise ReconciliationError("; ".join(errors))
    return data


def build_reconciliation_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    source = data["source"]
    return [
        {
            "Profile Row ID": row["id"],
            "Source Reference ID": source["reference_id"],
            "Source Publication": f"{source['publication']} ({source['version']})",
            "Official Source": source["official_url"],
            "Source Sections": "; ".join(row["nist_sections"]),
            "Integration Boundary": row["integration_boundary"],
            "Threat or Failure": row["threat_or_failure"],
            "Required Connection": row["required_connection"],
            "Disposition": row["disposition"],
            "Current Check Evidence": "; ".join(row["check_refs"]),
            "Planned Controls": "; ".join(row["planned_control_ids"]),
            "Gap or Boundary Owner": row["gap_owner"],
            "Remaining Work or Boundary": row["gap_description"],
            "Rationale": row["rationale"],
            "Limitations": row["limitations"],
            "Claim Boundary": data["claim_boundary"],
        }
        for row in data["rows"]
    ]
