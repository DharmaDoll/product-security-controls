#!/usr/bin/env python3
"""Validate and render the organization-owned FIRST PSIRT capability profile."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "psb-first-psirt-capability-profile/v1"
PROFILE_ID = "first-psirt-capability"
RESULTS = {"PASS", "FAIL", "NOT_CHECKED", "ERROR", "N/A"}
ROW_ID_RE = re.compile(r"^PSIRT-[BIA]-[0-9]{3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_SOURCES = {
    "REF-GOV-003": "https://www.first.org/standards/frameworks/psirts/psirt_maturity_document",
    "REF-GOV-004": "https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1",
}


class PsirtProfileError(ValueError):
    """Raised when the public PSIRT profile cannot be trusted."""


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_profile(data: dict[str, Any], controls: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"PSIRT profile schema must be {SCHEMA!r}")
    if data.get("profile_id") != PROFILE_ID:
        errors.append(f"PSIRT profile_id must be {PROFILE_ID!r}")
    for field in ("title", "claim_boundary"):
        if not _nonempty(data.get(field)):
            errors.append(f"PSIRT profile {field} must be non-empty")

    snapshots = data.get("source_snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != 2:
        errors.append("PSIRT profile requires exactly two source snapshots")
        snapshots = []
    seen_sources: set[str] = set()
    for index, source in enumerate(snapshots, start=1):
        label = f"PSIRT source {index}"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
            continue
        reference = source.get("reference_id")
        if reference not in EXPECTED_SOURCES:
            errors.append(f"{label} has unknown reference_id {reference!r}")
        elif source.get("official_url") != EXPECTED_SOURCES[reference]:
            errors.append(f"{label} official_url does not match {reference}")
        if reference in seen_sources:
            errors.append(f"{label} duplicates {reference}")
        seen_sources.add(reference)
        for field in ("title", "version", "observed_on"):
            if not _nonempty(source.get(field)):
                errors.append(f"{label} {field} must be non-empty")
        if not isinstance(source.get("sha256"), str) or not SHA256_RE.fullmatch(source["sha256"]):
            errors.append(f"{label} sha256 must be 64 lowercase hexadecimal characters")
        if not isinstance(source.get("byte_size"), int) or source["byte_size"] <= 0:
            errors.append(f"{label} byte_size must be a positive integer")
    if seen_sources != set(EXPECTED_SOURCES):
        errors.append("PSIRT profile source snapshot set is incomplete")

    catalog = data.get("service_catalog")
    if not isinstance(catalog, list) or not catalog:
        errors.append("PSIRT service_catalog must be a non-empty list")
        catalog = []
    service_ids: set[str] = set()
    for index, service in enumerate(catalog, start=1):
        label = f"PSIRT service {index}"
        if not isinstance(service, dict):
            errors.append(f"{label} must be an object")
            continue
        if set(service) != {"id", "area", "title"}:
            errors.append(f"{label} has missing or unknown fields")
        service_id = service.get("id")
        if not _nonempty(service_id):
            errors.append(f"{label} id must be non-empty")
        elif service_id in service_ids:
            errors.append(f"{label} duplicates id {service_id}")
        service_ids.add(service_id)
        if not _nonempty(service.get("area")) or not _nonempty(service.get("title")):
            errors.append(f"{label} area and title must be non-empty")

    known_checks = {
        f"{control['id']}-{check['id']}"
        for control in controls
        for check in control["checks"]
    }
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows:
        errors.append("PSIRT profile rows must be a non-empty list")
        return errors
    row_ids: set[str] = set()
    levels: Counter[int] = Counter()
    required = {
        "id", "minimum_level", "capability_area", "capability",
        "threat_or_failure", "responsible_role", "required_evidence",
        "service_refs", "repository_check_refs", "assessment_result", "limitations",
    }
    for index, row in enumerate(rows, start=1):
        label = f"PSIRT row {index}"
        if not isinstance(row, dict):
            errors.append(f"{label} must be an object")
            continue
        if set(row) != required:
            errors.append(f"{label} has missing or unknown fields")
        row_id = row.get("id")
        if not isinstance(row_id, str) or not ROW_ID_RE.fullmatch(row_id):
            errors.append(f"{label} has invalid id {row_id!r}")
        elif row_id in row_ids:
            errors.append(f"{label} duplicates id {row_id}")
        row_ids.add(row_id)
        level = row.get("minimum_level")
        if level not in {1, 2, 3}:
            errors.append(f"{label} minimum_level must be 1, 2, or 3")
        else:
            levels[level] += 1
            expected_letter = {1: "B", 2: "I", 3: "A"}[level]
            if isinstance(row_id, str) and not row_id.startswith(f"PSIRT-{expected_letter}-"):
                errors.append(f"{label} id does not match minimum_level")
        for field in ("capability_area", "capability", "threat_or_failure", "responsible_role", "limitations"):
            if not _nonempty(row.get(field)):
                errors.append(f"{label} {field} must be non-empty")
        evidence = row.get("required_evidence")
        if not isinstance(evidence, list) or not evidence or any(not _nonempty(item) for item in evidence):
            errors.append(f"{label} required_evidence must be a non-empty string list")
        refs = row.get("service_refs")
        if not isinstance(refs, list) or not refs or any(ref not in service_ids for ref in refs):
            errors.append(f"{label} service_refs must resolve to the catalog")
        check_refs = row.get("repository_check_refs")
        if not isinstance(check_refs, list) or any(ref not in known_checks for ref in check_refs):
            errors.append(f"{label} repository_check_refs must resolve exactly")
        if row.get("assessment_result") not in RESULTS:
            errors.append(f"{label} assessment_result is invalid")
        elif row["assessment_result"] != "NOT_CHECKED":
            errors.append(f"{label} public assessment_result must remain NOT_CHECKED")
    if set(levels) != {1, 2, 3}:
        errors.append("PSIRT profile must keep all three cumulative levels visible")
    return errors


def load_profile(path: Path, controls: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PsirtProfileError(f"cannot load PSIRT profile: {exc}") from exc
    if not isinstance(data, dict):
        raise PsirtProfileError("PSIRT profile root must be an object")
    errors = validate_profile(data, controls)
    if errors:
        raise PsirtProfileError("; ".join(errors))
    return data


def build_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    services = {item["id"]: item for item in data["service_catalog"]}
    source_identity = "; ".join(
        f"{item['reference_id']} {item['version']} sha256:{item['sha256']}"
        for item in data["source_snapshots"]
    )
    return [
        {
            "Profile Row ID": row["id"],
            "Cumulative Minimum Level": str(row["minimum_level"]),
            "Capability Area": row["capability_area"],
            "Capability": row["capability"],
            "Threat or Failure": row["threat_or_failure"],
            "Responsible Role": row["responsible_role"],
            "Required Organization Evidence": "; ".join(row["required_evidence"]),
            "FIRST Service References": "; ".join(
                f"{ref} {services[ref]['title']}" for ref in row["service_refs"]
            ),
            "Repository Supporting Checks": "; ".join(row["repository_check_refs"]),
            "Assessment Result": row["assessment_result"],
            "Evidence Freshness": "NOT_CHECKED",
            "Assignee": "",
            "Evidence URL": "",
            "Exception ID": "",
            "Notes": "",
            "Limitations": row["limitations"],
            "Source Snapshot Identity": source_identity,
            "Claim Boundary": data["claim_boundary"],
        }
        for row in data["rows"]
    ]
