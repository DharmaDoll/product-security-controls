#!/usr/bin/env python3
"""Validate and render the pinned SITF coverage and attack-flow profiles."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from control_metadata import REPOSITORY_ROOT, discover_controls
from framework_registry import discover_registries


PROFILE_SCHEMA = "psb-sitf-coverage/v1"
FLOW_SCHEMA = "psb-sitf-attack-flows/v1"
PROFILE_ID = "sitf-technique-coverage"
REGISTRY_NAME = "sitf"
DISPOSITIONS = {"implemented", "planned", "gap", "out-of-scope"}
COMPONENTS = {"endpoint", "vcs", "cicd", "registry", "production"}
TECHNIQUE_ID_RE = re.compile(r"^T-[EVCRP][0-9]{3}$")
FLOW_ID_RE = re.compile(r"^SITF-FLOW-[0-9]{3}$")
CONTROL_ID_RE = re.compile(r"^PSB-[A-Z]+-[0-9]{3}$")


class SitfCoverageError(ValueError):
    """Raised when a SITF profile cannot be trusted."""


def _text(value: Any, label: str, errors: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} must be a non-empty string")
        return ""
    return value.strip()


def _known_checks(controls: list[dict[str, Any]]) -> set[str]:
    return {
        f"{control['id']}-{check['id']}"
        for control in controls
        for check in control["checks"]
    }


def _registry_entries(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["id"]: entry for entry in registry.get("entries", [])}


def validate_coverage(
    data: dict[str, Any],
    registry: dict[str, Any],
    controls: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != PROFILE_SCHEMA:
        errors.append(f"coverage: schema must be {PROFILE_SCHEMA!r}")
    if data.get("profile_id") != PROFILE_ID:
        errors.append(f"coverage: profile_id must be {PROFILE_ID!r}")
    if data.get("registry_name") != REGISTRY_NAME:
        errors.append(f"coverage: registry_name must be {REGISTRY_NAME!r}")
    if data.get("mapping_version") != registry.get("mapping_version"):
        errors.append("coverage: mapping_version does not match the SITF registry")
    _text(data.get("title"), "coverage: title", errors)
    claim_boundary = _text(data.get("claim_boundary"), "coverage: claim_boundary", errors)
    if "compliance" not in claim_boundary.lower():
        errors.append("coverage: claim_boundary must explicitly reject a compliance claim")

    entries = _registry_entries(registry)
    if len(entries) != 81:
        errors.append(f"coverage: SITF registry must contain 81 techniques, found {len(entries)}")
    for technique_id, entry in entries.items():
        if not TECHNIQUE_ID_RE.fullmatch(technique_id):
            errors.append(f"coverage: invalid SITF technique id {technique_id!r}")
        if entry.get("component") not in COMPONENTS:
            errors.append(f"coverage: {technique_id} has an invalid component")
        _text(entry.get("stage"), f"coverage: {technique_id} stage", errors)

    boundaries = data.get("component_boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != COMPONENTS:
        errors.append("coverage: component_boundaries must define all five SITF components")
        boundaries = {}
    for component in sorted(COMPONENTS):
        boundary = boundaries.get(component)
        if not isinstance(boundary, dict):
            errors.append(f"coverage: component boundary {component!r} must be an object")
            continue
        _text(boundary.get("owner"), f"coverage: {component} owner", errors)
        _text(boundary.get("limitation"), f"coverage: {component} limitation", errors)

    known_checks = _known_checks(controls)
    rows = data.get("techniques")
    if not isinstance(rows, list) or not rows:
        errors.append("coverage: techniques must be a non-empty list")
        return errors

    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        label = f"coverage technique {index}"
        if not isinstance(row, dict):
            errors.append(f"{label}: must be an object")
            continue
        allowed = {
            "technique_id",
            "disposition",
            "check_refs",
            "planned_control_ids",
            "remaining_work",
            "rationale",
        }
        extra = set(row) - allowed
        if extra:
            errors.append(f"{label}: unknown fields {sorted(extra)}")

        technique_id = _text(row.get("technique_id"), f"{label}: technique_id", errors)
        if technique_id in seen:
            errors.append(f"{label}: duplicate technique {technique_id!r}")
        seen.add(technique_id)
        if technique_id not in entries:
            errors.append(f"{label}: unknown SITF technique {technique_id!r}")

        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            errors.append(f"{label}: invalid disposition {disposition!r}")
        rationale = _text(row.get("rationale"), f"{label}: rationale", errors)
        if "complies-with" in rationale.lower():
            errors.append(f"{label}: rationale must not claim compliance")

        check_refs = row.get("check_refs", [])
        if not isinstance(check_refs, list) or any(
            not isinstance(reference, str) for reference in check_refs
        ):
            errors.append(f"{label}: check_refs must be a string list")
            check_refs = []
        elif len(check_refs) != len(set(check_refs)):
            errors.append(f"{label}: check_refs must be unique")
        for reference in check_refs:
            if reference not in known_checks:
                errors.append(f"{label}: unknown check reference {reference!r}")

        planned = row.get("planned_control_ids", [])
        if not isinstance(planned, list) or any(
            not isinstance(control_id, str)
            or not CONTROL_ID_RE.fullmatch(control_id)
            for control_id in planned
        ):
            errors.append(f"{label}: planned_control_ids must contain control IDs")
            planned = []
        elif len(planned) != len(set(planned)):
            errors.append(f"{label}: planned_control_ids must be unique")

        remaining_work = row.get("remaining_work", "")
        if not isinstance(remaining_work, str):
            errors.append(f"{label}: remaining_work must be a string")
            remaining_work = ""

        if disposition == "implemented":
            if not check_refs:
                errors.append(f"{label}: implemented requires exact check_refs")
            if planned or remaining_work.strip():
                errors.append(f"{label}: implemented cannot carry planned or gap work")
        elif disposition == "planned":
            if not planned or not remaining_work.strip():
                errors.append(f"{label}: planned requires controls and remaining work")
        elif disposition == "gap":
            if planned:
                errors.append(f"{label}: gap cannot claim a planned control")
            if not remaining_work.strip():
                errors.append(f"{label}: gap requires remaining work")
        elif disposition == "out-of-scope":
            if check_refs or planned or not remaining_work.strip():
                errors.append(f"{label}: out-of-scope requires only a boundary reason")

    missing = sorted(set(entries) - seen)
    unexpected = sorted(seen - set(entries))
    if missing:
        errors.append(f"coverage: missing SITF techniques {missing}")
    if unexpected:
        errors.append(f"coverage: unexpected SITF techniques {unexpected}")
    if len(rows) != len(entries):
        errors.append(
            f"coverage: technique row count {len(rows)} does not match registry {len(entries)}"
        )
    return errors


def validate_attack_flows(
    data: dict[str, Any],
    registry: dict[str, Any],
    coverage: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != FLOW_SCHEMA:
        errors.append(f"attack flows: schema must be {FLOW_SCHEMA!r}")
    if data.get("profile_id") != "sitf-attack-flows":
        errors.append("attack flows: unexpected profile_id")
    if data.get("source_profile_id") != coverage.get("profile_id"):
        errors.append("attack flows: source_profile_id does not match coverage")
    if data.get("mapping_version") != registry.get("mapping_version"):
        errors.append("attack flows: mapping_version does not match the SITF registry")
    _text(data.get("title"), "attack flows: title", errors)
    _text(data.get("claim_boundary"), "attack flows: claim_boundary", errors)

    entries = _registry_entries(registry)
    dispositions = {
        row["technique_id"]: row["disposition"]
        for row in coverage.get("techniques", [])
        if isinstance(row, dict) and isinstance(row.get("technique_id"), str)
    }
    flows = data.get("flows")
    if not isinstance(flows, list) or not flows:
        errors.append("attack flows: flows must be a non-empty list")
        return errors
    seen: set[str] = set()
    for index, flow in enumerate(flows, start=1):
        label = f"attack flow {index}"
        if not isinstance(flow, dict):
            errors.append(f"{label}: must be an object")
            continue
        flow_id = _text(flow.get("id"), f"{label}: id", errors)
        if not FLOW_ID_RE.fullmatch(flow_id):
            errors.append(f"{label}: invalid flow id {flow_id!r}")
        if flow_id in seen:
            errors.append(f"{label}: duplicate flow id {flow_id!r}")
        seen.add(flow_id)
        _text(flow.get("title"), f"{label}: title", errors)
        _text(flow.get("scenario"), f"{label}: scenario", errors)
        steps = flow.get("steps")
        if not isinstance(steps, list) or len(steps) < 3:
            errors.append(f"{label}: steps must contain at least three techniques")
            continue
        components: set[str] = set()
        for step_index, step in enumerate(steps, start=1):
            step_label = f"{label} step {step_index}"
            if not isinstance(step, dict):
                errors.append(f"{step_label}: must be an object")
                continue
            if set(step) != {"technique_id", "objective"}:
                errors.append(f"{step_label}: must contain technique_id and objective")
            technique_id = _text(
                step.get("technique_id"), f"{step_label}: technique_id", errors
            )
            _text(step.get("objective"), f"{step_label}: objective", errors)
            entry = entries.get(technique_id)
            if entry is None:
                errors.append(f"{step_label}: unknown SITF technique {technique_id!r}")
            else:
                components.add(entry["component"])
            if technique_id not in dispositions:
                errors.append(f"{step_label}: technique is absent from coverage")
        if len(components) < 3:
            errors.append(f"{label}: must cross at least three SITF components")
    return errors


def load_profiles(
    coverage_path: Path,
    flow_path: Path,
    registry: dict[str, Any],
    controls: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
        flows = json.loads(flow_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SitfCoverageError(f"cannot load SITF profiles: {exc}") from exc
    if not isinstance(coverage, dict) or not isinstance(flows, dict):
        raise SitfCoverageError("SITF profile roots must be objects")
    errors = validate_coverage(coverage, registry, controls)
    if not errors:
        errors.extend(validate_attack_flows(flows, registry, coverage))
    if errors:
        raise SitfCoverageError("; ".join(errors))
    return coverage, flows


def build_coverage_rows(
    coverage: dict[str, Any], registry: dict[str, Any]
) -> list[dict[str, str]]:
    entries = _registry_entries(registry)
    boundaries = coverage["component_boundaries"]
    rows: list[dict[str, str]] = []
    for item in coverage["techniques"]:
        entry = entries[item["technique_id"]]
        boundary = boundaries[entry["component"]]
        rows.append(
            {
                "Technique ID": entry["id"],
                "Technique": entry["title"],
                "Component": entry["component"],
                "Stage": entry["stage"],
                "Disposition": item["disposition"],
                "Exact or Supporting Checks": "; ".join(item.get("check_refs", [])),
                "Planned Controls": "; ".join(item.get("planned_control_ids", [])),
                "Gap or Boundary Owner": boundary["owner"],
                "Remaining Work or Boundary": item.get("remaining_work", ""),
                "Rationale": item["rationale"],
                "Component Limitation": boundary["limitation"],
                "Source Version": registry["mapping_version"],
                "Official Source": entry["source_url"],
                "Claim Boundary": coverage["claim_boundary"],
            }
        )
    return rows


def build_attack_flow_rows(
    flows: dict[str, Any],
    coverage: dict[str, Any],
    registry: dict[str, Any],
) -> list[dict[str, str]]:
    entries = _registry_entries(registry)
    dispositions = {
        row["technique_id"]: row["disposition"] for row in coverage["techniques"]
    }
    rows: list[dict[str, str]] = []
    for flow in flows["flows"]:
        for sequence, step in enumerate(flow["steps"], start=1):
            entry = entries[step["technique_id"]]
            rows.append(
                {
                    "Flow ID": flow["id"],
                    "Flow": flow["title"],
                    "Scenario": flow["scenario"],
                    "Sequence": str(sequence),
                    "Technique ID": entry["id"],
                    "Technique": entry["title"],
                    "Component": entry["component"],
                    "Objective": step["objective"],
                    "Coverage Disposition": dispositions[entry["id"]],
                    "Claim Boundary": flows["claim_boundary"],
                }
            )
    return rows


def disposition_counts(rows: list[dict[str, str]]) -> Counter[str]:
    return Counter(row["Disposition"] for row in rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    registries = discover_registries()
    registry = registries.get(REGISTRY_NAME)
    if registry is None:
        raise SitfCoverageError("SITF registry is missing")
    coverage, flows = load_profiles(
        REPOSITORY_ROOT / "policies" / "integration" / "sitf-coverage.json",
        REPOSITORY_ROOT / "policies" / "integration" / "sitf-attack-flows.json",
        registry,
        discover_controls(),
    )
    if not args.check_only:
        counts = disposition_counts(build_coverage_rows(coverage, registry))
        print(
            "SITF profile valid: "
            f"{sum(counts.values())} techniques, {len(flows['flows'])} attack flows, "
            + ", ".join(f"{key}={counts[key]}" for key in sorted(DISPOSITIONS))
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
