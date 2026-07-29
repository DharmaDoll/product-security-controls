#!/usr/bin/env python3
"""Verify PSB-AI-004 installed runtime inventory and sanitized audit evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from approval_core import EvaluationError, load_json, parse_timestamp


ASSESSMENT_POLICY_SCHEMA = "psb-ai-runtime-assessment-policy/v1"
INVENTORY_POLICY_SCHEMA = "psb-ai-runtime-inventory-policy/v1"
AUDIT_POLICY_SCHEMA = "psb-ai-runtime-audit-policy/v1"
INVENTORY_SCHEMA = "psb-ai-runtime-inventory/v1"
AUDIT_STATE_SCHEMA = "psb-ai-runtime-audit-state/v1"
HEX_REFERENCE = re.compile(r"^[0-9a-f]{64}$")
TOOL_REFERENCE = re.compile(r"^[A-Za-z0-9_-]{1,128}(?:__[A-Za-z0-9_-]{1,128})*$")


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    provider: str | None
    pass_reason: str
    fail_reason: str


def require_policy(
    assessment_policy: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if assessment_policy.get("schema_version") != ASSESSMENT_POLICY_SCHEMA:
        raise EvaluationError("runtime assessment policy schema is unsupported")
    inventory_policy = assessment_policy.get("inventory")
    audit_policy = assessment_policy.get("audit")
    if (
        not isinstance(inventory_policy, dict)
        or inventory_policy.get("schema_version") != INVENTORY_POLICY_SCHEMA
    ):
        raise EvaluationError("runtime inventory policy is unavailable")
    if (
        not isinstance(audit_policy, dict)
        or audit_policy.get("schema_version") != AUDIT_POLICY_SCHEMA
    ):
        raise EvaluationError("runtime audit policy is unavailable")
    extension_policy = runtime_policy.get("extension_capabilities")
    extensions = (
        extension_policy.get("extensions")
        if isinstance(extension_policy, dict)
        else None
    )
    if (
        not isinstance(extensions, dict)
        or extension_policy.get("default_decision") != "deny"
    ):
        raise EvaluationError("runtime extension policy is unavailable")
    return inventory_policy, audit_policy, extensions


def expected_extensions(extensions: dict[str, Any]) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {}
    for extension_id, extension in extensions.items():
        if not isinstance(extension_id, str) or not isinstance(extension, dict):
            raise EvaluationError("runtime extension policy is malformed")
        kind = extension.get("kind")
        dependency_record_id = extension.get("dependency_record_id")
        if (
            kind not in {"mcp", "skill"}
            or not isinstance(dependency_record_id, str)
            or not dependency_record_id
        ):
            raise EvaluationError("runtime extension policy is malformed")
        item: dict[str, Any] = {
            "id": extension_id,
            "kind": kind,
            "dependency_record_id": dependency_record_id,
        }
        if kind == "mcp":
            identity = extension.get("identity")
            if not isinstance(identity, dict):
                raise EvaluationError("runtime MCP identity policy is malformed")
            item["identity"] = identity
        else:
            item["direct_tool_authority"] = extension.get(
                "direct_tool_authority"
            )
        expected[extension_id] = item
    return expected


def inventory_matches(
    inventory: dict[str, Any],
    provider: str,
    inventory_policy: dict[str, Any],
    expected: dict[str, dict[str, Any]],
    minimum_product_version: str,
    now_text: str,
) -> bool:
    if inventory.get("schema_version") != INVENTORY_SCHEMA:
        raise EvaluationError(f"{provider} runtime inventory schema is unsupported")
    if inventory.get("collection_status") != inventory_policy.get(
        "required_collection_status"
    ):
        raise EvaluationError(f"{provider} runtime inventory collection is unavailable")
    captured_at = parse_timestamp(
        inventory.get("captured_at"),
        f"{provider} inventory captured_at",
    )
    now = parse_timestamp(now_text, "runtime assessment now")
    maximum_age = inventory_policy.get("maximum_age_seconds")
    if not isinstance(maximum_age, int) or maximum_age < 1:
        raise EvaluationError("runtime inventory freshness policy is malformed")
    fresh = 0 <= (now - captured_at).total_seconds() <= maximum_age
    allowed_inventory_fields = inventory_policy.get("allowed_inventory_fields")
    if (
        not isinstance(allowed_inventory_fields, list)
        or not all(isinstance(value, str) for value in allowed_inventory_fields)
    ):
        raise EvaluationError("runtime inventory field policy is malformed")

    items = inventory.get("extensions")
    if not isinstance(items, list):
        raise EvaluationError(f"{provider} runtime inventory extensions are malformed")
    actual: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise EvaluationError(f"{provider} runtime inventory entry is malformed")
        extension_id = item.get("id")
        if (
            not isinstance(extension_id, str)
            or not extension_id
            or extension_id in actual
        ):
            raise EvaluationError(f"{provider} runtime inventory identity is malformed")
        actual[extension_id] = item

    return all(
        (
            inventory.get("provider") == provider,
            version_at_least(
                inventory.get("product_version"), minimum_product_version
            ),
            inventory.get("collection_source") == "managed-endpoint-assessment",
            inventory.get("plugin_installation_enabled") is False,
            inventory_policy.get("allow_unknown_extensions") is False,
            inventory_policy.get("require_exact_dependency_record") is True,
            fresh,
            set(inventory) == set(allowed_inventory_fields),
            actual == expected,
        )
    )


def version_at_least(actual: Any, minimum: str) -> bool:
    if not isinstance(actual, str):
        return False
    try:
        actual_parts = tuple(int(part) for part in actual.split("."))
        minimum_parts = tuple(int(part) for part in minimum.split("."))
    except ValueError:
        return False
    return (
        len(actual_parts) == 3
        and len(minimum_parts) == 3
        and actual_parts >= minimum_parts
    )


def load_json_lines(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError, UnicodeError) as error:
        raise EvaluationError("runtime audit events are unavailable") from error
    if not lines:
        raise EvaluationError("runtime audit events are empty")
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvaluationError("runtime audit events are malformed") from error
        if not isinstance(event, dict):
            raise EvaluationError("runtime audit event is not an object")
        events.append(event)
    return events


def safe_reference(value: Any, *, nullable: bool = False) -> bool:
    return (nullable and value is None) or (
        isinstance(value, str) and bool(HEX_REFERENCE.fullmatch(value))
    )


def audit_matches(
    audit_policy: dict[str, Any],
    audit_state: dict[str, Any],
    events: list[dict[str, Any]],
    now_text: str,
) -> bool:
    if audit_state.get("schema_version") != AUDIT_STATE_SCHEMA:
        raise EvaluationError("runtime audit state schema is unsupported")
    if audit_state.get("available") is not True:
        raise EvaluationError("runtime audit state is unavailable")
    allowed_fields = audit_policy.get("allowed_event_fields")
    required_decisions = audit_policy.get("required_decisions")
    allowed_reason_codes = audit_policy.get("allowed_reason_codes")
    allowed_state_fields = audit_policy.get("allowed_state_fields")
    if (
        not isinstance(allowed_fields, list)
        or not all(isinstance(value, str) for value in allowed_fields)
        or not isinstance(required_decisions, list)
        or not all(isinstance(value, str) for value in required_decisions)
        or not isinstance(allowed_reason_codes, list)
        or not all(isinstance(value, str) for value in allowed_reason_codes)
        or not isinstance(allowed_state_fields, list)
        or not all(isinstance(value, str) for value in allowed_state_fields)
    ):
        raise EvaluationError("runtime audit event policy is malformed")
    allowed_field_set = set(allowed_fields)
    decisions: set[str] = set()
    event_schema = audit_policy.get("event_schema_version")
    event_policy_revision = audit_policy.get("policy_revision")
    maximum_event_age = audit_policy.get("maximum_event_age_seconds")
    if not isinstance(maximum_event_age, int) or maximum_event_age < 1:
        raise EvaluationError("runtime audit freshness policy is malformed")
    now = parse_timestamp(now_text, "runtime assessment now")
    events_ok = True
    for event in events:
        decision = event.get("decision")
        if isinstance(decision, str):
            decisions.add(decision)
        events_ok = events_ok and all(
            (
                set(event) == allowed_field_set,
                event.get("schema_version") == event_schema,
                event.get("control_id") == "PSB-AI-004",
                event.get("policy_revision") == event_policy_revision,
                event.get("provider") in {"claude-code", "codex"},
                safe_reference(event.get("session_ref"))
                or event.get("session_ref") == "unavailable",
                safe_reference(event.get("event_ref"))
                or event.get("event_ref") == "unavailable",
                isinstance(event.get("tool_ref"), str)
                and bool(TOOL_REFERENCE.fullmatch(event["tool_ref"])),
                decision in required_decisions,
                event.get("reason_code") in allowed_reason_codes,
                safe_reference(event.get("request_ref"), nullable=True),
                safe_reference(event.get("approval_ref"), nullable=True),
            )
        )
        timestamp = parse_timestamp(
            event.get("timestamp"), "runtime audit timestamp"
        )
        events_ok = events_ok and (
            0 <= (now - timestamp).total_seconds() <= maximum_event_age
        )

    retention_days = audit_state.get("retention_days")
    maximum_retention = audit_policy.get("maximum_retention_days")
    storage_ok = all(
        (
            audit_state.get("managed_owner")
            is audit_policy.get("require_managed_owner")
            is True,
            set(audit_state) == set(allowed_state_fields),
            audit_state.get("owner") == "root",
            audit_state.get("directory_mode") == audit_policy.get("directory_mode"),
            audit_state.get("file_mode") == audit_policy.get("file_mode"),
            isinstance(retention_days, int),
            isinstance(maximum_retention, int),
            isinstance(retention_days, int)
            and isinstance(maximum_retention, int)
            and 0 < retention_days <= maximum_retention,
            audit_state.get("export_enabled")
            is audit_policy.get("require_export")
            is True,
            audit_state.get("export_destination_class")
            == "organization-security-log",
        )
    )
    return events_ok and decisions == set(required_decisions) and storage_ok


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify PSB-AI-004 installed inventory and audit evidence."
    )
    parser.add_argument("assessment_policy", type=Path)
    parser.add_argument("runtime_policy", type=Path)
    parser.add_argument("claude_inventory", type=Path)
    parser.add_argument("codex_inventory", type=Path)
    parser.add_argument("audit_state", type=Path)
    parser.add_argument("audit_events", type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--now", required=True)
    args = parser.parse_args()

    try:
        assessment_policy = load_json(
            args.assessment_policy.resolve(), "runtime assessment policy"
        )
        runtime_policy = load_json(
            args.runtime_policy.resolve(), "runtime policy"
        )
        inventory_policy, audit_policy, extensions = require_policy(
            assessment_policy, runtime_policy
        )
        expected = expected_extensions(extensions)
        supported_adapters = runtime_policy.get("supported_adapters")
        if not isinstance(supported_adapters, dict):
            raise EvaluationError("runtime adapter version policy is unavailable")
        minimum_versions: dict[str, str] = {}
        for provider in ("claude-code", "codex"):
            adapter = supported_adapters.get(provider)
            minimum = (
                adapter.get("minimum_product_version")
                if isinstance(adapter, dict)
                else None
            )
            if not isinstance(minimum, str):
                raise EvaluationError(
                    "runtime adapter version policy is unavailable"
                )
            minimum_versions[provider] = minimum
        results = [
            CheckResult(
                "AAR-018",
                inventory_matches(
                    load_json(
                        args.claude_inventory.resolve(),
                        "Claude Code runtime inventory",
                    ),
                    "claude-code",
                    inventory_policy,
                    expected,
                    minimum_versions["claude-code"],
                    args.now,
                ),
                "claude-code",
                "installed runtime inventory exactly matches reviewed extensions",
                "runtime inventory is stale broad incomplete or differs from reviewed extensions",
            ),
            CheckResult(
                "AAR-018",
                inventory_matches(
                    load_json(
                        args.codex_inventory.resolve(), "Codex runtime inventory"
                    ),
                    "codex",
                    inventory_policy,
                    expected,
                    minimum_versions["codex"],
                    args.now,
                ),
                "codex",
                "installed runtime inventory exactly matches reviewed extensions",
                "runtime inventory is stale broad incomplete or differs from reviewed extensions",
            ),
            CheckResult(
                "AAR-019",
                audit_matches(
                    audit_policy,
                    load_json(args.audit_state.resolve(), "runtime audit state"),
                    load_json_lines(args.audit_events.resolve()),
                    args.now,
                ),
                None,
                "audit decisions are complete redacted access-controlled and retention-bound",
                "audit evidence is incomplete sensitive broadly accessible or over-retained",
            ),
        ]
    except EvaluationError as error:
        print(f"ERROR PSB-AI-004 runtime evidence verification failed: {error}")
        return 2
    except Exception:
        print(
            "ERROR PSB-AI-004 runtime evidence verification failed: "
            "unexpected evaluator failure"
        )
        return 2

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        provider = f" provider={result.provider}" if result.provider else ""
        reason = result.pass_reason if result.passed else result.fail_reason
        print(f"{status} PSB-AI-004/{result.check_id}{provider} {reason}")
    failures = sum(not result.passed for result in results)
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} profile={args.profile} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
