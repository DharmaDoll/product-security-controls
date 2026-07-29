#!/usr/bin/env python3
"""Verify that product hook failures cannot become remote side effects."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-hook-failure-boundary-policy/v1"
EVIDENCE_SCHEMA = "psb-ai-hook-failure-boundary-evidence/v1"
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
CASE_FIELDS = {
    "scenario_id",
    "scenario_class",
    "provider",
    "product_version",
    "managed_hook_matched",
    "hook_state",
    "exit_code",
    "hook_decision",
    "hook_audit_committed",
    "request_binding_status",
    "permit_issuer_status",
    "permit_status",
    "gateway_available",
    "gateway_enforcement",
    "gateway_decision",
    "gateway_audit_committed",
    "native_product_would_continue",
    "external_side_effect_observed",
}


class EvaluationError(Exception):
    """Hook lifecycle evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Result:
    provider: str
    scenario_id: str
    passed: bool
    reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"{status} PSB-AI-004/AAR-022 provider={self.provider} "
            f"scenario={self.scenario_id} {self.reason}"
        )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is unavailable") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be an object")
    return value


def version_at_least(actual: Any, minimum: Any) -> bool:
    if not isinstance(actual, str) or not isinstance(minimum, str):
        return False
    try:
        actual_parts = tuple(int(value) for value in actual.split("."))
        minimum_parts = tuple(int(value) for value in minimum.split("."))
    except ValueError:
        return False
    return (
        len(actual_parts) == 3
        and len(minimum_parts) == 3
        and actual_parts >= minimum_parts
    )


def require_policy(
    policy: dict[str, Any],
) -> tuple[dict[str, Any], set[str], set[str], dict[str, Any]]:
    providers = policy.get("supported_providers")
    required_classes = policy.get("required_scenario_classes")
    failure_states = policy.get("native_failure_states")
    gateway = policy.get("gateway")
    if (
        policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("default_decision") != "deny"
        or not isinstance(providers, dict)
        or set(providers) != {"claude-code", "codex"}
        or not isinstance(required_classes, list)
        or not all(isinstance(value, str) for value in required_classes)
        or not isinstance(failure_states, list)
        or not all(isinstance(value, str) for value in failure_states)
        or not isinstance(gateway, dict)
    ):
        raise EvaluationError("hook failure boundary policy is malformed")
    for provider in providers.values():
        if (
            not isinstance(provider, dict)
            or not isinstance(provider.get("minimum_product_version"), str)
        ):
            raise EvaluationError("hook provider policy is malformed")
    required_set = set(required_classes)
    failure_set = set(failure_states)
    if required_set != {
        "completed-allow",
        "explicit-deny",
        "not-started",
        "timed-out",
        "abnormal-exit",
        "invalid-output",
        "invalid-permit",
    } or failure_set != {
        "not-started",
        "timed-out",
        "abnormal-exit",
        "invalid-output",
    }:
        raise EvaluationError("hook failure scenario policy is incomplete")
    expected_gateway = {
        "enforcement_point": "mcp-side-effect-gateway",
        "required_enforcement": "mandatory",
        "require_managed_hook_match": True,
        "require_hook_exit_zero": True,
        "require_hook_allow_decision": True,
        "require_hook_audit_commit": True,
        "require_request_binding": "matched",
        "require_permit_issuer": "trusted",
        "require_permit_status": "valid",
        "require_gateway_audit_commit": True,
    }
    if gateway != expected_gateway:
        raise EvaluationError("hook downstream gateway policy is unsafe")
    return providers, required_set, failure_set, gateway


def require_case_shape(case: Any) -> dict[str, Any]:
    if not isinstance(case, dict) or set(case) != CASE_FIELDS:
        raise EvaluationError("hook lifecycle case is malformed")
    scenario_id = case.get("scenario_id")
    if not isinstance(scenario_id, str) or not SAFE_ID.fullmatch(scenario_id):
        raise EvaluationError("hook lifecycle scenario identity is malformed")
    if case.get("hook_state") not in {
        "completed",
        "not-started",
        "timed-out",
        "abnormal-exit",
        "invalid-output",
    }:
        raise EvaluationError("hook lifecycle process state is malformed")
    if case.get("hook_decision") not in {"allow", "deny", None}:
        raise EvaluationError("hook lifecycle decision is malformed")
    if case.get("exit_code") is not None and not isinstance(
        case.get("exit_code"), int
    ):
        raise EvaluationError("hook lifecycle exit code is malformed")
    for field in (
        "managed_hook_matched",
        "hook_audit_committed",
        "gateway_available",
        "gateway_audit_committed",
        "native_product_would_continue",
        "external_side_effect_observed",
    ):
        if not isinstance(case.get(field), bool):
            raise EvaluationError("hook lifecycle boolean evidence is malformed")
    if case.get("request_binding_status") not in {
        "matched",
        "mismatched",
        "unavailable",
    } or case.get("permit_issuer_status") not in {
        "trusted",
        "untrusted",
        "unavailable",
    } or case.get("permit_status") not in {"valid", "invalid", "missing"}:
        raise EvaluationError("hook permit evidence is malformed")
    if case.get("gateway_enforcement") not in {"mandatory", "optional"}:
        raise EvaluationError("hook gateway enforcement evidence is malformed")
    if case.get("gateway_decision") not in {"allow", "deny", "error"}:
        raise EvaluationError("hook gateway decision evidence is malformed")
    return case


def process_shape_matches(case: dict[str, Any]) -> bool:
    state = case["hook_state"]
    scenario_class = case["scenario_class"]
    if scenario_class in {"completed-allow", "explicit-deny", "invalid-permit"}:
        return state == "completed" and case["exit_code"] == 0
    if scenario_class in {"not-started", "timed-out"}:
        return (
            state == scenario_class
            and case["exit_code"] is None
            and case["hook_decision"] is None
        )
    if scenario_class == "abnormal-exit":
        return (
            state == "abnormal-exit"
            and isinstance(case["exit_code"], int)
            and case["exit_code"] not in {0, 2}
            and case["hook_decision"] is None
        )
    if scenario_class == "invalid-output":
        return (
            state == "invalid-output"
            and case["exit_code"] == 0
            and case["hook_decision"] is None
        )
    return False


def evaluate_case(
    case: dict[str, Any],
    providers: dict[str, Any],
    failure_states: set[str],
) -> Result:
    provider = case.get("provider")
    if provider not in providers or not version_at_least(
        case.get("product_version"),
        providers[provider]["minimum_product_version"],
    ):
        raise EvaluationError("hook provider or version evidence is unsupported")
    if not case["gateway_available"]:
        raise EvaluationError("downstream side-effect gateway is unavailable")
    if not process_shape_matches(case):
        raise EvaluationError("hook lifecycle state is internally inconsistent")

    common_gateway = all(
        (
            case["gateway_enforcement"] == "mandatory",
            case["gateway_audit_committed"],
        )
    )
    completed_allow = all(
        (
            case["scenario_class"] == "completed-allow",
            case["managed_hook_matched"],
            case["hook_state"] == "completed",
            case["exit_code"] == 0,
            case["hook_decision"] == "allow",
            case["hook_audit_committed"],
            case["request_binding_status"] == "matched",
            case["permit_issuer_status"] == "trusted",
            case["permit_status"] == "valid",
            common_gateway,
            case["gateway_decision"] == "allow",
            case["external_side_effect_observed"],
        )
    )
    denied_before_effect = all(
        (
            case["scenario_class"] != "completed-allow",
            case["permit_status"] != "valid",
            common_gateway,
            case["gateway_decision"] == "deny",
            not case["external_side_effect_observed"],
        )
    )
    if case["scenario_class"] == "explicit-deny":
        denied_before_effect = denied_before_effect and all(
            (
                case["hook_decision"] == "deny",
                case["hook_audit_committed"],
                not case["native_product_would_continue"],
            )
        )
    if case["scenario_class"] in failure_states:
        denied_before_effect = denied_before_effect and all(
            (
                case["native_product_would_continue"],
                not case["hook_audit_committed"],
            )
        )
    if case["scenario_class"] == "invalid-permit":
        denied_before_effect = denied_before_effect and all(
            (
                case["hook_decision"] == "allow",
                case["hook_audit_committed"],
                case["request_binding_status"] != "matched",
                case["permit_issuer_status"] != "trusted",
            )
        )
    passed = completed_allow or denied_before_effect
    reason = (
        "gateway allowed one completed audited request-bound hook permit"
        if completed_allow
        else (
            "gateway denied missing or invalid hook permit before side effect"
            if denied_before_effect
            else "hook failure or permit bypass reached an unsafe gateway outcome"
        )
    )
    return Result(provider, case["scenario_id"], passed, reason)


def evaluate(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Result]:
    providers, required_classes, failure_states, _ = require_policy(policy)
    if set(evidence) != {
        "schema_version",
        "profile",
        "assessment_scope",
        "cases",
    }:
        raise EvaluationError("hook lifecycle evidence fields are malformed")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvaluationError("hook lifecycle evidence schema is unsupported")
    if not isinstance(evidence.get("profile"), str) or not SAFE_ID.fullmatch(
        evidence["profile"]
    ):
        raise EvaluationError("hook lifecycle profile identity is malformed")
    if evidence.get("assessment_scope") not in {"complete", "negative"}:
        raise EvaluationError("hook lifecycle assessment scope is malformed")
    cases = evidence.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationError("hook lifecycle cases are missing")
    results: list[Result] = []
    coverage: dict[str, set[str]] = {provider: set() for provider in providers}
    seen: set[str] = set()
    for value in cases:
        case = require_case_shape(value)
        if case["scenario_id"] in seen:
            raise EvaluationError("hook lifecycle scenario identity is duplicated")
        seen.add(case["scenario_id"])
        if case["scenario_class"] not in required_classes:
            raise EvaluationError("hook lifecycle scenario class is unsupported")
        result = evaluate_case(case, providers, failure_states)
        coverage[result.provider].add(case["scenario_class"])
        results.append(result)
    if evidence["assessment_scope"] == "complete" and any(
        classes != required_classes for classes in coverage.values()
    ):
        raise EvaluationError("hook lifecycle assessment coverage is incomplete")
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "hook failure boundary policy")
        evidence = load_json(args.evidence, "hook lifecycle evidence")
        if isinstance(evidence.get("profile"), str):
            profile = evidence["profile"]
        results = evaluate(policy, evidence)
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004/AAR-022 "
            f"profile={profile} hook failure boundary evaluation failed: {error}"
        )
        print(f"RESULT ERROR profile={profile} checks=0 failures=1")
        return 2
    for result in results:
        print(result.render())
    failures = sum(not result.passed for result in results)
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} profile={profile} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
