#!/usr/bin/env python3
"""Verify idempotent reconciliation after uncertain remote side effects."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-side-effect-reconciliation-policy/v1"
EVIDENCE_SCHEMA = "psb-ai-side-effect-reconciliation-evidence/v1"
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")
CASE_FIELDS = {
    "scenario_id",
    "request_digest",
    "idempotency_key",
    "original_approval",
    "replacement_approval",
    "dispatches",
    "backend",
    "reconciliation",
}
ORIGINAL_FIELDS = {"approval_id", "consumed_before_dispatch", "restored"}
REPLACEMENT_FIELDS = {"approval_id", "consumed_before_dispatch"}
DISPATCH_FIELDS = {
    "attempt_id",
    "approval_id",
    "request_digest",
    "idempotency_key",
    "outcome",
}
BACKEND_FIELDS = {
    "available",
    "idempotency_enforced",
    "lookup_status",
    "recorded_request_digest",
    "mutation_count",
}
RECONCILIATION_FIELDS = {
    "available",
    "automatic_retry",
    "decision",
    "evidence_complete",
}


class EvaluationError(Exception):
    """Reconciliation evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Result:
    scenario_id: str
    passed: bool
    reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"{status} PSB-AI-004/AAR-023 "
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


def require_policy(policy: dict[str, Any]) -> dict[str, set[str]]:
    expected_scalars = {
        "default_decision": "block-unknown",
        "maximum_mutations_per_request": 1,
        "require_original_approval_consumed_before_dispatch": True,
        "allow_original_approval_restore": False,
        "allow_automatic_retry": False,
        "require_backend_idempotency": True,
        "require_stable_idempotency_key": True,
        "require_stable_request_digest": True,
        "require_distinct_replacement_approval": True,
    }
    if policy.get("schema_version") != POLICY_SCHEMA or any(
        policy.get(field) != value for field, value in expected_scalars.items()
    ):
        raise EvaluationError("side-effect reconciliation policy is unsafe")
    list_fields = {
        "required_secure_scenarios",
        "allowed_dispatch_outcomes",
        "allowed_backend_statuses",
        "allowed_reconciliation_decisions",
    }
    values: dict[str, set[str]] = {}
    for field in list_fields:
        entries = policy.get(field)
        if not isinstance(entries, list) or not entries or not all(
            isinstance(entry, str) for entry in entries
        ):
            raise EvaluationError("side-effect reconciliation policy is malformed")
        values[field] = set(entries)
    if values["required_secure_scenarios"] != {
        "applied-response",
        "timeout-after-apply",
        "timeout-before-apply",
        "replacement-approved-retry",
        "unknown-outcome-blocked",
    }:
        raise EvaluationError("secure reconciliation scenario policy is incomplete")
    if values["allowed_dispatch_outcomes"] != {
        "applied-response",
        "not-applied-response",
        "timeout",
    } or values["allowed_backend_statuses"] != {
        "applied",
        "not-applied",
        "unknown",
        "conflict",
    } or values["allowed_reconciliation_decisions"] != {
        "complete-no-retry",
        "require-new-approval",
        "retry-with-replacement-approval",
        "block-unknown",
    }:
        raise EvaluationError("reconciliation state policy is incomplete")
    return values


def safe_id(value: Any) -> bool:
    return isinstance(value, str) and bool(SAFE_ID.fullmatch(value))


def require_case(
    value: Any, policy_values: dict[str, set[str]]
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CASE_FIELDS:
        raise EvaluationError("side-effect reconciliation case is malformed")
    if not safe_id(value.get("scenario_id")) or not HEX_DIGEST.fullmatch(
        str(value.get("request_digest", ""))
    ) or not safe_id(value.get("idempotency_key")):
        raise EvaluationError("reconciliation case identity is malformed")
    original = value.get("original_approval")
    replacement = value.get("replacement_approval")
    dispatches = value.get("dispatches")
    backend = value.get("backend")
    reconciliation = value.get("reconciliation")
    if (
        not isinstance(original, dict)
        or set(original) != ORIGINAL_FIELDS
        or not safe_id(original.get("approval_id"))
        or not isinstance(original.get("consumed_before_dispatch"), bool)
        or not isinstance(original.get("restored"), bool)
    ):
        raise EvaluationError("original approval evidence is malformed")
    if replacement is not None and (
        not isinstance(replacement, dict)
        or set(replacement) != REPLACEMENT_FIELDS
        or not safe_id(replacement.get("approval_id"))
        or not isinstance(replacement.get("consumed_before_dispatch"), bool)
    ):
        raise EvaluationError("replacement approval evidence is malformed")
    if not isinstance(dispatches, list) or not dispatches:
        raise EvaluationError("side-effect dispatch evidence is missing")
    attempts: set[str] = set()
    for dispatch in dispatches:
        if (
            not isinstance(dispatch, dict)
            or set(dispatch) != DISPATCH_FIELDS
            or not safe_id(dispatch.get("attempt_id"))
            or dispatch["attempt_id"] in attempts
            or not safe_id(dispatch.get("approval_id"))
            or not HEX_DIGEST.fullmatch(str(dispatch.get("request_digest", "")))
            or not safe_id(dispatch.get("idempotency_key"))
            or dispatch.get("outcome")
            not in policy_values["allowed_dispatch_outcomes"]
        ):
            raise EvaluationError("side-effect dispatch evidence is malformed")
        attempts.add(dispatch["attempt_id"])
    if (
        not isinstance(backend, dict)
        or set(backend) != BACKEND_FIELDS
        or not isinstance(backend.get("available"), bool)
        or not isinstance(backend.get("idempotency_enforced"), bool)
        or backend.get("lookup_status")
        not in policy_values["allowed_backend_statuses"]
        or (
            backend.get("recorded_request_digest") is not None
            and not HEX_DIGEST.fullmatch(
                str(backend.get("recorded_request_digest"))
            )
        )
        or (
            backend.get("mutation_count") is not None
            and (
                not isinstance(backend.get("mutation_count"), int)
                or backend["mutation_count"] < 0
            )
        )
    ):
        raise EvaluationError("backend outcome evidence is malformed")
    if (
        not isinstance(reconciliation, dict)
        or set(reconciliation) != RECONCILIATION_FIELDS
        or not isinstance(reconciliation.get("available"), bool)
        or not isinstance(reconciliation.get("automatic_retry"), bool)
        or not isinstance(reconciliation.get("evidence_complete"), bool)
        or reconciliation.get("decision")
        not in policy_values["allowed_reconciliation_decisions"]
    ):
        raise EvaluationError("reconciliation decision evidence is malformed")
    return value


def expected_scenario_state(case: dict[str, Any]) -> bool:
    scenario = case["scenario_id"]
    dispatches = case["dispatches"]
    backend = case["backend"]
    reconciliation = case["reconciliation"]
    original_id = case["original_approval"]["approval_id"]
    replacement = case["replacement_approval"]
    if scenario == "applied-response":
        return all(
            (
                len(dispatches) == 1,
                dispatches[0]["approval_id"] == original_id,
                dispatches[0]["outcome"] == "applied-response",
                replacement is None,
                backend["lookup_status"] == "applied",
                backend["mutation_count"] == 1,
                reconciliation["decision"] == "complete-no-retry",
            )
        )
    if scenario == "timeout-after-apply":
        return all(
            (
                len(dispatches) == 1,
                dispatches[0]["approval_id"] == original_id,
                dispatches[0]["outcome"] == "timeout",
                replacement is None,
                backend["lookup_status"] == "applied",
                backend["mutation_count"] == 1,
                reconciliation["decision"] == "complete-no-retry",
            )
        )
    if scenario == "timeout-before-apply":
        return all(
            (
                len(dispatches) == 1,
                dispatches[0]["approval_id"] == original_id,
                dispatches[0]["outcome"] == "timeout",
                replacement is None,
                backend["lookup_status"] == "not-applied",
                backend["mutation_count"] == 0,
                reconciliation["decision"] == "require-new-approval",
            )
        )
    if scenario == "replacement-approved-retry":
        return all(
            (
                len(dispatches) == 2,
                dispatches[0]["approval_id"] == original_id,
                dispatches[0]["outcome"] == "timeout",
                isinstance(replacement, dict),
                replacement.get("consumed_before_dispatch") is True,
                replacement.get("approval_id") != original_id,
                dispatches[1]["approval_id"] == replacement.get("approval_id"),
                dispatches[1]["outcome"] == "applied-response",
                backend["lookup_status"] == "applied",
                backend["mutation_count"] == 1,
                reconciliation["decision"] == "retry-with-replacement-approval",
            )
        )
    if scenario == "unknown-outcome-blocked":
        return all(
            (
                len(dispatches) == 1,
                dispatches[0]["approval_id"] == original_id,
                dispatches[0]["outcome"] == "timeout",
                replacement is None,
                backend["lookup_status"] == "unknown",
                backend["mutation_count"] is None,
                reconciliation["decision"] == "block-unknown",
            )
        )
    return False


def evaluate_case(case: dict[str, Any]) -> Result:
    backend = case["backend"]
    reconciliation = case["reconciliation"]
    if not backend["available"] or not reconciliation["available"]:
        raise EvaluationError("side-effect outcome reconciliation is unavailable")
    dispatches = case["dispatches"]
    digest = case["request_digest"]
    idempotency_key = case["idempotency_key"]
    backend_binding_ok = (
        backend["recorded_request_digest"] == digest
        if backend["lookup_status"] == "applied"
        else backend["recorded_request_digest"] is None
    )
    common_safe = all(
        (
            case["original_approval"]["consumed_before_dispatch"],
            not case["original_approval"]["restored"],
            not reconciliation["automatic_retry"],
            reconciliation["evidence_complete"],
            backend["idempotency_enforced"],
            backend["lookup_status"] != "conflict",
            backend_binding_ok,
            backend["mutation_count"] is None
            or backend["mutation_count"] <= 1,
            all(dispatch["request_digest"] == digest for dispatch in dispatches),
            all(
                dispatch["idempotency_key"] == idempotency_key
                for dispatch in dispatches
            ),
        )
    )
    passed = common_safe and expected_scenario_state(case)
    reason = (
        "uncertain outcome was reconciled without approval replay or duplicate mutation"
        if passed
        else "approval idempotency or outcome state permits unsafe replay"
    )
    return Result(case["scenario_id"], passed, reason)


def evaluate(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Result]:
    policy_values = require_policy(policy)
    if set(evidence) != {"schema_version", "profile", "cases"}:
        raise EvaluationError("reconciliation evidence fields are malformed")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvaluationError("reconciliation evidence schema is unsupported")
    if not safe_id(evidence.get("profile")):
        raise EvaluationError("reconciliation profile identity is malformed")
    cases = evidence.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationError("reconciliation cases are missing")
    seen: set[str] = set()
    results: list[Result] = []
    for value in cases:
        case = require_case(value, policy_values)
        if case["scenario_id"] in seen:
            raise EvaluationError("reconciliation scenario is duplicated")
        seen.add(case["scenario_id"])
        results.append(evaluate_case(case))
    if evidence["profile"] == "secure" and seen != policy_values[
        "required_secure_scenarios"
    ]:
        raise EvaluationError("secure reconciliation scenario coverage is incomplete")
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "side-effect reconciliation policy")
        evidence = load_json(args.evidence, "side-effect reconciliation evidence")
        if isinstance(evidence.get("profile"), str):
            profile = evidence["profile"]
        results = evaluate(policy, evidence)
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004/AAR-023 "
            f"profile={profile} side-effect reconciliation failed: {error}"
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
