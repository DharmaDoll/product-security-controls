#!/usr/bin/env python3
"""Verify typed command classification without executing a command."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-command-broker-policy/v1"
EVIDENCE_SCHEMA = "psb-ai-command-broker-evidence/v1"
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
ENV_ASSIGNMENT = re.compile(r"^[A-Z_][A-Z0-9_]*=.*$", re.ASCII)
CASE_FIELDS = {
    "scenario_id",
    "provider",
    "command_form",
    "argv",
    "resolution_status",
    "resolved_argv",
    "observed_decision",
    "observed_action_class",
    "observed_hitl",
}


class EvaluationError(Exception):
    """Command classification evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Classification:
    decision: str
    action_class: str | None
    hitl: str


@dataclass(frozen=True)
class Result:
    provider: str
    scenario_id: str
    passed: bool
    classification: Classification

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        action = self.classification.action_class or "unclassified"
        reason = (
            "typed command decision matches managed policy"
            if self.passed
            else "observed command decision can bypass managed classification"
        )
        return (
            f"{status} PSB-AI-004/AAR-024 provider={self.provider} "
            f"scenario={self.scenario_id} "
            f"decision={self.classification.decision} "
            f"action_class={action} {reason}"
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


def require_policy(
    policy: dict[str, Any],
) -> tuple[dict[str, set[str]], dict[str, dict[str, str]], set[str]]:
    if (
        policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("default_decision") != "deny"
        or policy.get("transparent_wrapper") != "env-assignments-only"
        or policy.get("hitl_strategy")
        != {
            "read-only": "none",
            "high-impact": "one-bound-approval",
            "opaque-or-unknown": "deny-without-prompt",
        }
    ):
        raise EvaluationError("command broker policy is unsafe")
    opaque_forms = policy.get("opaque_forms")
    required_scenarios = policy.get("required_secure_scenarios")
    read_only = policy.get("read_only_operations")
    high_impact = policy.get("high_impact_operations")
    if (
        not isinstance(opaque_forms, list)
        or set(opaque_forms)
        != {
            "shell-string",
            "script",
            "task-runner",
            "interpreter-code",
            "unknown-wrapper",
        }
        or not isinstance(required_scenarios, list)
        or not all(isinstance(value, str) for value in required_scenarios)
        or not isinstance(read_only, dict)
        or not isinstance(high_impact, dict)
    ):
        raise EvaluationError("command broker policy is malformed")
    normalized_read: dict[str, set[str]] = {}
    for executable, operations in read_only.items():
        if (
            not isinstance(executable, str)
            or not isinstance(operations, list)
            or not operations
            or not all(isinstance(value, str) for value in operations)
        ):
            raise EvaluationError("read-only command policy is malformed")
        normalized_read[executable] = set(operations)
    normalized_high: dict[str, dict[str, str]] = {}
    for executable, operations in high_impact.items():
        if (
            not isinstance(executable, str)
            or not isinstance(operations, dict)
            or not operations
            or not all(
                isinstance(operation, str) and isinstance(action, str)
                for operation, action in operations.items()
            )
        ):
            raise EvaluationError("high-impact command policy is malformed")
        normalized_high[executable] = operations
    required_set = set(required_scenarios)
    if required_set != {
        "read-only-direct",
        "high-impact-direct",
        "environment-wrapper",
        "force-push",
        "resolved-git-alias",
        "unresolved-git-alias",
        "shell-string",
        "script-file",
        "task-runner",
        "interpreter-code",
        "unknown-command",
    }:
        raise EvaluationError("secure command scenario policy is incomplete")
    return normalized_read, normalized_high, required_set


def valid_argv(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(
            isinstance(argument, str)
            and 0 < len(argument) <= 512
            and "\x00" not in argument
            for argument in value
        )
    )


def require_case(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CASE_FIELDS:
        raise EvaluationError("command broker case is malformed")
    if not isinstance(value.get("scenario_id"), str) or not SAFE_ID.fullmatch(
        value["scenario_id"]
    ):
        raise EvaluationError("command scenario identity is malformed")
    if value.get("provider") not in {"claude-code", "codex"}:
        raise EvaluationError("command provider is unsupported")
    if value.get("command_form") not in {
        "direct-argv",
        "wrapped-argv",
        "git-alias",
        "shell-string",
        "script",
        "task-runner",
        "interpreter-code",
        "unknown-wrapper",
    }:
        raise EvaluationError("command form is unsupported")
    if not valid_argv(value.get("argv")):
        raise EvaluationError("command argv evidence is malformed")
    resolved = value.get("resolved_argv")
    if not isinstance(resolved, list) or not all(
        isinstance(argument, str)
        and 0 < len(argument) <= 512
        and "\x00" not in argument
        for argument in resolved
    ):
        raise EvaluationError("resolved argv evidence is malformed")
    if value.get("resolution_status") not in {
        "complete",
        "unresolved",
        "opaque",
        "unavailable",
    }:
        raise EvaluationError("command resolution status is malformed")
    if value.get("observed_decision") not in {
        "allow",
        "require-bound-approval",
        "deny",
    } or value.get("observed_hitl") not in {"none", "one-bound-approval"}:
        raise EvaluationError("observed command decision is malformed")
    action = value.get("observed_action_class")
    if action is not None and not isinstance(action, str):
        raise EvaluationError("observed command action class is malformed")
    return value


def classify_resolved(
    argv: list[str],
    read_only: dict[str, set[str]],
    high_impact: dict[str, dict[str, str]],
) -> Classification:
    if len(argv) < 2:
        return Classification("deny", None, "none")
    executable = argv[0]
    operation = argv[1]
    if operation in read_only.get(executable, set()):
        return Classification("allow", "read-only", "none")
    policy_operation = operation
    if executable == "git" and operation == "push" and any(
        argument == "--force"
        or argument.startswith("--force=")
        or argument == "--force-with-lease"
        or argument.startswith("--force-with-lease=")
        for argument in argv[2:]
    ):
        policy_operation = "push-force"
    if executable == "git" and operation == "reset" and "--hard" in argv[2:]:
        policy_operation = "reset-hard"
    action_class = high_impact.get(executable, {}).get(policy_operation)
    if action_class is not None:
        return Classification(
            "require-bound-approval",
            action_class,
            "one-bound-approval",
        )
    return Classification("deny", None, "none")


def classify_case(
    case: dict[str, Any],
    read_only: dict[str, set[str]],
    high_impact: dict[str, dict[str, str]],
) -> Classification:
    form = case["command_form"]
    status = case["resolution_status"]
    argv = case["argv"]
    resolved = case["resolved_argv"]
    if form in {
        "shell-string",
        "script",
        "task-runner",
        "interpreter-code",
        "unknown-wrapper",
    }:
        if status != "opaque" or resolved:
            raise EvaluationError("opaque command evidence is inconsistent")
        return Classification("deny", None, "none")
    if form == "git-alias":
        if status == "unresolved" and not resolved:
            return Classification("deny", None, "none")
        if status != "complete" or not valid_argv(resolved):
            raise EvaluationError("Git alias resolution evidence is inconsistent")
        return classify_resolved(resolved, read_only, high_impact)
    if form == "direct-argv":
        if status != "complete" or resolved != argv:
            raise EvaluationError("direct argv resolution evidence is inconsistent")
        return classify_resolved(resolved, read_only, high_impact)
    if form == "wrapped-argv":
        if (
            status != "complete"
            or argv[0] != "env"
            or len(argv) < 3
            or not ENV_ASSIGNMENT.fullmatch(argv[1])
        ):
            raise EvaluationError("environment wrapper evidence is inconsistent")
        index = 1
        while index < len(argv) and ENV_ASSIGNMENT.fullmatch(argv[index]):
            index += 1
        if index >= len(argv) or resolved != argv[index:]:
            raise EvaluationError("environment wrapper resolution is inconsistent")
        return classify_resolved(resolved, read_only, high_impact)
    raise EvaluationError("command form is unsupported")


def evaluate(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Result]:
    read_only, high_impact, required_scenarios = require_policy(policy)
    if set(evidence) != {
        "schema_version",
        "profile",
        "engine_available",
        "cases",
    }:
        raise EvaluationError("command broker evidence fields are malformed")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvaluationError("command broker evidence schema is unsupported")
    if not isinstance(evidence.get("profile"), str) or not SAFE_ID.fullmatch(
        evidence["profile"]
    ):
        raise EvaluationError("command broker profile identity is malformed")
    if evidence.get("engine_available") is not True:
        raise EvaluationError("command resolution engine is unavailable")
    cases = evidence.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationError("command broker cases are missing")
    results: list[Result] = []
    seen: set[str] = set()
    for value in cases:
        case = require_case(value)
        if case["scenario_id"] in seen:
            raise EvaluationError("command scenario is duplicated")
        seen.add(case["scenario_id"])
        expected = classify_case(case, read_only, high_impact)
        passed = all(
            (
                case["observed_decision"] == expected.decision,
                case["observed_action_class"] == expected.action_class,
                case["observed_hitl"] == expected.hitl,
            )
        )
        results.append(Result(case["provider"], case["scenario_id"], passed, expected))
    if evidence["profile"] == "secure" and seen != required_scenarios:
        raise EvaluationError("secure command scenario coverage is incomplete")
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "command broker policy")
        evidence = load_json(args.evidence, "command broker evidence")
        if isinstance(evidence.get("profile"), str):
            profile = evidence["profile"]
        results = evaluate(policy, evidence)
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004/AAR-024 "
            f"profile={profile} command broker evaluation failed: {error}"
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
