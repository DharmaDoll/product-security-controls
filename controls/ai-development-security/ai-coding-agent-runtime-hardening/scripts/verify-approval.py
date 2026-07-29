#!/usr/bin/env python3
"""Verify a bound high-impact action approval without executing the action."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from approval_core import EvaluationError, evaluate_approval, load_json


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    pass_reason: str
    fail_reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        reason = self.pass_reason if self.passed else self.fail_reason
        return f"{status} PSB-AI-004/{self.check_id} {reason}"


def evaluate(
    policy_path: Path,
    request_path: Path,
    approval_path: Path,
    replay_path: Path,
    validation_path: Path,
    now_text: str,
) -> tuple[str, str, list[CheckResult]]:
    evaluation = evaluate_approval(
        load_json(policy_path, "runtime policy"),
        load_json(request_path, "action request"),
        load_json(approval_path, "action approval"),
        load_json(replay_path, "approval replay state"),
        load_json(validation_path, "approval validation state"),
        now_text,
    )
    return evaluation.request_id, evaluation.approval_id, [
        CheckResult(
            "AAR-008",
            evaluation.classified,
            "operation is classified as a high-impact action",
            "operation is unclassified or its declared action class is incorrect",
        ),
        CheckResult(
            "AAR-009",
            evaluation.binding_ok,
            "approval is independently issued and bound to the exact request",
            "approval binding approver or request digest does not match",
        ),
        CheckResult(
            "AAR-010",
            evaluation.time_ok,
            "approval is current and within the maximum lifetime",
            "approval is denied expired not yet valid or exceeds maximum lifetime",
        ),
        CheckResult(
            "AAR-011",
            evaluation.replay_ok and evaluation.issuer_ok,
            "approval is unused and its issuer is trusted",
            "approval was replayed or its issuer is not trusted",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify one PSB-AI-004 high-impact action approval."
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("request", type=Path)
    parser.add_argument("approval", type=Path)
    parser.add_argument("replay_state", type=Path)
    parser.add_argument("validation_state", type=Path)
    parser.add_argument(
        "--now",
        required=True,
        help="Explicit UTC RFC3339 evaluation time for deterministic evidence.",
    )
    args = parser.parse_args()

    try:
        request_id, approval_id, results = evaluate(
            args.policy.resolve(),
            args.request.resolve(),
            args.approval.resolve(),
            args.replay_state.resolve(),
            args.validation_state.resolve(),
            args.now,
        )
    except EvaluationError as error:
        print(f"ERROR PSB-AI-004 approval evaluation failed: {error}")
        return 2
    except Exception:
        print(
            "ERROR PSB-AI-004 approval evaluation failed: "
            "unexpected evaluator failure"
        )
        return 2

    failures = sum(not result.passed for result in results)
    for result in results:
        print(result.render())
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} request_id={request_id} approval_id={approval_id} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
