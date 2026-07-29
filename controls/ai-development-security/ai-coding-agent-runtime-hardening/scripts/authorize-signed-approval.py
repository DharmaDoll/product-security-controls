#!/usr/bin/env python3
"""Verify and atomically consume one signed PSB-AI-004 approval."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from approval_core import EvaluationError, load_json
from signed_approval import authorize_and_consume


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticate and consume one PSB-AI-004 approval."
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("request", type=Path)
    parser.add_argument("envelope", type=Path)
    parser.add_argument("trust", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    parser.add_argument("--now", required=True)
    args = parser.parse_args()

    try:
        result = authorize_and_consume(
            load_json(args.policy.resolve(), "runtime policy"),
            load_json(args.request.resolve(), "action request"),
            load_json(args.envelope.resolve(), "signed approval envelope"),
            args.trust,
            args.ledger,
            args.openssl,
            args.now,
        )
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004 signed approval authorization failed: "
            f"{error}"
        )
        return 2
    except Exception:
        print(
            "ERROR PSB-AI-004 signed approval authorization failed: "
            "unexpected evaluator failure"
        )
        return 2

    signature_status = "PASS" if result.signature_ok else "FAIL"
    approval_status = "PASS" if result.approval_ok else "FAIL"
    consumption_status = "PASS" if result.consumed else "FAIL"
    print(
        f"{signature_status} PSB-AI-004/AAR-016 "
        "issuer signature and exact approval binding are valid"
        if result.signature_ok
        else f"{signature_status} PSB-AI-004/AAR-016 "
        "issuer signature is invalid"
    )
    print(
        f"{approval_status} PSB-AI-004/AAR-016 "
        "approval policy lifetime and request binding are valid"
        if result.approval_ok
        else f"{approval_status} PSB-AI-004/AAR-016 "
        "approval policy lifetime or request binding is invalid"
    )
    print(
        f"{consumption_status} PSB-AI-004/AAR-017 "
        "approval was atomically consumed once"
        if result.consumed
        else f"{consumption_status} PSB-AI-004/AAR-017 "
        "approval was already consumed or was not eligible"
    )
    status = "PASS" if result.allowed else "FAIL"
    failures = sum(
        (
            not result.signature_ok,
            not result.approval_ok,
            not result.consumed,
        )
    )
    print(
        f"RESULT {status} request_id={result.request_id} "
        f"approval_id={result.approval_id} key_id={result.key_id} "
        f"checks=3 failures={failures}"
    )
    return 0 if result.allowed else 1


if __name__ == "__main__":
    sys.exit(main())
