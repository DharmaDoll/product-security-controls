#!/usr/bin/env python3
"""Create deterministic negative PSB-GOV-004 fixtures from the secure bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--scenario",
        required=True,
        choices=(
            "missing-consumer",
            "stale-inventory",
            "partial-revocation",
            "replacement-only",
            "old-authority-still-valid",
            "out-of-order",
            "secret-bearing",
            "adapter-error",
        ),
    )
    args = parser.parse_args()
    with args.source.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    first_case = bundle["cases"][0]
    evidence = first_case["evidence"]

    if args.scenario == "missing-consumer":
        evidence["consumer_dispositions"].pop()
    elif args.scenario == "stale-inventory":
        bundle["inventory"]["captured_at"] = "2026-08-08T00:00:00Z"
    elif args.scenario == "partial-revocation":
        evidence["provider_receipts_complete"] = False
    elif args.scenario == "replacement-only":
        evidence["old_authority_probe"]["status"] = "NOT_TESTED"
    elif args.scenario == "old-authority-still-valid":
        evidence["old_authority_probe"]["result"] = "ALLOWED"
    elif args.scenario == "out-of-order":
        transitions = first_case["incident"]["state_transitions"]
        transitions[2], transitions[3] = transitions[3], transitions[2]
    elif args.scenario == "secret-bearing":
        evidence["credential_value"] = "SYNTHETIC_FORBIDDEN_FIXTURE_VALUE"
    elif args.scenario == "adapter-error":
        evidence["adapter_status"] = "ERROR"

    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
