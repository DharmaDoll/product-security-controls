#!/usr/bin/env python3
"""Create deterministic negative fixtures for the organization verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--scenario",
        required=True,
        choices=[
            "adapter-error",
            "count-mismatch",
            "partial",
            "secret-bearing",
            "stale",
            "weak-policy",
        ],
    )
    args = parser.parse_args()

    document = json.loads(args.source.read_text(encoding="utf-8"))
    if args.scenario == "adapter-error":
        document["collector"]["source_health"]["members"] = "ERROR"
    elif args.scenario == "count-mismatch":
        document["access_inventory"]["expected_principal_count"] += 1
    elif args.scenario == "partial":
        document["collector"]["pages_complete"] = False
    elif args.scenario == "secret-bearing":
        document["collector"]["token"] = "SYNTHETIC_FORBIDDEN_VALUE"
    elif args.scenario == "stale":
        document["collector"]["observed_at"] = "2026-08-20T00:00:00Z"
    elif args.scenario == "weak-policy":
        document["maximum_snapshot_age_hours"] = 720
        document["allow_local_exceptions"] = True

    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
