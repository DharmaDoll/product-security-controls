#!/usr/bin/env python3
"""Create deterministic negative repository-recovery fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def policy_id(value: dict[str, Any]) -> str:
    normalized = dict(value)
    normalized.pop("policy_id", None)
    raw = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return f"repository-recovery-policy@sha256:{hashlib.sha256(raw).hexdigest()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument(
        "--scenario",
        required=True,
        choices=(
            "bind-policy",
            "missing-repository",
            "mismatch",
            "partial",
            "sensitive",
            "stale",
            "weakened-policy",
        ),
    )
    args = parser.parse_args()
    value = json.loads(args.source.read_text(encoding="utf-8"))
    if args.scenario == "stale":
        value["sections"]["inventory"]["collected_at"] = "2026-08-23T12:00:00Z"
    elif args.scenario == "partial":
        value["sections"]["inventory"]["pagination_complete"] = False
    elif args.scenario == "missing-repository":
        value["sections"]["inventory"]["repositories"] = value["sections"][
            "inventory"
        ]["repositories"][:1]
    elif args.scenario == "sensitive":
        value["token"] = "SYNTHETIC_TEST_VALUE_DO_NOT_USE"
    elif args.scenario == "mismatch":
        value["sections"]["restore_drill"]["drill"]["restores"][0][
            "content_digest"
        ] = "sha256:" + "9" * 64
    elif args.scenario == "weakened-policy":
        value["max_bulk_delete_targets"] = 2
        value["policy_id"] = policy_id(value)
    elif args.scenario == "bind-policy":
        if args.policy is None:
            parser.error("--policy is required for bind-policy")
        related_policy = json.loads(args.policy.read_text(encoding="utf-8"))
        value["policy_id"] = related_policy["policy_id"]
    args.output.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
