#!/usr/bin/env python3
"""Print the canonical content-derived identity for a recovery policy."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import verify


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="return an error when the embedded policy_id does not match",
    )
    args = parser.parse_args()
    try:
        policy = verify.read_json(args.policy, "policy", 1048576)
        computed = verify.expected_policy_id(policy)
        embedded = policy.get("policy_id")
        if args.check and embedded != computed:
            raise verify.EvidenceError(
                "policy_id does not match canonical policy content"
            )
    except verify.EvidenceError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    print(computed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
