#!/usr/bin/env python3
"""Run a read-only assessment of sanitized repository recovery evidence."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTROL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CONTROL_DIR / "scripts"))

import verify as recovery_verify  # noqa: E402


ASSESSMENT_SCHEMA = "psb-control-assessment/v1"
CONTROL_ID = "PSB-SOURCE-005"


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def unavailable_results(status: str, message: str) -> dict[str, dict[str, Any]]:
    return {
        check_id: {"status": status, "messages": [message]}
        for check_id in recovery_verify.CHECK_MESSAGES
    }


def write_text(path: Path, content: str) -> None:
    if path.is_symlink():
        raise recovery_verify.EvidenceError("assessment output path is symbolic")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_json(
    source: str,
    evaluated_at: datetime,
    policy_id: str,
    results: dict[str, dict[str, Any]],
) -> str:
    summary = {status: 0 for status in ("PASS", "FAIL", "NOT_CHECKED", "ERROR")}
    rows = []
    for check_id in recovery_verify.CHECK_MESSAGES:
        item = results[check_id]
        summary[item["status"]] += 1
        rows.append(
            {
                "check_id": check_id,
                "status": item["status"],
                "messages": item["messages"],
            }
        )
    document = {
        "schema": ASSESSMENT_SCHEMA,
        "control_id": CONTROL_ID,
        "source": source,
        "evaluated_at": utc_text(evaluated_at),
        "policy_id": policy_id,
        "summary": summary,
        "results": rows,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def build_csv(results: dict[str, dict[str, Any]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=("control_id", "check_id", "status", "message")
    )
    writer.writeheader()
    for check_id in recovery_verify.CHECK_MESSAGES:
        item = results[check_id]
        writer.writerow(
            {
                "control_id": CONTROL_ID,
                "check_id": check_id,
                "status": item["status"],
                "message": "; ".join(item["messages"]),
            }
        )
    return stream.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--policy", type=Path, default=CONTROL_DIR / "secure" / "policy.json"
    )
    evidence_group = parser.add_mutually_exclusive_group()
    evidence_group.add_argument("--evidence", type=Path)
    evidence_group.add_argument("--fixture", type=Path)
    parser.add_argument("--as-of")
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--csv-output", required=True, type=Path)
    args = parser.parse_args()

    evaluated_at = datetime.now(timezone.utc)
    policy_id = "unavailable"
    try:
        evaluated_at = (
            recovery_verify.parse_time(args.as_of, "evaluation time")
            if args.as_of
            else datetime.now(timezone.utc)
        )
        policy = recovery_verify.read_json(args.policy, "policy", 1048576)
        recovery_verify.validate_policy(policy)
        policy_id = policy["policy_id"]
        evidence_path = args.fixture or args.evidence
        if evidence_path is None:
            source = "no-organization-evidence"
            results = unavailable_results(
                "NOT_CHECKED", "organization evidence was not supplied"
            )
        else:
            source = "test-fixture" if args.fixture else "organization-evidence"
            policy, results = recovery_verify.assess_files(
                args.policy, evidence_path, evaluated_at
            )
            policy_id = policy["policy_id"]
    except recovery_verify.EvidenceError as error:
        source = "test-fixture" if args.fixture else "organization-evidence"
        if args.fixture is None and args.evidence is None:
            source = "no-organization-evidence"
        results = unavailable_results(
            "ERROR", f"evidence could not be evaluated: {error}"
        )

    try:
        write_text(
            args.json_output,
            build_json(source, evaluated_at, policy_id, results),
        )
        write_text(args.csv_output, build_csv(results))
    except (OSError, recovery_verify.EvidenceError) as error:
        print(f"ERROR assessment output could not be written: {error}", file=sys.stderr)
        return 2

    print(f"SOURCE {source}")
    for line in recovery_verify.render_results(policy_id, results):
        print(line)
    return recovery_verify.exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
