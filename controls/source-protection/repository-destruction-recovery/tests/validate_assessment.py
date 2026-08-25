#!/usr/bin/env python3
"""Validate sanitized JSON and CSV assessment artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


CHECK_IDS = {"RDR-001", "RDR-002", "RDR-003", "RDR-006"}
STATUSES = {"PASS", "FAIL", "NOT_CHECKED", "ERROR"}
POLICY_ID_RE = re.compile(r"^repository-recovery-policy@sha256:[0-9a-f]{64}$")


def expected_exit(statuses: set[str]) -> int:
    if "ERROR" in statuses:
        return 2
    if "FAIL" in statuses:
        return 1
    if "NOT_CHECKED" in statuses:
        return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_path", type=Path)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-exit", required=True, type=int)
    args = parser.parse_args()

    document = json.loads(args.json_path.read_text(encoding="utf-8"))
    assert set(document) == {
        "schema",
        "control_id",
        "source",
        "evaluated_at",
        "policy_id",
        "summary",
        "results",
    }
    assert document["schema"] == "psb-control-assessment/v1"
    assert document["control_id"] == "PSB-SOURCE-005"
    assert document["source"] == args.source
    assert POLICY_ID_RE.fullmatch(document["policy_id"])
    assert set(document["summary"]) == STATUSES
    assert sum(document["summary"].values()) == len(CHECK_IDS)
    assert len(document["results"]) == len(CHECK_IDS)

    by_id = {item["check_id"]: item for item in document["results"]}
    assert set(by_id) == CHECK_IDS
    statuses = set()
    for item in by_id.values():
        assert set(item) == {"check_id", "status", "messages"}
        assert item["status"] in STATUSES
        assert isinstance(item["messages"], list) and item["messages"]
        assert all(isinstance(message, str) and message for message in item["messages"])
        statuses.add(item["status"])
    assert expected_exit(statuses) == args.expected_exit
    for status in STATUSES:
        assert document["summary"][status] == sum(
            item["status"] == status for item in by_id.values()
        )

    with args.csv_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == len(CHECK_IDS)
    assert {row["check_id"] for row in rows} == CHECK_IDS
    assert all(row["control_id"] == "PSB-SOURCE-005" for row in rows)
    assert all(row["status"] in STATUSES for row in rows)
    assert all(row["message"] for row in rows)

    serialized = args.json_path.read_text(encoding="utf-8") + args.csv_path.read_text(
        encoding="utf-8"
    )
    assert "SYNTHETIC_TEST_VALUE_DO_NOT_USE" not in serialized
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
