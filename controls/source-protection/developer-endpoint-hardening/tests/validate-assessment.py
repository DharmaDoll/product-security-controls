#!/usr/bin/env python3
"""Validate sanitized assessment JSON and matching CSV artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


STATUSES = {"PASS", "FAIL", "NOT_CHECKED", "ERROR", "N/A"}
RESULT_KEYS = {"check_id", "title", "status", "evidence_code", "detail"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("json_result", type=Path)
    parser.add_argument("csv_result", type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-exit", type=int, required=True)
    args = parser.parse_args()

    document = json.loads(args.json_result.read_text(encoding="utf-8"))
    if document["schema_version"] != "1.0":
        raise SystemExit("invalid schema version")
    if document["control_id"] != "PSB-SOURCE-001":
        raise SystemExit("invalid control id")
    if document["source"] != args.source:
        raise SystemExit("invalid assessment source")
    datetime.fromisoformat(document["generated_at"])
    results = document["results"]
    if len(results) != 28:
        raise SystemExit("assessment must contain all 28 checks")
    if len({result["check_id"] for result in results}) != len(results):
        raise SystemExit("duplicate assessment check id")
    for result in results:
        if set(result) != RESULT_KEYS:
            raise SystemExit("assessment result has unexpected fields")
        if result["status"] not in STATUSES:
            raise SystemExit("assessment result has invalid status")
        rendered = json.dumps(result, ensure_ascii=False)
        if "/home/" in rendered or "\\Users\\" in rendered:
            raise SystemExit("assessment result contains a host user path")

    counts = Counter(result["status"] for result in results)
    expected_summary = {status: counts[status] for status in document["summary"]}
    if document["summary"] != expected_summary:
        raise SystemExit("assessment summary does not match results")
    if counts["ERROR"]:
        calculated_exit = 2
    elif counts["FAIL"]:
        calculated_exit = 1
    elif counts["NOT_CHECKED"]:
        calculated_exit = 3
    else:
        calculated_exit = 0
    if calculated_exit != args.expected_exit:
        raise SystemExit("assessment exit state does not match results")

    with args.csv_result.open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    if len(csv_rows) != len(results):
        raise SystemExit("assessment CSV row count does not match JSON")
    if [row["Check ID"] for row in csv_rows] != [
        result["check_id"] for result in results
    ]:
        raise SystemExit("assessment CSV order does not match JSON")
    print("PASS assessment JSON and CSV are complete and sanitized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
