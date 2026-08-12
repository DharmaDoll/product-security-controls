#!/usr/bin/env python3
"""Create deterministic negative cases from the secure remediated fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--scenario", required=True, choices=("stale", "partial", "mismatch", "overdue", "old-active", "same-digest", "sensitive"))
args = parser.parse_args()
data = json.loads(args.source.read_text(encoding="utf-8"))

if args.scenario == "stale":
    data["inventory"]["collected_at"] = "2026-08-12T10:00:00Z"
elif args.scenario == "partial":
    data["risk_evidence"]["sources"] = data["risk_evidence"]["sources"][:-1]
elif args.scenario == "mismatch":
    data["replacement"]["release"]["signature_subject"] = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
elif args.scenario == "overdue":
    data = json.loads((args.source.parent / "case-in-progress.json").read_text(encoding="utf-8"))
    data["case_id"] = "REFRESH-2026-0004"
    data["requested_state"] = "OVERDUE"
    data["decision"]["decided_at"] = "2026-08-01T10:00:00Z"
    data["decision"]["due_at"] = "2026-08-04T10:00:00Z"
elif args.scenario == "old-active":
    data["post_inventory"]["deployments"][1]["digest"] = data["artifact"]["digest"]
elif args.scenario == "same-digest":
    old_digest = data["artifact"]["digest"]
    data["replacement"]["digest"] = old_digest
    data["replacement"]["build"]["provenance_subject"] = old_digest
    data["replacement"]["release"]["sbom_subject"] = old_digest
    data["replacement"]["release"]["signature_subject"] = old_digest
    data["replacement"]["release"]["publication_digest"] = old_digest
    for admission in data["admissions"]:
        admission["digest"] = old_digest
    for deployment in data["post_inventory"]["deployments"]:
        deployment["digest"] = old_digest
elif args.scenario == "sensitive":
    data["token"] = "SYNTHETIC_TEST_VALUE_DO_NOT_USE"

args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
