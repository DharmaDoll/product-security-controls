#!/usr/bin/env python3
"""Synthetic DockSec CLI used only to test the PSB adapter contract."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


if sys.argv[1:] == ["--version"]:
    print("DockSec 2026.7.5")
    raise SystemExit(0)

expected = [
    "--scan-only",
    "--offline",
    "--fail-on",
    "high",
    "--json",
    "--no-cache",
]
if len(sys.argv) != 2 + len(expected) or sys.argv[2:] != expected:
    print("synthetic invalid arguments", file=sys.stderr)
    raise SystemExit(2)

if any(
    os.getenv(name)
    for name in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "LLM_PROVIDER",
        "LLM_MODEL",
    )
):
    print("synthetic AI environment leak", file=sys.stderr)
    raise SystemExit(3)

target = Path(sys.argv[1]).name
if "usage-error" in target:
    print("synthetic usage failure", file=sys.stderr)
    raise SystemExit(2)
if "runtime-error" in target:
    print("synthetic scanner failure", file=sys.stderr)
    raise SystemExit(3)
if "malformed" in target:
    print("{not-json")
    raise SystemExit(0)

counts = {
    "CRITICAL": 0,
    "HIGH": 1 if "finding" in target else 0,
    "MEDIUM": 0,
    "LOW": 0,
    "UNKNOWN": 0,
}
payload = {
    "scan_info": {
        "dockerfile": target,
        "scan_mode": "scan_only",
    },
    "vulnerabilities": [],
    "severity_counts": counts,
}
if "ai-output" in target:
    payload["ai_analysis"] = {"synthetic": "must-not-control-gate"}
print(json.dumps(payload))
raise SystemExit(1 if counts["HIGH"] else 0)
