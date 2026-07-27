#!/usr/bin/env python3
"""Validate source-access credential policy metadata without reading secrets."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable


EXPECTED_TEXT = {
    "automation_authentication": "github-app-or-short-lived-workload-identity",
    "classic_pat": "exception-only",
    "pat_profile": "fine-grained-owner-repository-permission-restricted",
    "broad_scopes": "exception-only",
    "credential_storage": "os-keychain-or-approved-secret-manager",
    "interactive_authentication": "phishing-resistant-mfa-and-sso",
    "ssh_private_keys": "hardware-backed-non-exportable",
    "revocation_triggers": "offboarding-role-change-device-loss-exposure-unused",
    "audit_events": "creation-authorization-use-change-revocation",
    "exceptions": "owned-approved-justified-expiring",
}


def bounded_days(maximum: int) -> Callable[[Any], bool]:
    return lambda value: isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= maximum


NUMERIC_RULES: dict[str, tuple[str, Callable[[Any], bool]]] = {
    "user_credential_max_days": ("integer-between-1-and-90", bounded_days(90)),
    "inventory_review_days": ("integer-between-1-and-90", bounded_days(90)),
}


def load_policy(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load policy metadata: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("policy metadata must be a JSON object")
    return value


def verify(path: Path) -> int:
    try:
        policy = load_policy(path)
    except ValueError as error:
        print(f"ERROR {error}")
        return 2

    failures = 0
    for key, expected in EXPECTED_TEXT.items():
        actual = policy.get(key, "<missing>")
        if actual == expected:
            print(f"PASS {key}={expected}")
        else:
            print(f"FAIL {key}: expected={expected} actual={actual}")
            failures += 1

    for key, (expected, predicate) in NUMERIC_RULES.items():
        actual = policy.get(key, "<missing>")
        if predicate(actual):
            print(f"PASS {key}={actual}")
        else:
            print(f"FAIL {key}: expected={expected} actual={actual}")
            failures += 1

    if failures:
        print(f"REJECTED credential policy: {failures} control checks failed")
        return 1

    print("ACCEPTED credential policy")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} POLICY.json", file=sys.stderr)
        return 2
    return verify(Path(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
