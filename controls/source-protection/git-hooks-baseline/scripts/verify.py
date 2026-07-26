#!/usr/bin/env python3
"""Verify the declarative Git security baseline and hook bundle."""

from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path


REQUIRED = {
    ("core", "hookspath"): ".githooks",
    ("push", "default"): "simple",
    ("commit", "gpgsign"): "true",
    ("tag", "gpgsign"): "true",
    ("user", "useconfigonly"): "true",
}
REQUIRED_HOOKS = {"pre-commit", "commit-msg", "pre-push", "scan-sensitive.py"}


def load_config(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError, configparser.Error) as error:
        raise ValueError(f"cannot parse {path}: {error}") from error
    return parser


def inspect(profile: Path) -> list[str]:
    config_path = profile / "recommended.gitconfig"
    parser = load_config(config_path)
    findings: list[str] = []

    for (section, option), expected in REQUIRED.items():
        actual = parser.get(section, option, fallback="<missing>").strip()
        if actual != expected:
            findings.append(
                f"{section}.{option}: expected={expected} actual={actual}"
            )

    credential_helper = parser.get("credential", "helper", fallback="").strip()
    if credential_helper == "store":
        findings.append("credential.helper: plaintext store is prohibited")
    safe_directory = parser.get("safe", "directory", fallback="").strip()
    if safe_directory == "*":
        findings.append("safe.directory: wildcard trust is prohibited")

    hooks_path = profile / ".githooks"
    for name in sorted(REQUIRED_HOOKS):
        hook = hooks_path / name
        if not hook.is_file():
            findings.append(f"hook {name}: missing")
        elif not hook.stat().st_mode & 0o111:
            findings.append(f"hook {name}: not executable")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    try:
        findings = inspect(args.profile)
    except ValueError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL {finding}")
    if findings:
        print(f"REJECTED {len(findings)} baseline finding(s)")
        return 1
    print("ACCEPTED Git hooks security baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
