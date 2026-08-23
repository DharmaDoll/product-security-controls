#!/usr/bin/env python3
"""Verify the small repository-owned Git hooks baseline."""

from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path


GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.0@"
    "sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"
)
REQUIRED_SETTINGS = {
    ("core", "hookspath"): ".githooks",
    ("push", "default"): "simple",
    ("commit", "gpgsign"): "true",
    ("tag", "gpgsign"): "true",
    ("user", "useconfigonly"): "true",
}
REQUIRED_HOOKS = {
    "commit-msg",
    "pre-commit",
    "pre-push",
    "run-gitleaks.sh",
    "scan-sensitive.py",
    "test-detection.sh",
}


def read_config(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError, configparser.Error) as error:
        raise ValueError(f"cannot parse {path}: {error}") from error
    return parser


def inspect_gitleaks_wrapper(path: Path) -> list[str]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error

    findings: list[str] = []
    required_fragments = {
        GITLEAKS_IMAGE: "Gitleaks container must use the reviewed immutable digest",
        "--pull never": "Gitleaks hook must not pull during commit",
        "--network none": "Gitleaks runtime network must be disabled",
        "readonly": "Gitleaks source mount must be read-only",
        "--redact": "Gitleaks output must redact matched values",
    }
    for fragment, message in required_fragments.items():
        if fragment not in content:
            findings.append(message)
    return findings


def inspect(profile: Path) -> list[str]:
    parser = read_config(profile / "recommended.gitconfig")
    findings: list[str] = []

    for (section, option), expected in REQUIRED_SETTINGS.items():
        actual = parser.get(section, option, fallback="<missing>").strip()
        if actual != expected:
            findings.append(f"{section}.{option}: expected={expected} actual={actual}")

    if parser.get("credential", "helper", fallback="").strip() == "store":
        findings.append("credential.helper: plaintext store is prohibited")
    if parser.get("safe", "directory", fallback="").strip() == "*":
        findings.append("safe.directory: wildcard trust is prohibited")

    hook_directory = profile / ".githooks"
    for name in sorted(REQUIRED_HOOKS):
        path = hook_directory / name
        if not path.is_file():
            findings.append(f"hook {name}: missing")
        elif not path.stat().st_mode & 0o111:
            findings.append(f"hook {name}: not executable")

    wrapper = hook_directory / "run-gitleaks.sh"
    if wrapper.is_file():
        findings.extend(inspect_gitleaks_wrapper(wrapper))
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
