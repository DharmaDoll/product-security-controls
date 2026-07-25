#!/usr/bin/env python3
"""Verify immutable `uses:` references in GitHub Actions workflows."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


USES_RE = re.compile(
    r"""^\s*(?:-\s*)?(?:"uses"|'uses'|uses)\s*:\s*(?P<value>.+?)\s*$"""
)
USES_KEY_RE = re.compile(r"""(?:"uses"|'uses'|uses)\s*:""")
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DOCKER_DIGEST_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-fA-F]{64}$")
WORKFLOW_SUFFIXES = {".yml", ".yaml"}


def strip_yaml_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if character == "#" and quote is None:
            return line[:index]
    return line


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def discover_files(inputs: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw_input in inputs:
        path = Path(raw_input)
        if not path.exists():
            raise FileNotFoundError(f"input does not exist: {raw_input}")
        if path.is_dir():
            files.extend(
                candidate
                for candidate in sorted(path.rglob("*"))
                if candidate.is_file() and candidate.suffix.lower() in WORKFLOW_SUFFIXES
            )
        elif path.is_file():
            if path.suffix.lower() not in WORKFLOW_SUFFIXES:
                raise ValueError(f"input is not a YAML workflow file: {raw_input}")
            files.append(path)
        else:
            raise ValueError(f"unsupported input type: {raw_input}")

    unique_files = list(dict.fromkeys(files))
    if not unique_files:
        raise ValueError("no .yml or .yaml workflow files found")
    return unique_files


def evaluate_reference(value: str) -> tuple[bool, str]:
    if value.startswith("./"):
        return True, "repository-local action"

    if value.startswith("docker://"):
        if DOCKER_DIGEST_RE.fullmatch(value):
            return True, "immutable sha256 container digest"
        return False, "Docker action must use an immutable sha256 digest"

    if "${{" in value:
        return False, "dynamic external reference is not immutable"
    if "@" not in value:
        return False, "external reference is missing @<full-commit-sha>"

    target, reference = value.rsplit("@", 1)
    if not target or "/" not in target:
        return False, "external reference target is invalid"
    if not FULL_SHA_RE.fullmatch(reference):
        return False, f"reference {reference!r} is not a full 40-character commit SHA"
    return True, "full 40-character commit SHA"


def verify_file(path: Path) -> tuple[int, int]:
    checked = 0
    violations = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {path}: {error}") from error

    for line_number, raw_line in enumerate(lines, start=1):
        candidate = strip_yaml_comment(raw_line).rstrip()
        if not candidate.strip() or candidate.lstrip().startswith("#"):
            continue
        match = USES_RE.match(candidate)
        if not match:
            if USES_KEY_RE.search(candidate):
                raise ValueError(
                    f"{path}:{line_number}: unsupported uses syntax; "
                    "use one scalar reference per line"
                )
            continue

        checked += 1
        value = unquote(match.group("value"))
        accepted, reason = evaluate_reference(value)
        result = "PASS" if accepted else "FAIL"
        print(f"{result} {path}:{line_number} {value} - {reason}")
        if not accepted:
            violations += 1

    return checked, violations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Require immutable GitHub Actions and Docker action references."
    )
    parser.add_argument("paths", nargs="+", help="Workflow file or directory to inspect.")
    args = parser.parse_args()

    try:
        files = discover_files(args.paths)
        checked = 0
        violations = 0
        for path in files:
            file_checked, file_violations = verify_file(path)
            checked += file_checked
            violations += file_violations
    except (OSError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    if checked == 0:
        print("ERROR no uses references found", file=sys.stderr)
        return 2
    if violations:
        print(f"REJECTED {violations} violation(s) in {checked} uses reference(s)")
        return 1

    print(f"ACCEPTED {checked} immutable uses reference(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
