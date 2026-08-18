#!/usr/bin/env python3
"""Detect deceptive Unicode controls and identifiers in Python source."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import keyword
import re
import sys
import tokenize
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-unicode-source-policy/v1"
CODE_POINT_RE = re.compile(r"^U\+([0-9A-F]{4,6})$")
ASCII_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
POLICY_FIELDS = {
    "schema",
    "language",
    "encoding",
    "file_extensions",
    "identifier_profile",
    "identifier_normalization",
    "forbidden_code_points",
    "forbidden_ranges",
}


@dataclass(frozen=True)
class Policy:
    digest: str
    extensions: tuple[str, ...]
    normalization: str
    forbidden: dict[int, str]
    ranges: tuple[tuple[int, int, str], ...]


@dataclass(frozen=True)
class SourceFile:
    path: Path
    label: str


@dataclass(frozen=True)
class Finding:
    line: int
    column: int
    code_points: tuple[int, ...]
    reason: str


def parse_code_point(value: Any, label: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a Unicode code point")
    match = CODE_POINT_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} must use U+XXXX notation")
    code_point = int(match.group(1), 16)
    if code_point > 0x10FFFF or 0xD800 <= code_point <= 0xDFFF:
        raise ValueError(f"{label} is not a Unicode scalar value")
    return code_point


def load_policy(path: Path) -> Policy:
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load policy: {error}") from error
    if not isinstance(data, dict) or set(data) != POLICY_FIELDS:
        raise ValueError("policy fields are incomplete or unknown")
    expected = {
        "schema": POLICY_SCHEMA,
        "language": "python",
        "encoding": "utf-8",
        "identifier_profile": "ascii",
        "identifier_normalization": "NFKC",
        "file_extensions": [".py"],
    }
    for field, value in expected.items():
        if data.get(field) != value:
            raise ValueError(f"policy {field} must be {value!r}")

    forbidden: dict[int, str] = {}
    entries = data.get("forbidden_code_points")
    if not isinstance(entries, list) or not entries:
        raise ValueError("policy forbidden_code_points must be a non-empty list")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"value", "reason"}:
            raise ValueError(f"forbidden_code_points[{index}] is malformed")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason:
            raise ValueError(f"forbidden_code_points[{index}].reason is empty")
        code_point = parse_code_point(entry.get("value"), f"forbidden_code_points[{index}]")
        if code_point in forbidden:
            raise ValueError(f"duplicate forbidden code point U+{code_point:04X}")
        forbidden[code_point] = reason

    ranges: list[tuple[int, int, str]] = []
    range_entries = data.get("forbidden_ranges")
    if not isinstance(range_entries, list) or not range_entries:
        raise ValueError("policy forbidden_ranges must be a non-empty list")
    for index, entry in enumerate(range_entries):
        if not isinstance(entry, dict) or set(entry) != {"start", "end", "reason"}:
            raise ValueError(f"forbidden_ranges[{index}] is malformed")
        start = parse_code_point(entry.get("start"), f"forbidden_ranges[{index}].start")
        end = parse_code_point(entry.get("end"), f"forbidden_ranges[{index}].end")
        reason = entry.get("reason")
        if start > end or not isinstance(reason, str) or not reason:
            raise ValueError(f"forbidden_ranges[{index}] has invalid bounds or reason")
        ranges.append((start, end, reason))

    return Policy(
        digest=hashlib.sha256(raw).hexdigest(),
        extensions=tuple(data["file_extensions"]),
        normalization=data["identifier_normalization"],
        forbidden=forbidden,
        ranges=tuple(ranges),
    )


def discover_files(inputs: list[str], extensions: tuple[str, ...]) -> list[SourceFile]:
    files: list[SourceFile] = []
    for raw_input in inputs:
        path = Path(raw_input)
        if not path.exists():
            raise ValueError(f"input does not exist: {raw_input}")
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_symlink() and candidate.suffix in extensions:
                    raise ValueError(f"symbolic-link source is unsupported: {candidate}")
                if candidate.is_file() and candidate.suffix in extensions:
                    files.append(SourceFile(candidate, candidate.relative_to(path).as_posix()))
        elif path.is_file() and path.suffix in extensions:
            if path.is_symlink():
                raise ValueError(f"symbolic-link source is unsupported: {raw_input}")
            files.append(SourceFile(path, path.name))
        elif path.is_file():
            raise ValueError(f"unsupported source extension: {raw_input}")
        else:
            raise ValueError(f"unsupported input type: {raw_input}")
    unique = list({(item.path.resolve(), item.label): item for item in files}.values())
    if not unique:
        raise ValueError("no supported Python source files found")
    paths_by_label: dict[str, Path] = {}
    for item in unique:
        existing = paths_by_label.get(item.label)
        if existing is not None and existing != item.path.resolve():
            raise ValueError(f"ambiguous source label from multiple roots: {item.label}")
        paths_by_label[item.label] = item.path.resolve()
    return sorted(unique, key=lambda item: (item.label, str(item.path)))


def location(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return line, column


def forbidden_reason(code_point: int, policy: Policy) -> str | None:
    if code_point in policy.forbidden:
        return policy.forbidden[code_point]
    for start, end, reason in policy.ranges:
        if start <= code_point <= end:
            return reason
    return None


def inspect_source(source: SourceFile, policy: Policy) -> tuple[list[Finding], int]:
    try:
        raw = source.path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot decode {source.label} as UTF-8: {error}") from error
    try:
        ast.parse(text, filename=source.label)
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (SyntaxError, tokenize.TokenError, IndentationError) as error:
        raise ValueError(f"cannot parse {source.label} as Python source: {error}") from error

    findings: list[Finding] = []
    for offset, character in enumerate(text):
        code_point = ord(character)
        reason = forbidden_reason(code_point, policy)
        if reason is not None:
            line, column = location(text, offset)
            findings.append((Finding(line, column, (code_point,), f"forbidden-{reason}")))

    identifier_count = 0
    for token in tokens:
        if token.type != tokenize.NAME or keyword.iskeyword(token.string):
            continue
        identifier_count += 1
        code_points = tuple(sorted({ord(char) for char in token.string if ord(char) > 0x7F}))
        if unicodedata.normalize(policy.normalization, token.string) != token.string:
            findings.append(
                Finding(
                    token.start[0],
                    token.start[1] + 1,
                    code_points,
                    "identifier-not-NFKC-stable",
                )
            )
        if not ASCII_IDENTIFIER_RE.fullmatch(token.string):
            findings.append(
                Finding(
                    token.start[0],
                    token.start[1] + 1,
                    code_points,
                    "non-ascii-identifier",
                )
            )
    return sorted(findings, key=lambda item: (item.line, item.column, item.reason)), identifier_count


def format_code_points(values: tuple[int, ...]) -> str:
    if not values:
        return "none"
    return ",".join(f"U+{value:04X}" for value in values)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        sources = discover_files(args.paths, policy.extensions)
        inspected_identifiers = 0
        findings_count = 0
        output: list[str] = []
        for source in sources:
            findings, identifier_count = inspect_source(source, policy)
            inspected_identifiers += identifier_count
            for finding in findings:
                output.append(
                    f"FAIL {source.label}:{finding.line}:{finding.column} "
                    f"code-points={format_code_points(finding.code_points)} "
                    f"{finding.reason}"
                )
            findings_count += len(findings)
    except ValueError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    print(f"POLICY sha256={policy.digest}")
    for line in output:
        print(line)
    if findings_count:
        print(f"REJECTED {findings_count} finding(s) in {len(sources)} Python file(s)")
        return 1
    print(
        f"ACCEPTED {len(sources)} Python file(s); "
        f"{inspected_identifiers} identifier token(s) inspected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
