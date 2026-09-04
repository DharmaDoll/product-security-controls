#!/usr/bin/env python3
"""Reject direct GitHub Actions expression interpolation in `run:` scripts."""

from __future__ import annotations

import argparse
import bisect
import re
import sys
from dataclasses import dataclass
from pathlib import Path


WORKFLOW_SUFFIXES = {".yml", ".yaml"}
RUN_RE = re.compile(
    r"""^(?P<indent> *)(?:-\s+)?(?:"run"|'run'|run)\s*:\s*(?P<value>.*?)\s*$"""
)
RUN_KEY_RE = re.compile(r"""(?:^|[\s{,])(?:"run"|'run'|run)\s*:""")
BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\d?$|^[|>]\d[+-]?$")
EXPRESSION_RE = re.compile(r"\${{.*?}}", re.DOTALL)


@dataclass(frozen=True)
class RunScalar:
    key_line: int
    content_line: int
    content: str


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


def indentation(line: str) -> int:
    if "\t" in line[: len(line) - len(line.lstrip())]:
        raise ValueError("tab indentation is unsupported")
    return len(line) - len(line.lstrip(" "))


def extract_run_scalars(path: Path) -> list[RunScalar]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {path}: {error}") from error

    scalars: list[RunScalar] = []
    index = 0
    while index < len(lines):
        raw_line = lines[index]
        candidate = strip_yaml_comment(raw_line).rstrip()
        if not candidate.strip() or candidate.lstrip().startswith("#"):
            index += 1
            continue

        match = RUN_RE.match(candidate)
        if not match:
            if RUN_KEY_RE.search(candidate):
                raise ValueError(
                    f"{path}:{index + 1}: unsupported run syntax; "
                    "use a scalar run value on its own line"
                )
            index += 1
            continue

        key_line = index + 1
        value = match.group("value").strip()
        if BLOCK_SCALAR_RE.fullmatch(value):
            key_indent = len(match.group("indent"))
            block_lines: list[str] = []
            index += 1
            content_line = index + 1
            while index < len(lines):
                block_line = lines[index]
                if block_line.strip() and indentation(block_line) <= key_indent:
                    break
                block_lines.append(block_line)
                index += 1
            if not block_lines:
                raise ValueError(f"{path}:{key_line}: run block has no content")
            scalars.append(
                RunScalar(
                    key_line=key_line,
                    content_line=content_line,
                    content="\n".join(block_lines),
                )
            )
            continue

        if not value:
            raise ValueError(f"{path}:{key_line}: run value is empty or unsupported")
        if value.startswith(("*", "&", "{", "[")):
            raise ValueError(
                f"{path}:{key_line}: aliased or flow-style run values are unsupported"
            )
        if value.startswith(("'", '"')) and not value.endswith(value[0]):
            raise ValueError(
                f"{path}:{key_line}: multiline quoted run values are unsupported"
            )
        scalars.append(
            RunScalar(key_line=key_line, content_line=key_line, content=value)
        )
        index += 1

    return scalars


def expression_line(scalar: RunScalar, offset: int) -> int:
    newline_offsets = [
        index for index, character in enumerate(scalar.content) if character == "\n"
    ]
    return scalar.content_line + bisect.bisect_left(newline_offsets, offset)


def verify_file(path: Path) -> tuple[int, int]:
    scalars = extract_run_scalars(path)
    violations = 0
    for scalar in scalars:
        matches = list(EXPRESSION_RE.finditer(scalar.content))
        expression_starts = scalar.content.count("${{")
        if len(matches) != expression_starts:
            raise ValueError(
                f"{path}:{scalar.key_line}: malformed or nested expression in run script"
            )
        for match in matches:
            line_number = expression_line(scalar, match.start())
            expression = " ".join(match.group(0).split())
            print(
                f"FAIL {path}:{line_number} {expression} - "
                "direct expression interpolation in run script"
            )
            violations += 1
    return len(scalars), violations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prohibit direct GitHub Actions expressions in run scripts."
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
        print("ERROR no run steps found", file=sys.stderr)
        return 2
    if violations:
        print(f"REJECTED {violations} expression(s) in {checked} run step(s)")
        return 1

    print(f"ACCEPTED {checked} run step(s) without direct expressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
