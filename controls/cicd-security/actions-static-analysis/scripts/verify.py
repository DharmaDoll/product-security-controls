#!/usr/bin/env python3
"""Verify the repository's zizmor workflow policy and normalized SARIF state."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ZIZMOR_ACTION = "zizmorcore/zizmor-action"
ZIZMOR_ACTION_SHA = "6fc4b006235f201fdab3722e17240ab420d580e5"
ZIZMOR_VERSION = "1.28.0"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?uses:\s*(?P<value>\S+)")
KEY_VALUE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_-]+):(?:\s*(?P<value>.*?))?\s*$"
)


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise OSError(f"input does not exist or is not a file: {path}")
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {path}: {error}") from error


def scalar(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def step_inputs(lines: list[str], uses_index: int) -> dict[str, tuple[str, int]]:
    uses_indent = len(lines[uses_index]) - len(lines[uses_index].lstrip(" "))
    inputs: dict[str, tuple[str, int]] = {}
    with_indent: int | None = None

    for index in range(uses_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent < uses_indent or (
            indent == uses_indent and line.lstrip().startswith("- ")
        ):
            break
        match = KEY_VALUE_RE.match(line)
        if match is None:
            continue
        key = match.group("key")
        if key == "with" and indent == uses_indent:
            with_indent = indent
            continue
        if with_indent is not None and indent > with_indent:
            inputs[key] = (scalar(match.group("value") or ""), index + 1)
    return inputs


def add_violation(
    violations: list[tuple[int, str]], line_number: int, message: str
) -> None:
    violations.append((line_number, message))


def verify_workflow(path: Path) -> int:
    lines = read_lines(path)
    violations: list[tuple[int, str]] = []
    action_steps: list[tuple[int, dict[str, tuple[str, int]]]] = []

    top_permissions = next(
        (
            (index + 1, scalar(match.group("value") or ""))
            for index, line in enumerate(lines)
            if (match := KEY_VALUE_RE.match(line))
            and match.group("key") == "permissions"
            and len(match.group("indent")) == 0
        ),
        None,
    )
    if top_permissions is None:
        add_violation(violations, 1, "top-level permissions must be explicit")
    elif top_permissions[1] != "{}":
        add_violation(
            violations,
            top_permissions[0],
            "top-level permissions must be deny-all ({})",
        )

    for index, line in enumerate(lines):
        match = USES_RE.match(line)
        if match is None:
            continue
        value = scalar(match.group("value"))
        if "@" not in value:
            add_violation(violations, index + 1, "uses reference has no immutable ref")
            continue
        action, reference = value.rsplit("@", 1)
        if FULL_SHA_RE.fullmatch(reference) is None:
            add_violation(
                violations,
                index + 1,
                f"{action} must use a full commit SHA",
            )
        if action == ZIZMOR_ACTION:
            if reference != ZIZMOR_ACTION_SHA:
                add_violation(
                    violations,
                    index + 1,
                    "zizmor-action is not pinned to the reviewed commit",
                )
            action_steps.append((index, step_inputs(lines, index)))

    if len(action_steps) != 2:
        add_violation(
            violations,
            1,
            "exactly two zizmor steps are required: blocking and SARIF reporting",
        )

    modes: list[str] = []
    required = {
        "inputs": ".github",
        "collect": "all",
        "online-audits": "false",
        "version": ZIZMOR_VERSION,
        "token": "",
        "fail-on-no-inputs": "true",
    }
    for uses_index, inputs in action_steps:
        for key, expected in required.items():
            actual = inputs.get(key)
            if actual is None:
                add_violation(
                    violations,
                    uses_index + 1,
                    f"zizmor input {key} must be explicit",
                )
            elif actual[0] != expected:
                add_violation(
                    violations,
                    actual[1],
                    f"zizmor input {key} must be {expected!r}",
                )
        mode = inputs.get("advanced-security")
        if mode is None:
            add_violation(
                violations,
                uses_index + 1,
                "advanced-security mode must be explicit",
            )
        else:
            modes.append(mode[0])

    if sorted(modes) != ["false", "true"]:
        add_violation(
            violations,
            1,
            "one blocking mode and one SARIF reporting mode are required",
        )

    report_condition = "if: github.event_name == 'push' && github.ref == 'refs/heads/main'"
    if report_condition not in (line.strip() for line in lines):
        add_violation(
            violations,
            1,
            "SARIF write job must be restricted to pushes on refs/heads/main",
        )

    security_event_lines = [
        index + 1
        for index, line in enumerate(lines)
        if line.strip() == "security-events: write"
    ]
    if len(security_event_lines) != 1:
        add_violation(
            violations,
            1,
            "security-events: write must occur exactly once in the trusted report job",
        )

    persist_lines = [
        index + 1
        for index, line in enumerate(lines)
        if line.strip() == "persist-credentials: false"
    ]
    if len(persist_lines) != 2:
        add_violation(
            violations,
            1,
            "both checkout steps must disable credential persistence",
        )

    for line_number, message in sorted(violations):
        print(f"FAIL {path}:{line_number} - {message}")
    if violations:
        print(f"REJECTED {len(violations)} workflow policy violation(s)")
        return 1

    print(
        f"ACCEPTED zizmor {ZIZMOR_VERSION} workflow with separate blocking and "
        "trusted SARIF jobs"
    )
    return 0


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def verify_sarif(path: Path) -> int:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise OSError(f"input does not exist: {path}") from error
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid SARIF JSON: {error.msg}") from error

    root = require_mapping(document, "SARIF document")
    if root.get("version") != "2.1.0":
        raise ValueError("SARIF version must be 2.1.0")
    runs = root.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF runs must be a non-empty array")

    findings: list[tuple[str, str, int]] = []
    for run_index, raw_run in enumerate(runs):
        run = require_mapping(raw_run, f"runs[{run_index}]")
        tool = require_mapping(run.get("tool"), f"runs[{run_index}].tool")
        driver = require_mapping(tool.get("driver"), f"runs[{run_index}].tool.driver")
        if str(driver.get("name", "")).lower() != "zizmor":
            raise ValueError(f"runs[{run_index}] was not produced by zizmor")
        if driver.get("version") != ZIZMOR_VERSION:
            raise ValueError(
                f"runs[{run_index}] zizmor version must be {ZIZMOR_VERSION}"
            )

        invocations = run.get("invocations")
        if not isinstance(invocations, list) or not invocations:
            raise ValueError(f"runs[{run_index}] has no scanner invocation status")
        for invocation_index, raw_invocation in enumerate(invocations):
            invocation = require_mapping(
                raw_invocation,
                f"runs[{run_index}].invocations[{invocation_index}]",
            )
            if invocation.get("executionSuccessful") is not True:
                print(
                    f"ERROR {path} scanner invocation was not successful",
                    file=sys.stderr,
                )
                return 2

        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError(f"runs[{run_index}].results must be an array")
        for result_index, raw_result in enumerate(results):
            result = require_mapping(
                raw_result, f"runs[{run_index}].results[{result_index}]"
            )
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id:
                raise ValueError(
                    f"runs[{run_index}].results[{result_index}] has no ruleId"
                )
            uri = "<unknown>"
            line_number = 0
            locations = result.get("locations", [])
            if isinstance(locations, list) and locations:
                location = require_mapping(locations[0], "result location")
                physical = require_mapping(
                    location.get("physicalLocation"), "physicalLocation"
                )
                artifact = require_mapping(
                    physical.get("artifactLocation"), "artifactLocation"
                )
                region = require_mapping(physical.get("region"), "region")
                uri = str(artifact.get("uri", "<unknown>"))
                start_line = region.get("startLine", 0)
                if isinstance(start_line, int):
                    line_number = start_line
            findings.append((rule_id, uri, line_number))

    for rule_id, uri, line_number in findings:
        print(f"FAIL {rule_id} {uri}:{line_number}")
    if findings:
        print(f"REJECTED {len(findings)} SARIF finding(s)")
        return 1

    print(f"ACCEPTED zizmor {ZIZMOR_VERSION} SARIF with 0 findings")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a zizmor workflow policy or normalized SARIF result."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    workflow_parser = subparsers.add_parser("workflow")
    workflow_parser.add_argument("path", type=Path)
    sarif_parser = subparsers.add_parser("sarif")
    sarif_parser.add_argument("path", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "workflow":
            return verify_workflow(args.path)
        return verify_sarif(args.path)
    except (OSError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
