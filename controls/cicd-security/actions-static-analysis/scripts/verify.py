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
CHECKOUT_ACTION = "actions/checkout"
GITHUB_HOSTED_RUNNER = "ubuntu-latest"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?uses:\s*(?P<value>\S+)")
KEY_VALUE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_-]+):(?:\s*(?P<value>.*?))?\s*$"
)
LIST_KEY_VALUE_RE = re.compile(
    r"^(?P<indent>\s*)-\s+(?P<key>[A-Za-z0-9_-]+):"
    r"(?:\s*(?P<value>.*?))?\s*$"
)


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise OSError(f"input does not exist or is not a file: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {path}: {error}") from error
    for index, line in enumerate(lines):
        leading_whitespace = line[: len(line) - len(line.lstrip())]
        if "\t" in leading_whitespace:
            raise ValueError(f"line {index + 1} uses unsupported tab indentation")
    return lines


def scalar(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def block_end(lines: list[str], parent_index: int) -> int:
    parent_indent = indentation(lines[parent_index])
    for index in range(parent_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) <= parent_indent:
            return index
    return len(lines)


def mapping_entries(
    lines: list[str], start: int, end: int, expected_indent: int
) -> dict[str, tuple[str, int]]:
    entries: dict[str, tuple[str, int]] = {}
    for index in range(start, end):
        match = KEY_VALUE_RE.match(lines[index])
        if match is None or len(match.group("indent")) != expected_indent:
            continue
        key = match.group("key")
        if key in entries:
            raise ValueError(f"line {index + 1} duplicates mapping key {key!r}")
        entries[key] = (scalar(match.group("value") or ""), index)
    return entries


def child_entries(lines: list[str], parent_index: int) -> dict[str, tuple[str, int]]:
    return mapping_entries(
        lines,
        parent_index + 1,
        block_end(lines, parent_index),
        indentation(lines[parent_index]) + 2,
    )


def list_values(lines: list[str], parent_index: int) -> list[tuple[str, int]]:
    values: list[tuple[str, int]] = []
    expected_indent = indentation(lines[parent_index]) + 2
    for index in range(parent_index + 1, block_end(lines, parent_index)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == expected_indent and line.lstrip().startswith("- "):
            values.append((scalar(line.lstrip()[2:]), index))
    return values


def list_item_indexes(lines: list[str], parent_index: int) -> list[int]:
    expected_indent = indentation(lines[parent_index]) + 2
    return [
        index
        for index in range(parent_index + 1, block_end(lines, parent_index))
        if lines[index].strip()
        and not lines[index].lstrip().startswith("#")
        and indentation(lines[index]) == expected_indent
        and lines[index].lstrip().startswith("- ")
    ]


def list_item_entries(
    lines: list[str], item_index: int, item_end: int
) -> dict[str, tuple[str, int]]:
    first = LIST_KEY_VALUE_RE.match(lines[item_index])
    if first is None:
        raise ValueError(f"line {item_index + 1} is not a supported mapping list item")
    entries = {
        first.group("key"): (scalar(first.group("value") or ""), item_index)
    }
    expected_indent = indentation(lines[item_index]) + 2
    for index in range(item_index + 1, item_end):
        match = KEY_VALUE_RE.match(lines[index])
        if match is None or len(match.group("indent")) != expected_indent:
            continue
        key = match.group("key")
        if key in entries:
            raise ValueError(f"line {index + 1} duplicates step key {key!r}")
        entries[key] = (scalar(match.group("value") or ""), index)
    return entries


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
            if key in inputs:
                raise ValueError(
                    f"line {index + 1} duplicates step input {key!r}"
                )
            inputs[key] = (scalar(match.group("value") or ""), index + 1)
    return inputs


def add_violation(
    violations: list[tuple[int, str]], line_number: int, message: str
) -> None:
    violations.append((line_number, message))


def verify_workflow(path: Path, default_branch: str) -> int:
    if not default_branch or any(character.isspace() for character in default_branch):
        raise ValueError("default branch must be a non-empty branch name without spaces")

    lines = read_lines(path)
    violations: list[tuple[int, str]] = []
    action_steps: list[tuple[int, str, dict[str, tuple[str, int]]]] = []
    top_entries = mapping_entries(lines, 0, len(lines), 0)

    top_permissions = top_entries.get("permissions")
    if top_permissions is None:
        add_violation(violations, 1, "top-level permissions must be explicit")
    elif top_permissions[0] != "{}":
        add_violation(
            violations,
            top_permissions[1] + 1,
            "top-level permissions must be deny-all ({})",
        )

    top_env = top_entries.get("env")
    if top_env is not None:
        add_violation(
            violations,
            top_env[1] + 1,
            "top-level env must not inject credentials into scanner jobs",
        )

    on_entry = top_entries.get("on")
    if on_entry is None or on_entry[0]:
        add_violation(
            violations,
            1 if on_entry is None else on_entry[1] + 1,
            "events must be an explicit pull_request and trusted push mapping",
        )
    else:
        events = child_entries(lines, on_entry[1])
        if set(events) != {"push", "pull_request"}:
            add_violation(
                violations,
                on_entry[1] + 1,
                "events must be exactly pull_request and push",
            )
        pull_request_entry = events.get("pull_request")
        if pull_request_entry is not None and (
            pull_request_entry[0]
            or child_entries(lines, pull_request_entry[1])
        ):
            add_violation(
                violations,
                pull_request_entry[1] + 1,
                "pull_request must scan every pull request without filters",
            )
        push_entry = events.get("push")
        if push_entry is not None:
            push_fields = child_entries(lines, push_entry[1])
            if push_entry[0] or set(push_fields) != {"branches"}:
                add_violation(
                    violations,
                    push_entry[1] + 1,
                    "push must contain only an explicit branches list",
                )
            branches_entry = push_fields.get("branches")
            branches = (
                [] if branches_entry is None else list_values(lines, branches_entry[1])
            )
            if [value for value, _ in branches] != [default_branch]:
                add_violation(
                    violations,
                    push_entry[1] + 1,
                    f"push branches must contain only {default_branch!r}",
                )

    jobs_entry = top_entries.get("jobs")
    jobs: dict[str, tuple[str, int]] = {}
    if jobs_entry is None or jobs_entry[0]:
        add_violation(violations, 1, "jobs must be an explicit mapping")
    else:
        jobs = child_entries(lines, jobs_entry[1])
        if set(jobs) != {"gate", "report"}:
            add_violation(
                violations,
                jobs_entry[1] + 1,
                "workflow must contain exactly gate and report jobs",
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
        action_steps.append((index, action, step_inputs(lines, index)))

    for index, line in enumerate(lines):
        match = KEY_VALUE_RE.match(line)
        if (
            match is not None
            and match.group("key") == "continue-on-error"
            and scalar(match.group("value") or "") != "false"
        ):
            add_violation(
                violations,
                index + 1,
                "continue-on-error must not hide scanner or checkout failures",
            )

    required = {
        "inputs": ".github",
        "collect": "all",
        "online-audits": "false",
        "persona": "auditor",
        "version": ZIZMOR_VERSION,
        "token": "",
        "fail-on-no-inputs": "true",
    }
    expected_permissions = {
        "gate": {"contents": "read"},
        "report": {
            "actions": "read",
            "contents": "read",
            "security-events": "write",
        },
    }
    expected_modes = {"gate": "false", "report": "true"}
    expected_job_names = {
        "gate": "Block workflow security findings",
        "report": "Upload trusted-branch SARIF",
    }
    expected_job_fields = {
        "gate": {"name", "runs-on", "permissions", "steps"},
        "report": {"name", "if", "runs-on", "permissions", "steps"},
    }

    for job_name in ("gate", "report"):
        job_entry = jobs.get(job_name)
        if job_entry is None:
            continue
        job_index = job_entry[1]
        job_end = block_end(lines, job_index)
        job_fields = child_entries(lines, job_index)

        if set(job_fields) != expected_job_fields[job_name]:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} job fields must be exactly "
                f"{sorted(expected_job_fields[job_name])!r}",
            )

        name = job_fields.get("name")
        if name is None or name[0] != expected_job_names[job_name]:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} name must be {expected_job_names[job_name]!r}",
            )

        runs_on = job_fields.get("runs-on")
        if runs_on is None or runs_on[0] != GITHUB_HOSTED_RUNNER:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} must run on {GITHUB_HOSTED_RUNNER}",
            )

        permissions_entry = job_fields.get("permissions")
        actual_permissions: dict[str, str] = {}
        if permissions_entry is not None and not permissions_entry[0]:
            permission_fields = child_entries(lines, permissions_entry[1])
            actual_permissions = {
                key: value for key, (value, _) in permission_fields.items()
            }
        if actual_permissions != expected_permissions[job_name]:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} permissions must be exactly {expected_permissions[job_name]!r}",
            )

        steps_entry = job_fields.get("steps")
        if steps_entry is None or steps_entry[0]:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} steps must be an explicit list",
            )
            continue
        steps_index = steps_entry[1]
        steps_end = block_end(lines, steps_index)
        step_indexes = list_item_indexes(lines, steps_index)
        if len(step_indexes) != 2:
            add_violation(
                violations,
                steps_index + 1,
                f"{job_name} must contain only checkout and zizmor steps",
            )
        for position, step_index in enumerate(step_indexes):
            step_end = (
                step_indexes[position + 1]
                if position + 1 < len(step_indexes)
                else steps_end
            )
            entries = list_item_entries(lines, step_index, step_end)
            if set(entries) != {"name", "uses", "with"}:
                add_violation(
                    violations,
                    step_index + 1,
                    f"{job_name} step fields must be exactly name, uses, and with",
                )
        for index in range(steps_index + 1, steps_end):
            match = KEY_VALUE_RE.match(lines[index])
            if match is not None and match.group("key") == "run":
                add_violation(
                    violations,
                    index + 1,
                    f"{job_name} must not execute repository commands",
                )

        job_steps = [
            step for step in action_steps if steps_index < step[0] < steps_end
        ]
        checkout_steps = [step for step in job_steps if step[1] == CHECKOUT_ACTION]
        zizmor_steps = [step for step in job_steps if step[1] == ZIZMOR_ACTION]
        if len(checkout_steps) != 1:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} must contain exactly one checkout step",
            )
        else:
            checkout_inputs = checkout_steps[0][2]
            if (
                set(checkout_inputs) != {"persist-credentials"}
                or checkout_inputs.get("persist-credentials", (None, 0))[0]
                != "false"
            ):
                add_violation(
                    violations,
                    checkout_steps[0][0] + 1,
                    f"{job_name} checkout inputs must be exactly "
                    "persist-credentials: false",
                )

        if len(zizmor_steps) != 1:
            add_violation(
                violations,
                job_index + 1,
                f"{job_name} must contain exactly one zizmor step",
            )
            continue

        uses_index, _, inputs = zizmor_steps[0]
        expected_inputs = {
            **required,
            "advanced-security": expected_modes[job_name],
        }
        if set(inputs) != set(expected_inputs):
            add_violation(
                violations,
                uses_index + 1,
                f"{job_name} zizmor inputs must contain only the reviewed keys",
            )
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
        if mode is None or mode[0] != expected_modes[job_name]:
            add_violation(
                violations,
                uses_index + 1 if mode is None else mode[1],
                f"{job_name} advanced-security must be {expected_modes[job_name]}",
            )

        if job_name == "report":
            report_condition = (
                "github.event_name == 'push' && "
                f"github.ref == 'refs/heads/{default_branch}'"
            )
            condition = job_fields.get("if")
            if condition is None or condition[0] != report_condition:
                add_violation(
                    violations,
                    job_index + 1,
                    "report must be restricted to the trusted default-branch push",
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
    workflow_parser.add_argument("--default-branch", default="main")
    sarif_parser = subparsers.add_parser("sarif")
    sarif_parser.add_argument("path", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "workflow":
            return verify_workflow(args.path, args.default_branch)
        return verify_sarif(args.path)
    except (OSError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
