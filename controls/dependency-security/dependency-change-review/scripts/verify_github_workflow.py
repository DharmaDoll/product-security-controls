#!/usr/bin/env python3
"""Verify the narrow GitHub dependency-review reference workflow contract."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


DEPENDENCY_REVIEW = (
    "actions/dependency-review-action@"
    "a1d282b36b6f3519aa1f3fc636f609c47dddb294"
)
REFERENCE_LICENSES = {
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
}
KEY_VALUE_RE = re.compile(
    r"^(?P<indent> *)(?P<list>- )?(?P<key>[A-Za-z0-9_-]+):(?: (?P<value>.*))?$"
)


class WorkflowError(Exception):
    """The workflow could not be parsed reliably."""


@dataclass(frozen=True)
class Line:
    number: int
    indent: int
    listed: bool
    key: str
    value: str


@dataclass(frozen=True)
class Step:
    name: str
    uses: str
    inputs: dict[str, str]


@dataclass(frozen=True)
class Workflow:
    events: set[str]
    top_permissions: str
    job_id: str
    job_name: str
    runner: str
    job_permissions: dict[str, str]
    steps: tuple[Step, ...]


def strip_comment(raw: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(raw):
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
            return raw[:index]
    return raw


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def tokenize(path: Path) -> list[Line]:
    if not path.is_file():
        raise WorkflowError(f"workflow is unavailable: {path}")
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise WorkflowError(f"cannot read workflow: {path}") from error

    result: list[Line] = []
    for number, raw in enumerate(raw_lines, start=1):
        if "\t" in raw:
            raise WorkflowError(f"{path}:{number}: tabs are unsupported")
        candidate = strip_comment(raw).rstrip()
        if not candidate.strip():
            continue
        match = KEY_VALUE_RE.fullmatch(candidate)
        if not match:
            raise WorkflowError(
                f"{path}:{number}: unsupported YAML syntax in reference workflow"
            )
        indent = len(match.group("indent"))
        if indent % 2:
            raise WorkflowError(f"{path}:{number}: indentation must use two spaces")
        result.append(
            Line(
                number=number,
                indent=indent,
                listed=match.group("list") is not None,
                key=match.group("key"),
                value=unquote(match.group("value") or ""),
            )
        )
    if not result:
        raise WorkflowError("workflow is empty")
    return result


def unique(lines: list[Line], *, indent: int, key: str, label: str) -> Line:
    matches = [line for line in lines if line.indent == indent and line.key == key]
    if len(matches) != 1:
        raise WorkflowError(f"workflow must contain one {label}")
    return matches[0]


def direct_children(lines: list[Line], parent: Line) -> list[Line]:
    parent_index = lines.index(parent)
    result: list[Line] = []
    for line in lines[parent_index + 1 :]:
        if line.indent <= parent.indent:
            break
        if line.indent == parent.indent + 2:
            result.append(line)
    return result


def mapping(children: list[Line], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in children:
        if line.listed or line.key in result or not line.value:
            raise WorkflowError(f"{label} must contain unique scalar values")
        result[line.key] = line.value
    return result


def parse_steps(lines: list[Line], steps_line: Line) -> tuple[Step, ...]:
    steps: list[Step] = []
    current_name: str | None = None
    current_uses: str | None = None
    current_inputs: dict[str, str] = {}
    in_with = False

    def finish() -> None:
        nonlocal current_name, current_uses, current_inputs, in_with
        if current_name is None:
            return
        if current_uses is None:
            raise WorkflowError("every reference step must have one uses value")
        steps.append(Step(current_name, current_uses, dict(current_inputs)))
        current_name = None
        current_uses = None
        current_inputs = {}
        in_with = False

    start = lines.index(steps_line)
    for line in lines[start + 1 :]:
        if line.indent <= steps_line.indent:
            break
        if line.indent == steps_line.indent + 2 and line.listed:
            if line.key != "name" or not line.value:
                raise WorkflowError("steps must use '- name: <text>'")
            finish()
            current_name = line.value
            continue
        if current_name is None:
            raise WorkflowError("step properties must follow a named step")
        if line.indent == steps_line.indent + 4 and not line.listed:
            if line.key == "uses":
                if current_uses is not None or not line.value:
                    raise WorkflowError("step uses must be one scalar")
                current_uses = line.value
                in_with = False
            elif line.key == "with" and not line.value:
                in_with = True
            else:
                raise WorkflowError(f"unsupported step property: {line.key}")
            continue
        if line.indent == steps_line.indent + 6 and in_with and not line.listed:
            if line.key in current_inputs or not line.value:
                raise WorkflowError("step inputs must contain unique scalar values")
            current_inputs[line.key] = line.value
            continue
        raise WorkflowError(f"unsupported nested step property at line {line.number}")
    finish()
    if not steps:
        raise WorkflowError("workflow has no steps")
    return tuple(steps)


def parse(path: Path) -> Workflow:
    lines = tokenize(path)
    top = [line for line in lines if line.indent == 0]
    allowed_top = {"name", "on", "permissions", "jobs"}
    if (
        {line.key for line in top} != allowed_top
        or any(line.listed for line in top)
        or len(top) != len(allowed_top)
    ):
        raise WorkflowError("workflow top-level keys must be name, on, permissions, jobs")

    on_line = unique(lines, indent=0, key="on", label="on mapping")
    if on_line.value:
        raise WorkflowError("workflow events must use a block mapping")
    event_lines = direct_children(lines, on_line)
    event_start = lines.index(on_line)
    event_block: list[Line] = []
    for line in lines[event_start + 1 :]:
        if line.indent <= on_line.indent:
            break
        event_block.append(line)
    if event_block != event_lines or any(line.listed or line.value for line in event_lines):
        raise WorkflowError("workflow events must be empty mapping entries")
    events = {line.key for line in event_lines}

    top_permissions = unique(
        lines, indent=0, key="permissions", label="top-level permissions"
    ).value
    jobs_line = unique(lines, indent=0, key="jobs", label="jobs mapping")
    if jobs_line.value:
        raise WorkflowError("jobs must use a block mapping")
    jobs = direct_children(lines, jobs_line)
    if len(jobs) != 1 or jobs[0].listed or jobs[0].value:
        raise WorkflowError("reference workflow must contain one mapping job")
    job_line = jobs[0]
    job_children = direct_children(lines, job_line)
    allowed_job_keys = {"name", "runs-on", "permissions", "steps"}
    if (
        {line.key for line in job_children} != allowed_job_keys
        or any(line.listed for line in job_children)
        or len(job_children) != len(allowed_job_keys)
    ):
        raise WorkflowError("job keys must be name, runs-on, permissions, steps")
    job_values = {
        line.key: line.value
        for line in job_children
        if line.key in {"name", "runs-on"} and line.value and not line.listed
    }
    if set(job_values) != {"name", "runs-on"}:
        raise WorkflowError("job must have scalar name and runs-on values")

    permissions_line = next(
        (line for line in job_children if line.key == "permissions"), None
    )
    steps_line = next((line for line in job_children if line.key == "steps"), None)
    if permissions_line is None or permissions_line.value:
        job_permissions: dict[str, str] = {}
    else:
        job_permissions = mapping(
            direct_children(lines, permissions_line), "job permissions"
        )
    if steps_line is None or steps_line.value:
        raise WorkflowError("job must have a steps mapping")

    return Workflow(
        events=events,
        top_permissions=top_permissions,
        job_id=job_line.key,
        job_name=job_values["name"],
        runner=job_values["runs-on"],
        job_permissions=job_permissions,
        steps=parse_steps(lines, steps_line),
    )


def split_csv(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def evaluate(workflow: Workflow) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if workflow.events != {"pull_request"}:
        findings.append(("DCR-009", "workflow-trigger-is-not-pull-request-only"))
    if workflow.top_permissions != "{}":
        findings.append(("DCR-009", "workflow-top-permissions-are-not-deny-all"))
    if workflow.job_id != "dependency-review" or workflow.job_name != "Dependency Review":
        findings.append(("DCR-001", "required-check-identity-is-not-stable"))
    if workflow.runner != "ubuntu-24.04":
        findings.append(("DCR-009", "reference-runner-is-not-reviewed-hosted-runner"))
    if workflow.job_permissions != {"contents": "read"}:
        findings.append(("DCR-009", "job-permissions-are-not-contents-read-only"))

    by_action = {step.uses: step for step in workflow.steps}
    review = by_action.get(DEPENDENCY_REVIEW)
    if set(by_action) != {DEPENDENCY_REVIEW} or len(workflow.steps) != 1:
        findings.append(("DCR-009", "workflow-actions-do-not-match-reviewed-identities"))
    if review is None:
        findings.append(("DCR-004", "dependency-review-action-is-missing"))
        return findings

    expected_keys = {
        "vulnerability-check",
        "license-check",
        "fail-on-severity",
        "fail-on-scopes",
        "allow-licenses",
        "warn-only",
        "retry-on-snapshot-warnings",
        "retry-on-snapshot-warnings-timeout",
        "show-openssf-scorecard",
        "comment-summary-in-pr",
    }
    if set(review.inputs) != expected_keys:
        findings.append(("DCR-009", "dependency-review-input-set-is-not-exact"))
    if review.inputs.get("vulnerability-check") != "true":
        findings.append(("DCR-004", "vulnerability-check-is-disabled"))
    if review.inputs.get("license-check") != "true":
        findings.append(("DCR-005", "license-check-is-disabled"))
    if review.inputs.get("fail-on-severity") != "high":
        findings.append(("DCR-004", "vulnerability-threshold-is-not-high"))
    if split_csv(review.inputs.get("fail-on-scopes", "")) != {
        "runtime",
        "development",
        "unknown",
    }:
        findings.append(("DCR-004", "dependency-scopes-are-incomplete"))
    if split_csv(review.inputs.get("allow-licenses", "")) != REFERENCE_LICENSES:
        findings.append(("DCR-005", "reference-license-allowlist-is-not-exact"))
    if review.inputs.get("warn-only") != "false":
        findings.append(("DCR-004", "warn-only-prevents-blocking"))
    if review.inputs.get("retry-on-snapshot-warnings") != "true":
        findings.append(("DCR-009", "snapshot-warning-retry-is-disabled"))
    if review.inputs.get("retry-on-snapshot-warnings-timeout") != "120":
        findings.append(("DCR-009", "snapshot-warning-timeout-is-not-bounded"))
    if review.inputs.get("show-openssf-scorecard") != "false":
        findings.append(("DCR-009", "unowned-scorecard-signal-is-enabled"))
    if review.inputs.get("comment-summary-in-pr") != "never":
        findings.append(("DCR-009", "pull-request-write-path-is-enabled"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the PSB-DEPS-004 GitHub reference workflow."
    )
    parser.add_argument("workflow", type=Path)
    args = parser.parse_args()
    try:
        workflow = parse(args.workflow)
        findings = evaluate(workflow)
    except WorkflowError as error:
        print(f"ERROR DCR-009 dependency review workflow unavailable: {error}")
        print("RESULT ERROR; reference workflow was not evaluated")
        return 2

    for check_id, reason in findings:
        print(f"BLOCK {check_id} reason={reason}")
    if findings:
        print(f"RESULT BLOCKED {len(findings)} workflow finding(s)")
        return 1

    print("PASS DCR-001 stable dependency review check identity configured")
    print("PASS DCR-004 high severity vulnerability policy covers all scopes")
    print("PASS DCR-005 explicit SPDX license allowlist configured")
    print("PASS DCR-009 pinned read-only pull-request blocking policy configured")
    print("RESULT ACCEPTED GitHub dependency review reference workflow passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
