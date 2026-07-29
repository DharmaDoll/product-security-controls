#!/usr/bin/env python3
"""Verify that untrusted GitHub pull-request jobs cannot cross into privileged CI."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-github-actions-untrusted-boundary-policy/v1"
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
UNTRUSTED_EVENTS = {"pull_request"}
PROHIBITED_EVENTS = {"pull_request_target", "workflow_run"}
JOB_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
KEY_VALUE_RE = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*):"
    r"(?: *(?P<value>.*?))? *$"
)
SECRET_REFERENCE_RE = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
UNTRUSTED_REVISION_RE = re.compile(
    r"github\.event\.pull_request\.(?:head|merge_commit_sha)",
    re.IGNORECASE,
)
WRITE_ACCESS_RE = re.compile(r"^write$", re.IGNORECASE)


class VerificationError(ValueError):
    """Workflow or policy could not be evaluated safely."""


@dataclass(frozen=True)
class Checkout:
    line: int
    persist_credentials: str | None
    ref: str | None


@dataclass(frozen=True)
class Job:
    job_id: str
    line: int
    condition: str | None
    runner: str | None
    environment: str | None
    needs: tuple[str, ...]
    reusable: str | None
    permissions: dict[str, str] | None
    permission_scalar: str | None
    checkouts: tuple[Checkout, ...]
    has_secret_reference: bool
    has_cache: bool
    raw_text: str


@dataclass(frozen=True)
class Workflow:
    path: Path
    events: tuple[str, ...]
    jobs: dict[str, Job]


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
    if quote is not None:
        raise VerificationError("unterminated quoted YAML scalar")
    return line


def scalar(value: str) -> str:
    result = value.strip()
    if (
        len(result) >= 2
        and result[0] == result[-1]
        and result[0] in {"'", '"'}
    ):
        return result[1:-1]
    return result


def read_lines(path: Path) -> list[str]:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"workflow is unavailable: {path}")
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise VerificationError(f"cannot read workflow: {path}") from error
    if any("\t" in line for line in raw_lines):
        raise VerificationError(f"{path}: tabs are unsupported in workflow YAML")
    lines: list[str] = []
    for line_number, line in enumerate(raw_lines, start=1):
        try:
            lines.append(strip_yaml_comment(line).rstrip())
        except VerificationError as error:
            raise VerificationError(f"{path}:{line_number}: {error}") from error
    return lines


def key_value(line: str) -> tuple[int, str, str] | None:
    match = KEY_VALUE_RE.fullmatch(line)
    if match is None:
        return None
    return (
        len(match.group("indent")),
        match.group("key"),
        scalar(match.group("value") or ""),
    )


def find_top_block(lines: list[str], key: str, path: Path) -> tuple[int, int]:
    starts = [
        index
        for index, line in enumerate(lines)
        if key_value(line) == (0, key, "")
    ]
    if len(starts) != 1:
        raise VerificationError(f"{path}: workflow must have one {key} mapping")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].strip() and not lines[index].startswith(" "):
            end = index
            break
    return start, end


def parse_events(lines: list[str], path: Path) -> tuple[str, ...]:
    start, end = find_top_block(lines, "on", path)
    events: list[str] = []
    for index in range(start + 1, end):
        line = lines[index]
        if not line.strip():
            continue
        parsed = key_value(line)
        if parsed is not None and parsed[0] == 2:
            if parsed[1] in events:
                raise VerificationError(f"{path}:{index + 1}: duplicate event")
            events.append(parsed[1])
    if not events:
        raise VerificationError(f"{path}: on mapping has no supported events")
    return tuple(events)


def parse_permissions(
    lines: list[str],
    index: int,
    end: int,
    path: Path,
) -> tuple[dict[str, str] | None, str | None]:
    parsed = key_value(lines[index])
    if parsed is None or parsed[1] != "permissions":
        raise VerificationError(f"{path}:{index + 1}: malformed permissions")
    value = parsed[2]
    if value:
        if value == "{}":
            return {}, None
        if value in {"read-all", "write-all"}:
            return None, value
        raise VerificationError(
            f"{path}:{index + 1}: unsupported permissions scalar"
        )
    permissions: dict[str, str] = {}
    for child_index in range(index + 1, end):
        line = lines[child_index]
        if not line.strip():
            continue
        child = key_value(line)
        indent = len(line) - len(line.lstrip(" "))
        if indent <= 4:
            break
        if child is None or child[0] != 6 or not child[2]:
            raise VerificationError(
                f"{path}:{child_index + 1}: unsupported permissions syntax"
            )
        if child[1] in permissions:
            raise VerificationError(
                f"{path}:{child_index + 1}: duplicate permission scope"
            )
        if child[2] not in {"none", "read", "write"}:
            raise VerificationError(
                f"{path}:{child_index + 1}: invalid permission access"
            )
        permissions[child[1]] = child[2]
    return permissions, None


def parse_checkouts(
    lines: list[str],
    start: int,
    end: int,
    path: Path,
) -> tuple[Checkout, ...]:
    checkouts: list[Checkout] = []
    for index in range(start, end):
        parsed = key_value(lines[index])
        if (
            parsed is None
            or parsed[0] != 8
            or parsed[1] != "uses"
            or not parsed[2].startswith("actions/checkout@")
        ):
            continue
        step_end = end
        for candidate in range(index + 1, end):
            text = lines[candidate]
            if text.strip() and len(text) - len(text.lstrip(" ")) == 6:
                step_end = candidate
                break
        persist_values: list[str] = []
        refs: list[str] = []
        for child_index in range(index + 1, step_end):
            child = key_value(lines[child_index])
            if child is None or child[0] != 10:
                continue
            if child[1] == "persist-credentials":
                persist_values.append(child[2])
            elif child[1] == "ref":
                refs.append(child[2])
        if len(persist_values) > 1 or len(refs) > 1:
            raise VerificationError(
                f"{path}:{index + 1}: duplicate checkout security input"
            )
        checkouts.append(
            Checkout(
                line=index + 1,
                persist_credentials=persist_values[0] if persist_values else None,
                ref=refs[0] if refs else None,
            )
        )
    return tuple(checkouts)


def parse_job(
    lines: list[str],
    start: int,
    end: int,
    job_id: str,
    path: Path,
) -> Job:
    direct: dict[str, tuple[int, str]] = {}
    for index in range(start + 1, end):
        parsed = key_value(lines[index])
        if parsed is None or parsed[0] != 4:
            continue
        key = parsed[1]
        if key in {
            "if",
            "runs-on",
            "environment",
            "needs",
            "uses",
            "secrets",
            "permissions",
        }:
            if key in direct:
                raise VerificationError(f"{path}:{index + 1}: duplicate job key {key}")
            direct[key] = (index, parsed[2])

    permissions: dict[str, str] | None = None
    permission_scalar: str | None = None
    if "permissions" in direct:
        permissions, permission_scalar = parse_permissions(
            lines, direct["permissions"][0], end, path
        )

    needs: tuple[str, ...] = ()
    if "needs" in direct:
        raw_needs = direct["needs"][1]
        if not raw_needs or raw_needs.startswith("["):
            raise VerificationError(
                f"{path}:{direct['needs'][0] + 1}: needs must be one job id"
            )
        needs = (raw_needs,)

    raw_lines = lines[start:end]
    has_cache = any(
        (
            parsed := key_value(line)
        ) is not None
        and (
            (parsed[1] == "uses" and parsed[2].startswith("actions/cache@"))
            or (parsed[1] == "cache" and bool(parsed[2]))
        )
        for line in raw_lines
    )
    return Job(
        job_id=job_id,
        line=start + 1,
        condition=direct.get("if", (0, None))[1],
        runner=direct.get("runs-on", (0, None))[1],
        environment=direct.get("environment", (0, None))[1],
        needs=needs,
        reusable=direct.get("uses", (0, None))[1],
        permissions=permissions,
        permission_scalar=permission_scalar,
        checkouts=parse_checkouts(lines, start, end, path),
        has_secret_reference=(
            "secrets" in direct
            or bool(SECRET_REFERENCE_RE.search("\n".join(raw_lines)))
        ),
        has_cache=has_cache,
        raw_text="\n".join(raw_lines),
    )


def parse_workflow(path: Path) -> Workflow:
    lines = read_lines(path)
    events = parse_events(lines, path)
    jobs_start, jobs_end = find_top_block(lines, "jobs", path)
    starts: list[tuple[int, str]] = []
    for index in range(jobs_start + 1, jobs_end):
        line = lines[index]
        if not line.strip():
            continue
        if len(line) - len(line.lstrip(" ")) != 2:
            continue
        parsed = key_value(line)
        if (
            parsed is None
            or parsed[2]
            or JOB_ID_RE.fullmatch(parsed[1]) is None
        ):
            raise VerificationError(
                f"{path}:{index + 1}: unsupported job declaration"
            )
        starts.append((index, parsed[1]))
    if not starts:
        raise VerificationError(f"{path}: workflow has no jobs")
    jobs: dict[str, Job] = {}
    for position, (start, job_id) in enumerate(starts):
        if job_id in jobs:
            raise VerificationError(f"{path}:{start + 1}: duplicate job {job_id}")
        end = starts[position + 1][0] if position + 1 < len(starts) else jobs_end
        jobs[job_id] = parse_job(lines, start, end, job_id, path)
    return Workflow(path=path, events=events, jobs=jobs)


def safe_relative_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{label} must be non-empty text")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise VerificationError(f"{label} must be a safe relative path")
    return path


def resolve_under(root: Path, relative: Path, label: str) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise VerificationError(f"{label} must not use symlinks")
    try:
        resolved = (root / relative).resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise VerificationError(f"{label} is unavailable") from error
    return resolved


def load_policy(
    policy_path: Path,
    root: Path,
) -> tuple[dict[Path, dict[str, Any]], set[Path]]:
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("trust policy is unavailable or malformed") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "workflow_roots", "workflows"}
        or raw.get("schema_version") != POLICY_SCHEMA
    ):
        raise VerificationError("trust policy fields are malformed")

    raw_roots = raw.get("workflow_roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        raise VerificationError("policy.workflow_roots must be a non-empty array")
    discovered: set[Path] = set()
    for index, raw_root in enumerate(raw_roots):
        relative = safe_relative_path(raw_root, f"workflow_roots[{index}]")
        workflow_root = resolve_under(root, relative, "workflow root")
        if not workflow_root.is_dir():
            raise VerificationError("workflow root must be a directory")
        for candidate in sorted(workflow_root.rglob("*")):
            if candidate.is_symlink():
                raise VerificationError("workflow roots must not contain symlinks")
            if candidate.is_file() and candidate.suffix.lower() in WORKFLOW_SUFFIXES:
                discovered.add(candidate.resolve())
    if not discovered:
        raise VerificationError("workflow roots contain no workflow files")

    raw_workflows = raw.get("workflows")
    if not isinstance(raw_workflows, list) or not raw_workflows:
        raise VerificationError("policy.workflows must be a non-empty array")
    policies: dict[Path, dict[str, Any]] = {}
    for workflow_index, raw_workflow in enumerate(raw_workflows):
        label = f"workflows[{workflow_index}]"
        if (
            not isinstance(raw_workflow, dict)
            or set(raw_workflow) != {"path", "events", "jobs"}
        ):
            raise VerificationError(f"{label} fields are malformed")
        relative = safe_relative_path(raw_workflow.get("path"), f"{label}.path")
        workflow_path = resolve_under(root, relative, f"{label}.path")
        if workflow_path in policies or workflow_path.suffix.lower() not in WORKFLOW_SUFFIXES:
            raise VerificationError(f"{label}.path is invalid or duplicated")
        events = raw_workflow.get("events")
        if (
            not isinstance(events, list)
            or not events
            or not all(isinstance(event, str) and event for event in events)
            or len(events) != len(set(events))
        ):
            raise VerificationError(f"{label}.events is malformed")
        raw_jobs = raw_workflow.get("jobs")
        if not isinstance(raw_jobs, dict) or not raw_jobs:
            raise VerificationError(f"{label}.jobs must be a non-empty object")
        jobs: dict[str, dict[str, Any]] = {}
        for job_id, raw_job in raw_jobs.items():
            job_label = f"{label}.jobs.{job_id}"
            if (
                not isinstance(job_id, str)
                or JOB_ID_RE.fullmatch(job_id) is None
                or not isinstance(raw_job, dict)
                or not set(raw_job).issubset({"trust", "runner", "required_if"})
                or set(raw_job) < {"trust", "runner"}
            ):
                raise VerificationError(f"{job_label} fields are malformed")
            trust = raw_job.get("trust")
            runner = raw_job.get("runner")
            required_if = raw_job.get("required_if")
            if trust not in {"untrusted", "trusted"}:
                raise VerificationError(f"{job_label}.trust is unsupported")
            if not isinstance(runner, str) or not runner:
                raise VerificationError(f"{job_label}.runner is malformed")
            if required_if is not None and (
                not isinstance(required_if, str) or not required_if
            ):
                raise VerificationError(f"{job_label}.required_if is malformed")
            jobs[job_id] = {
                "trust": trust,
                "runner": runner,
                "required_if": required_if,
            }
        policies[workflow_path] = {"events": tuple(events), "jobs": jobs}
    if set(policies) != discovered:
        raise VerificationError(
            "trust policy does not cover exactly the discovered workflows"
        )
    return policies, discovered


def evaluate(
    workflow: Workflow,
    policy: dict[str, Any],
) -> list[tuple[int, str, str]]:
    if workflow.events != policy["events"]:
        raise VerificationError(
            f"{workflow.path}: policy events do not match workflow events"
        )
    if set(workflow.jobs) != set(policy["jobs"]):
        raise VerificationError(
            f"{workflow.path}: policy job set does not match workflow jobs"
        )
    violations: list[tuple[int, str, str]] = []
    for event in workflow.events:
        if event in PROHIBITED_EVENTS:
            violations.append(
                (1, "-", f"{event} cannot establish a privileged trust boundary")
            )

    has_untrusted_event = bool(
        set(workflow.events) & (UNTRUSTED_EVENTS | PROHIBITED_EVENTS)
    )
    untrusted_jobs = {
        job_id
        for job_id, job_policy in policy["jobs"].items()
        if job_policy["trust"] == "untrusted"
    }
    for job_id, job in workflow.jobs.items():
        job_policy = policy["jobs"][job_id]
        if job.runner != job_policy["runner"]:
            violations.append(
                (job.line, job_id, "runner does not match the reviewed hosted runner")
            )
        if (
            not job.runner
            or "self-hosted" in job.runner
            or "${{" in job.runner
            or job.runner.startswith("[")
        ):
            violations.append(
                (job.line, job_id, "dynamic or self-hosted runner is prohibited")
            )

        if job_policy["trust"] == "untrusted":
            if job.permissions is None:
                violations.append(
                    (job.line, job_id, "untrusted job permissions must be explicit")
                )
            elif job.permission_scalar is not None:
                violations.append(
                    (job.line, job_id, f"{job.permission_scalar} is prohibited")
                )
            elif any(WRITE_ACCESS_RE.fullmatch(value) for value in job.permissions.values()):
                violations.append(
                    (job.line, job_id, "untrusted job cannot receive write permissions")
                )
            if job.has_secret_reference:
                violations.append(
                    (job.line, job_id, "untrusted job cannot reference secrets")
                )
            if job.environment is not None:
                violations.append(
                    (job.line, job_id, "untrusted job cannot use an environment")
                )
            if job.reusable is not None:
                violations.append(
                    (job.line, job_id, "untrusted job cannot call a reusable workflow")
                )
            if job.has_cache:
                violations.append(
                    (job.line, job_id, "untrusted job cannot restore or save shared caches")
                )
            for checkout in job.checkouts:
                if checkout.persist_credentials != "false":
                    violations.append(
                        (
                            checkout.line,
                            job_id,
                            "untrusted checkout must set persist-credentials false",
                        )
                    )
                if checkout.ref is not None:
                    violations.append(
                        (
                            checkout.line,
                            job_id,
                            "untrusted checkout must use the event merge revision",
                        )
                    )
        else:
            required_if = job_policy["required_if"]
            if has_untrusted_event and (
                required_if is None or job.condition != required_if
            ):
                violations.append(
                    (
                        job.line,
                        job_id,
                        "trusted job is not restricted by the reviewed trusted-run condition",
                    )
                )
            if any(dependency in untrusted_jobs for dependency in job.needs):
                violations.append(
                    (
                        job.line,
                        job_id,
                        "trusted job cannot elevate an untrusted job in the same run",
                    )
                )
            if UNTRUSTED_REVISION_RE.search(job.raw_text):
                violations.append(
                    (
                        job.line,
                        job_id,
                        "trusted job cannot execute or checkout a pull-request revision",
                    )
                )
    return sorted(violations)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise VerificationError("root must be a directory")
        policies, paths = load_policy(args.policy, root)
        violation_count = 0
        job_count = 0
        for path in sorted(paths):
            workflow = parse_workflow(path)
            violations = evaluate(workflow, policies[path])
            job_count += len(workflow.jobs)
            display_path = path.relative_to(root)
            if violations:
                for line, job_id, message in violations:
                    print(f"FAIL {display_path}:{line} job={job_id} - {message}")
                violation_count += len(violations)
            else:
                print(
                    f"PASS {display_path} jobs={len(workflow.jobs)} "
                    "fork-safe trust boundaries"
                )
    except (OSError, VerificationError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    if violation_count:
        print(
            f"REJECTED {violation_count} trust-boundary violation(s) "
            f"across {job_count} job(s)"
        )
        return 1
    print(
        f"ACCEPTED {len(paths)} workflow(s) and {job_count} job(s) "
        "with fork-safe trust boundaries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
