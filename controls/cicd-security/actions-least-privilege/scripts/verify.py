#!/usr/bin/env python3
"""Verify explicit purpose-bound GitHub Actions token permissions."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-github-actions-permissions-policy/v1"
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
JOB_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
KEY_VALUE_RE = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*):"
    r"(?: *(?P<value>.*?))? *$"
)
PERMISSION_SCOPES = {
    "actions",
    "artifact-metadata",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "security-events",
    "statuses",
    "vulnerability-alerts",
}
PURPOSE_CEILINGS = {
    "test": {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "models": "read",
        "packages": "read",
        "pull-requests": "read",
        "statuses": "read",
    },
    "report": {
        "actions": "read",
        "checks": "write",
        "contents": "read",
        "models": "read",
        "packages": "read",
        "pull-requests": "read",
        "security-events": "write",
        "statuses": "write",
    },
    "release": {
        "actions": "read",
        "artifact-metadata": "write",
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
        "packages": "write",
    },
    "deploy": {
        "actions": "read",
        "contents": "read",
        "deployments": "write",
        "id-token": "write",
        "packages": "read",
    },
}
LEVEL = {"none": 0, "read": 1, "write": 2}
JOB_POLICY_FIELDS = {
    "purpose",
    "permissions",
    "required_if",
    "environment",
}


class VerificationError(ValueError):
    """Workflow or policy could not be evaluated safely."""


@dataclass(frozen=True)
class PermissionSet:
    values: dict[str, str] | None
    scalar: str | None
    line: int


@dataclass(frozen=True)
class Job:
    job_id: str
    line: int
    permissions: PermissionSet | None
    condition: str | None
    environment: str | None


@dataclass(frozen=True)
class Workflow:
    path: Path
    top_permissions: PermissionSet | None
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


def parse_permission_set(
    lines: list[str],
    index: int,
    indent: int,
    path: Path,
) -> PermissionSet:
    parsed = key_value(lines[index])
    if parsed is None or parsed[1] != "permissions":
        raise VerificationError(f"{path}:{index + 1}: permissions are malformed")
    value = parsed[2]
    if value:
        if value == "{}":
            return PermissionSet({}, None, index + 1)
        if value in {"read-all", "write-all"}:
            return PermissionSet(None, value, index + 1)
        raise VerificationError(
            f"{path}:{index + 1}: unsupported permissions scalar"
        )

    permissions: dict[str, str] = {}
    for child_index in range(index + 1, len(lines)):
        line = lines[child_index]
        if not line.strip():
            continue
        child = key_value(line)
        child_indent = len(line) - len(line.lstrip(" "))
        if child_indent <= indent:
            break
        if child is None or child[0] != indent + 2:
            raise VerificationError(
                f"{path}:{child_index + 1}: unsupported permissions syntax"
            )
        _, scope, access = child
        if scope not in PERMISSION_SCOPES:
            raise VerificationError(
                f"{path}:{child_index + 1}: unsupported permission scope {scope}"
            )
        allowed = (
            {"none", "write"}
            if scope == "id-token"
            else {"none", "read"}
            if scope in {"models", "vulnerability-alerts"}
            else {"none", "read", "write"}
        )
        if access not in allowed:
            raise VerificationError(
                f"{path}:{child_index + 1}: invalid access for {scope}"
            )
        if scope in permissions:
            raise VerificationError(
                f"{path}:{child_index + 1}: duplicate permission scope {scope}"
            )
        permissions[scope] = access
    return PermissionSet(permissions, None, index + 1)


def nested_environment(
    lines: list[str],
    index: int,
    path: Path,
) -> str:
    names: list[str] = []
    for child_index in range(index + 1, len(lines)):
        line = lines[child_index]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= 4:
            break
        child = key_value(line)
        if child is None or child[0] != 6:
            raise VerificationError(
                f"{path}:{child_index + 1}: unsupported environment syntax"
            )
        if child[1] == "name" and child[2]:
            names.append(child[2])
    if len(names) != 1:
        raise VerificationError(
            f"{path}:{index + 1}: environment.name must be one scalar"
        )
    return names[0]


def parse_workflow(path: Path) -> Workflow:
    lines = read_lines(path)
    jobs_indexes = [
        index
        for index, line in enumerate(lines)
        if key_value(line) == (0, "jobs", "")
    ]
    if len(jobs_indexes) != 1:
        raise VerificationError(f"{path}: workflow must have one jobs mapping")
    jobs_index = jobs_indexes[0]
    jobs_end = len(lines)
    for index in range(jobs_index + 1, len(lines)):
        if lines[index].strip() and not lines[index].startswith(" "):
            jobs_end = index
            break

    top_permissions_indexes = [
        index
        for index, line in enumerate(lines)
        if (parsed := key_value(line)) is not None
        and parsed[0] == 0
        and parsed[1] == "permissions"
    ]
    if len(top_permissions_indexes) > 1:
        raise VerificationError(f"{path}: duplicate top-level permissions")
    top_permissions = (
        parse_permission_set(lines, top_permissions_indexes[0], 0, path)
        if top_permissions_indexes
        else None
    )

    job_starts: list[tuple[int, str]] = []
    for index in range(jobs_index + 1, jobs_end):
        line = lines[index]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if indent != 2:
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
        job_starts.append((index, parsed[1]))
    if not job_starts:
        raise VerificationError(f"{path}: workflow has no jobs")

    jobs: dict[str, Job] = {}
    for position, (start, job_id) in enumerate(job_starts):
        if job_id in jobs:
            raise VerificationError(
                f"{path}:{start + 1}: duplicate job {job_id}"
            )
        end = (
            job_starts[position + 1][0]
            if position + 1 < len(job_starts)
            else jobs_end
        )
        permissions: PermissionSet | None = None
        condition: str | None = None
        environment: str | None = None
        direct_seen: set[str] = set()
        for index in range(start + 1, end):
            line = lines[index]
            if not line.strip():
                continue
            parsed = key_value(line)
            if parsed is None or parsed[0] != 4:
                continue
            _, key, value = parsed
            if key not in {"permissions", "if", "environment"}:
                continue
            if key in direct_seen:
                raise VerificationError(
                    f"{path}:{index + 1}: duplicate job key {key}"
                )
            direct_seen.add(key)
            if key == "permissions":
                permissions = parse_permission_set(lines, index, 4, path)
            elif key == "if":
                if not value or value in {">", "|"}:
                    raise VerificationError(
                        f"{path}:{index + 1}: job if must be one scalar"
                    )
                condition = value
            else:
                environment = (
                    value
                    if value
                    else nested_environment(lines, index, path)
                )
        jobs[job_id] = Job(
            job_id=job_id,
            line=start + 1,
            permissions=permissions,
            condition=condition,
            environment=environment,
        )
    return Workflow(path=path, top_permissions=top_permissions, jobs=jobs)


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


def require_permission_mapping(
    value: Any,
    purpose: str,
    label: str,
) -> dict[str, str]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    permissions: dict[str, str] = {}
    ceiling = PURPOSE_CEILINGS[purpose]
    for raw_scope, raw_access in value.items():
        if (
            not isinstance(raw_scope, str)
            or raw_scope not in PERMISSION_SCOPES
            or not isinstance(raw_access, str)
            or raw_access not in LEVEL
        ):
            raise VerificationError(f"{label} contains an invalid permission")
        if (
            raw_scope not in ceiling
            or LEVEL[raw_access] > LEVEL[ceiling[raw_scope]]
        ):
            raise VerificationError(
                f"{label} exceeds the {purpose} purpose ceiling"
            )
        permissions[raw_scope] = raw_access
    return permissions


def load_policy(
    policy_path: Path,
    root: Path,
) -> tuple[dict[Path, dict[str, dict[str, Any]]], set[Path]]:
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("permissions policy is unavailable or malformed") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "workflow_roots", "workflows"}
        or raw.get("schema_version") != POLICY_SCHEMA
    ):
        raise VerificationError("permissions policy fields are malformed")

    raw_roots = raw.get("workflow_roots")
    if (
        not isinstance(raw_roots, list)
        or not raw_roots
        or len(raw_roots) != len(set(map(str, raw_roots)))
    ):
        raise VerificationError("policy.workflow_roots is malformed")
    discovered: set[Path] = set()
    for index, raw_root in enumerate(raw_roots):
        relative = safe_relative_path(raw_root, f"workflow_roots[{index}]")
        workflow_root = resolve_under(root, relative, "workflow root")
        if not workflow_root.is_dir():
            raise VerificationError("workflow root must be a directory")
        for candidate in sorted(workflow_root.rglob("*")):
            if candidate.is_symlink():
                raise VerificationError("workflow roots must not contain symlinks")
            if (
                candidate.is_file()
                and candidate.suffix.lower() in WORKFLOW_SUFFIXES
            ):
                discovered.add(candidate.resolve())
    if not discovered:
        raise VerificationError("workflow roots contain no workflow files")

    raw_workflows = raw.get("workflows")
    if not isinstance(raw_workflows, list) or not raw_workflows:
        raise VerificationError("policy.workflows must be a non-empty array")
    policies: dict[Path, dict[str, dict[str, Any]]] = {}
    for workflow_index, raw_workflow in enumerate(raw_workflows):
        label = f"workflows[{workflow_index}]"
        if (
            not isinstance(raw_workflow, dict)
            or set(raw_workflow) != {"path", "jobs"}
        ):
            raise VerificationError(f"{label} fields are malformed")
        relative = safe_relative_path(raw_workflow.get("path"), f"{label}.path")
        workflow_path = resolve_under(root, relative, f"{label}.path")
        if (
            workflow_path.suffix.lower() not in WORKFLOW_SUFFIXES
            or not workflow_path.is_file()
            or workflow_path in policies
        ):
            raise VerificationError(f"{label}.path is invalid or duplicated")
        raw_jobs = raw_workflow.get("jobs")
        if not isinstance(raw_jobs, dict) or not raw_jobs:
            raise VerificationError(f"{label}.jobs must be a non-empty object")
        job_policies: dict[str, dict[str, Any]] = {}
        for job_id, raw_job in raw_jobs.items():
            job_label = f"{label}.jobs.{job_id}"
            if (
                not isinstance(job_id, str)
                or JOB_ID_RE.fullmatch(job_id) is None
                or not isinstance(raw_job, dict)
                or not {"purpose", "permissions"}.issubset(raw_job)
                or not set(raw_job).issubset(JOB_POLICY_FIELDS)
            ):
                raise VerificationError(f"{job_label} fields are malformed")
            purpose = raw_job.get("purpose")
            if purpose not in PURPOSE_CEILINGS:
                raise VerificationError(f"{job_label}.purpose is unsupported")
            permissions = require_permission_mapping(
                raw_job.get("permissions"),
                purpose,
                f"{job_label}.permissions",
            )
            required_if = raw_job.get("required_if")
            environment = raw_job.get("environment")
            has_write = any(access == "write" for access in permissions.values())
            if has_write and (
                not isinstance(required_if, str) or not required_if
            ):
                raise VerificationError(
                    f"{job_label} write permissions require required_if"
                )
            if required_if is not None and (
                not isinstance(required_if, str) or not required_if
            ):
                raise VerificationError(f"{job_label}.required_if is malformed")
            if purpose in {"release", "deploy"} and (
                not isinstance(environment, str) or not environment
            ):
                raise VerificationError(
                    f"{job_label} requires a protected environment"
                )
            if environment is not None and (
                not isinstance(environment, str) or not environment
            ):
                raise VerificationError(f"{job_label}.environment is malformed")
            job_policies[job_id] = {
                "purpose": purpose,
                "permissions": permissions,
                "required_if": required_if,
                "environment": environment,
            }
        policies[workflow_path] = job_policies
    if set(policies) != discovered:
        raise VerificationError(
            "permissions policy does not cover exactly the discovered workflows"
        )
    return policies, discovered


def evaluate(
    workflow: Workflow,
    job_policies: dict[str, dict[str, Any]],
) -> list[tuple[int, str, str]]:
    violations: list[tuple[int, str, str]] = []
    top = workflow.top_permissions
    if top is None:
        violations.append(
            (1, "-", "top-level permissions must be explicit deny-all ({})")
        )
    elif top.values != {} or top.scalar is not None:
        violations.append(
            (
                top.line,
                "-",
                "top-level permissions must be explicit deny-all ({})",
            )
        )
    if set(workflow.jobs) != set(job_policies):
        raise VerificationError(
            f"{workflow.path}: policy job set does not match workflow jobs"
        )

    for job_id, job in workflow.jobs.items():
        policy = job_policies[job_id]
        permissions = job.permissions
        if permissions is None:
            violations.append(
                (
                    job.line,
                    job_id,
                    "job permissions must be explicit",
                )
            )
            continue
        if permissions.scalar is not None:
            violations.append(
                (
                    permissions.line,
                    job_id,
                    f"{permissions.scalar} is prohibited",
                )
            )
            continue
        actual = permissions.values or {}
        expected = policy["permissions"]
        if actual != expected:
            violations.append(
                (
                    permissions.line,
                    job_id,
                    "resolved permissions do not match reviewed job policy",
                )
            )
        ceiling = PURPOSE_CEILINGS[policy["purpose"]]
        for scope, access in actual.items():
            if scope not in ceiling or LEVEL[access] > LEVEL[ceiling[scope]]:
                violations.append(
                    (
                        permissions.line,
                        job_id,
                        f"{scope}:{access} exceeds {policy['purpose']} purpose",
                    )
                )
        required_if = policy["required_if"]
        if required_if is not None and job.condition != required_if:
            violations.append(
                (
                    job.line,
                    job_id,
                    "write-capable job is not restricted by the reviewed ref condition",
                )
            )
        environment = policy["environment"]
        if environment is not None and job.environment != environment:
            violations.append(
                (
                    job.line,
                    job_id,
                    "privileged job does not use the reviewed protected environment",
                )
            )
        if actual.get("id-token") == "write" and policy["purpose"] not in {
            "release",
            "deploy",
        }:
            violations.append(
                (
                    permissions.line,
                    job_id,
                    "id-token:write is not allowed for this job purpose",
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
                    print(
                        f"FAIL {display_path}:{line} job={job_id} - {message}"
                    )
                violation_count += len(violations)
            else:
                print(
                    f"PASS {display_path} jobs={len(workflow.jobs)} "
                    "explicit least-privilege permissions"
                )
    except (OSError, VerificationError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    if violation_count:
        print(
            f"REJECTED {violation_count} permission violation(s) "
            f"across {job_count} job(s)"
        )
        return 1
    print(
        f"ACCEPTED {len(paths)} workflow(s) and {job_count} job(s) "
        "with reviewed least-privilege permissions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
