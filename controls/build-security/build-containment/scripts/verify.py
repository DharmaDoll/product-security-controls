#!/usr/bin/env python3
"""Verify build/deploy separation, least privilege, sandbox, and egress."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class InputError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load build plan {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError("build plan must be a JSON object")
    return value


def object_field(value: dict[str, Any], field: str, label: str) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise InputError(f"{label}.{field} must be an object")
    return result


def list_field(value: dict[str, Any], field: str, label: str) -> list[Any]:
    result = value.get(field)
    if not isinstance(result, list):
        raise InputError(f"{label}.{field} must be a list")
    return result


def is_safe_origin(value: Any) -> bool:
    if not isinstance(value, str) or value == "*":
        return False
    parsed = urlparse(value)
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.path in {"", "/"}
    )


def write_permissions(permissions: dict[str, Any]) -> list[str]:
    return sorted(
        key
        for key, value in permissions.items()
        if value == "write" and key != "id-token"
    )


def verify_common(job: dict[str, Any], label: str) -> list[str]:
    findings: list[str] = []
    network = object_field(job, "network", label)
    if network.get("default") != "deny":
        findings.append(f"{label} network default must be deny")
    allow = list_field(network, "allow", f"{label}.network")
    for endpoint in allow:
        if not is_safe_origin(endpoint):
            findings.append(f"{label} has unsafe egress endpoint: {endpoint}")

    sandbox = object_field(job, "sandbox", label)
    for field in ("ephemeral", "read_only_root"):
        if sandbox.get(field) is not True:
            findings.append(f"{label} sandbox.{field} must be true")
    for field in ("run_as_root", "docker_socket"):
        if sandbox.get(field) is not False:
            findings.append(f"{label} sandbox.{field} must be false")

    telemetry = object_field(job, "telemetry", label)
    for field in ("process", "network"):
        if telemetry.get(field) is not True:
            findings.append(f"{label} telemetry.{field} must be true")
    return findings


def verify(path: Path) -> list[str]:
    plan = load_json(path)
    findings: list[str] = []
    defaults = object_field(plan, "default_permissions", "plan")
    default_writes = write_permissions(defaults)
    if default_writes or defaults.get("id-token") == "write":
        findings.append("default permissions must not grant write or id-token")

    jobs = list_field(plan, "jobs", "plan")
    if not jobs:
        raise InputError("plan.jobs must not be empty")
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw_job in enumerate(jobs):
        if not isinstance(raw_job, dict):
            raise InputError(f"plan.jobs[{index}] must be an object")
        job_id = raw_job.get("id")
        if not isinstance(job_id, str) or not job_id or job_id in by_id:
            raise InputError(f"plan.jobs[{index}].id must be unique non-empty text")
        by_id[job_id] = raw_job
        findings.extend(verify_common(raw_job, f"job {job_id}"))

    build_jobs = [job for job in jobs if job.get("executes_source") is True]
    deploy_jobs = [job for job in jobs if job.get("environment") == "production"]
    if not build_jobs:
        findings.append("plan must contain a source-executing build job")
    if not deploy_jobs:
        findings.append("plan must contain a separate production deploy job")

    for job in build_jobs:
        label = f"job {job['id']}"
        permissions = object_field(job, "permissions", label)
        writes = write_permissions(permissions)
        if writes:
            findings.append(f"{label} has write permissions: {', '.join(writes)}")
        if permissions.get("id-token") == "write":
            findings.append(f"{label} must not have id-token write")
        credentials = list_field(job, "credentials", label)
        if credentials:
            findings.append(f"{label} must not receive credentials")
        if job.get("environment") is not None:
            findings.append(f"{label} must not target an environment")
        if job.get("trigger_trust") != "untrusted":
            findings.append(f"{label} trigger trust must be explicitly untrusted")

    for job in deploy_jobs:
        label = f"job {job['id']}"
        if job.get("executes_source") is not False:
            findings.append(f"{label} must not execute source code")
        if job.get("trigger_trust") != "protected-release":
            findings.append(f"{label} must use protected-release trigger")
        needs = list_field(job, "needs", label)
        inputs = list_field(job, "inputs", label)
        if not any(item in needs for item in [build.get("id") for build in build_jobs]):
            findings.append(f"{label} must depend on a build job")
        if "build:artifact" not in inputs:
            findings.append(f"{label} must consume only the verified build artifact")
        credentials = list_field(job, "credentials", label)
        if len(credentials) != 1 or not isinstance(credentials[0], dict):
            findings.append(f"{label} must use exactly one short-lived OIDC credential")
        else:
            credential = credentials[0]
            if credential.get("type") != "oidc":
                findings.append(f"{label} credential must be OIDC")
            ttl = credential.get("ttl_minutes")
            if not isinstance(ttl, int) or not 0 < ttl <= 15:
                findings.append(f"{label} OIDC TTL must be at most 15 minutes")
            audience = credential.get("audience")
            if not isinstance(audience, str) or not audience or audience == "*":
                findings.append(f"{label} OIDC audience must be exact")

    if any(job in deploy_jobs for job in build_jobs):
        findings.append("source-executing build and production deploy must be separate jobs")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    try:
        findings = verify(args.plan)
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print("PASS isolated least-privilege build and protected deploy verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
