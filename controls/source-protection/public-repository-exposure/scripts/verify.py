#!/usr/bin/env python3
"""Verify a public-repository exposure policy and sanitized evidence snapshot."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any


REQUIRED_SURFACES = {
    "code",
    "git-history",
    "issues",
    "pull-requests",
    "discussions",
    "wiki",
    "actions-logs-artifacts",
    "releases",
    "pages",
}
REQUIRED_CONTROLS = {
    "secret-scanning",
    "push-protection",
    "delegated-bypass-review",
    "visibility-review",
    "all-history-scan",
}
REQUIRED_REMEDIATION = [
    "revoke-or-rotate-first",
    "remove-current-content",
    "review-history-rewrite",
    "review-forks-clones-caches",
    "contact-github-support-if-needed",
    "rescan-all-surfaces",
]
REQUIRED_QUERY_SURFACES = {"code", "issues", "pull-requests"}
EVIDENCE_CODE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FORBIDDEN_EVIDENCE_KEYS = {"secret", "token", "credential", "matched_value", "content"}


class InputError(ValueError):
    """Raised when input cannot be reliably parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{path} must contain an object")
    return value


def parse_date(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise InputError(f"{label} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise InputError(f"{label} must be an ISO date") from error


def duplicate_values(values: list[str]) -> set[str]:
    return {value for value in values if values.count(value) > 1}


def inspect_policy(policy: dict[str, Any]) -> tuple[list[str], set[str]]:
    findings: list[str] = []
    if policy.get("schema_version") != "1.0":
        findings.append("policy schema_version must be 1.0")
    if policy.get("repository") != "{repository}":
        findings.append("policy repository must use the {repository} placeholder")

    visibility = policy.get("visibility")
    if not isinstance(visibility, dict):
        raise InputError("policy visibility must be an object")
    if visibility.get("required") != "public":
        findings.append("policy must explicitly review public visibility")
    approval = visibility.get("approval")
    if not isinstance(approval, dict):
        raise InputError("policy visibility approval must be an object")
    if not isinstance(approval.get("owner"), str) or not approval["owner"].strip():
        findings.append("public visibility approval must have an owner")
    reviewed_on = parse_date(approval.get("reviewed_on"), "approval.reviewed_on")
    expires_on = parse_date(approval.get("expires_on"), "approval.expires_on")
    if expires_on <= reviewed_on:
        findings.append("public visibility approval must expire after its review date")

    surfaces = policy.get("required_surfaces")
    if not isinstance(surfaces, list) or not all(
        isinstance(surface, str) for surface in surfaces
    ):
        raise InputError("policy required_surfaces must be a string list")
    if set(surfaces) != REQUIRED_SURFACES or len(surfaces) != len(REQUIRED_SURFACES):
        findings.append("policy must cover every required public GitHub surface once")

    controls = policy.get("required_repository_controls")
    if not isinstance(controls, list) or not all(
        isinstance(control, str) for control in controls
    ):
        raise InputError("policy required_repository_controls must be a string list")
    if set(controls) != REQUIRED_CONTROLS or len(controls) != len(REQUIRED_CONTROLS):
        findings.append("policy must require every repository-side control once")

    remediation = policy.get("remediation_sequence")
    if remediation != REQUIRED_REMEDIATION:
        findings.append("policy remediation order must revoke or rotate before cleanup")

    queries = policy.get("queries")
    if not isinstance(queries, list) or not queries:
        raise InputError("policy queries must be a non-empty list")
    query_ids: list[str] = []
    query_surfaces: set[str] = set()
    for index, query in enumerate(queries):
        if not isinstance(query, dict):
            raise InputError(f"policy queries[{index}] must be an object")
        query_id = query.get("id")
        surface = query.get("surface")
        expression = query.get("query")
        engine = query.get("engine")
        if not isinstance(query_id, str) or not query_id.startswith("DORK-"):
            findings.append(f"policy query {index} must have a stable DORK- id")
        else:
            query_ids.append(query_id)
        if surface not in REQUIRED_SURFACES:
            findings.append(f"policy query {index} has an unknown surface")
        else:
            query_surfaces.add(surface)
        if engine not in {
            "github-code-search",
            "github-issues-search",
        }:
            findings.append(f"policy query {index} has an unapproved engine")
        if not isinstance(expression, str) or "repo:{repository}" not in expression:
            findings.append(f"policy query {index} is not repository scoped")
    for duplicate in sorted(duplicate_values(query_ids)):
        findings.append(f"policy query id is duplicated: {duplicate}")
    if not REQUIRED_QUERY_SURFACES.issubset(query_surfaces):
        findings.append("policy queries must cover code issues and pull requests")
    return findings, set(query_ids)


def find_forbidden_keys(value: object, path: str = "evidence") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_EVIDENCE_KEYS:
                findings.append(f"{path}.{key} must not contain raw matched data")
            findings.extend(find_forbidden_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_forbidden_keys(child, f"{path}[{index}]"))
    return findings


def inspect_evidence(evidence: dict[str, Any], query_ids: set[str]) -> list[str]:
    findings = find_forbidden_keys(evidence)
    if evidence.get("schema_version") != "1.0":
        findings.append("evidence schema_version must be 1.0")
    repository = evidence.get("repository")
    if (
        not isinstance(repository, str)
        or repository.count("/") != 1
        or "{" in repository
        or "*" in repository
    ):
        findings.append("evidence repository must identify one owner/repository")
    captured_at = parse_date(evidence.get("captured_at"), "evidence.captured_at")
    if evidence.get("visibility") != "public":
        findings.append("evidence must confirm the reviewed public visibility")

    visibility_review = evidence.get("visibility_review")
    if not isinstance(visibility_review, dict):
        raise InputError("evidence visibility_review must be an object")
    if visibility_review.get("status") != "approved":
        findings.append("evidence must contain an approved visibility review")
    if not isinstance(visibility_review.get("owner"), str) or not visibility_review[
        "owner"
    ].strip():
        findings.append("evidence visibility review must have an owner")
    if parse_date(
        visibility_review.get("expires_on"), "evidence.visibility_review.expires_on"
    ) <= captured_at:
        findings.append("evidence visibility approval must be current at capture time")

    controls = evidence.get("repository_controls")
    if not isinstance(controls, dict):
        raise InputError("evidence repository_controls must be an object")
    for control in sorted(REQUIRED_CONTROLS):
        if controls.get(control) != "enabled":
            findings.append(f"repository control is not enabled: {control}")
    if set(controls) != REQUIRED_CONTROLS:
        findings.append("evidence repository_controls has an unexpected control set")

    surface_results = evidence.get("surface_results")
    if not isinstance(surface_results, list):
        raise InputError("evidence surface_results must be a list")
    seen_surfaces: list[str] = []
    for index, result in enumerate(surface_results):
        if not isinstance(result, dict):
            raise InputError(f"evidence surface_results[{index}] must be an object")
        surface = result.get("surface")
        if isinstance(surface, str):
            seen_surfaces.append(surface)
        if result.get("status") != "completed":
            findings.append(f"surface scan did not complete: {surface}")
        count = result.get("findings")
        if not isinstance(count, int) or isinstance(count, bool) or count != 0:
            findings.append(f"surface has unresolved findings: {surface}")
        code = result.get("evidence_code")
        if not isinstance(code, str) or EVIDENCE_CODE_RE.fullmatch(code) is None:
            findings.append(f"surface has invalid sanitized evidence code: {surface}")
    if set(seen_surfaces) != REQUIRED_SURFACES or len(seen_surfaces) != len(
        REQUIRED_SURFACES
    ):
        findings.append("evidence must contain one result for every required surface")

    query_results = evidence.get("query_results")
    if not isinstance(query_results, list):
        raise InputError("evidence query_results must be a list")
    seen_queries: list[str] = []
    for index, result in enumerate(query_results):
        if not isinstance(result, dict):
            raise InputError(f"evidence query_results[{index}] must be an object")
        query_id = result.get("id")
        if isinstance(query_id, str):
            seen_queries.append(query_id)
        if result.get("status") != "completed":
            findings.append(f"dork query did not complete: {query_id}")
        count = result.get("findings")
        if not isinstance(count, int) or isinstance(count, bool) or count != 0:
            findings.append(f"dork query has unresolved findings: {query_id}")
    if set(seen_queries) != query_ids or len(seen_queries) != len(query_ids):
        findings.append("evidence must contain one result for every policy query")

    history = evidence.get("history_scan")
    if not isinstance(history, dict):
        raise InputError("evidence history_scan must be an object")
    if (
        history.get("status") != "completed"
        or history.get("scanner_exit_code") != 0
        or history.get("findings") != 0
    ):
        findings.append("all-history scan must complete cleanly")
    if evidence.get("open_exposures") != 0:
        findings.append("evidence contains unresolved public exposures")
    errors = evidence.get("tool_errors")
    if not isinstance(errors, list):
        raise InputError("evidence tool_errors must be a list")
    if errors:
        findings.append("tool errors cannot be interpreted as a clean assessment")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        policy = load_json(args.policy)
        evidence = load_json(args.evidence)
        findings, query_ids = inspect_policy(policy)
        findings.extend(inspect_evidence(evidence, query_ids))
    except InputError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL {finding}")
    if findings:
        print(f"REJECTED {len(findings)} exposure-control finding(s)")
        return 1
    print("ACCEPTED public repository exposure policy and sanitized evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
