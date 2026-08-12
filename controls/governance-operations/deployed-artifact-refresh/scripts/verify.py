#!/usr/bin/env python3
"""Verify an exact deployed-artifact refresh case without mutating providers."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-deployed-artifact-refresh-policy/v1"
CASE_SCHEMA = "psb-deployed-artifact-refresh-case/v1"
POLICY_ID_RE = re.compile(r"^artifact-refresh-policy@sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
CASE_ID_RE = re.compile(r"^REFRESH-[0-9]{4}-[0-9]{4}$")
SENSITIVE_FIELDS = {"credential", "customer_data", "endpoint", "exploit", "secret", "token"}
EXPECTED_SOURCES = {"deployment-inventory", "registry-lifecycle", "support-catalog", "vulnerability-monitor"}
EXPECTED_CLOSURE = {
    "require_new_digest": True,
    "require_hosted_build": True,
    "require_platform_provenance": True,
    "require_artifact_bound_sbom": True,
    "require_signature": True,
    "require_immutable_publication": True,
    "require_admission_for_all_targets": True,
    "require_zero_active_old_digest": True,
    "allow_scope_reduction": False,
}
NOW = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)


class EvidenceError(ValueError):
    """The result cannot be established from trustworthy evidence."""


class SecurityFinding(ValueError):
    """Trustworthy evidence establishes an unsafe refresh state."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} cannot be loaded or parsed") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} root must be an object")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc)


def exact_id(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise EvidenceError(f"{label} has invalid immutable identity")
    return value


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be a list")
    return value


def find_sensitive(value: Any, path: str = "root") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SENSITIVE_FIELDS:
                return f"{path}.{key}"
            found = find_sensitive(child, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = find_sensitive(child, f"{path}[{index}]")
            if found:
                return found
    return None


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema") != POLICY_SCHEMA:
        raise EvidenceError("policy schema is unsupported")
    exact_id(policy.get("policy_id"), POLICY_ID_RE, "policy_id")
    if parse_time(policy.get("as_of"), "policy.as_of") != NOW:
        raise EvidenceError("policy as_of does not match the evaluation time")
    if policy.get("evidence_max_age_seconds") != 3600:
        raise SecurityFinding("policy evidence freshness baseline is weakened")
    if policy.get("inventory_max_age_seconds") != 900:
        raise SecurityFinding("policy inventory freshness baseline is weakened")
    if set(require_list(policy.get("required_evidence_sources"), "policy.required_evidence_sources")) != EXPECTED_SOURCES:
        raise SecurityFinding("policy evidence sources are incomplete")
    if policy.get("deadlines_hours") != {"critical": 24, "high": 72, "medium": 168}:
        raise SecurityFinding("policy deadlines are weakened or incomplete")
    if policy.get("owners") != {"rebuild": "build-platform", "release": "release-engineering", "closure": "incident-response"}:
        raise SecurityFinding("policy owners are incomplete")
    if policy.get("closure") != EXPECTED_CLOSURE:
        raise SecurityFinding("policy closure requirements are weakened")
    output = require_object(policy.get("output"), "policy.output")
    if set(output.get("forbidden_fields", [])) != SENSITIVE_FIELDS:
        raise SecurityFinding("policy output forbidden fields are incomplete")
    if set(output.get("allowed_fields", [])) != {"case_id", "state", "old_digest_instances", "replacement_targets"}:
        raise SecurityFinding("policy output allowlist is unsafe")


def validate_inventory(case: dict[str, Any], policy: dict[str, Any]) -> tuple[str, str, set[str]]:
    artifact = require_object(case.get("artifact"), "case.artifact")
    old_digest = exact_id(artifact.get("digest"), DIGEST_RE, "artifact.digest")
    sbom = artifact.get("sbom_serial")
    if not isinstance(sbom, str) or not sbom.startswith("urn:uuid:"):
        raise EvidenceError("artifact SBOM serial is invalid")
    exact_id(artifact.get("source_revision"), REVISION_RE, "artifact.source_revision")
    parse_time(artifact.get("built_at"), "artifact.built_at")
    inventory = require_object(case.get("inventory"), "case.inventory")
    if inventory.get("status") != "COMPLETE":
        raise EvidenceError("deployment inventory is incomplete or unavailable")
    collected = parse_time(inventory.get("collected_at"), "inventory.collected_at")
    if (NOW - collected).total_seconds() > policy["inventory_max_age_seconds"]:
        raise EvidenceError("deployment inventory is stale")
    scope = inventory.get("scope_id")
    if not isinstance(scope, str) or "@sha256:" not in scope:
        raise EvidenceError("inventory scope is not immutable")
    targets = require_list(inventory.get("expected_targets"), "inventory.expected_targets")
    if not targets or any(not isinstance(item, str) or not item for item in targets) or len(targets) != len(set(targets)):
        raise EvidenceError("inventory target scope is empty malformed or duplicate")
    deployments = require_list(inventory.get("deployments"), "inventory.deployments")
    observed: set[str] = set()
    for deployment in deployments:
        item = require_object(deployment, "inventory.deployment")
        environment = item.get("environment")
        if environment in observed:
            raise EvidenceError("deployment inventory contains duplicate environment")
        observed.add(environment)
        if environment not in targets or item.get("active") is not True:
            raise EvidenceError("deployment inventory scope or active state is inconsistent")
        if item.get("digest") != old_digest or item.get("sbom_serial") != sbom:
            raise EvidenceError("deployment artifact or SBOM identity mismatch")
        if not isinstance(item.get("deployment_id"), str) or not item["deployment_id"]:
            raise EvidenceError("deployment identity is missing")
    if observed != set(targets):
        raise EvidenceError("deployment inventory does not cover every expected target")
    return old_digest, scope, set(targets)


def validate_risk(case: dict[str, Any], policy: dict[str, Any], old_digest: str) -> tuple[bool, str]:
    risk = require_object(case.get("risk_evidence"), "case.risk_evidence")
    if risk.get("status") != "COMPLETE":
        raise EvidenceError("risk evidence is incomplete or unavailable")
    collected = parse_time(risk.get("collected_at"), "risk_evidence.collected_at")
    if (NOW - collected).total_seconds() > policy["evidence_max_age_seconds"]:
        raise EvidenceError("risk evidence is stale")
    sources: set[str] = set()
    for source in require_list(risk.get("sources"), "risk_evidence.sources"):
        item = require_object(source, "risk_evidence.source")
        if item.get("status") != "HEALTHY" or not isinstance(item.get("id"), str):
            raise EvidenceError("risk evidence source is unhealthy")
        sources.add(item["id"])
    if sources != EXPECTED_SOURCES:
        raise EvidenceError("risk evidence source set is incomplete")
    if risk.get("artifact_digest") != old_digest:
        raise EvidenceError("risk evidence artifact identity mismatch")
    if not isinstance(risk.get("affected"), bool):
        raise EvidenceError("risk affected state is invalid")
    severity = risk.get("severity")
    if severity not in policy["deadlines_hours"]:
        raise EvidenceError("risk severity is unsupported")
    if risk.get("support_state") not in {"supported", "end-of-support"}:
        raise EvidenceError("support lifecycle state is invalid")
    if not isinstance(risk.get("reason_class"), str) or not risk["reason_class"]:
        raise EvidenceError("risk reason class is absent")
    return risk["affected"], severity


def validate_decision(case: dict[str, Any], policy: dict[str, Any], affected: bool, severity: str, scope: str) -> bool:
    decision = require_object(case.get("decision"), "case.decision")
    if not isinstance(decision.get("decision_id"), str) or not decision["decision_id"]:
        raise EvidenceError("decision identity is missing")
    decided = parse_time(decision.get("decided_at"), "decision.decided_at")
    due = parse_time(decision.get("due_at"), "decision.due_at")
    expected_due = decided.timestamp() + policy["deadlines_hours"][severity] * 3600
    if due.timestamp() != expected_due:
        raise SecurityFinding("decision deadline does not match policy")
    if decision.get("owner") != policy["owners"]["rebuild"]:
        raise SecurityFinding("decision owner does not match policy")
    if decision.get("target_scope_id") != scope:
        raise SecurityFinding("decision target scope differs from the inventory")
    expected_status = "REBUILD_REQUIRED" if affected else "NO_REBUILD"
    if decision.get("status") != expected_status:
        raise SecurityFinding("decision status does not match current risk")
    return affected and NOW > due


def validate_replacement(case: dict[str, Any], old_digest: str, targets: set[str], scope: str, policy: dict[str, Any]) -> tuple[bool, int, int]:
    replacement_value = case.get("replacement")
    if replacement_value is None:
        return False, len(targets), len(targets)
    replacement = require_object(replacement_value, "case.replacement")
    new_digest = exact_id(replacement.get("digest"), DIGEST_RE, "replacement.digest")
    exact_id(replacement.get("source_revision"), REVISION_RE, "replacement.source_revision")
    if new_digest == old_digest:
        raise SecurityFinding("replacement reuses the affected artifact digest")
    build = require_object(replacement.get("build"), "replacement.build")
    if build.get("status") != "SUCCESS" or build.get("platform") != "approved-hosted":
        raise SecurityFinding("replacement was not produced by the approved hosted build")
    if build.get("platform_provenance") is not True or build.get("provenance_subject") != new_digest:
        raise SecurityFinding("replacement platform provenance is absent or mismatched")
    if not isinstance(build.get("invocation_id"), str) or not build["invocation_id"]:
        raise EvidenceError("replacement build invocation is missing")
    release = require_object(replacement.get("release"), "replacement.release")
    for field in ("sbom_subject", "signature_subject", "publication_digest"):
        if release.get(field) != new_digest:
            raise EvidenceError(f"replacement release {field} is mismatched")
    if release.get("immutable") is not True:
        raise SecurityFinding("replacement publication is mutable")
    admitted: set[str] = set()
    for admission in require_list(case.get("admissions"), "case.admissions"):
        item = require_object(admission, "case.admission")
        if item.get("status") != "ADMITTED" or item.get("digest") != new_digest:
            raise SecurityFinding("replacement admission is rejected or mismatched")
        environment = item.get("environment")
        if environment in admitted:
            raise EvidenceError("replacement admission target is duplicate")
        admitted.add(environment)
    if admitted != targets:
        raise SecurityFinding("replacement admission does not cover every target")
    post = require_object(case.get("post_inventory"), "case.post_inventory")
    if post.get("status") != "COMPLETE":
        raise EvidenceError("post-deployment inventory is incomplete")
    collected = parse_time(post.get("collected_at"), "post_inventory.collected_at")
    if (NOW - collected).total_seconds() > policy["inventory_max_age_seconds"]:
        raise EvidenceError("post-deployment inventory is stale")
    if post.get("scope_id") != scope:
        raise EvidenceError("post-deployment inventory scope was reduced or changed")
    observed: set[str] = set()
    old_instances = 0
    for deployment in require_list(post.get("deployments"), "post_inventory.deployments"):
        item = require_object(deployment, "post_inventory.deployment")
        environment = item.get("environment")
        if environment in observed:
            raise EvidenceError("post-deployment inventory contains duplicate target")
        observed.add(environment)
        if item.get("active") is not True:
            raise EvidenceError("post-deployment inventory contains inactive target record")
        digest = exact_id(item.get("digest"), DIGEST_RE, "post deployment digest")
        if digest == old_digest:
            old_instances += 1
        if digest != new_digest:
            raise SecurityFinding("post-deployment target does not run the replacement digest")
    if observed != targets:
        raise EvidenceError("post-deployment inventory does not cover every original target")
    if old_instances:
        raise SecurityFinding("affected artifact digest remains active")
    return True, old_instances, len(admitted)


def evaluate(policy: dict[str, Any], case: dict[str, Any]) -> tuple[str, int, int]:
    validate_policy(policy)
    if case.get("schema") != CASE_SCHEMA:
        raise EvidenceError("case schema is unsupported")
    case_id = exact_id(case.get("case_id"), CASE_ID_RE, "case_id")
    sensitive = find_sensitive(case)
    if sensitive:
        raise EvidenceError(f"case contains forbidden sensitive field {sensitive.rsplit('.', 1)[-1]}")
    old_digest, scope, targets = validate_inventory(case, policy)
    affected, severity = validate_risk(case, policy, old_digest)
    overdue = validate_decision(case, policy, affected, severity, scope)
    if not affected:
        if case.get("replacement") is not None or case.get("admissions") or case.get("post_inventory") is not None:
            raise SecurityFinding("not-affected case contains unsupported replacement state")
        state, old_instances, replacement_targets = "NOT_AFFECTED", len(targets), 0
    elif case.get("replacement") is None:
        state = "OVERDUE" if overdue else "IN_PROGRESS"
        old_instances, replacement_targets = len(targets), 0
    else:
        completed, old_instances, replacement_targets = validate_replacement(case, old_digest, targets, scope, policy)
        state = "REMEDIATED" if completed else ("OVERDUE" if overdue else "IN_PROGRESS")
    if case.get("requested_state") != state:
        raise SecurityFinding("requested state does not match verified state")
    return state, old_instances, replacement_targets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--case", required=True, type=Path)
    args = parser.parse_args()
    try:
        policy = load_json(args.policy, "policy")
        case = load_json(args.case, "case")
        state, old_instances, replacement_targets = evaluate(policy, case)
    except SecurityFinding as exc:
        print(f"FINDING {exc}")
        return 1
    except EvidenceError as exc:
        print(f"ERROR {exc}")
        return 2
    case_id = case["case_id"]
    print(f"{state} case={case_id} old_digest_instances={old_instances} replacement_targets={replacement_targets}")
    return 0 if state in {"NOT_AFFECTED", "REMEDIATED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
