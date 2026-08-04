#!/usr/bin/env python3
"""Verify a secure IaC golden-path policy and sanitized Terraform plan JSON."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable


APPROVED_REGIONS = {"ap-northeast-1", "asia-northeast1", "japaneast"}
REQUIRED_CONTROLS = {
    "PSB-CICD-001",
    "PSB-CICD-003",
    "PSB-CICD-006",
    "PSB-BUILD-001",
    "PSB-BUILD-003",
    "PSB-SOURCE-002",
    "PSB-IAC-001",
    "PSB-DETECT-001",
    "PSB-REL-002",
    "PSB-REL-003",
    "PSB-CONTAINER-001",
}
PLANNED_CONTROLS: set[str] = set()
REQUIRED_RULES = {
    "encryption",
    "private-network",
    "no-public-ip",
    "least-privilege-admin",
    "approved-image",
    "required-tags",
    "approved-region",
}
APPROVED_ADMIN = {
    "aws": "ssm-session-manager",
    "gcp": "iap-os-login",
    "azure": "entra-bastion",
}


class InputError(ValueError):
    """Input could not be evaluated."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def object_at(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise InputError(f"{label}.{key} must be an object")
    return child


def resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(plan.get("format_version"), str):
        raise InputError("plan format_version is missing")
    planned = object_at(plan, "planned_values", "plan")
    root = object_at(planned, "root_module", "plan.planned_values")
    values = root.get("resources")
    if not isinstance(values, list) or not values:
        raise InputError("plan must contain resources")
    if not all(isinstance(item, dict) for item in values):
        raise InputError("plan resources must be objects")
    return values


def resource_values(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    address = item.get("address")
    values = item.get("values")
    if not isinstance(address, str) or not isinstance(values, dict):
        raise InputError("plan resource requires address and values")
    return address, values


def check_module(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    module = object_at(policy, "module", "policy")
    issues = []
    if not str(module.get("source", "")).startswith("registry."):
        issues.append("module source is not an approved registry")
    version = module.get("version")
    if not isinstance(version, str) or version in {"", "main", "master", "latest"}:
        issues.append("module version is mutable")
    integrity = module.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha256:") or len(integrity) != 71:
        issues.append("module integrity is not a SHA-256 digest")
    if set(module.get("providers", [])) != {"aws", "gcp", "azure"}:
        issues.append("provider profiles are incomplete")
    if module.get("secure_defaults_locked") is not True:
        issues.append("secure defaults can be silently overridden")
    return issues


def check_compute_defaults(policy: dict[str, Any], items: list[dict[str, Any]]) -> list[str]:
    module = object_at(policy, "module", "policy")
    expected_image = module.get("approved_image")
    providers = set()
    issues = []
    for item in items:
        address, values = resource_values(item)
        provider = values.get("provider")
        providers.add(provider)
        if not address.startswith("module.secure_compute."):
            issues.append(f"{address} bypasses approved module")
        if values.get("disk_encryption") in {None, "", "none", "platform-unspecified"}:
            issues.append(f"{address} lacks required disk encryption")
        if values.get("public_ip") is not False:
            issues.append(f"{address} exposes a public IP")
        if values.get("network_zone") != "private":
            issues.append(f"{address} is not on a private network")
        if values.get("image") != expected_image:
            issues.append(f"{address} does not use the approved digest image")
        tags = values.get("tags")
        if not isinstance(tags, dict) or not {"owner", "data-classification"} <= set(tags):
            issues.append(f"{address} lacks required tags")
        if values.get("region") not in APPROVED_REGIONS:
            issues.append(f"{address} uses an unapproved region")
    if providers != {"aws", "gcp", "azure"}:
        issues.append("plan does not exercise all provider profiles")
    return issues


def check_admin(_: dict[str, Any], items: list[dict[str, Any]]) -> list[str]:
    issues = []
    for item in items:
        address, values = resource_values(item)
        provider = values.get("provider")
        if values.get("admin_access") != APPROVED_ADMIN.get(provider):
            issues.append(f"{address} uses an unapproved administration path")
        if values.get("iam_wildcard") is not False:
            issues.append(f"{address} contains wildcard administration privilege")
    return issues


def check_plan_gate(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    gate = object_at(policy, "plan_gate", "policy")
    issues = []
    if gate.get("input") != "terraform-show-json":
        issues.append("gate does not inspect the resolved Terraform plan JSON")
    if gate.get("decision") != "deny":
        issues.append("gate has no deny decision")
    if set(gate.get("required_rules", [])) != REQUIRED_RULES:
        issues.append("gate rule set is incomplete")
    return issues


def check_fail_closed(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    gate = object_at(policy, "plan_gate", "policy")
    issues = []
    if gate.get("failure_mode") != "block":
        issues.append("policy finding does not block")
    if gate.get("unknown_values") != "block-or-explicit-review":
        issues.append("unknown plan values are accepted")
    if gate.get("scanner_error") != "error":
        issues.append("scanner failure can appear clean")
    return issues


def check_ci_composition(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    ci = object_at(policy, "ci_composition", "policy")
    issues = []
    if ci.get("template") != "reusable-workflow":
        issues.append("security jobs are copied rather than centrally reusable")
    if ci.get("immutable_reference") is not True:
        issues.append("reusable workflow reference is mutable")
    if ci.get("permissions") != "explicit-job-minimum":
        issues.append("workflow permissions are not explicit and minimal")
    if set(ci.get("implemented_controls", [])) != REQUIRED_CONTROLS:
        issues.append("implemented control composition is incomplete")
    if set(ci.get("planned_controls", [])) != PLANNED_CONTROLS:
        issues.append("planned gates are absent or represented as implemented")
    expected_feedback = {
        "control": "PSB-DETECT-001",
        "adapter": "docksec",
        "role": "optional-developer-remediation-orchestrator",
        "gate": "scan-only-offline-structured-findings",
        "ai_remediation": "optional-non-blocking",
        "tool_failure": "error",
        "upstream_action": "rejected-by-project-policy",
    }
    if ci.get("container_feedback") != expected_feedback:
        issues.append(
            "container feedback is not deterministic AI-independent and fail-closed"
        )
    expected_sbom_inventory = {
        "control": "PSB-REL-003",
        "format": "CycloneDX-1.7",
        "artifact_binding": "sha256-release-manifest",
        "publication": "immutable-no-downgrade",
        "adapter": "dependency-track-4.14.3-normalized",
        "project_binding": "pre-created-uuid-exact-version",
        "upload_permission": "BOM_UPLOAD",
        "success": "BOM_PROCESSED",
        "failure": "ERROR",
    }
    if ci.get("sbom_inventory") != expected_sbom_inventory:
        issues.append(
            "SBOM inventory composition is not artifact-bound least-privilege and fail-closed"
        )
    return issues


def check_identity(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    identity = object_at(policy, "deployment_identity", "policy")
    issues = []
    if identity.get("control") != "PSB-CICD-006":
        issues.append("deployment identity is not composed with PSB-CICD-006")
    if identity.get("type") != "oidc" or identity.get("job") != "deploy-only":
        issues.append("deployment does not use deploy-only OIDC")
    audience = identity.get("audience")
    if not isinstance(audience, str) or audience in {"", "*"}:
        issues.append("OIDC audience is not exact")
    ttl = identity.get("ttl_minutes")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 15:
        issues.append("OIDC lifetime exceeds 15 minutes")
    if identity.get("stored_cloud_keys") is not False:
        issues.append("stored cloud keys remain enabled")
    expected_claims = {
        "iss",
        "aud",
        "sub",
        "repository_id",
        "repository_owner_id",
        "ref",
        "environment",
        "job_workflow_ref",
    }
    if set(identity.get("exact_trust_claims", [])) != expected_claims:
        issues.append("OIDC trust claims are not the exact PSB-CICD-006 set")
    reusable = identity.get("reusable_workflow_ref")
    if not isinstance(reusable, str) or not re.search(r"@[0-9a-f]{40}$", reusable):
        issues.append("OIDC reusable workflow identity is mutable")
    if identity.get("replay") != "single-use-jti":
        issues.append("OIDC replay protection is absent")
    if identity.get("credential_scope") != "exact-role-action-resource":
        issues.append("exchanged cloud credential is not resource bounded")
    return issues


def check_provider_enforcement(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    enforcement = object_at(policy, "provider_enforcement", "policy")
    issues = []
    if enforcement.get("mode") != "fail":
        issues.append("provider enforcement only warns")
    if set(enforcement.get("operations", [])) != {"create", "update"}:
        issues.append("provider enforcement misses create or update")
    if enforcement.get("coverage") != "all-provisioning-paths":
        issues.append("CI bypass paths are not covered")
    version = enforcement.get("policy_version")
    if not isinstance(version, str) or version in {"", "latest"}:
        issues.append("provider policy version is mutable")
    return issues


def check_drift(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    drift = object_at(policy, "drift", "policy")
    issues = []
    hours = drift.get("scan_hours")
    if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 24:
        issues.append("drift interval exceeds 24 hours")
    if drift.get("desired_state_source") != "approved-iac-revision":
        issues.append("drift has no approved desired-state source")
    if drift.get("unresolved_state") != "error":
        issues.append("drift scanner failure can appear clean")
    return issues


def check_remediation(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    drift = object_at(policy, "drift", "policy")
    allowed = drift.get("safe_auto_remediation")
    issues = []
    if not isinstance(allowed, list) or not allowed or set(allowed) - {
        "remove-public-ip",
        "restore-required-tags",
    }:
        issues.append("automatic remediation is empty or destructive")
    if drift.get("destructive_remediation") != "approval-required":
        issues.append("destructive remediation lacks approval")
    return issues


def check_exceptions(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    return [] if policy.get("exceptions") == "exact-owned-justified-expiring" else [
        "exceptions are broad unowned unjustified or permanent"
    ]


def check_plan_artifacts(policy: dict[str, Any], _: list[dict[str, Any]]) -> list[str]:
    return [] if policy.get("plan_artifacts") == "encrypted-access-controlled-expiring-never-committed" else [
        "plan artifacts can expose persistent sensitive values"
    ]


CHECKS: list[tuple[str, str, Callable[[dict[str, Any], list[dict[str, Any]]], list[str]]]] = [
    ("IAC-001", "approved versioned module distribution", check_module),
    ("IAC-002", "secure multi-cloud compute defaults", check_compute_defaults),
    ("IAC-003", "least-privilege administration paths", check_admin),
    ("IAC-004", "resolved plan decision gate", check_plan_gate),
    ("IAC-005", "fail-closed policy evaluation", check_fail_closed),
    ("IAC-006", "reusable CI control composition", check_ci_composition),
    ("IAC-007", "short-lived deployment identity", check_identity),
    ("IAC-008", "provider-side bypass enforcement", check_provider_enforcement),
    ("IAC-009", "continuous drift detection", check_drift),
    ("IAC-010", "bounded corrective action", check_remediation),
    ("IAC-011", "narrow expiring exceptions", check_exceptions),
    ("IAC-012", "sensitive plan artifact handling", check_plan_artifacts),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = load_json(args.policy, "policy")
        plan = load_json(args.plan, "plan")
        plan_resources = resources(plan)
        findings = 0
        for check_id, title, function in CHECKS:
            issues = function(policy, plan_resources)
            if issues:
                findings += 1
                print(f"FAIL {check_id} {title}: {'; '.join(issues)}")
            else:
                print(f"PASS {check_id} {title}")
    except (InputError, TypeError) as error:
        print(f"ERROR {error}")
        return 2
    if findings:
        print(f"REJECTED golden path: {findings} control checks failed")
        return 1
    print("ACCEPTED golden path")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
