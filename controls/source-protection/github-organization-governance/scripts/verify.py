#!/usr/bin/env python3
"""Verify a secret-free GitHub Organization governance snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-github-organization-governance-policy/v1"
SNAPSHOT_SCHEMA = "psb-github-organization-governance-snapshot/v1"
MAX_INPUT_BYTES = 2_000_000
REQUIRED_SOURCES = {
    "actions",
    "applications",
    "audit",
    "members",
    "organization",
    "repositories",
    "teams",
}
REQUIRED_FEATURES = {
    "dependency_graph",
    "dependabot_alerts",
    "secret_scanning",
    "secret_scanning_push_protection",
}
REQUIRED_AUDIT_CATEGORIES = {
    "actions-policy",
    "application-access",
    "membership",
    "organization-settings",
    "repository-visibility",
    "rulesets",
}
REQUIRED_FORBIDDEN_WRITE_PERMISSIONS = {
    "actions",
    "administration",
    "members",
    "organization_administration",
    "workflows",
}
FORBIDDEN_SENSITIVE_FIELDS = {
    "access_token",
    "authorization",
    "client_secret",
    "credential_value",
    "hashed_token",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_value",
    "token",
}
CHECK_ORDER = [f"GHO-{number:03d}" for number in range(1, 11)]
PASS_MESSAGES = {
    "GHO-001": "organization snapshot is complete fresh stable and policy bound",
    "GHO-002": "organization authentication and provisioning are enforced",
    "GHO-003": "Organization Owner authority is bounded attributable and recently reviewed",
    "GHO-004": "member team and outside-collaborator access is owned scoped and current",
    "GHO-005": "organization repository defaults deny broad ambient authority",
    "GHO-006": "organization Actions policy limits repositories actions token authority and fork trust",
    "GHO-007": "installed application access is complete resource bounded and recently reviewed",
    "GHO-008": "every repository has the required security configuration or a current public review",
    "GHO-009": "audit export drift evaluation and alert delivery are healthy",
    "GHO-010": "weak policy local exceptions and evidence failure cannot produce a clean result",
}


class EvidenceError(Exception):
    """The input cannot support a security decision."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {label}") from error
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise EvidenceError(f"{label} size is invalid")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise EvidenceError(f"cannot parse {label}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value, raw


def require_object(parent: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise EvidenceError(f"{label}.{key} must be an object")
    return value


def require_list(parent: dict[str, Any], key: str, label: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise EvidenceError(f"{label}.{key} must be an array")
    return value


def require_text(parent: dict[str, Any], key: str, label: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label}.{key} must be non-empty text")
    return value


def require_bool(parent: dict[str, Any], key: str, label: str) -> bool:
    value = parent.get(key)
    if not isinstance(value, bool):
        raise EvidenceError(f"{label}.{key} must be boolean")
    return value


def require_int(parent: dict[str, Any], key: str, label: str) -> int:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{label}.{key} must be a non-negative integer")
    return value


def require_string_set(parent: dict[str, Any], key: str, label: str) -> set[str]:
    values = require_list(parent, key, label)
    if any(not isinstance(value, str) or not value for value in values):
        raise EvidenceError(f"{label}.{key} must contain non-empty text")
    result = set(values)
    if len(result) != len(values):
        raise EvidenceError(f"{label}.{key} contains duplicates")
    return result


def require_int_set(parent: dict[str, Any], key: str, label: str) -> set[int]:
    values = require_list(parent, key, label)
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in values):
        raise EvidenceError(f"{label}.{key} must contain positive integer IDs")
    result = set(values)
    if len(result) != len(values):
        raise EvidenceError(f"{label}.{key} contains duplicate IDs")
    return result


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(f"{label} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def age_hours(observed: datetime, evaluation_time: datetime, label: str) -> float:
    seconds = (evaluation_time - observed).total_seconds()
    if seconds < -300:
        raise EvidenceError(f"{label} is in the future")
    return max(seconds, 0) / 3600


def age_days(observed: datetime, evaluation_time: datetime, label: str) -> float:
    return age_hours(observed, evaluation_time, label) / 24


def reject_sensitive_fields(value: Any, path: str = "snapshot") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_SENSITIVE_FIELDS:
                raise EvidenceError(f"{path} contains forbidden sensitive field {key}")
            reject_sensitive_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_fields(child, f"{path}[{index}]")


def add_finding(findings: dict[str, list[str]], check_id: str, reason: str) -> None:
    findings.setdefault(check_id, []).append(reason)


def validate_policy(policy: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if policy.get("schema") != POLICY_SCHEMA:
        raise EvidenceError("policy schema is unsupported")
    if require_text(policy, "snapshot_schema", "policy") != SNAPSHOT_SCHEMA:
        raise EvidenceError("policy snapshot schema is unsupported")

    weak: list[str] = []
    maximum_snapshot_age_hours = require_int(policy, "maximum_snapshot_age_hours", "policy")
    maximum_access_review_age_days = require_int(policy, "maximum_access_review_age_days", "policy")
    if not 1 <= maximum_snapshot_age_hours <= 24:
        weak.append("snapshot freshness exceeds 24 hours")
    if not 1 <= maximum_access_review_age_days <= 90:
        weak.append("access review interval exceeds 90 days")

    identity = require_object(policy, "identity", "policy")
    allowed_modes = require_string_set(identity, "allowed_provisioning_modes", "policy.identity")
    if require_bool(identity, "require_two_factor_authentication", "policy.identity") is not True:
        weak.append("two-factor authentication is optional")
    if require_bool(identity, "require_sso", "policy.identity") is not True:
        weak.append("SSO is optional")
    if not allowed_modes or not allowed_modes <= {"enterprise-managed-users", "saml-scim"}:
        weak.append("manual or unknown provisioning is allowed")
    maximum_offboarding_sla_hours = require_int(
        identity, "maximum_offboarding_sla_hours", "policy.identity"
    )
    if not 1 <= maximum_offboarding_sla_hours <= 24:
        weak.append("offboarding SLA exceeds 24 hours")

    owners = require_object(policy, "owners", "policy")
    minimum_owners = require_int(owners, "minimum", "policy.owners")
    maximum_owners = require_int(owners, "maximum", "policy.owners")
    if minimum_owners < 2 or maximum_owners > 3 or maximum_owners < minimum_owners:
        weak.append("Owner bounds do not require two to three identities")
    if require_bool(owners, "require_human_identity", "policy.owners") is not True:
        weak.append("shared or service Owner identity is allowed")
    if require_bool(
        owners, "require_phishing_resistant_authentication", "policy.owners"
    ) is not True:
        weak.append("phishing-resistant Owner authentication is optional")

    outside = require_object(policy, "outside_collaborators", "policy")
    maximum_grant_days = require_int(outside, "maximum_grant_days", "policy.outside_collaborators")
    allowed_outside_permissions = require_string_set(
        outside,
        "allowed_repository_permissions",
        "policy.outside_collaborators",
    )
    if not 1 <= maximum_grant_days <= 90:
        weak.append("outside collaborator grant exceeds 90 days")
    if not allowed_outside_permissions or not allowed_outside_permissions <= {"pull", "triage"}:
        weak.append("outside collaborator write or administration is allowed")

    expected_defaults = {
        "default_repository_permission": "none",
        "members_can_create_repositories": False,
        "members_can_create_public_repositories": False,
        "members_can_create_private_repositories": False,
        "members_can_create_internal_repositories": False,
        "members_can_fork_private_repositories": False,
    }
    organization_defaults = require_object(policy, "organization_defaults", "policy")
    if any(organization_defaults.get(key) != value for key, value in expected_defaults.items()):
        weak.append("organization defaults permit ambient repository authority")

    expected_actions = {
        "enabled_repositories": "selected",
        "allowed_actions": "selected",
        "require_full_length_sha": True,
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
        "fork_pull_request_workflows_send_write_tokens": False,
        "fork_pull_request_workflows_send_secrets": False,
    }
    actions = require_object(policy, "actions", "policy")
    if any(actions.get(key) != value for key, value in expected_actions.items()):
        weak.append("organization Actions policy permits broad execution or token authority")

    integrations = require_object(policy, "integrations", "policy")
    maximum_integration_review_age_days = require_int(
        integrations, "maximum_review_age_days", "policy.integrations"
    )
    forbidden_write_permissions = require_string_set(
        integrations, "forbidden_write_permissions", "policy.integrations"
    )
    if not 1 <= maximum_integration_review_age_days <= 90:
        weak.append("integration review interval exceeds 90 days")
    if not REQUIRED_FORBIDDEN_WRITE_PERMISSIONS <= forbidden_write_permissions:
        weak.append("high-risk integration write permissions are not forbidden")

    repository_security = require_object(policy, "repository_security", "policy")
    required_features = require_string_set(
        repository_security, "required_features", "policy.repository_security"
    )
    maximum_public_review_age_days = require_int(
        repository_security,
        "maximum_public_review_age_days",
        "policy.repository_security",
    )
    if not REQUIRED_FEATURES <= required_features:
        weak.append("required repository security features are incomplete")
    if not 1 <= maximum_public_review_age_days <= 90:
        weak.append("public exposure review interval exceeds 90 days")

    monitoring = require_object(policy, "monitoring", "policy")
    minimum_retention_days = require_int(monitoring, "minimum_retention_days", "policy.monitoring")
    maximum_alert_test_age_days = require_int(
        monitoring, "maximum_alert_test_age_days", "policy.monitoring"
    )
    required_categories = require_string_set(
        monitoring, "required_categories", "policy.monitoring"
    )
    export_boundary = require_text(
        monitoring, "required_export_boundary", "policy.monitoring"
    )
    if minimum_retention_days < 180:
        weak.append("audit retention is below 180 days")
    if not 1 <= maximum_alert_test_age_days <= 30:
        weak.append("alert delivery test interval exceeds 30 days")
    if not REQUIRED_AUDIT_CATEGORIES <= required_categories:
        weak.append("required audit categories are incomplete")
    if export_boundary != "independent-security-account":
        weak.append("audit export is not independent from GitHub administration")
    if require_bool(policy, "allow_local_exceptions", "policy") is not False:
        weak.append("local ungoverned exceptions are allowed")

    parsed = {
        "maximum_snapshot_age_hours": maximum_snapshot_age_hours,
        "maximum_access_review_age_days": maximum_access_review_age_days,
        "identity": identity,
        "owners": owners,
        "outside": outside,
        "allowed_outside_permissions": allowed_outside_permissions,
        "maximum_grant_days": maximum_grant_days,
        "organization_defaults": organization_defaults,
        "actions": actions,
        "integrations": integrations,
        "maximum_integration_review_age_days": maximum_integration_review_age_days,
        "forbidden_write_permissions": forbidden_write_permissions,
        "repository_security": repository_security,
        "required_features": required_features,
        "maximum_public_review_age_days": maximum_public_review_age_days,
        "monitoring": monitoring,
        "minimum_retention_days": minimum_retention_days,
        "maximum_alert_test_age_days": maximum_alert_test_age_days,
        "required_categories": required_categories,
    }
    return parsed, weak


def validate_inventory_shape(snapshot: dict[str, Any], evaluation_time: datetime, maximum_age: int) -> None:
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise EvidenceError("snapshot schema is unsupported")
    reject_sensitive_fields(snapshot)

    collector = require_object(snapshot, "collector", "snapshot")
    if require_text(collector, "status", "snapshot.collector") != "COMPLETE":
        raise EvidenceError("collector status is not COMPLETE")
    if require_bool(collector, "pages_complete", "snapshot.collector") is not True:
        raise EvidenceError("collector pagination is incomplete")
    if require_bool(collector, "live_mutation", "snapshot.collector") is not False:
        raise EvidenceError("read-only snapshot reports live mutation")
    if require_list(collector, "errors", "snapshot.collector"):
        raise EvidenceError("collector reports errors")
    require_text(collector, "api_version", "snapshot.collector")
    observed_at = parse_time(collector.get("observed_at"), "snapshot.collector.observed_at")
    if age_hours(observed_at, evaluation_time, "snapshot.collector.observed_at") > maximum_age:
        raise EvidenceError("organization snapshot is stale")
    source_health = require_object(collector, "source_health", "snapshot.collector")
    if not REQUIRED_SOURCES <= set(source_health):
        raise EvidenceError("collector source inventory is incomplete")
    if any(source_health.get(source) != "HEALTHY" for source in REQUIRED_SOURCES):
        raise EvidenceError("one or more collector sources are unavailable or unhealthy")

    organization = require_object(snapshot, "organization", "snapshot")
    require_text(organization, "login", "snapshot.organization")
    if require_int(organization, "database_id", "snapshot.organization") <= 0:
        raise EvidenceError("snapshot.organization.database_id must be positive")
    require_text(organization, "node_id", "snapshot.organization")

    access = require_object(snapshot, "access_inventory", "snapshot")
    if require_bool(access, "complete", "snapshot.access_inventory") is not True:
        raise EvidenceError("access inventory is incomplete")
    principals = require_list(access, "principals", "snapshot.access_inventory")
    outside = require_list(access, "outside_collaborators", "snapshot.access_inventory")
    teams = require_list(access, "teams", "snapshot.access_inventory")
    count_pairs = (
        ("expected_principal_count", principals),
        ("expected_outside_collaborator_count", outside),
        ("expected_team_count", teams),
    )
    for key, values in count_pairs:
        if require_int(access, key, "snapshot.access_inventory") != len(values):
            raise EvidenceError(f"access inventory count mismatch for {key}")
        if any(not isinstance(value, dict) for value in values):
            raise EvidenceError(f"snapshot.access_inventory.{key} entries must be objects")
    principal_ids = [require_int(item, "actor_id", "principal") for item in principals]
    outside_ids = [require_int(item, "actor_id", "outside collaborator") for item in outside]
    team_ids = [require_int(item, "team_id", "team") for item in teams]
    if len(set(principal_ids)) != len(principal_ids):
        raise EvidenceError("principal IDs are duplicated")
    if len(set(outside_ids)) != len(outside_ids):
        raise EvidenceError("outside collaborator IDs are duplicated")
    if set(principal_ids) & set(outside_ids):
        raise EvidenceError("principal and outside collaborator IDs overlap")
    if len(set(team_ids)) != len(team_ids):
        raise EvidenceError("team IDs are duplicated")

    integrations = require_object(snapshot, "integrations", "snapshot")
    if require_bool(integrations, "complete", "snapshot.integrations") is not True:
        raise EvidenceError("application inventory is incomplete")
    for expected_key, list_key in (
        ("expected_github_app_count", "github_apps"),
        ("expected_oauth_app_count", "oauth_apps"),
    ):
        values = require_list(integrations, list_key, "snapshot.integrations")
        if require_int(integrations, expected_key, "snapshot.integrations") != len(values):
            raise EvidenceError(f"application inventory count mismatch for {list_key}")
        if any(not isinstance(value, dict) for value in values):
            raise EvidenceError(f"snapshot.integrations.{list_key} entries must be objects")

    repository_security = require_object(snapshot, "repository_security", "snapshot")
    if require_bool(repository_security, "complete", "snapshot.repository_security") is not True:
        raise EvidenceError("repository security inventory is incomplete")
    repositories = require_list(repository_security, "repositories", "snapshot.repository_security")
    if require_int(
        repository_security, "expected_repository_count", "snapshot.repository_security"
    ) != len(repositories):
        raise EvidenceError("repository security inventory count mismatch")
    if any(not isinstance(value, dict) for value in repositories):
        raise EvidenceError("snapshot.repository_security.repositories entries must be objects")
    repository_ids = [require_int(item, "repository_id", "repository") for item in repositories]
    if len(set(repository_ids)) != len(repository_ids):
        raise EvidenceError("repository IDs are duplicated")

    require_object(snapshot, "actions", "snapshot")
    monitoring = require_object(snapshot, "monitoring", "snapshot")
    audit_log = require_object(monitoring, "audit_log", "snapshot.monitoring")
    drift = require_object(monitoring, "drift", "snapshot.monitoring")
    alert_delivery = require_object(monitoring, "alert_delivery", "snapshot.monitoring")
    if require_text(audit_log, "status", "snapshot.monitoring.audit_log") in {"ERROR", "UNAVAILABLE"}:
        raise EvidenceError("audit log collection is unavailable")
    if require_bool(audit_log, "complete", "snapshot.monitoring.audit_log") is not True:
        raise EvidenceError("audit log collection is incomplete")
    audit_observed = parse_time(
        audit_log.get("observed_at"), "snapshot.monitoring.audit_log.observed_at"
    )
    if age_hours(audit_observed, evaluation_time, "audit log observation") > maximum_age:
        raise EvidenceError("audit log evidence is stale")
    drift_observed = parse_time(drift.get("evaluated_at"), "snapshot.monitoring.drift.evaluated_at")
    if age_hours(drift_observed, evaluation_time, "drift evaluation") > maximum_age:
        raise EvidenceError("drift evidence is stale")
    if require_text(drift, "status", "snapshot.monitoring.drift") in {"ERROR", "UNAVAILABLE"}:
        raise EvidenceError("drift evaluation is unavailable")
    if require_text(alert_delivery, "status", "snapshot.monitoring.alert_delivery") in {
        "ERROR",
        "UNAVAILABLE",
    }:
        raise EvidenceError("alert delivery evidence is unavailable")
    require_list(snapshot, "local_exceptions", "snapshot")


def evaluate(
    policy: dict[str, Any],
    snapshot: dict[str, Any],
    evaluation_time: datetime,
) -> dict[str, list[str]]:
    findings: dict[str, list[str]] = {}
    organization = require_object(snapshot, "organization", "snapshot")
    access = require_object(snapshot, "access_inventory", "snapshot")
    principals = require_list(access, "principals", "snapshot.access_inventory")
    outside = require_list(access, "outside_collaborators", "snapshot.access_inventory")
    teams = require_list(access, "teams", "snapshot.access_inventory")
    principal_ids = {require_int(item, "actor_id", "principal") for item in principals}

    identity_policy = policy["identity"]
    identity_reasons: list[str] = []
    if organization.get("two_factor_requirement_enabled") is not True:
        identity_reasons.append("organization 2FA requirement is disabled")
    if organization.get("sso_enforced") is not True:
        identity_reasons.append("SSO is not enforced")
    if organization.get("provisioning_mode") not in set(identity_policy["allowed_provisioning_modes"]):
        identity_reasons.append("identity provisioning mode is not approved")
    if organization.get("provisioning_status") != "HEALTHY":
        identity_reasons.append("identity provisioning is not healthy")
    if organization.get("unlinked_identity_count") != 0:
        identity_reasons.append("unlinked organization identities remain")
    offboarding_sla = organization.get("offboarding_sla_hours")
    if isinstance(offboarding_sla, bool) or not isinstance(offboarding_sla, int):
        identity_reasons.append("offboarding SLA is missing")
    elif offboarding_sla > identity_policy["maximum_offboarding_sla_hours"]:
        identity_reasons.append("offboarding SLA exceeds policy")
    for reason in identity_reasons:
        add_finding(findings, "GHO-002", reason)

    owners = [item for item in principals if item.get("role") == "owner"]
    owner_policy = policy["owners"]
    if not owner_policy["minimum"] <= len(owners) <= owner_policy["maximum"]:
        add_finding(findings, "GHO-003", "Owner count is outside the two-to-three identity boundary")
    for owner in owners:
        actor_id = owner["actor_id"]
        if owner.get("identity_type") != "human":
            add_finding(findings, "GHO-003", f"Owner actor {actor_id} is not an attributable human")
        if owner.get("authentication_assurance") != "phishing-resistant":
            add_finding(findings, "GHO-003", f"Owner actor {actor_id} lacks phishing-resistant authentication")
        if owner.get("provisioning_state") != "ACTIVE":
            add_finding(findings, "GHO-003", f"Owner actor {actor_id} is not actively provisioned")
        reviewed_at = parse_time(owner.get("reviewed_at"), f"Owner actor {actor_id} reviewed_at")
        if age_days(reviewed_at, evaluation_time, f"Owner actor {actor_id} review") > policy[
            "maximum_access_review_age_days"
        ]:
            add_finding(findings, "GHO-003", f"Owner actor {actor_id} review is stale")

    for principal in principals:
        if principal.get("role") == "owner":
            continue
        actor_id = principal["actor_id"]
        if principal.get("role") != "member":
            add_finding(findings, "GHO-004", f"principal actor {actor_id} has an unknown role")
        if principal.get("provisioning_state") != "ACTIVE":
            add_finding(findings, "GHO-004", f"member actor {actor_id} is not actively provisioned")
        if principal.get("affiliation") in {None, "former-employee", "unknown"}:
            add_finding(findings, "GHO-004", f"member actor {actor_id} has no current affiliation")
        reviewed_at = parse_time(principal.get("reviewed_at"), f"member actor {actor_id} reviewed_at")
        if age_days(reviewed_at, evaluation_time, f"member actor {actor_id} review") > policy[
            "maximum_access_review_age_days"
        ]:
            add_finding(findings, "GHO-004", f"member actor {actor_id} review is stale")

    repository_security = require_object(snapshot, "repository_security", "snapshot")
    repositories = require_list(repository_security, "repositories", "snapshot.repository_security")
    repository_ids = {require_int(item, "repository_id", "repository") for item in repositories}
    for collaborator in outside:
        actor_id = collaborator["actor_id"]
        if collaborator.get("sponsor_actor_id") not in principal_ids:
            add_finding(findings, "GHO-004", f"outside collaborator actor {actor_id} lacks a current sponsor")
        collaborator_repositories = require_int_set(
            collaborator, "repository_ids", f"outside collaborator actor {actor_id}"
        )
        if not collaborator_repositories or not collaborator_repositories <= repository_ids:
            add_finding(findings, "GHO-004", f"outside collaborator actor {actor_id} repository scope is invalid")
        if collaborator.get("permission") not in policy["allowed_outside_permissions"]:
            add_finding(findings, "GHO-004", f"outside collaborator actor {actor_id} has excessive permission")
        granted_at = parse_time(collaborator.get("granted_at"), f"outside collaborator actor {actor_id} granted_at")
        expires_at = parse_time(collaborator.get("expires_at"), f"outside collaborator actor {actor_id} expires_at")
        if expires_at <= evaluation_time:
            add_finding(findings, "GHO-004", f"outside collaborator actor {actor_id} grant is expired")
        if (expires_at - granted_at).total_seconds() > policy["maximum_grant_days"] * 86400:
            add_finding(findings, "GHO-004", f"outside collaborator actor {actor_id} grant is overlong")
        reviewed_at = parse_time(collaborator.get("reviewed_at"), f"outside collaborator actor {actor_id} reviewed_at")
        if age_days(reviewed_at, evaluation_time, f"outside collaborator actor {actor_id} review") > policy[
            "maximum_access_review_age_days"
        ]:
            add_finding(findings, "GHO-004", f"outside collaborator actor {actor_id} review is stale")

    for team in teams:
        team_id = team["team_id"]
        if team.get("owner_actor_id") not in principal_ids:
            add_finding(findings, "GHO-004", f"team {team_id} lacks a current accountable owner")
        reviewed_at = parse_time(team.get("reviewed_at"), f"team {team_id} reviewed_at")
        if age_days(reviewed_at, evaluation_time, f"team {team_id} review") > policy[
            "maximum_access_review_age_days"
        ]:
            add_finding(findings, "GHO-004", f"team {team_id} review is stale")
        grants = require_list(team, "repository_grants", f"team {team_id}")
        if not grants or any(not isinstance(grant, dict) for grant in grants):
            raise EvidenceError(f"team {team_id} repository grants are malformed")
        for grant in grants:
            if grant.get("repository_id") not in repository_ids:
                add_finding(findings, "GHO-004", f"team {team_id} references an unknown repository")
            if grant.get("permission") not in {"pull", "triage", "push", "maintain"}:
                add_finding(findings, "GHO-004", f"team {team_id} has broad repository administration")

    for key, expected in policy["organization_defaults"].items():
        if organization.get(key) != expected:
            add_finding(findings, "GHO-005", f"organization default {key} is not restricted")

    actions = require_object(snapshot, "actions", "snapshot")
    for key, expected in policy["actions"].items():
        if actions.get(key) != expected:
            add_finding(findings, "GHO-006", f"Actions setting {key} differs from policy")
    enabled_repository_ids = require_int_set(actions, "enabled_repository_ids", "snapshot.actions")
    active_repository_ids = {
        repository["repository_id"] for repository in repositories if repository.get("archived") is False
    }
    if enabled_repository_ids != active_repository_ids:
        add_finding(findings, "GHO-006", "Actions selected repository inventory is incomplete or excessive")

    integrations = require_object(snapshot, "integrations", "snapshot")
    application_entries = require_list(integrations, "github_apps", "snapshot.integrations") + require_list(
        integrations, "oauth_apps", "snapshot.integrations"
    )
    for application in application_entries:
        identifier = application.get("installation_id", application.get("application_id", "unknown"))
        if application.get("owner_actor_id") not in principal_ids:
            add_finding(findings, "GHO-007", f"application {identifier} lacks a current owner")
        if application.get("repository_selection") != "selected":
            add_finding(findings, "GHO-007", f"application {identifier} is not limited to selected repositories")
        application_repositories = require_int_set(
            application, "repository_ids", f"application {identifier}"
        )
        if not application_repositories or not application_repositories <= repository_ids:
            add_finding(findings, "GHO-007", f"application {identifier} repository scope is invalid")
        permissions = require_object(application, "permissions", f"application {identifier}")
        for permission in sorted(policy["forbidden_write_permissions"]):
            if permissions.get(permission) == "write":
                add_finding(findings, "GHO-007", f"application {identifier} has forbidden {permission} write")
        reviewed_at = parse_time(application.get("reviewed_at"), f"application {identifier} reviewed_at")
        if age_days(reviewed_at, evaluation_time, f"application {identifier} review") > policy[
            "maximum_integration_review_age_days"
        ]:
            add_finding(findings, "GHO-007", f"application {identifier} review is stale")

    for repository in repositories:
        repository_id = repository["repository_id"]
        configuration = repository.get("security_configuration")
        if not isinstance(configuration, str) or configuration in {"", "ad-hoc", "none"}:
            add_finding(findings, "GHO-008", f"repository {repository_id} lacks an organization security configuration")
        features = require_object(repository, "features", f"repository {repository_id}")
        missing_features = sorted(
            feature for feature in policy["required_features"] if features.get(feature) is not True
        )
        if missing_features:
            add_finding(
                findings,
                "GHO-008",
                f"repository {repository_id} is missing required security features",
            )
        if repository.get("visibility") == "public":
            review = repository.get("public_exposure_review")
            if not isinstance(review, dict) or review.get("status") != "PASS" or review.get("control") != "PSB-SOURCE-003":
                add_finding(findings, "GHO-008", f"public repository {repository_id} lacks a PSB-SOURCE-003 review")
            else:
                reviewed_at = parse_time(
                    review.get("reviewed_at"), f"public repository {repository_id} reviewed_at"
                )
                if age_days(reviewed_at, evaluation_time, f"public repository {repository_id} review") > policy[
                    "maximum_public_review_age_days"
                ]:
                    add_finding(findings, "GHO-008", f"public repository {repository_id} review is stale")
        elif repository.get("visibility") not in {"private", "internal"}:
            add_finding(findings, "GHO-008", f"repository {repository_id} visibility is unknown")

    monitoring = require_object(snapshot, "monitoring", "snapshot")
    audit_log = require_object(monitoring, "audit_log", "snapshot.monitoring")
    drift = require_object(monitoring, "drift", "snapshot.monitoring")
    alert_delivery = require_object(monitoring, "alert_delivery", "snapshot.monitoring")
    if audit_log.get("status") != "HEALTHY":
        add_finding(findings, "GHO-009", "audit collection is not healthy")
    if require_int(audit_log, "retention_days", "snapshot.monitoring.audit_log") < policy[
        "minimum_retention_days"
    ]:
        add_finding(findings, "GHO-009", "audit retention is below policy")
    if audit_log.get("export_boundary") != policy["monitoring"]["required_export_boundary"]:
        add_finding(findings, "GHO-009", "audit export is not independently administered")
    audit_categories = require_string_set(audit_log, "categories", "snapshot.monitoring.audit_log")
    if not policy["required_categories"] <= audit_categories:
        add_finding(findings, "GHO-009", "audit category coverage is incomplete")
    if require_int(audit_log, "sequence_gap_count", "snapshot.monitoring.audit_log") != 0:
        add_finding(findings, "GHO-009", "audit sequence gaps remain unresolved")
    if drift.get("status") != "HEALTHY" or require_int(
        drift, "open_finding_count", "snapshot.monitoring.drift"
    ) != 0:
        add_finding(findings, "GHO-009", "organization posture drift remains open")
    if alert_delivery.get("status") != "DELIVERED":
        add_finding(findings, "GHO-009", "alert delivery test did not succeed")
    alert_tested_at = parse_time(
        alert_delivery.get("tested_at"), "snapshot.monitoring.alert_delivery.tested_at"
    )
    if age_days(alert_tested_at, evaluation_time, "alert delivery test") > policy[
        "maximum_alert_test_age_days"
    ]:
        add_finding(findings, "GHO-009", "alert delivery test is stale")

    if require_list(snapshot, "local_exceptions", "snapshot"):
        add_finding(findings, "GHO-010", "local exceptions bypass PSB-GOV-002 governance")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--evaluation-time", required=True)
    args = parser.parse_args()

    try:
        evaluation_time = parse_time(args.evaluation_time, "evaluation time")
        policy_document, policy_raw = load_json(args.policy, "governance policy")
        policy, weak_policy = validate_policy(policy_document)
        if weak_policy:
            print("FAIL GHO-010 policy can weaken the governance baseline: " + "; ".join(weak_policy))
            return 1

        snapshot, _ = load_json(args.snapshot, "organization snapshot")
        expected_policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
        if snapshot.get("policy_sha256") != expected_policy_sha256:
            raise EvidenceError("organization snapshot is not bound to the exact policy bytes")
        validate_inventory_shape(
            snapshot,
            evaluation_time,
            policy["maximum_snapshot_age_hours"],
        )
        findings = evaluate(policy, snapshot, evaluation_time)
    except EvidenceError as error:
        print(
            f"ERROR GitHub organization governance evidence unavailable: {error}",
            file=sys.stderr,
        )
        return 2

    if findings:
        for check_id in CHECK_ORDER:
            reasons = findings.get(check_id)
            if reasons:
                print(f"FAIL {check_id} " + "; ".join(reasons))
        return 1

    for check_id in CHECK_ORDER:
        print(f"PASS {check_id} {PASS_MESSAGES[check_id]}")
    print("NOT_CHECKED live GitHub settings IdP enforcement audit backend and mutation remain organization evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
