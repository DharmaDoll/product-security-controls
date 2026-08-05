#!/usr/bin/env python3
"""Verify provider-neutral container registry policy and evidence offline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


CHECK_ORDER = {f"REG-{number:03d}": number for number in range(1, 8)}
POLICY_VERSION_RE = re.compile(r"^[a-z0-9-]+@sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
ALLOWED_ACTIONS = {"admin", "delete", "pull", "push", "read-audit"}
AUDITED_ACTIONS = {"admin", "delete", "push"}
REQUIRED_AUDIT_FIELDS = {
    "action",
    "actor",
    "digest",
    "outcome",
    "repository",
    "request_id",
    "timestamp",
}
REQUIRED_SOURCES = {
    "audit-collector",
    "authorization-evaluator",
    "lifecycle-controller",
    "registry-api",
}
LIFECYCLE_STATES = {"active", "deprecated", "quarantined", "removed"}
EXPECTED_TRANSITIONS = {
    "active": ["deprecated", "quarantined"],
    "deprecated": ["quarantined", "removed"],
    "quarantined": ["removed"],
    "removed": [],
}
FORBIDDEN_KEYS = {
    "access_key",
    "access_token",
    "client_secret",
    "credential_value",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}


class InputError(ValueError):
    """Input or evidence cannot be evaluated safely."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise InputError(f"cannot read {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise InputError(f"invalid {label} JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    reject_secret_fields(value, label)
    return value


def reject_secret_fields(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise InputError(f"{label} contains a non-text key")
            if key.lower() in FORBIDDEN_KEYS:
                raise InputError(f"{label} contains forbidden credential field {key}")
            reject_secret_fields(child, label)
    elif isinstance(value, list):
        for child in value:
            reject_secret_fields(child, label)


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def objects(value: Any, label: str, *, non_empty: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise InputError(f"{label} must be a {qualifier}array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise InputError(f"{label}[{index}] must be an object")
        result.append(item)
    return result


def strings(value: Any, label: str, *, non_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise InputError(f"{label} must be a {qualifier}array")
    if not all(isinstance(item, str) and item for item in value):
        raise InputError(f"{label} must contain non-empty strings")
    if len(set(value)) != len(value):
        raise InputError(f"{label} must not contain duplicates")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{label} must be non-empty text")
    return value


def integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InputError(f"{label} must be an integer")
    return value


def instant(value: Any, label: str) -> datetime:
    raw = text(value, label)
    if not raw.endswith("Z"):
        raise InputError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} must be an RFC3339 UTC timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise InputError(f"{label} must use UTC")
    return parsed


def schema(value: dict[str, Any], expected: str, label: str) -> None:
    if value.get("schema") != expected:
        raise InputError(f"unsupported {label} schema")


def add(issues: list[tuple[str, str]], check_id: str, message: str) -> None:
    issues.append((check_id, message))


def exact_repository(value: Any, label: str) -> str:
    repository = text(value, label)
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise InputError(f"{label} must be an exact normalized repository")
    return repository


def exact_digest(value: Any, label: str) -> str:
    digest = text(value, label)
    if DIGEST_RE.fullmatch(digest) is None:
        raise InputError(f"{label} must be an exact sha256 digest")
    return digest


def request_id(value: Any, label: str) -> str:
    request = text(value, label)
    if REQUEST_RE.fullmatch(request) is None:
        raise InputError(f"{label} is invalid")
    return request


def freshness(
    observed: datetime,
    evaluation_time: datetime,
    maximum_age_seconds: int,
    label: str,
) -> None:
    if observed > evaluation_time:
        raise InputError(f"{label} is in the future")
    if evaluation_time - observed > timedelta(seconds=maximum_age_seconds):
        raise InputError(f"{label} is stale")


def validate_policy(policy: dict[str, Any]) -> list[tuple[str, str]]:
    schema(policy, "psb-container-registry-policy/v1", "policy")
    issues: list[tuple[str, str]] = []
    version = policy.get("policy_version")
    if not isinstance(version, str) or POLICY_VERSION_RE.fullmatch(version) is None:
        add(issues, "REG-007", "policy version is not immutable and digest-pinned")

    registries = objects(policy.get("registries"), "policy.registries", non_empty=True)
    registry_ids: set[str] = set()
    for item in registries:
        registry_id = text(item.get("id"), "registry.id")
        if registry_id == "*" or registry_id in registry_ids:
            add(issues, "REG-001", "registry identities must be unique and exact")
        registry_ids.add(registry_id)
        endpoint = text(item.get("endpoint"), "registry.endpoint")
        try:
            parsed = urlsplit(endpoint)
            endpoint_port = parsed.port
        except ValueError:
            parsed = urlsplit("invalid://invalid")
            endpoint_port = -1
        if (
            parsed.scheme != "https"
            or parsed.hostname != registry_id
            or parsed.username is not None
            or parsed.password is not None
            or endpoint_port not in {None, 443}
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            add(issues, "REG-001", "registry endpoint must be exact credential-free HTTPS")
        if item.get("minimum_tls_version") not in {"TLS1.2", "TLS1.3"}:
            add(issues, "REG-001", "registry minimum TLS version must be TLS1.2 or later")
        trust = item.get("trusted_ca_sha256")
        if not isinstance(trust, str) or SHA256_RE.fullmatch(trust) is None:
            add(issues, "REG-001", "registry trust anchor must be an exact SHA-256")

    authorization = mapping(policy.get("authorization"), "policy.authorization")
    if authorization.get("default") != "deny":
        add(issues, "REG-002", "registry authorization must default deny")
    public_repositories = strings(
        authorization.get("public_anonymous_pull_repositories"),
        "policy public anonymous pull repositories",
    )
    if any(item == "*" or REPOSITORY_RE.fullmatch(item) is None for item in public_repositories):
        add(issues, "REG-002", "anonymous pull repositories must be exact and reviewed")
    roles = objects(authorization.get("roles"), "policy.authorization.roles", non_empty=True)
    role_ids: set[str] = set()
    for role in roles:
        role_id = text(role.get("id"), "authorization role id")
        if role_id in role_ids:
            raise InputError("authorization role ids must be unique")
        role_ids.add(role_id)
        actors = strings(role.get("actors"), f"role {role_id} actors", non_empty=True)
        repositories = strings(
            role.get("repositories"), f"role {role_id} repositories", non_empty=True
        )
        actions = set(strings(role.get("actions"), f"role {role_id} actions", non_empty=True))
        if "*" in actors or "*" in repositories:
            add(issues, "REG-002", f"role {role_id} contains a wildcard actor or repository")
        if any(REPOSITORY_RE.fullmatch(item) is None for item in repositories if item != "*"):
            add(issues, "REG-002", f"role {role_id} contains a non-exact repository")
        if not actions <= ALLOWED_ACTIONS:
            raise InputError(f"role {role_id} contains an unsupported action")
        if actions == ALLOWED_ACTIONS:
            add(issues, "REG-002", f"role {role_id} combines all registry authority")

    identity = mapping(policy.get("identity"), "policy.identity")
    if identity.get("source_control") != "PSB-CICD-006":
        add(issues, "REG-003", "workload identity source must be PSB-CICD-006")
    if identity.get("credential_kind") != "oidc-exchange":
        add(issues, "REG-003", "registry automation must use an OIDC exchange")
    audience = identity.get("audience")
    if not isinstance(audience, str) or audience == "*" or audience not in registry_ids:
        add(issues, "REG-003", "identity audience must be one exact trusted registry")
    maximum_ttl = integer(identity.get("maximum_ttl_seconds"), "identity maximum TTL")
    if not 1 <= maximum_ttl <= 3600:
        add(issues, "REG-003", "identity maximum TTL must be between 1 and 3600 seconds")
    if identity.get("stored_credentials_allowed") is not False:
        add(issues, "REG-003", "stored registry credentials are allowed")

    protection = mapping(policy.get("release_protection"), "policy.release_protection")
    protected_repositories = strings(
        protection.get("protected_repositories"),
        "protected repositories",
        non_empty=True,
    )
    if any(item == "*" or REPOSITORY_RE.fullmatch(item) is None for item in protected_repositories):
        add(issues, "REG-004", "protected repositories must be exact")
    prefixes = strings(
        protection.get("protected_tag_prefixes"),
        "protected tag prefixes",
        non_empty=True,
    )
    if any(item == "*" or not item.strip() for item in prefixes):
        add(issues, "REG-004", "protected tag prefixes must be non-wildcard")
    if protection.get("allow_tag_overwrite") is not False:
        add(issues, "REG-004", "protected release tag overwrite is allowed")
    if protection.get("allow_protected_digest_delete") is not False:
        add(issues, "REG-004", "protected digest deletion is allowed")

    audit = mapping(policy.get("audit"), "policy.audit")
    if not AUDITED_ACTIONS <= set(
        strings(audit.get("required_actions"), "audit required actions")
    ):
        add(issues, "REG-005", "audit policy must cover push delete and admin")
    sensitive = set(
        strings(audit.get("sensitive_read_repositories"), "sensitive read repositories")
    )
    if not set(protected_repositories) <= sensitive:
        add(issues, "REG-005", "protected repository reads are not classified as sensitive")
    if not REQUIRED_AUDIT_FIELDS <= set(
        strings(audit.get("required_fields"), "audit required fields")
    ):
        add(issues, "REG-005", "audit required fields are incomplete")
    lag = integer(audit.get("maximum_lag_seconds"), "audit maximum lag")
    if not 1 <= lag <= 900:
        add(issues, "REG-005", "audit maximum lag must be between 1 and 900 seconds")
    retention = integer(audit.get("minimum_retention_days"), "audit minimum retention")
    if not 30 <= retention <= 3650:
        add(issues, "REG-005", "audit retention must be between 30 and 3650 days")

    lifecycle = mapping(policy.get("lifecycle"), "policy.lifecycle")
    if (
        set(strings(lifecycle.get("allowed_states"), "lifecycle allowed states"))
        != LIFECYCLE_STATES
    ):
        add(issues, "REG-006", "lifecycle must distinguish all four reviewed states")
    transitions = mapping(lifecycle.get("state_transitions"), "lifecycle state transitions")
    if transitions != EXPECTED_TRANSITIONS:
        add(issues, "REG-006", "lifecycle state transitions are not the reviewed state machine")
    active_days = integer(lifecycle.get("maximum_active_age_days"), "maximum active age")
    deprecated_days = integer(
        lifecycle.get("deprecation_removal_days"), "deprecation removal days"
    )
    quarantine_days = integer(
        lifecycle.get("maximum_quarantine_days"), "maximum quarantine days"
    )
    if not 1 <= active_days <= 365:
        add(issues, "REG-006", "maximum active age must be between 1 and 365 days")
    if not 1 <= deprecated_days <= 90:
        add(issues, "REG-006", "deprecation removal deadline must be within 90 days")
    if not 1 <= quarantine_days <= 90:
        add(issues, "REG-006", "quarantine deadline must be within 90 days")
    if lifecycle.get("stale_action") != "quarantine":
        add(issues, "REG-006", "stale images are not assigned to quarantine")
    if lifecycle.get("evidence_error_action") != "error":
        add(issues, "REG-006", "lifecycle evidence failure can be treated as quarantine")

    evidence = mapping(policy.get("evidence"), "policy.evidence")
    maximum_age = integer(evidence.get("maximum_age_seconds"), "evidence maximum age")
    if not 1 <= maximum_age <= 3600:
        add(issues, "REG-007", "evidence freshness window must be between 1 and 3600 seconds")
    sources = set(strings(evidence.get("required_sources"), "required evidence sources"))
    if not REQUIRED_SOURCES <= sources:
        add(issues, "REG-007", "required evidence source inventory is incomplete")
    return issues


def role_allows(policy: dict[str, Any], actor: str, repository: str, action: str) -> bool:
    authorization = mapping(policy.get("authorization"), "policy.authorization")
    if actor == "anonymous" and action == "pull":
        public = strings(
            authorization.get("public_anonymous_pull_repositories"),
            "public anonymous pull repositories",
        )
        if repository in public or "*" in public:
            return True
    for role in objects(authorization.get("roles"), "authorization roles"):
        actors = strings(role.get("actors"), "role actors")
        repositories = strings(role.get("repositories"), "role repositories")
        actions = strings(role.get("actions"), "role actions")
        if (
            (actor in actors or "*" in actors)
            and (repository in repositories or "*" in repositories)
            and action in actions
        ):
            return True
    return authorization.get("default") == "allow"


def validate_identity(
    policy: dict[str, Any],
    identity: dict[str, Any],
    evaluation_time: datetime,
) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    schema(identity, "psb-container-registry-identity/v1", "identity")
    issues: list[tuple[str, str]] = []
    expected = mapping(policy.get("identity"), "policy.identity")
    actor = text(identity.get("actor"), "identity.actor")
    repository = exact_repository(identity.get("repository"), "identity.repository")
    actions = strings(identity.get("actions"), "identity.actions", non_empty=True)
    if not set(actions) <= ALLOWED_ACTIONS:
        raise InputError("identity.actions contains an unsupported action")
    request_id(identity.get("request_id"), "identity.request_id")
    issued_at = instant(identity.get("issued_at"), "identity.issued_at")
    expires_at = instant(identity.get("expires_at"), "identity.expires_at")
    if expires_at <= issued_at:
        raise InputError("identity expiry must be after issue time")
    if identity.get("source_control") != expected.get("source_control"):
        add(issues, "REG-003", "identity receipt is not sourced from PSB-CICD-006")
    if actor == "*":
        add(issues, "REG-003", "identity actor must be exact")
    if identity.get("credential_kind") != expected.get("credential_kind"):
        add(issues, "REG-003", "identity credential kind does not match policy")
    if identity.get("audience") != expected.get("audience"):
        add(issues, "REG-003", "identity audience does not match the registry")
    ttl = int((expires_at - issued_at).total_seconds())
    maximum_ttl = integer(expected.get("maximum_ttl_seconds"), "identity maximum TTL")
    if ttl > maximum_ttl:
        add(issues, "REG-003", "identity lifetime exceeds the policy maximum")
    if not issued_at <= evaluation_time < expires_at:
        add(issues, "REG-003", "identity is not current at evaluation time")
    if identity.get("stored_credential") is not False:
        add(issues, "REG-003", "identity evidence reports a stored credential")
    for action in actions:
        if not role_allows(policy, actor, repository, action):
            add(issues, "REG-003", "identity scope is not authorized by an exact registry role")
    return issues, {
        "actor": actor,
        "repository": repository,
        "actions": actions,
    }


def validate_operations(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    identity_scope: dict[str, Any],
    evaluation_time: datetime,
    maximum_age: int,
) -> tuple[list[tuple[str, str]], list[dict[str, Any]]]:
    schema(evidence, "psb-container-registry-operations/v1", "operations")
    if evidence.get("complete") is not True:
        raise InputError("registry operation evidence is incomplete")
    freshness(
        instant(evidence.get("observed_at"), "operations.observed_at"),
        evaluation_time,
        maximum_age,
        "registry operation evidence",
    )
    operations = objects(evidence.get("operations"), "operations", non_empty=True)
    issues: list[tuple[str, str]] = []
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    protection = mapping(policy.get("release_protection"), "policy.release_protection")
    protected_repositories = set(
        strings(protection.get("protected_repositories"), "protected repositories")
    )
    protected_prefixes = strings(
        protection.get("protected_tag_prefixes"), "protected tag prefixes"
    )
    published_tags: dict[tuple[str, str], str] = {}
    protected_digests: set[tuple[str, str]] = set()
    previous_time: datetime | None = None
    identity_operation_seen = False
    for index, operation in enumerate(operations):
        label = f"operations[{index}]"
        request = request_id(operation.get("request_id"), f"{label}.request_id")
        if request in seen:
            raise InputError("operation request ids must be unique")
        seen.add(request)
        actor = text(operation.get("actor"), f"{label}.actor")
        repository = exact_repository(operation.get("repository"), f"{label}.repository")
        action = text(operation.get("action"), f"{label}.action")
        if action not in ALLOWED_ACTIONS:
            raise InputError(f"{label}.action is unsupported")
        digest = exact_digest(operation.get("digest"), f"{label}.digest")
        tag = text(operation.get("tag"), f"{label}.tag")
        if TAG_RE.fullmatch(tag) is None:
            raise InputError(f"{label}.tag is not a normalized OCI tag")
        occurred_at = instant(operation.get("timestamp"), f"{label}.timestamp")
        if occurred_at > evaluation_time:
            raise InputError(f"{label}.timestamp is in the future")
        if previous_time is not None and occurred_at < previous_time:
            raise InputError("registry operations must be ordered by timestamp")
        previous_time = occurred_at
        outcome = text(operation.get("outcome"), f"{label}.outcome")
        if outcome not in {"allowed", "denied"}:
            raise InputError(f"{label}.outcome must be allowed or denied")
        authorized = role_allows(policy, actor, repository, action)
        protected = repository in protected_repositories and any(
            tag.startswith(prefix) for prefix in protected_prefixes
        )
        tag_key = (repository, tag)
        deletes_protected_digest = (repository, digest) in protected_digests
        if (
            action == "delete"
            and (protected or deletes_protected_digest)
            and not protection.get("allow_protected_digest_delete")
        ):
            authorized = False
        if (
            protected
            and action == "push"
            and tag_key in published_tags
            and published_tags[tag_key] != digest
            and not protection.get("allow_tag_overwrite")
        ):
            authorized = False
        expected = "allowed" if authorized else "denied"
        if outcome != expected:
            add(issues, "REG-002", "recorded authorization outcome differs from policy")
        if actor == "anonymous" and action != "pull" and outcome == "allowed":
            add(issues, "REG-002", "an anonymous write or administrative action was allowed")
        if (
            actor == identity_scope["actor"]
            and action in identity_scope["actions"]
        ):
            identity_operation_seen = True
            if repository != identity_scope["repository"] and outcome == "allowed":
                add(
                    issues,
                    "REG-002",
                    "the workload identity performed a cross-repository action",
                )
        if action == "push" and outcome == "allowed":
            published_tags[tag_key] = digest
            if protected:
                protected_digests.add((repository, digest))
        normalized.append(
            {
                "request_id": request,
                "actor": actor,
                "repository": repository,
                "action": action,
                "digest": digest,
                "tag": tag,
                "timestamp": operation["timestamp"],
                "occurred_at": occurred_at,
                "outcome": outcome,
            }
        )
    if not identity_operation_seen:
        raise InputError("workload identity operation evidence is missing")
    return issues, normalized


def check_release_protection(
    policy: dict[str, Any], operations: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    protection = mapping(policy.get("release_protection"), "policy.release_protection")
    repositories = set(
        strings(protection.get("protected_repositories"), "protected repositories")
    )
    prefixes = strings(protection.get("protected_tag_prefixes"), "protected prefixes")
    issues: list[tuple[str, str]] = []
    tag_digests: dict[tuple[str, str], str] = {}
    protected_digests: set[tuple[str, str]] = set()
    protected_seen = False
    for operation in sorted(operations, key=lambda item: item["occurred_at"]):
        protected = operation["repository"] in repositories and any(
            operation["tag"].startswith(prefix) for prefix in prefixes
        )
        if not protected:
            continue
        protected_seen = True
        if operation["outcome"] != "allowed":
            continue
        key = (operation["repository"], operation["tag"])
        if operation["action"] == "push":
            previous = tag_digests.get(key)
            if previous is not None and previous != operation["digest"]:
                add(issues, "REG-004", "a protected release tag was replaced")
            tag_digests[key] = operation["digest"]
            protected_digests.add((operation["repository"], operation["digest"]))
        elif operation["action"] == "delete":
            add(issues, "REG-004", "a protected release digest was deleted")
    for operation in operations:
        if (
            operation["action"] == "delete"
            and operation["outcome"] == "allowed"
            and (operation["repository"], operation["digest"]) in protected_digests
        ):
            add(issues, "REG-004", "a protected release digest was deleted")
    if not protected_seen:
        raise InputError("protected release operation evidence is missing")
    return issues


def validate_audit(
    policy: dict[str, Any],
    audit: dict[str, Any],
    operations: list[dict[str, Any]],
    evaluation_time: datetime,
    maximum_age: int,
) -> list[tuple[str, str]]:
    schema(audit, "psb-container-registry-audit/v1", "audit")
    if audit.get("status") != "ok":
        raise InputError("audit collector status is not ok")
    if audit.get("complete") is not True:
        raise InputError("audit evidence is incomplete")
    observed_at = instant(audit.get("observed_at"), "audit.observed_at")
    freshness(observed_at, evaluation_time, maximum_age, "audit evidence")
    issues: list[tuple[str, str]] = []
    if audit.get("redacted") is not True:
        add(issues, "REG-005", "audit evidence is not marked redacted")
    records = objects(audit.get("records"), "audit.records")
    by_request: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        label = f"audit.records[{index}]"
        text(record.get("event_id"), f"{label}.event_id")
        request = request_id(record.get("request_id"), f"{label}.request_id")
        if request in by_request:
            raise InputError("audit request ids must be unique")
        for field in REQUIRED_AUDIT_FIELDS:
            if field not in record:
                raise InputError(f"{label} is missing {field}")
        exact_repository(record.get("repository"), f"{label}.repository")
        exact_digest(record.get("digest"), f"{label}.digest")
        instant(record.get("timestamp"), f"{label}.timestamp")
        text(record.get("actor"), f"{label}.actor")
        if record.get("action") not in ALLOWED_ACTIONS:
            raise InputError(f"{label}.action is unsupported")
        if record.get("outcome") not in {"allowed", "denied"}:
            raise InputError(f"{label}.outcome must be allowed or denied")
        by_request[request] = record

    audit_policy = mapping(policy.get("audit"), "policy.audit")
    sensitive = set(
        strings(audit_policy.get("sensitive_read_repositories"), "sensitive repositories")
    ) | set(
        strings(
            mapping(policy.get("release_protection"), "release protection").get(
                "protected_repositories"
            ),
            "protected repositories",
        )
    )
    maximum_lag = integer(audit_policy.get("maximum_lag_seconds"), "audit lag")
    for operation in operations:
        required = operation["action"] in AUDITED_ACTIONS or (
            operation["action"] == "pull" and operation["repository"] in sensitive
        )
        if not required:
            continue
        record = by_request.get(operation["request_id"])
        if record is None:
            add(issues, "REG-005", "a required registry operation has no audit record")
            continue
        for field in REQUIRED_AUDIT_FIELDS:
            if record.get(field) != operation.get(field):
                add(issues, "REG-005", "an audit record does not match its registry operation")
                break
        if observed_at - operation["occurred_at"] > timedelta(seconds=maximum_lag):
            add(issues, "REG-005", "an audit record exceeded the maximum collection lag")
    return issues


def validate_lifecycle(
    policy: dict[str, Any],
    inventory: dict[str, Any],
    evaluation_time: datetime,
    maximum_age: int,
) -> list[tuple[str, str]]:
    schema(inventory, "psb-container-registry-inventory/v1", "inventory")
    if inventory.get("status") != "ok":
        raise InputError("lifecycle inventory status is not ok")
    if inventory.get("complete") is not True:
        raise InputError("lifecycle inventory is incomplete")
    freshness(
        instant(inventory.get("observed_at"), "inventory.observed_at"),
        evaluation_time,
        maximum_age,
        "lifecycle inventory",
    )
    lifecycle = mapping(policy.get("lifecycle"), "policy.lifecycle")
    active_days = integer(lifecycle.get("maximum_active_age_days"), "maximum active age")
    deprecated_days = integer(
        lifecycle.get("deprecation_removal_days"), "deprecation removal days"
    )
    quarantine_days = integer(
        lifecycle.get("maximum_quarantine_days"), "maximum quarantine days"
    )
    issues: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    images = objects(inventory.get("images"), "inventory.images", non_empty=True)
    for index, image in enumerate(images):
        label = f"inventory.images[{index}]"
        repository = exact_repository(image.get("repository"), f"{label}.repository")
        digest = exact_digest(image.get("digest"), f"{label}.digest")
        identity = (repository, digest)
        if identity in seen:
            raise InputError("lifecycle image identities must be unique")
        seen.add(identity)
        created_at = instant(image.get("created_at"), f"{label}.created_at")
        changed_at = instant(image.get("state_changed_at"), f"{label}.state_changed_at")
        if changed_at < created_at or changed_at > evaluation_time:
            raise InputError(f"{label} state time is inconsistent")
        state = text(image.get("state"), f"{label}.state")
        if state not in LIFECYCLE_STATES:
            raise InputError(f"{label}.state is unsupported")
        deployable = image.get("deployable")
        available = image.get("available")
        if not isinstance(deployable, bool) or not isinstance(available, bool):
            raise InputError(f"{label} deployable and available must be booleans")
        if state == "active":
            if evaluation_time - created_at > timedelta(days=active_days):
                add(issues, "REG-006", "a stale image remains active")
            if not deployable or not available:
                add(issues, "REG-006", "an active image is not consistently available")
            continue

        if deployable:
            add(issues, "REG-006", "a non-active image remains deployable")
        decision = mapping(image.get("decision"), f"{label}.decision")
        decision_status = text(decision.get("status"), f"{label}.decision.status")
        text(decision.get("source"), f"{label}.decision.source")
        if decision_status == "error":
            raise InputError(
                "lifecycle decision evidence failed; scanner failure is not quarantine evidence"
            )
        if decision_status != "verified":
            raise InputError(f"{label} lifecycle decision evidence is not verified")

        if state in {"deprecated", "quarantined"}:
            due = instant(image.get("removal_due_at"), f"{label}.removal_due_at")
            allowed_days = deprecated_days if state == "deprecated" else quarantine_days
            if due > changed_at + timedelta(days=allowed_days):
                add(issues, "REG-006", f"{state} image removal deadline is unbounded")
            if due < evaluation_time and available:
                add(issues, "REG-006", f"expired {state} image remains available")
        elif state == "removed":
            removed_at = instant(image.get("removed_at"), f"{label}.removed_at")
            if removed_at < changed_at or removed_at > evaluation_time:
                raise InputError(f"{label}.removed_at is inconsistent")
            if available:
                add(issues, "REG-006", "removed image remains available")
    return issues


def validate_health(
    policy: dict[str, Any], health: dict[str, Any], evaluation_time: datetime
) -> int:
    schema(health, "psb-container-registry-evidence-health/v1", "evidence health")
    configured = mapping(policy.get("evidence"), "policy.evidence")
    configured_age = integer(configured.get("maximum_age_seconds"), "evidence maximum age")
    maximum_age = min(max(configured_age, 1), 3600)
    freshness(
        instant(health.get("observed_at"), "evidence health observed_at"),
        evaluation_time,
        maximum_age,
        "evidence health manifest",
    )
    sources = objects(health.get("sources"), "evidence health sources", non_empty=True)
    names: set[str] = set()
    for source in sources:
        name = text(source.get("name"), "evidence source name")
        if name in names:
            raise InputError("evidence source names must be unique")
        names.add(name)
        if source.get("status") != "ok":
            raise InputError(f"required evidence source {name} is unavailable")
        if source.get("complete") is not True:
            raise InputError(f"required evidence source {name} is incomplete")
        freshness(
            instant(source.get("last_success_at"), f"source {name} last_success_at"),
            evaluation_time,
            maximum_age,
            f"required evidence source {name}",
        )
    if not REQUIRED_SOURCES <= names:
        raise InputError("required evidence source health inventory is incomplete")
    return maximum_age


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify provider-neutral container registry policy evidence."
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--operations", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--evidence-health", type=Path, required=True)
    parser.add_argument("--evaluation-time", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        evaluation_time = instant(args.evaluation_time, "evaluation time")
        policy = load_json(args.policy, "policy")
        identity = load_json(args.identity, "identity")
        operations = load_json(args.operations, "operations")
        audit = load_json(args.audit, "audit")
        inventory = load_json(args.inventory, "inventory")
        health = load_json(args.evidence_health, "evidence health")

        issues = validate_policy(policy)
        maximum_age = validate_health(policy, health, evaluation_time)
        identity_issues, identity_scope = validate_identity(
            policy, identity, evaluation_time
        )
        operation_issues, normalized_operations = validate_operations(
            policy,
            operations,
            identity_scope,
            evaluation_time,
            maximum_age,
        )
        issues.extend(identity_issues)
        issues.extend(operation_issues)
        issues.extend(check_release_protection(policy, normalized_operations))
        issues.extend(
            validate_audit(
                policy,
                audit,
                normalized_operations,
                evaluation_time,
                maximum_age,
            )
        )
        issues.extend(
            validate_lifecycle(
                policy,
                inventory,
                evaluation_time,
                maximum_age,
            )
        )
    except InputError as error:
        print(f"ERROR PSB-CONTAINER-002 registry evaluation unavailable: {error}")
        return 2

    if issues:
        print("FAIL PSB-CONTAINER-002 registry policy rejected")
        for check_id, message in sorted(
            set(issues), key=lambda item: (CHECK_ORDER[item[0]], item[1])
        ):
            print(f"FAIL {check_id} {message}")
        return 1

    print("PASS PSB-CONTAINER-002 registry policy accepted")
    print("PASS REG-001 TLS-only trusted registry identity verified")
    print("PASS REG-002 repository-scoped default-deny authorization verified")
    print("PASS REG-003 short-lived PSB-CICD-006 identity binding verified")
    print("PASS REG-004 protected release mutation and deletion denied")
    print("PASS REG-005 attributable redacted audit correlation verified")
    print("PASS REG-006 bounded non-deployable image lifecycle verified")
    print("PASS REG-007 complete fresh evidence sources verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
