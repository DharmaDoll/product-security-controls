#!/usr/bin/env python3
"""Verify provider-neutral supply-chain credential containment evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REFERENCE_MAX_INVENTORY_AGE_HOURS = 24
REFERENCE_MAX_AUTHORIZATION_HOURS = 4
REFERENCE_ROLES = {"incident-commander", "credential-owner"}
REFERENCE_DISPOSITIONS = {
    "migrated",
    "removed",
    "quarantined",
    "owner-approved-not-applicable",
}
REFERENCE_SURFACES = {
    "source-access",
    "ci-secret",
    "package-publishing",
    "container-registry",
    "cloud-deployment",
    "ssh-access",
    "artifact-signing",
}
REFERENCE_STATES = [
    "SUSPECTED",
    "CONTAINMENT_AUTHORIZED",
    "OLD_AUTHORITY_DISABLED",
    "DEPENDENT_AUTHORITY_INVALIDATED",
    "REPLACEMENT_BOUND",
    "CONSUMERS_MIGRATED",
    "OLD_AUTHORITY_DENIED",
    "IMPACT_REVIEWED",
    "CLOSED",
]
REFERENCE_CLASS_ACTIONS = {
    "reusable-bearer": {
        "containment": {"disable-old-authority", "invalidate-dependent-authority"},
        "replacement": {
            "issue-least-privilege-replacement",
            "bind-replacement",
        },
        "replacement_required": True,
        "maximum_lifetime_hours": 720,
    },
    "ssh-key": {
        "containment": {"remove-old-key", "invalidate-dependent-authority"},
        "replacement": {"enroll-new-key", "bind-replacement"},
        "replacement_required": True,
        "maximum_lifetime_hours": 2160,
    },
    "signing-key": {
        "containment": {
            "revoke-signer-trust",
            "publish-fresh-signer-status",
            "review-signed-artifacts",
        },
        "replacement": {"distribute-replacement-trust", "bind-replacement"},
        "replacement_required": True,
        "maximum_lifetime_hours": 2160,
    },
    "short-lived-session": {
        "containment": {"block-replay-or-issuer-path", "repair-trust-policy"},
        "replacement": set(),
        "replacement_required": False,
        "maximum_lifetime_hours": 1,
    },
}
REQUIRED_ACTION_SCOPE = {
    "containment",
    "replacement",
    "migration",
    "denial-test",
    "impact-review",
    "closure",
}
ALLOWED_IMPACT_KINDS = {
    "repository",
    "workflow",
    "package",
    "image",
    "attestation",
    "release",
    "artifact",
    "deployment",
}
FORBIDDEN_FIELDS = {
    "secret",
    "secret_value",
    "token",
    "token_value",
    "credential_value",
    "password",
    "private_key",
    "private_key_material",
    "signing_material",
    "key_material",
    "raw_value",
}
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@+-]*$")


class VerificationError(ValueError):
    """Evidence cannot support a security decision."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return value


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{label} must be a list")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VerificationError(f"{label} must be non-empty text")
    return value.strip()


def require_id(value: Any, label: str) -> str:
    identifier = require_text(value, label)
    if not ID_RE.fullmatch(identifier):
        raise VerificationError(f"{label} must be a stable non-secret identifier")
    return identifier


def require_string_set(value: Any, label: str, *, nonempty: bool = True) -> set[str]:
    items = require_list(value, label)
    if nonempty and not items:
        raise VerificationError(f"{label} must not be empty")
    if not all(isinstance(item, str) and item.strip() for item in items):
        raise VerificationError(f"{label} must contain non-empty strings")
    normalized = {item.strip() for item in items}
    if len(normalized) != len(items):
        raise VerificationError(f"{label} must not contain duplicates")
    return normalized


def parse_timestamp(value: Any, label: str) -> datetime:
    text = require_text(value, label)
    if not text.endswith("Z"):
        raise VerificationError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise VerificationError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise VerificationError(f"{label} must use UTC")
    return parsed


def reject_sensitive_content(value: Any, path: str = "input") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in FORBIDDEN_FIELDS:
                raise VerificationError(f"{path} contains forbidden sensitive field {key}")
            reject_sensitive_content(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_content(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
            raise VerificationError(f"{path} contains forbidden credential material")


def validate_policy(policy: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    findings: list[str] = []
    if policy.get("schema") != "psb-credential-response-policy/1.0":
        raise VerificationError("policy schema is unsupported")

    inventory_age = policy.get("max_inventory_age_hours")
    auth_hours = policy.get("max_authorization_hours")
    if not isinstance(inventory_age, int) or inventory_age <= 0:
        raise VerificationError("policy max_inventory_age_hours must be a positive integer")
    if not isinstance(auth_hours, int) or auth_hours <= 0:
        raise VerificationError("policy max_authorization_hours must be a positive integer")
    if inventory_age > REFERENCE_MAX_INVENTORY_AGE_HOURS:
        findings.append("policy permits credential inventory older than 24 hours")
    if auth_hours > REFERENCE_MAX_AUTHORIZATION_HOURS:
        findings.append("policy permits response authorization longer than 4 hours")

    roles = require_string_set(policy.get("authorization_roles"), "policy.authorization_roles")
    dispositions = require_string_set(
        policy.get("consumer_dispositions"), "policy.consumer_dispositions"
    )
    surfaces = require_string_set(
        policy.get("required_coverage_surfaces"), "policy.required_coverage_surfaces"
    )
    states = [require_text(item, "policy.required_state_order entry") for item in require_list(
        policy.get("required_state_order"), "policy.required_state_order"
    )]
    if roles != REFERENCE_ROLES:
        findings.append("policy authorization roles are not independently bounded")
    if dispositions != REFERENCE_DISPOSITIONS:
        findings.append("policy consumer dispositions permit incomplete migration")
    if surfaces != REFERENCE_SURFACES:
        findings.append("policy does not require all seven supply-chain credential surfaces")
    if states != REFERENCE_STATES:
        findings.append("policy state machine does not require containment migration denial and impact review before closure")

    classes = require_object(policy.get("credential_classes"), "policy.credential_classes")
    if set(classes) != set(REFERENCE_CLASS_ACTIONS):
        findings.append("policy credential-class response coverage is incomplete")
    for class_name, reference in REFERENCE_CLASS_ACTIONS.items():
        raw = classes.get(class_name)
        if raw is None:
            continue
        config = require_object(raw, f"policy.credential_classes.{class_name}")
        containment = require_string_set(
            config.get("containment_actions"),
            f"policy.credential_classes.{class_name}.containment_actions",
            nonempty=False,
        )
        replacement = require_string_set(
            config.get("replacement_actions"),
            f"policy.credential_classes.{class_name}.replacement_actions",
            nonempty=False,
        )
        if containment != reference["containment"]:
            findings.append(f"policy {class_name} containment actions are incomplete")
        if replacement != reference["replacement"]:
            findings.append(f"policy {class_name} replacement actions are incomplete")
        if config.get("replacement_required") is not reference["replacement_required"]:
            findings.append(f"policy {class_name} replacement decision is unsafe")
        lifetime = config.get("maximum_replacement_lifetime_hours")
        if not isinstance(lifetime, int) or lifetime <= 0:
            raise VerificationError(
                f"policy {class_name} maximum replacement lifetime must be positive"
            )
        if lifetime > reference["maximum_lifetime_hours"]:
            findings.append(f"policy {class_name} replacement lifetime exceeds the reference ceiling")

    denial = require_object(policy.get("denial_probe"), "policy.denial_probe")
    if (
        denial.get("required") is not True
        or denial.get("independent_from_replacement") is not True
        or denial.get("skipped_or_unsupported_state") != "ERROR"
    ):
        findings.append("policy does not require an independent fail-closed old-authority denial probe")
    if policy.get("live_mutation") != "NOT_CHECKED":
        findings.append("policy permits unreviewed live provider mutation")
    if policy.get("dry_run_required") is not True:
        findings.append("policy does not require a dry-run response plan")
    if policy.get("empty_audit_result") != "NOT_PROOF_OF_NO_ABUSE":
        findings.append("policy treats an empty audit result as proof of no abuse")
    return classes, findings


def validate_inventory(
    inventory: dict[str, Any], policy: dict[str, Any], evaluation_time: datetime
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    findings: list[str] = []
    if inventory.get("schema") != "psb-credential-relationship-inventory/1.0":
        raise VerificationError("credential inventory schema is unsupported")
    if inventory.get("adapter_status") != "HEALTHY":
        raise VerificationError("credential inventory adapter is unavailable or unhealthy")
    if inventory.get("complete") is not True:
        raise VerificationError("credential inventory is incomplete")
    if inventory.get("relationship_graph_complete") is not True:
        raise VerificationError("credential relationship graph is incomplete")
    captured_at = parse_timestamp(inventory.get("captured_at"), "inventory.captured_at")
    age_hours = (evaluation_time - captured_at).total_seconds() / 3600
    if age_hours < 0:
        raise VerificationError("credential inventory is from the future")
    max_age = policy.get("max_inventory_age_hours")
    if age_hours > max_age or age_hours > REFERENCE_MAX_INVENTORY_AGE_HOURS:
        raise VerificationError("credential inventory is stale")

    surfaces = require_string_set(inventory.get("coverage_surfaces"), "inventory.coverage_surfaces")
    if surfaces != REFERENCE_SURFACES:
        findings.append("credential relationship graph does not cover all seven supply-chain surfaces")

    credentials: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(require_list(inventory.get("credentials"), "inventory.credentials")):
        credential = require_object(raw, f"inventory.credentials[{index}]")
        identifier = require_id(credential.get("credential_id"), f"inventory.credentials[{index}].credential_id")
        if identifier in credentials:
            raise VerificationError(f"credential identifier {identifier} is ambiguous")
        credential_class = require_text(
            credential.get("credential_class"), f"credential {identifier} credential_class"
        )
        if credential_class not in REFERENCE_CLASS_ACTIONS:
            raise VerificationError(f"credential {identifier} has unsupported credential class")
        surface = require_text(credential.get("surface"), f"credential {identifier} surface")
        if surface not in surfaces:
            raise VerificationError(f"credential {identifier} surface is absent from inventory coverage")
        require_text(credential.get("provider"), f"credential {identifier} provider")
        require_text(credential.get("owner"), f"credential {identifier} owner")
        require_text(credential.get("purpose"), f"credential {identifier} purpose")
        require_string_set(credential.get("scopes"), f"credential {identifier} scopes")
        require_string_set(credential.get("resources"), f"credential {identifier} resources")
        require_string_set(credential.get("consumers"), f"credential {identifier} consumers")
        parse_timestamp(credential.get("expires_at"), f"credential {identifier} expires_at")
        credentials[identifier] = credential
    if not credentials:
        raise VerificationError("credential inventory is empty")
    return credentials, findings


def validate_state_transitions(
    incident_id: str,
    incident: dict[str, Any],
    policy: dict[str, Any],
    evaluation_time: datetime,
) -> list[str]:
    findings: list[str] = []
    transitions = require_list(incident.get("state_transitions"), f"incident {incident_id} state_transitions")
    states: list[str] = []
    timestamps: list[datetime] = []
    outcomes: dict[str, str] = {}
    for index, raw in enumerate(transitions):
        transition = require_object(raw, f"incident {incident_id} state_transitions[{index}]")
        state = require_text(transition.get("state"), f"incident {incident_id} state")
        if state in outcomes:
            raise VerificationError(f"incident {incident_id} duplicates state {state}")
        states.append(state)
        timestamps.append(parse_timestamp(transition.get("at"), f"incident {incident_id} state {state} timestamp"))
        outcomes[state] = require_text(transition.get("outcome"), f"incident {incident_id} state {state} outcome")
    configured_states = [
        require_text(item, "policy state")
        for item in require_list(policy.get("required_state_order"), "policy.required_state_order")
    ]
    if states != configured_states:
        raise VerificationError(f"incident {incident_id} state transitions are missing or out of order")
    if timestamps != sorted(timestamps) or any(timestamp > evaluation_time for timestamp in timestamps):
        raise VerificationError(f"incident {incident_id} state transition timestamps are out of order or future dated")
    if states != REFERENCE_STATES:
        findings.append(f"incident {incident_id} closure path omits mandatory containment states")
    if any(outcome not in {"COMPLETED", "NOT_REQUIRED"} for outcome in outcomes.values()):
        raise VerificationError(f"incident {incident_id} contains an incomplete state transition")
    return findings


def validate_response_plan(incident_id: str, incident: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    plan = require_list(incident.get("response_plan"), f"incident {incident_id} response_plan")
    if not plan:
        raise VerificationError(f"incident {incident_id} response plan is empty")
    sequences: list[int] = []
    actions: list[str] = []
    for index, raw in enumerate(plan):
        step = require_object(raw, f"incident {incident_id} response_plan[{index}]")
        sequence = step.get("sequence")
        if not isinstance(sequence, int) or sequence <= 0:
            raise VerificationError(f"incident {incident_id} response plan sequence is invalid")
        sequences.append(sequence)
        action = require_text(step.get("action"), f"incident {incident_id} response action")
        required_state = require_text(
            step.get("requires_state"), f"incident {incident_id} response requires_state"
        )
        actions.append(action)
        if action == "repository-cleanup" and required_state not in {
            "OLD_AUTHORITY_DENIED",
            "IMPACT_REVIEWED",
        }:
            findings.append(f"incident {incident_id} permits repository cleanup before old-authority denial")
        if action in {"artifact-quarantine", "artifact-delete", "artifact-republish"} and required_state != "IMPACT_REVIEWED":
            findings.append(f"incident {incident_id} permits destructive artifact action before impact review")
        if action == "close-incident" and required_state != "IMPACT_REVIEWED":
            findings.append(f"incident {incident_id} permits closure before impact review")
    if sequences != list(range(1, len(plan) + 1)):
        raise VerificationError(f"incident {incident_id} response plan sequence is incomplete")
    if actions[0] != "preserve-evidence":
        findings.append(f"incident {incident_id} response plan does not preserve evidence first")
    return findings


def validate_replacement(
    incident_id: str,
    credential: dict[str, Any],
    evidence: dict[str, Any],
    reference: dict[str, Any],
) -> list[str]:
    findings: list[str] = []
    replacement = evidence.get("replacement")
    probe = require_object(evidence.get("replacement_probe"), f"incident {incident_id} replacement_probe")
    if reference["replacement_required"]:
        replacement = require_object(replacement, f"incident {incident_id} replacement")
        replacement_id = require_id(replacement.get("credential_id"), f"incident {incident_id} replacement credential_id")
        if replacement_id == credential.get("credential_id"):
            raise VerificationError(f"incident {incident_id} replacement reuses the old credential identifier")
        if probe.get("status") != "SUCCESS" or probe.get("credential_id") != replacement_id:
            raise VerificationError(f"incident {incident_id} replacement probe is unavailable or mismatched")
        if replacement.get("owner") != credential.get("owner"):
            findings.append(f"incident {incident_id} replacement owner differs from the reviewed owner")
        if replacement.get("purpose") != credential.get("purpose"):
            findings.append(f"incident {incident_id} replacement purpose is broader or different")
        for field in ("scopes", "resources", "consumers"):
            old_values = require_string_set(credential.get(field), f"incident {incident_id} old {field}")
            new_values = require_string_set(replacement.get(field), f"incident {incident_id} replacement {field}")
            if not new_values <= old_values:
                findings.append(f"incident {incident_id} replacement {field} exceed the old authority")
        bound_at = parse_timestamp(replacement.get("bound_at"), f"incident {incident_id} replacement bound_at")
        expires_at = parse_timestamp(replacement.get("expires_at"), f"incident {incident_id} replacement expires_at")
        old_expires = parse_timestamp(credential.get("expires_at"), f"incident {incident_id} old expires_at")
        lifetime = (expires_at - bound_at).total_seconds() / 3600
        if lifetime <= 0:
            raise VerificationError(f"incident {incident_id} replacement lifetime is invalid")
        if lifetime > reference["maximum_lifetime_hours"] or expires_at > old_expires:
            findings.append(f"incident {incident_id} replacement is longer lived than allowed")
    else:
        if replacement is not None or probe.get("status") != "NOT_REQUIRED":
            findings.append(f"incident {incident_id} short-lived authority incorrectly requires replacement")
    return findings


def validate_case(
    raw_case: Any,
    credentials: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    evaluation_time: datetime,
) -> tuple[str, str, str, int, int, list[str]]:
    case = require_object(raw_case, "response case")
    incident = require_object(case.get("incident"), "response case incident")
    evidence = require_object(case.get("evidence"), "response case evidence")
    if incident.get("schema") != "psb-credential-exposure-incident/1.0":
        raise VerificationError("incident schema is unsupported")
    if evidence.get("schema") != "psb-credential-response-evidence/1.0":
        raise VerificationError("response evidence schema is unsupported")
    incident_id = require_id(incident.get("incident_id"), "incident.incident_id")
    credential_id = require_id(incident.get("credential_id"), f"incident {incident_id} credential_id")
    credential = credentials.get(credential_id)
    if credential is None:
        raise VerificationError(f"incident {incident_id} credential is absent from inventory")
    credential_class = require_text(credential.get("credential_class"), f"incident {incident_id} credential_class")
    reference = REFERENCE_CLASS_ACTIONS[credential_class]
    findings: list[str] = []

    detected_at = parse_timestamp(incident.get("detected_at"), f"incident {incident_id} detected_at")
    window = require_object(incident.get("exposure_window"), f"incident {incident_id} exposure_window")
    window_start = parse_timestamp(window.get("start"), f"incident {incident_id} exposure start")
    window_end = parse_timestamp(window.get("end"), f"incident {incident_id} exposure end")
    if not window_start <= detected_at <= window_end <= evaluation_time:
        raise VerificationError(f"incident {incident_id} exposure window is invalid")
    digest = require_text(incident.get("detection_evidence_sha256"), f"incident {incident_id} detection digest")
    if not DIGEST_RE.fullmatch(digest):
        raise VerificationError(f"incident {incident_id} detection evidence digest is invalid")

    authorization = require_object(incident.get("authorization"), f"incident {incident_id} authorization")
    authorization_id = require_id(authorization.get("authorization_id"), f"incident {incident_id} authorization_id")
    if authorization.get("status") != "AUTHORIZED":
        findings.append(f"incident {incident_id} response is not authorized")
    role = require_text(authorization.get("role"), f"incident {incident_id} authorization role")
    if role not in REFERENCE_ROLES:
        findings.append(f"incident {incident_id} authorization role is not independently approved")
    require_text(authorization.get("authorized_by"), f"incident {incident_id} authorized_by")
    auth_created = parse_timestamp(authorization.get("created_at"), f"incident {incident_id} authorization created_at")
    auth_expires = parse_timestamp(authorization.get("expires_at"), f"incident {incident_id} authorization expires_at")
    auth_hours = (auth_expires - auth_created).total_seconds() / 3600
    raw_transitions = require_list(
        incident.get("state_transitions"), f"incident {incident_id} state_transitions"
    )
    if not raw_transitions:
        raise VerificationError(f"incident {incident_id} state transitions are empty")
    closure_at = parse_timestamp(
        require_object(raw_transitions[-1], f"incident {incident_id} final state").get("at"),
        f"incident {incident_id} final state timestamp",
    )
    if auth_created < detected_at or auth_expires <= auth_created or auth_expires < closure_at:
        raise VerificationError(
            f"incident {incident_id} authorization does not cover the response window"
        )
    if auth_hours > REFERENCE_MAX_AUTHORIZATION_HOURS:
        findings.append(f"incident {incident_id} authorization exceeds 4 hours")
    action_scope = require_string_set(authorization.get("action_scope"), f"incident {incident_id} action_scope")
    if action_scope != REQUIRED_ACTION_SCOPE:
        findings.append(f"incident {incident_id} authorization does not bind the complete response scope")
    if incident.get("dry_run") is not True:
        findings.append(f"incident {incident_id} is not a dry-run response")
    if incident.get("live_mutation") != "NOT_CHECKED":
        findings.append(f"incident {incident_id} overclaims or permits live provider mutation")
    findings.extend(validate_state_transitions(incident_id, incident, policy, evaluation_time))
    findings.extend(validate_response_plan(incident_id, incident))

    if evidence.get("credential_id") != credential_id or evidence.get("authorization_id") != authorization_id:
        raise VerificationError(f"incident {incident_id} evidence identity does not match incident and authorization")
    if evidence.get("adapter_status") != "HEALTHY":
        raise VerificationError(f"incident {incident_id} provider adapter is unavailable or unhealthy")
    if evidence.get("provider_receipts_complete") is not True:
        raise VerificationError(f"incident {incident_id} provider receipts are partial")
    if evidence.get("consumer_inventory_complete") is not True:
        raise VerificationError(f"incident {incident_id} consumer inventory is incomplete")

    receipts = require_list(evidence.get("operation_receipts"), f"incident {incident_id} operation_receipts")
    actions: set[str] = set()
    receipt_ids: set[str] = set()
    live_receipt = False
    for index, raw in enumerate(receipts):
        receipt = require_object(raw, f"incident {incident_id} operation_receipts[{index}]")
        receipt_id = require_id(receipt.get("receipt_id"), f"incident {incident_id} receipt_id")
        if receipt_id in receipt_ids:
            raise VerificationError(f"incident {incident_id} duplicates provider receipt")
        receipt_ids.add(receipt_id)
        action = require_text(receipt.get("action"), f"incident {incident_id} receipt action")
        if action in actions:
            raise VerificationError(f"incident {incident_id} duplicates provider action {action}")
        actions.add(action)
        if receipt.get("status") != "SUCCESS":
            raise VerificationError(f"incident {incident_id} provider action {action} did not succeed")
        receipt_at = parse_timestamp(receipt.get("at"), f"incident {incident_id} receipt timestamp")
        if not auth_created <= receipt_at <= auth_expires or receipt_at > evaluation_time:
            raise VerificationError(
                f"incident {incident_id} provider receipt falls outside the authorized response window"
            )
        require_id(receipt.get("idempotency_id"), f"incident {incident_id} receipt idempotency_id")
        live_receipt = live_receipt or receipt.get("live_mutation") is not False
    required_actions = reference["containment"] | reference["replacement"]
    if not required_actions <= actions:
        findings.append(f"incident {incident_id} credential-class containment or replacement actions are absent")
    if live_receipt:
        findings.append(f"incident {incident_id} receipts perform unreviewed live mutation")

    dispositions = require_list(evidence.get("consumer_dispositions"), f"incident {incident_id} consumer_dispositions")
    disposition_ids: set[str] = set()
    for index, raw in enumerate(dispositions):
        disposition = require_object(raw, f"incident {incident_id} consumer_dispositions[{index}]")
        consumer_id = require_id(disposition.get("consumer_id"), f"incident {incident_id} consumer_id")
        if consumer_id in disposition_ids:
            raise VerificationError(f"incident {incident_id} duplicates consumer disposition")
        disposition_ids.add(consumer_id)
        status = require_text(disposition.get("disposition"), f"incident {incident_id} consumer disposition")
        require_text(disposition.get("owner"), f"incident {incident_id} consumer owner")
        if status not in REFERENCE_DISPOSITIONS:
            findings.append(f"incident {incident_id} consumer {consumer_id} remains unresolved")
    known_consumers = require_string_set(credential.get("consumers"), f"incident {incident_id} known consumers")
    if disposition_ids != known_consumers:
        raise VerificationError(f"incident {incident_id} is missing a known consumer disposition")

    findings.extend(validate_replacement(incident_id, credential, evidence, reference))
    old_probe = require_object(evidence.get("old_authority_probe"), f"incident {incident_id} old_authority_probe")
    if old_probe.get("status") != "SUCCESS":
        raise VerificationError(f"incident {incident_id} old-authority denial test was skipped unsupported or failed")
    if old_probe.get("credential_id") != credential_id:
        raise VerificationError(f"incident {incident_id} old-authority denial test targets a different credential")
    if old_probe.get("result") != "DENIED":
        findings.append(f"incident {incident_id} old authority is still valid")
    if old_probe.get("independent_from_replacement") is not True:
        findings.append(f"incident {incident_id} old-authority denial is not independent from replacement success")
    parse_timestamp(old_probe.get("at"), f"incident {incident_id} old-authority probe timestamp")

    audit = require_object(evidence.get("audit"), f"incident {incident_id} audit")
    if audit.get("status") != "COMPLETE":
        raise VerificationError(f"incident {incident_id} audit query is incomplete")
    if (
        parse_timestamp(audit.get("window_start"), f"incident {incident_id} audit window_start") != window_start
        or parse_timestamp(audit.get("window_end"), f"incident {incident_id} audit window_end") != window_end
    ):
        raise VerificationError(f"incident {incident_id} audit query does not match the exposure window")
    require_string_set(audit.get("event_ids"), f"incident {incident_id} audit event_ids", nonempty=False)
    if audit.get("empty_result_claim") != "NOT_PROOF_OF_NO_ABUSE":
        findings.append(f"incident {incident_id} treats empty audit results as proof of no abuse")

    impacts = require_list(evidence.get("impact_references"), f"incident {incident_id} impact_references")
    if not impacts:
        raise VerificationError(f"incident {incident_id} impact review is empty")
    impact_ids: set[tuple[str, str]] = set()
    for index, raw in enumerate(impacts):
        impact = require_object(raw, f"incident {incident_id} impact_references[{index}]")
        kind = require_text(impact.get("kind"), f"incident {incident_id} impact kind")
        if kind not in ALLOWED_IMPACT_KINDS:
            raise VerificationError(f"incident {incident_id} impact kind is unsupported")
        identifier = require_id(impact.get("id"), f"incident {incident_id} impact id")
        if (kind, identifier) in impact_ids:
            raise VerificationError(f"incident {incident_id} duplicates impact reference")
        impact_ids.add((kind, identifier))

    return incident_id, credential_id, credential_class, len(known_consumers), len(impacts), findings


def verify(
    policy: dict[str, Any], bundle: dict[str, Any], evaluation_time: datetime
) -> tuple[list[str], list[str]]:
    reject_sensitive_content(policy, "policy")
    reject_sensitive_content(bundle, "bundle")
    classes, findings = validate_policy(policy)
    del classes
    if bundle.get("schema") != "psb-credential-response-bundle/1.0":
        raise VerificationError("response bundle schema is unsupported")
    inventory = require_object(bundle.get("inventory"), "bundle.inventory")
    credentials, inventory_findings = validate_inventory(inventory, policy, evaluation_time)
    findings.extend(inventory_findings)
    cases = require_list(bundle.get("cases"), "bundle.cases")
    if not cases:
        raise VerificationError("response bundle contains no incident cases")
    summaries: list[str] = []
    seen_incidents: set[str] = set()
    impact_kinds: set[str] = set()
    for raw_case in cases:
        incident_id, credential_id, credential_class, consumers, impacts, case_findings = validate_case(
            raw_case, credentials, policy, evaluation_time
        )
        if incident_id in seen_incidents:
            raise VerificationError(f"response bundle duplicates incident {incident_id}")
        seen_incidents.add(incident_id)
        case_evidence = require_object(require_object(raw_case, "response case").get("evidence"), "response evidence")
        for raw_impact in require_list(case_evidence.get("impact_references"), "impact references"):
            impact_kinds.add(require_text(require_object(raw_impact, "impact").get("kind"), "impact kind"))
        findings.extend(case_findings)
        if not case_findings and not findings:
            summaries.append(
                "PASS PSB-GOV-004 closure ready: "
                f"incident={incident_id} credential={credential_id} class={credential_class} "
                f"consumers={consumers} impacts={impacts} old_authority=DENIED "
                "live_mutation=NOT_CHECKED"
            )
        else:
            summaries.append(
                "FAIL PSB-GOV-004 closure not ready: "
                f"incident={incident_id} credential={credential_id} findings={len(case_findings)}"
            )
    if not impact_kinds <= ALLOWED_IMPACT_KINDS:
        raise VerificationError("response bundle has unsupported impact coverage")
    return findings, summaries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--evaluation-time", required=True)
    args = parser.parse_args()
    try:
        evaluation_time = parse_timestamp(args.evaluation_time, "--evaluation-time")
        policy = load_json(args.policy, "credential response policy")
        bundle = load_json(args.bundle, "credential response bundle")
        findings, summaries = verify(policy, bundle, evaluation_time)
    except VerificationError as error:
        print(f"ERROR PSB-GOV-004 verification unavailable: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL {finding}")
    for summary in summaries:
        print(summary)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
