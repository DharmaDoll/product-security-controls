#!/usr/bin/env python3
"""Evaluate normalized evidence for privileged CI/CD control-plane changes."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


CONTROL = "PSB-CICD-008"
POLICY_SCHEMA = "psb-cicd-control-plane-policy/v1"
EVIDENCE_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IDENTITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$")
REQUIRED_SERVICES = {
    "scm",
    "ci",
    "cloud-identity",
    "artifact-registry",
    "signing-service",
}
REQUIRED_CHANGE_TYPES = {
    "branch-protection",
    "environment-protection",
    "runner-registration-policy",
    "federated-trust-policy",
    "registry-protection",
    "signing-policy",
}
FORBIDDEN_FIELDS = {
    "access_key",
    "access_token",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}


class InputError(ValueError):
    """Evidence cannot be evaluated safely."""


def reject_secret_fields(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_FIELDS:
                raise InputError(f"{label} contains forbidden credential field {key}")
            reject_secret_fields(child, label)
    elif isinstance(value, list):
        for child in value:
            reject_secret_fields(child, label)


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


def text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise InputError(f"{label} must be {'text' if allow_empty else 'non-empty text'}")
    return value


def boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise InputError(f"{label} must be boolean")
    return value


def integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InputError(f"{label} must be an integer")
    return value


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def objects(value: Any, label: str, *, non_empty: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (non_empty and not value):
        raise InputError(f"{label} must be an array")
    if not all(isinstance(item, dict) for item in value):
        raise InputError(f"{label} must contain objects")
    return value


def strings(value: Any, label: str, *, non_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        raise InputError(f"{label} must be a string array")
    if not all(isinstance(item, str) and item for item in value):
        raise InputError(f"{label} must contain non-empty strings")
    if len(value) != len(set(value)):
        raise InputError(f"{label} must not contain duplicates")
    return value


def instant(value: Any, label: str) -> datetime:
    raw = text(value, label)
    if not raw.endswith("Z"):
        raise InputError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        return datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} must be an RFC3339 UTC timestamp") from error


def add(issues: list[tuple[str, str]], check: str, message: str) -> None:
    issues.append((check, message))


def validate(policy: dict[str, Any], evidence: dict[str, Any], now: datetime) -> list[tuple[str, str]]:
    if policy.get("schema") != POLICY_SCHEMA:
        raise InputError("unsupported policy schema")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise InputError("unsupported change evidence schema")

    maximum_age = integer(policy.get("maximum_evidence_age_seconds"), "maximum evidence age")
    if maximum_age <= 0:
        raise InputError("maximum evidence age must be positive")
    collected_at = instant(evidence.get("collected_at"), "collected_at")
    window_start = instant(evidence.get("window_start"), "window_start")
    window_end = instant(evidence.get("window_end"), "window_end")
    if not window_start <= window_end <= collected_at <= now:
        raise InputError("evidence timestamps are inconsistent or from the future")
    if now - collected_at > timedelta(seconds=maximum_age):
        raise InputError("change evidence is stale")

    collector = object_value(evidence.get("collector"), "collector")
    if not boolean(collector.get("available"), "collector.available"):
        raise InputError("control-plane evidence collector is unavailable")
    if not boolean(collector.get("complete"), "collector.complete"):
        raise InputError("control-plane evidence collection is incomplete")

    issues: list[tuple[str, str]] = []
    policy_version = text(policy.get("policy_version"), "policy version")
    if not DIGEST_RE.fullmatch(policy_version):
        add(issues, "CPC-003", "policy version is not digest-pinned")
    if maximum_age > 900:
        add(issues, "CPC-007", "maximum evidence age exceeds 900 seconds")
    if not boolean(policy.get("fail_closed"), "fail_closed"):
        add(issues, "CPC-007", "policy permits evidence failure to pass")

    required_services = set(strings(policy.get("required_services"), "required services"))
    covered_services = set(strings(collector.get("covered_services"), "covered services"))
    if not required_services <= covered_services:
        add(issues, "CPC-007", "collector does not cover every required service")
    if required_services != REQUIRED_SERVICES:
        add(issues, "CPC-007", "policy does not require the complete control-plane service inventory")
    if not PINNED_IDENTITY_RE.fullmatch(text(collector.get("identity"), "collector identity")):
        add(issues, "CPC-007", "collector identity is not digest-pinned")

    allowed_types = set(strings(policy.get("allowed_change_types"), "allowed change types"))
    authorized_roles = object_value(
        policy.get("authorized_roles_by_service"), "authorized roles by service"
    )
    required_assurance = text(policy.get("required_identity_assurance"), "identity assurance")
    max_session = integer(policy.get("maximum_session_seconds"), "maximum session seconds")
    max_reauth = integer(
        policy.get("maximum_reauthentication_age_seconds"),
        "maximum reauthentication age seconds",
    )
    min_approvals = integer(policy.get("minimum_independent_approvals"), "minimum approvals")
    emergency_deadline = integer(
        policy.get("emergency_review_deadline_seconds"),
        "emergency review deadline",
    )
    if max_session <= 0 or max_session > 3600 or max_reauth <= 0 or max_reauth > 900:
        add(issues, "CPC-002", "session or reauthentication policy is too broad")
    if min_approvals < 1:
        add(issues, "CPC-004", "ordinary changes do not require independent approval")
    if emergency_deadline <= 0 or emergency_deadline > 3600:
        add(issues, "CPC-006", "emergency review deadline exceeds one hour")
    if required_assurance != "phishing-resistant" or not boolean(
        policy.get("require_human_actor"), "require_human_actor"
    ):
        add(issues, "CPC-001", "policy does not require a named human with phishing-resistant authentication")
    if not boolean(policy.get("require_exact_before_after_digest"), "require exact digest"):
        add(issues, "CPC-003", "policy does not require exact before and after digests")
    if not boolean(policy.get("require_provider_audit_event"), "require audit event"):
        add(issues, "CPC-005", "policy does not require a provider audit event")
    if "*" in allowed_types:
        add(issues, "CPC-003", "policy allows unclassified privileged changes")
    if not REQUIRED_CHANGE_TYPES <= allowed_types:
        add(issues, "CPC-003", "policy omits required privileged change types")
    for service in required_services:
        roles = authorized_roles.get(service)
        if not isinstance(roles, list) or not roles or not all(
            isinstance(role, str) and role for role in roles
        ):
            add(issues, "CPC-001", f"service {service} lacks an explicit administrator role allow-list")

    change_ids: set[str] = set()
    audit_ids: set[str] = set()
    for position, change in enumerate(objects(evidence.get("changes"), "changes"), start=1):
        label = f"change {position}"
        change_id = text(change.get("change_id"), f"{label}.change_id")
        if change_id in change_ids:
            raise InputError("change IDs must be unique")
        change_ids.add(change_id)
        service = text(change.get("service"), f"{label}.service")
        change_type = text(change.get("change_type"), f"{label}.change_type")
        target = object_value(change.get("target"), f"{label}.target")
        target_id = text(target.get("id"), f"{label}.target.id")
        text(target.get("type"), f"{label}.target.type")
        if service not in required_services or service not in covered_services:
            add(issues, "CPC-007", f"{label} service is outside complete collector coverage")
        if change_type not in allowed_types:
            add(issues, "CPC-003", f"{label} type is not explicitly allowed")
        if target_id == "*":
            add(issues, "CPC-003", f"{label} target is wildcarded")

        actor = object_value(change.get("actor"), f"{label}.actor")
        actor_id = text(actor.get("id"), f"{label}.actor.id")
        actor_role = text(actor.get("role"), f"{label}.actor.role")
        session_id = text(actor.get("session_id"), f"{label}.actor.session_id")
        issued = instant(actor.get("session_issued_at"), f"{label}.session_issued_at")
        expires = instant(actor.get("session_expires_at"), f"{label}.session_expires_at")
        reauthenticated = instant(actor.get("reauthenticated_at"), f"{label}.reauthenticated_at")
        if (
            actor.get("kind") != "human"
            or not boolean(actor.get("organization_member"), f"{label}.organization_member")
            or actor.get("identity_assurance") != required_assurance
        ):
            add(issues, "CPC-001", f"{label} actor is not a current named human with required assurance")
        service_roles = authorized_roles.get(service, [])
        if actor_role not in service_roles:
            add(issues, "CPC-001", f"{label} actor role is not authorized for the service")
        if not issued <= reauthenticated < expires or expires - issued > timedelta(seconds=max_session):
            add(issues, "CPC-002", f"{label} session lifetime or reauthentication timestamps are invalid")

        request = object_value(change.get("request"), f"{label}.request")
        request_id = text(request.get("id"), f"{label}.request.id")
        requested = instant(request.get("requested_at"), f"{label}.request.requested_at")
        before = text(request.get("before_digest"), f"{label}.request.before_digest")
        after = text(request.get("after_digest"), f"{label}.request.after_digest")
        if request.get("policy_version") != policy_version:
            add(issues, "CPC-003", f"{label} request is not bound to the evaluated policy")
        if not DIGEST_RE.fullmatch(before) or not DIGEST_RE.fullmatch(after) or before == after:
            add(issues, "CPC-003", f"{label} lacks distinct exact before and after digests")
        if request.get("ticket") in (None, "", "none") or not request.get("reason"):
            add(issues, "CPC-003", f"{label} lacks an owned reason or change record")

        execution = object_value(change.get("execution"), f"{label}.execution")
        executed = instant(execution.get("executed_at"), f"{label}.execution.executed_at")
        if not requested <= executed < expires:
            add(issues, "CPC-002", f"{label} executes outside the request or authenticated session window")
        if executed - reauthenticated > timedelta(seconds=max_reauth):
            add(issues, "CPC-002", f"{label} lacks recent step-up authentication")
        expected_execution = {
            "status": "applied",
            "actor_id": actor_id,
            "session_id": session_id,
            "request_id": request_id,
            "before_digest": before,
            "after_digest": after,
        }
        if any(execution.get(key) != value for key, value in expected_execution.items()):
            add(issues, "CPC-005", f"{label} execution identity does not match its request and session")

        emergency = object_value(change.get("emergency"), f"{label}.emergency")
        emergency_used = boolean(emergency.get("used"), f"{label}.emergency.used")
        approvals = objects(change.get("approvals"), f"{label}.approvals")
        valid_approvers = {
            approval.get("actor_id")
            for approval in approvals
            if approval.get("actor_id") not in (None, "", actor_id)
            and approval.get("request_id") == request_id
            and approval.get("after_digest") == after
            and instant(approval.get("approved_at"), f"{label}.approval.approved_at") <= executed
        }
        if not emergency_used and len(valid_approvers) < min_approvals:
            add(issues, "CPC-004", f"{label} lacks enough independent digest-bound approvals")
        if emergency_used:
            expires_at = instant(emergency.get("expires_at"), f"{label}.emergency.expires_at")
            if not emergency.get("reason") or expires_at - executed > timedelta(seconds=emergency_deadline):
                add(issues, "CPC-006", f"{label} emergency path is unowned or too long")
            post_review = emergency.get("post_review")
            if not isinstance(post_review, dict):
                add(issues, "CPC-006", f"{label} emergency path lacks post-change review")
            else:
                reviewed = instant(post_review.get("reviewed_at"), f"{label}.post_review.reviewed_at")
                if (
                    post_review.get("reviewer_id") in (None, "", actor_id)
                    or post_review.get("request_id") != request_id
                    or post_review.get("after_digest") != after
                    or post_review.get("decision") not in {"accepted", "reverted"}
                    or not executed <= reviewed <= expires_at
                ):
                    add(issues, "CPC-006", f"{label} emergency review is not independent timely and digest-bound")

        audit = object_value(change.get("audit"), f"{label}.audit")
        audit_id = text(audit.get("provider_event_id"), f"{label}.audit.provider_event_id", allow_empty=True)
        recorded = instant(audit.get("recorded_at"), f"{label}.audit.recorded_at")
        expected_audit = {
            "actor_id": actor_id,
            "session_id": session_id,
            "request_id": request_id,
            "target_id": target_id,
            "after_digest": after,
        }
        if (
            not audit_id
            or audit_id in audit_ids
            or not executed <= recorded <= collected_at
            or any(audit.get(key) != value for key, value in expected_audit.items())
        ):
            add(issues, "CPC-005", f"{label} provider audit event is missing duplicated or incorrectly bound")
        if audit_id:
            audit_ids.add(audit_id)

    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--change-evidence", type=Path, required=True)
    parser.add_argument("--evaluation-time", required=True)
    args = parser.parse_args()
    try:
        policy = load_json(args.policy, "policy")
        evidence = load_json(args.change_evidence, "change evidence")
        now = instant(args.evaluation_time, "evaluation time")
        issues = validate(policy, evidence, now)
    except InputError as error:
        print(f"ERROR {CONTROL} control-plane change evaluation unavailable: {error}")
        return 2

    if issues:
        for check, message in sorted(set(issues)):
            print(f"FAIL {check} {message}")
        return 1
    print(f"PASS {CONTROL} privileged control-plane changes are identity and evidence bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
