#!/usr/bin/env python3
"""Join reviewed AWS IAM trust-policy changes into PSB-CICD-008 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


CLOUDTRAIL_SCHEMA = "psb-aws-cloudtrail-export/v1"
SESSION_SCHEMA = "psb-aws-admin-session-export/v1"
REGISTER_SCHEMA = "psb-aws-privileged-change-register/v1"
ROLE_SCHEMA = "psb-aws-iam-role-snapshot/v1"
OUTPUT_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
TARGET_EVENT = "UpdateAssumeRolePolicy"
SNAPSHOT_MAX_DELAY = timedelta(minutes=5)
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
ROLE_ID_RE = re.compile(r"^AROA[A-Z0-9]{12,124}$")
ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9_+=,.@-]{1,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IDENTITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$")
SENSITIVE_FIELDS = {
    "accesskeyid",
    "authorization",
    "password",
    "privatekey",
    "secret",
    "secretaccesskey",
    "sessiontoken",
    "sourceipaddress",
    "token",
    "useragent",
}


class NormalizationError(ValueError):
    """AWS fragments cannot create complete trusted evidence."""


def load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise NormalizationError(f"cannot load {label}") from error
    if not isinstance(value, dict):
        raise NormalizationError(f"{label} must be an object")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise NormalizationError(f"{label} must be non-empty text")
    return value


def objects(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise NormalizationError(f"{label} must be an array of objects")
    return value


def instant(value: Any, label: str) -> datetime:
    raw = text(value, label)
    if not raw.endswith("Z"):
        raise NormalizationError(f"{label} must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise NormalizationError(f"{label} must be RFC3339 UTC") from error


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def digest(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def policy(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NormalizationError(f"{label} must be a decoded JSON object")
    if value.get("Version") != "2012-10-17":
        raise NormalizationError(f"{label} has an unsupported IAM policy version")
    statements = value.get("Statement")
    if not isinstance(statements, list) or not statements or not all(
        isinstance(statement, dict) for statement in statements
    ):
        raise NormalizationError(f"{label} has malformed IAM statements")
    return value


def ensure_no_sensitive_output(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            compact = key.lower().replace("_", "")
            if compact in SENSITIVE_FIELDS:
                raise NormalizationError(f"normalized output contains forbidden field {key}")
            ensure_no_sensitive_output(child)
    elif isinstance(value, list):
        for child in value:
            ensure_no_sensitive_output(child)


def validate_cloudtrail_receipt(
    cloudtrail: dict[str, Any], account_id: str
) -> tuple[datetime, datetime]:
    collection = cloudtrail.get("collection")
    if not isinstance(collection, dict):
        raise NormalizationError("AWS CloudTrail collection receipt must be an object")
    events = objects(cloudtrail.get("events"), "CloudTrail events")
    if (
        collection.get("source") != "organization-trail-management-events"
        or collection.get("event_source") != "iam.amazonaws.com"
        or collection.get("event_name") != TARGET_EVENT
        or collection.get("account_id") != account_id
        or collection.get("complete") is not True
        or collection.get("pagination_complete") is not True
        or not isinstance(collection.get("pages"), int)
        or isinstance(collection.get("pages"), bool)
        or collection.get("pages", 0) < 1
        or collection.get("selected_events") != len(events)
        or not PINNED_IDENTITY_RE.fullmatch(
            text(collection.get("collector_identity"), "CloudTrail collector identity")
        )
    ):
        raise NormalizationError("AWS CloudTrail collection receipt is incomplete or mismatched")
    window_start = instant(collection.get("window_start"), "CloudTrail window_start")
    window_end = instant(collection.get("window_end"), "CloudTrail window_end")
    if not window_start < window_end <= instant(
        cloudtrail.get("collected_at"), "CloudTrail collected_at"
    ):
        raise NormalizationError("AWS CloudTrail collection window is invalid")
    return window_start, window_end


def role_snapshot(
    snapshot: dict[str, Any], account_id: str
) -> tuple[dict[str, Any], datetime]:
    if snapshot.get("schema") != ROLE_SCHEMA:
        raise NormalizationError("unsupported AWS IAM role snapshot schema")
    if snapshot.get("complete") is not True or snapshot.get("account_id") != account_id:
        raise NormalizationError("AWS IAM role snapshot is incomplete or mismatched")
    collected_at = instant(snapshot.get("collected_at"), "IAM role collected_at")
    roles = objects(snapshot.get("roles"), "IAM roles")
    if len(roles) != 1:
        raise NormalizationError("IAM role snapshot must contain exactly one requested role")
    configuration = roles[0].get("configuration")
    collection = snapshot.get("collection")
    if not isinstance(configuration, dict) or not isinstance(collection, dict):
        raise NormalizationError("IAM role snapshot lacks configuration or receipt")
    role_id = text(configuration.get("role_id"), "IAM role ID")
    role_name = text(configuration.get("role_name"), "IAM role name")
    role_arn = text(configuration.get("arn"), "IAM role ARN")
    expected_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    if (
        ROLE_ID_RE.fullmatch(role_id) is None
        or ROLE_NAME_RE.fullmatch(role_name) is None
        or role_arn != expected_arn
        or configuration.get("path") != "/"
        or not isinstance(configuration.get("max_session_duration"), int)
        or isinstance(configuration.get("max_session_duration"), bool)
        or not 3600 <= configuration["max_session_duration"] <= 43200
        or collection.get("api") != "iam:GetRole"
        or collection.get("role_name") != role_name
        or collection.get("role_id") != role_id
        or not isinstance(collection.get("request_id"), str)
        or not collection["request_id"]
        or not PINNED_IDENTITY_RE.fullmatch(
            text(collection.get("collector_identity"), "IAM collector identity")
        )
    ):
        raise NormalizationError("AWS IAM role snapshot identity or receipt is mismatched")
    policy(configuration.get("assume_role_policy_document"), "IAM current trust policy")
    return configuration, collected_at


def normalize(
    cloudtrail: dict[str, Any],
    sessions: dict[str, Any],
    register: dict[str, Any],
    roles: dict[str, Any],
) -> dict[str, Any]:
    if cloudtrail.get("schema") != CLOUDTRAIL_SCHEMA:
        raise NormalizationError("unsupported AWS CloudTrail schema")
    if sessions.get("schema") != SESSION_SCHEMA:
        raise NormalizationError("unsupported AWS session schema")
    if register.get("schema") != REGISTER_SCHEMA:
        raise NormalizationError("unsupported AWS change register schema")
    if not all(source.get("complete") is True for source in (cloudtrail, sessions, register)):
        raise NormalizationError("one or more AWS evidence sources are incomplete")
    account_id = text(cloudtrail.get("account_id"), "AWS account ID")
    if ACCOUNT_RE.fullmatch(account_id) is None:
        raise NormalizationError("AWS account ID must be twelve digits")
    window_start, window_end = validate_cloudtrail_receipt(cloudtrail, account_id)
    current_role, role_collected_at = role_snapshot(roles, account_id)
    if window_end < role_collected_at:
        raise NormalizationError(
            "IAM role snapshot is not covered by a complete later CloudTrail window"
        )

    session_index: dict[str, dict[str, Any]] = {}
    for session in objects(sessions.get("sessions"), "AWS sessions"):
        key = text(session.get("aws_session_principal_id"), "AWS session principal ID")
        if key in session_index:
            raise NormalizationError("AWS session principal IDs must be unique")
        session_index[key] = session

    change_index: dict[tuple[str, str], dict[str, Any]] = {}
    for change in objects(register.get("changes"), "AWS change register"):
        key = (
            text(change.get("provider_event_id"), "AWS provider event ID"),
            text(change.get("aws_request_id"), "AWS request ID"),
        )
        if key in change_index:
            raise NormalizationError("AWS change register join keys must be unique")
        change_index[key] = change

    changes: list[dict[str, Any]] = []
    seen_events: set[str] = set()
    events = objects(cloudtrail.get("events"), "CloudTrail events")
    for event in events:
        if event.get("eventName") != TARGET_EVENT:
            continue
        event_id = text(event.get("eventID"), "CloudTrail event ID")
        request_id = text(event.get("requestID"), "CloudTrail request ID")
        if event_id in seen_events:
            raise NormalizationError("CloudTrail event IDs must be unique")
        seen_events.add(event_id)
        event_version = text(event.get("eventVersion"), "CloudTrail event version")
        try:
            major_text, minor_text = event_version.split(".", 1)
            major, minor = int(major_text), int(minor_text)
        except (ValueError, TypeError) as error:
            raise NormalizationError("CloudTrail event version is malformed") from error
        event_time = instant(event.get("eventTime"), "CloudTrail event time")
        if (
            major != 1
            or minor < 8
            or event.get("eventSource") != "iam.amazonaws.com"
            or event.get("recipientAccountId") != account_id
            or event.get("managementEvent") is not True
            or event.get("readOnly") is not False
            or event.get("eventCategory") != "Management"
            or not window_start <= event_time <= window_end
            or "errorCode" in event
            or "errorMessage" in event
        ):
            raise NormalizationError("CloudTrail IAM update event is unsuccessful or mismatched")
        request_parameters = event.get("requestParameters")
        identity = event.get("userIdentity")
        if not isinstance(request_parameters, dict) or not isinstance(identity, dict):
            raise NormalizationError("CloudTrail event lacks request or identity details")
        role_name = text(request_parameters.get("roleName"), "CloudTrail role name")
        requested_policy = policy(
            request_parameters.get("policyDocument"), "CloudTrail requested trust policy"
        )
        session_context = identity.get("sessionContext")
        if not isinstance(session_context, dict):
            raise NormalizationError("CloudTrail assumed-role event lacks session context")
        issuer = session_context.get("sessionIssuer")
        attributes = session_context.get("attributes")
        if not isinstance(issuer, dict) or not isinstance(attributes, dict):
            raise NormalizationError("CloudTrail session issuer or attributes are absent")
        aws_session_principal = text(
            identity.get("principalId"), "CloudTrail session principal ID"
        )
        session = session_index.get(aws_session_principal)
        change = change_index.get((event_id, request_id))
        if session is None or change is None:
            raise NormalizationError(
                "AWS IAM event lacks an exact session or change-register join"
            )
        if (
            identity.get("type") != "AssumedRole"
            or identity.get("accountId") != account_id
            or identity.get("arn") != session.get("aws_session_arn")
            or issuer.get("principalId") != session.get("aws_session_issuer_principal_id")
            or issuer.get("arn") != session.get("aws_session_issuer_arn")
            or session_context.get("sourceIdentity") != session.get("aws_source_identity")
            or attributes.get("creationDate") != session.get("session_issued_at")
            or session.get("organization_member") is not True
        ):
            raise NormalizationError(
                "CloudTrail identity does not resolve to one current attributed session"
            )
        current_role_id = current_role["role_id"]
        current_role_arn = current_role["arn"]
        if (
            role_name != current_role["role_name"]
            or change.get("role_id") != current_role_id
            or change.get("role_arn") != current_role_arn
        ):
            raise NormalizationError(
                "CloudTrail register and IAM snapshot do not name one stable role"
            )
        if not event_time <= role_collected_at <= event_time + SNAPSHOT_MAX_DELAY:
            raise NormalizationError("IAM role snapshot is stale or precedes the update event")
        later_events = [
            candidate
            for candidate in events
            if candidate.get("eventName") == TARGET_EVENT
            and isinstance(candidate.get("requestParameters"), dict)
            and candidate["requestParameters"].get("roleName") == role_name
            and event_time
            < instant(candidate.get("eventTime"), "later CloudTrail event time")
            <= role_collected_at
        ]
        if later_events:
            raise NormalizationError(
                "IAM role snapshot is ambiguous because a later trust update exists"
            )
        current_policy = current_role["assume_role_policy_document"]
        before_digest = change.get("before_digest")
        after_digest = digest(current_policy)
        if (
            not isinstance(before_digest, str)
            or DIGEST_RE.fullmatch(before_digest) is None
            or before_digest == after_digest
            or digest(requested_policy) != after_digest
            or change.get("after_digest") != after_digest
        ):
            raise NormalizationError(
                "AWS requested current and reviewed trust-policy digests do not match"
            )
        approvals = objects(change.get("approvals"), "AWS change approvals")
        emergency = change.get("emergency")
        if not isinstance(emergency, dict):
            raise NormalizationError("AWS change emergency record must be an object")
        target_id = f"{account_id}:role:{current_role_id}"
        principal_id = text(session.get("principal_id"), "principal ID")
        normalized_session_id = text(session.get("session_id"), "session ID")
        normalized_request_id = text(change.get("request_id"), "change request ID")
        changes.append(
            {
                "change_id": text(change.get("change_id"), "change ID"),
                "service": "cloud-identity",
                "change_type": "federated-trust-policy",
                "target": {"type": "aws-iam-workload-identity-trust", "id": target_id},
                "actor": {
                    "id": principal_id,
                    "kind": "human",
                    "role": text(session.get("role"), "principal role"),
                    "organization_member": session["organization_member"],
                    "identity_assurance": text(
                        session.get("identity_assurance"), "identity assurance"
                    ),
                    "session_id": normalized_session_id,
                    "session_issued_at": text(
                        session.get("session_issued_at"), "session issued_at"
                    ),
                    "session_expires_at": text(
                        session.get("session_expires_at"), "session expires_at"
                    ),
                    "reauthenticated_at": text(
                        session.get("reauthenticated_at"), "reauthenticated_at"
                    ),
                },
                "request": {
                    "id": normalized_request_id,
                    "requested_at": change["requested_at"],
                    "policy_version": change["policy_version"],
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                    "reason": change["reason"],
                    "ticket": change["ticket"],
                },
                "approvals": approvals,
                "execution": {
                    "status": "applied",
                    "executed_at": timestamp(event_time),
                    "actor_id": principal_id,
                    "session_id": normalized_session_id,
                    "request_id": normalized_request_id,
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                },
                "audit": {
                    "provider_event_id": event_id,
                    "recorded_at": timestamp(event_time),
                    "actor_id": principal_id,
                    "session_id": normalized_session_id,
                    "request_id": normalized_request_id,
                    "target_id": target_id,
                    "after_digest": after_digest,
                },
                "emergency": emergency,
            }
        )

    if not changes:
        raise NormalizationError("AWS export contains no reviewed IAM trust-policy changes")
    collected_at = max(
        instant(source.get("collected_at"), "source collected_at")
        for source in (cloudtrail, sessions, register, roles)
    )
    event_times = [instant(change["execution"]["executed_at"], "execution time") for change in changes]
    output = {
        "schema": OUTPUT_SCHEMA,
        "collected_at": timestamp(collected_at),
        "window_start": timestamp(min(event_times)),
        "window_end": timestamp(max(event_times)),
        "collector": {
            "available": True,
            "complete": True,
            "identity": "aws-iam-trust-normalizer@sha256:49d0ace867b8a3ddb68f490dfe5e7c27d7ccb483d52572acfe10c3b8ab7d94cc",
            "covered_services": ["cloud-identity"],
        },
        "changes": sorted(changes, key=lambda item: item["change_id"]),
    }
    ensure_no_sensitive_output(output)
    return output


def write_output(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise NormalizationError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = handle.name
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
        raise NormalizationError("cannot write normalized AWS evidence") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cloudtrail-events", type=Path, required=True)
    parser.add_argument("--identity-sessions", type=Path, required=True)
    parser.add_argument("--change-register", type=Path, required=True)
    parser.add_argument("--iam-roles", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = normalize(
            load(args.cloudtrail_events, "AWS CloudTrail events"),
            load(args.identity_sessions, "AWS identity sessions"),
            load(args.change_register, "AWS change register"),
            load(args.iam_roles, "AWS IAM role snapshot"),
        )
        write_output(args.output, output)
    except NormalizationError as error:
        print(f"ERROR AWS control-plane normalization unavailable: {error}", file=sys.stderr)
        return 2
    print(f"NORMALIZED {len(output['changes'])} AWS IAM trust-policy change event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
