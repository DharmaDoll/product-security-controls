#!/usr/bin/env python3
"""Join reviewed AWS KMS signing-key policy changes into PSB-CICD-008 evidence."""

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


CLOUDTRAIL_SCHEMA = "psb-aws-kms-cloudtrail-export/v1"
SESSION_SCHEMA = "psb-aws-admin-session-export/v1"
REGISTER_SCHEMA = "psb-aws-kms-privileged-change-register/v1"
KEY_SCHEMA = "psb-aws-kms-key-snapshot/v1"
OUTPUT_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
TARGET_EVENT = "PutKeyPolicy"
EVENT_SOURCE = "kms.amazonaws.com"
SNAPSHOT_MAX_DELAY = timedelta(minutes=5)
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")
KEY_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IDENTITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$")
SENSITIVE_FIELDS = {
    "accesskeyid",
    "authorization",
    "password",
    "plaintext",
    "privatekey",
    "secret",
    "secretaccesskey",
    "sessiontoken",
    "sourceipaddress",
    "token",
    "useragent",
}


class NormalizationError(ValueError):
    """KMS evidence fragments cannot create complete trusted evidence."""


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
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise NormalizationError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict) or value.get("Version") != "2012-10-17":
        raise NormalizationError(f"{label} must be an IAM policy object")
    statements = value.get("Statement")
    if not isinstance(statements, list) or not statements:
        raise NormalizationError(f"{label} has malformed statements")
    for statement in statements:
        if not isinstance(statement, dict) or not all(
            name in statement for name in ("Principal", "Action", "Resource")
        ):
            raise NormalizationError(
                f"{label} has an ineffective statement without Principal Action or Resource"
            )
    return value


def ensure_no_sensitive_output(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().replace("_", "") in SENSITIVE_FIELDS:
                raise NormalizationError(f"normalized output contains forbidden field {key}")
            ensure_no_sensitive_output(child)
    elif isinstance(value, list):
        for child in value:
            ensure_no_sensitive_output(child)


def cloudtrail_window(
    cloudtrail: dict[str, Any], account_id: str, region: str
) -> tuple[datetime, datetime]:
    events = objects(cloudtrail.get("events"), "KMS CloudTrail events")
    collection = cloudtrail.get("collection")
    if not isinstance(collection, dict):
        raise NormalizationError("KMS CloudTrail collection receipt must be an object")
    if (
        collection.get("source") != "organization-trail-management-events"
        or collection.get("event_source") != EVENT_SOURCE
        or collection.get("event_name") != TARGET_EVENT
        or collection.get("account_id") != account_id
        or collection.get("region") != region
        or collection.get("complete") is not True
        or collection.get("pagination_complete") is not True
        or not isinstance(collection.get("pages"), int)
        or isinstance(collection.get("pages"), bool)
        or collection.get("pages", 0) < 1
        or collection.get("selected_events") != len(events)
        or PINNED_IDENTITY_RE.fullmatch(
            text(collection.get("collector_identity"), "KMS CloudTrail collector identity")
        )
        is None
    ):
        raise NormalizationError("KMS CloudTrail collection receipt is incomplete or mismatched")
    window_start = instant(collection.get("window_start"), "KMS CloudTrail window_start")
    window_end = instant(collection.get("window_end"), "KMS CloudTrail window_end")
    if not window_start < window_end <= instant(
        cloudtrail.get("collected_at"), "KMS CloudTrail collected_at"
    ):
        raise NormalizationError("KMS CloudTrail collection window is invalid")
    return window_start, window_end


def key_snapshot(
    snapshot: dict[str, Any], account_id: str, region: str
) -> tuple[dict[str, Any], datetime]:
    if snapshot.get("schema") != KEY_SCHEMA:
        raise NormalizationError("unsupported KMS key snapshot schema")
    if (
        snapshot.get("complete") is not True
        or snapshot.get("account_id") != account_id
        or snapshot.get("region") != region
    ):
        raise NormalizationError("KMS key snapshot is incomplete or mismatched")
    collected_at = instant(snapshot.get("collected_at"), "KMS key collected_at")
    keys = objects(snapshot.get("keys"), "KMS keys")
    collection = snapshot.get("collection")
    if len(keys) != 1 or not isinstance(collection, dict):
        raise NormalizationError("KMS snapshot must contain one key and receipt")
    configuration = keys[0].get("configuration")
    if not isinstance(configuration, dict):
        raise NormalizationError("KMS snapshot lacks canonical key configuration")
    key_id = text(configuration.get("key_id"), "KMS key ID")
    key_arn = text(configuration.get("key_arn"), "KMS key ARN")
    creation_date = text(configuration.get("creation_date"), "KMS key creation date")
    expected_arn = f"arn:aws:kms:{region}:{account_id}:key/{key_id}"
    signing_algorithms = configuration.get("signing_algorithms")
    if (
        KEY_ID_RE.fullmatch(key_id) is None
        or key_arn != expected_arn
        or configuration.get("account_id") != account_id
        or timestamp(instant(creation_date, "KMS key creation date")) != creation_date
        or configuration.get("enabled") is not True
        or configuration.get("key_state") != "Enabled"
        or configuration.get("key_manager") != "CUSTOMER"
        or configuration.get("key_usage") != "SIGN_VERIFY"
        or not isinstance(configuration.get("key_spec"), str)
        or not isinstance(signing_algorithms, list)
        or not signing_algorithms
        or not all(isinstance(item, str) and item for item in signing_algorithms)
        or collection.get("describe_api") != "kms:DescribeKey"
        or collection.get("policy_api") != "kms:GetKeyPolicy"
        or collection.get("key_id") != key_id
        or collection.get("key_arn") != key_arn
        or collection.get("policy_name") != "default"
        or not all(
            isinstance(collection.get(field), str) and collection[field]
            for field in ("describe_request_id", "policy_request_id")
        )
        or PINNED_IDENTITY_RE.fullmatch(
            text(collection.get("collector_identity"), "KMS snapshot collector identity")
        )
        is None
    ):
        raise NormalizationError("KMS key identity state or collection receipt is mismatched")
    configuration["key_policy"] = policy(
        configuration.get("key_policy"), "KMS current key policy"
    )
    return configuration, collected_at


def normalize(
    cloudtrail: dict[str, Any],
    sessions: dict[str, Any],
    register: dict[str, Any],
    keys: dict[str, Any],
) -> dict[str, Any]:
    if cloudtrail.get("schema") != CLOUDTRAIL_SCHEMA:
        raise NormalizationError("unsupported KMS CloudTrail schema")
    if sessions.get("schema") != SESSION_SCHEMA:
        raise NormalizationError("unsupported AWS session schema")
    if register.get("schema") != REGISTER_SCHEMA:
        raise NormalizationError("unsupported KMS change register schema")
    if not all(source.get("complete") is True for source in (cloudtrail, sessions, register)):
        raise NormalizationError("one or more KMS evidence sources are incomplete")
    account_id = text(cloudtrail.get("account_id"), "AWS account ID")
    region = text(cloudtrail.get("region"), "AWS region")
    if ACCOUNT_RE.fullmatch(account_id) is None or REGION_RE.fullmatch(region) is None:
        raise NormalizationError("AWS account ID or region is malformed")
    window_start, window_end = cloudtrail_window(cloudtrail, account_id, region)
    current_key, key_collected_at = key_snapshot(keys, account_id, region)
    if window_end < key_collected_at:
        raise NormalizationError(
            "KMS key snapshot is not covered by a complete later CloudTrail window"
        )

    session_index: dict[str, dict[str, Any]] = {}
    for session in objects(sessions.get("sessions"), "AWS sessions"):
        principal = text(session.get("aws_session_principal_id"), "AWS session principal ID")
        if principal in session_index:
            raise NormalizationError("AWS session principal IDs must be unique")
        session_index[principal] = session
    change_index: dict[tuple[str, str], dict[str, Any]] = {}
    for change in objects(register.get("changes"), "KMS change register"):
        join = (
            text(change.get("provider_event_id"), "KMS provider event ID"),
            text(change.get("aws_request_id"), "KMS request ID"),
        )
        if join in change_index:
            raise NormalizationError("KMS change register join keys must be unique")
        change_index[join] = change

    events = objects(cloudtrail.get("events"), "KMS CloudTrail events")
    seen_events: set[str] = set()
    changes: list[dict[str, Any]] = []
    for event in events:
        if event.get("eventName") != TARGET_EVENT:
            continue
        event_id = text(event.get("eventID"), "KMS CloudTrail event ID")
        request_id = text(event.get("requestID"), "KMS CloudTrail request ID")
        if event_id in seen_events:
            raise NormalizationError("KMS CloudTrail event IDs must be unique")
        seen_events.add(event_id)
        try:
            major_text, minor_text = text(
                event.get("eventVersion"), "KMS CloudTrail event version"
            ).split(".", 1)
            major, minor = int(major_text), int(minor_text)
        except (ValueError, TypeError) as error:
            raise NormalizationError("KMS CloudTrail event version is malformed") from error
        event_time = instant(event.get("eventTime"), "KMS CloudTrail event time")
        if (
            major != 1
            or minor < 8
            or event.get("eventSource") != EVENT_SOURCE
            or event.get("awsRegion") != region
            or event.get("recipientAccountId") != account_id
            or event.get("managementEvent") is not True
            or event.get("readOnly") is not False
            or event.get("eventCategory") != "Management"
            or not window_start <= event_time <= window_end
            or "errorCode" in event
            or "errorMessage" in event
        ):
            raise NormalizationError("KMS policy event is unsuccessful or mismatched")
        request_parameters = event.get("requestParameters")
        identity = event.get("userIdentity")
        resources = event.get("resources")
        if (
            not isinstance(request_parameters, dict)
            or not isinstance(identity, dict)
            or not isinstance(resources, list)
        ):
            raise NormalizationError("KMS event lacks request identity or resource details")
        key_id = text(request_parameters.get("keyId"), "KMS event key ID")
        policy_name = request_parameters.get("policyName", "default")
        requested_policy = policy(request_parameters.get("policy"), "KMS requested key policy")
        bypass = request_parameters.get("bypassPolicyLockoutSafetyCheck", False)
        if not isinstance(bypass, bool):
            raise NormalizationError("KMS lockout-safety bypass must be boolean")
        session_context = identity.get("sessionContext")
        if not isinstance(session_context, dict):
            raise NormalizationError("KMS assumed-role event lacks session context")
        issuer = session_context.get("sessionIssuer")
        attributes = session_context.get("attributes")
        if not isinstance(issuer, dict) or not isinstance(attributes, dict):
            raise NormalizationError("KMS session issuer or attributes are absent")
        session = session_index.get(text(identity.get("principalId"), "KMS session principal ID"))
        change = change_index.get((event_id, request_id))
        if session is None or change is None:
            raise NormalizationError("KMS event lacks an exact session or change-register join")
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
                "KMS CloudTrail identity does not resolve to one current attributed session"
            )
        key_arn = current_key["key_arn"]
        resource_arns = [resource.get("ARN") for resource in resources if isinstance(resource, dict)]
        if (
            key_id not in {current_key["key_id"], key_arn}
            or key_arn not in resource_arns
            or policy_name != "default"
            or change.get("key_id") != current_key["key_id"]
            or change.get("key_arn") != key_arn
            or change.get("policy_name") != policy_name
            or change.get("bypass_policy_lockout_safety_check") is not bypass
        ):
            raise NormalizationError("KMS event register and snapshot do not name one signing key policy")
        if bypass:
            raise NormalizationError(
                "KMS lockout-safety bypass requires a separate emergency adapter"
            )
        if not event_time <= key_collected_at <= event_time + SNAPSHOT_MAX_DELAY:
            raise NormalizationError("KMS key snapshot is stale or precedes the event")
        later_events = [
            candidate
            for candidate in events
            if candidate.get("eventName") == TARGET_EVENT
            and isinstance(candidate.get("requestParameters"), dict)
            and candidate["requestParameters"].get("keyId") in {current_key["key_id"], key_arn}
            and event_time
            < instant(candidate.get("eventTime"), "later KMS event time")
            <= key_collected_at
        ]
        if later_events:
            raise NormalizationError(
                "KMS key snapshot is ambiguous because a later policy update exists"
            )
        before_digest = change.get("before_digest")
        after_digest = digest(current_key["key_policy"])
        if (
            not isinstance(before_digest, str)
            or DIGEST_RE.fullmatch(before_digest) is None
            or before_digest == after_digest
            or digest(requested_policy) != after_digest
            or change.get("after_digest") != after_digest
        ):
            raise NormalizationError(
                "KMS requested current and reviewed key-policy digests do not match"
            )
        approvals = objects(change.get("approvals"), "KMS change approvals")
        emergency = change.get("emergency")
        if not isinstance(emergency, dict):
            raise NormalizationError("KMS emergency record must be an object")
        principal_id = text(session.get("principal_id"), "principal ID")
        normalized_session_id = text(session.get("session_id"), "session ID")
        normalized_request_id = text(change.get("request_id"), "change request ID")
        changes.append(
            {
                "change_id": text(change.get("change_id"), "change ID"),
                "service": "signing-service",
                "change_type": "signing-policy",
                "target": {"type": "aws-kms-signing-key-policy", "id": key_arn},
                "actor": {
                    "id": principal_id,
                    "kind": "human",
                    "role": text(session.get("role"), "principal role"),
                    "organization_member": session["organization_member"],
                    "identity_assurance": text(
                        session.get("identity_assurance"), "identity assurance"
                    ),
                    "session_id": normalized_session_id,
                    "session_issued_at": text(session.get("session_issued_at"), "session issued_at"),
                    "session_expires_at": text(session.get("session_expires_at"), "session expires_at"),
                    "reauthenticated_at": text(session.get("reauthenticated_at"), "reauthenticated_at"),
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
                    "target_id": key_arn,
                    "after_digest": after_digest,
                },
                "emergency": emergency,
            }
        )
    if not changes:
        raise NormalizationError("KMS export contains no reviewed signing-key policy changes")
    collected_at = max(
        instant(source.get("collected_at"), "source collected_at")
        for source in (cloudtrail, sessions, register, keys)
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
            "identity": "aws-kms-policy-normalizer@sha256:30f750590882c5977e497af061e35f675ff0d4e1ee9ef52377215f9176b87ad8",
            "covered_services": ["signing-service"],
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
        raise NormalizationError("cannot write normalized KMS evidence") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cloudtrail-events", type=Path, required=True)
    parser.add_argument("--identity-sessions", type=Path, required=True)
    parser.add_argument("--change-register", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = normalize(
            load(args.cloudtrail_events, "KMS CloudTrail events"),
            load(args.identity_sessions, "AWS identity sessions"),
            load(args.change_register, "KMS change register"),
            load(args.keys, "KMS key snapshot"),
        )
        write_output(args.output, output)
    except NormalizationError as error:
        print(f"ERROR KMS control-plane normalization unavailable: {error}", file=sys.stderr)
        return 2
    print(f"NORMALIZED {len(output['changes'])} KMS signing-key policy change event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
