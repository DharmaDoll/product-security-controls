#!/usr/bin/env python3
"""Join reviewed AWS ECR repository-policy changes into PSB-CICD-008 evidence."""

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


CLOUDTRAIL_SCHEMA = "psb-aws-ecr-cloudtrail-export/v1"
SESSION_SCHEMA = "psb-aws-admin-session-export/v1"
REGISTER_SCHEMA = "psb-aws-ecr-privileged-change-register/v1"
REPOSITORY_SCHEMA = "psb-aws-ecr-repository-snapshot/v1"
OUTPUT_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
TARGET_EVENT = "SetRepositoryPolicy"
EVENT_SOURCE = "ecr.amazonaws.com"
SNAPSHOT_MAX_DELAY = timedelta(minutes=5)
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")
REPOSITORY_RE = re.compile(
    r"^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$"
)
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
    """ECR evidence fragments cannot create complete trusted evidence."""


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
    if not isinstance(value, dict):
        raise NormalizationError(f"{label} must be a JSON object or encoded object")
    if value.get("Version") not in {"2008-10-17", "2012-10-17"}:
        raise NormalizationError(f"{label} has an unsupported policy version")
    statements = value.get("Statement")
    if not isinstance(statements, list) or not statements or not all(
        isinstance(statement, dict) for statement in statements
    ):
        raise NormalizationError(f"{label} has malformed statements")
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


def cloudtrail_window(
    cloudtrail: dict[str, Any], account_id: str, region: str
) -> tuple[datetime, datetime]:
    events = objects(cloudtrail.get("events"), "ECR CloudTrail events")
    collection = cloudtrail.get("collection")
    if not isinstance(collection, dict):
        raise NormalizationError("ECR CloudTrail collection receipt must be an object")
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
            text(collection.get("collector_identity"), "ECR CloudTrail collector identity")
        )
        is None
    ):
        raise NormalizationError("ECR CloudTrail collection receipt is incomplete or mismatched")
    window_start = instant(collection.get("window_start"), "ECR CloudTrail window_start")
    window_end = instant(collection.get("window_end"), "ECR CloudTrail window_end")
    if not window_start < window_end <= instant(
        cloudtrail.get("collected_at"), "ECR CloudTrail collected_at"
    ):
        raise NormalizationError("ECR CloudTrail collection window is invalid")
    return window_start, window_end


def repository_snapshot(
    snapshot: dict[str, Any], account_id: str, region: str
) -> tuple[dict[str, Any], datetime]:
    if snapshot.get("schema") != REPOSITORY_SCHEMA:
        raise NormalizationError("unsupported ECR repository snapshot schema")
    if (
        snapshot.get("complete") is not True
        or snapshot.get("account_id") != account_id
        or snapshot.get("region") != region
    ):
        raise NormalizationError("ECR repository snapshot is incomplete or mismatched")
    collected_at = instant(snapshot.get("collected_at"), "ECR repository collected_at")
    repositories = objects(snapshot.get("repositories"), "ECR repositories")
    collection = snapshot.get("collection")
    if len(repositories) != 1 or not isinstance(collection, dict):
        raise NormalizationError("ECR snapshot must contain one repository and receipt")
    configuration = repositories[0].get("configuration")
    if not isinstance(configuration, dict):
        raise NormalizationError("ECR snapshot lacks canonical repository configuration")
    registry_id = text(configuration.get("registry_id"), "ECR registry ID")
    repository_name = text(configuration.get("repository_name"), "ECR repository name")
    repository_arn = text(configuration.get("repository_arn"), "ECR repository ARN")
    created_at = text(configuration.get("created_at"), "ECR repository creation time")
    expected_arn = f"arn:aws:ecr:{region}:{account_id}:repository/{repository_name}"
    if (
        registry_id != account_id
        or REPOSITORY_RE.fullmatch(repository_name) is None
        or repository_arn != expected_arn
        or timestamp(instant(created_at, "ECR repository creation time")) != created_at
        or collection.get("describe_api") != "ecr:DescribeRepositories"
        or collection.get("policy_api") != "ecr:GetRepositoryPolicy"
        or collection.get("registry_id") != registry_id
        or collection.get("repository_name") != repository_name
        or collection.get("repository_arn") != repository_arn
        or collection.get("created_at") != created_at
        or not all(
            isinstance(collection.get(field), str) and collection[field]
            for field in ("describe_request_id", "policy_request_id")
        )
        or PINNED_IDENTITY_RE.fullmatch(
            text(collection.get("collector_identity"), "ECR snapshot collector identity")
        )
        is None
    ):
        raise NormalizationError("ECR repository identity or collection receipt is mismatched")
    configuration["repository_policy"] = policy(
        configuration.get("repository_policy"), "ECR current repository policy"
    )
    return configuration, collected_at


def normalize(
    cloudtrail: dict[str, Any],
    sessions: dict[str, Any],
    register: dict[str, Any],
    repositories: dict[str, Any],
) -> dict[str, Any]:
    if cloudtrail.get("schema") != CLOUDTRAIL_SCHEMA:
        raise NormalizationError("unsupported ECR CloudTrail schema")
    if sessions.get("schema") != SESSION_SCHEMA:
        raise NormalizationError("unsupported AWS session schema")
    if register.get("schema") != REGISTER_SCHEMA:
        raise NormalizationError("unsupported ECR change register schema")
    if not all(source.get("complete") is True for source in (cloudtrail, sessions, register)):
        raise NormalizationError("one or more ECR evidence sources are incomplete")
    account_id = text(cloudtrail.get("account_id"), "AWS account ID")
    region = text(cloudtrail.get("region"), "AWS region")
    if ACCOUNT_RE.fullmatch(account_id) is None or REGION_RE.fullmatch(region) is None:
        raise NormalizationError("AWS account ID or region is malformed")
    window_start, window_end = cloudtrail_window(cloudtrail, account_id, region)
    current_repository, repository_collected_at = repository_snapshot(
        repositories, account_id, region
    )
    if window_end < repository_collected_at:
        raise NormalizationError(
            "ECR repository snapshot is not covered by a complete later CloudTrail window"
        )

    session_index: dict[str, dict[str, Any]] = {}
    for session in objects(sessions.get("sessions"), "AWS sessions"):
        principal = text(session.get("aws_session_principal_id"), "AWS session principal ID")
        if principal in session_index:
            raise NormalizationError("AWS session principal IDs must be unique")
        session_index[principal] = session
    change_index: dict[tuple[str, str], dict[str, Any]] = {}
    for change in objects(register.get("changes"), "ECR change register"):
        key = (
            text(change.get("provider_event_id"), "ECR provider event ID"),
            text(change.get("aws_request_id"), "ECR request ID"),
        )
        if key in change_index:
            raise NormalizationError("ECR change register join keys must be unique")
        change_index[key] = change

    events = objects(cloudtrail.get("events"), "ECR CloudTrail events")
    seen_events: set[str] = set()
    changes: list[dict[str, Any]] = []
    for event in events:
        if event.get("eventName") != TARGET_EVENT:
            continue
        event_id = text(event.get("eventID"), "ECR CloudTrail event ID")
        request_id = text(event.get("requestID"), "ECR CloudTrail request ID")
        if event_id in seen_events:
            raise NormalizationError("ECR CloudTrail event IDs must be unique")
        seen_events.add(event_id)
        try:
            major_text, minor_text = text(
                event.get("eventVersion"), "ECR CloudTrail event version"
            ).split(".", 1)
            major, minor = int(major_text), int(minor_text)
        except (ValueError, TypeError) as error:
            raise NormalizationError("ECR CloudTrail event version is malformed") from error
        event_time = instant(event.get("eventTime"), "ECR CloudTrail event time")
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
            raise NormalizationError("ECR policy event is unsuccessful or mismatched")
        request_parameters = event.get("requestParameters")
        identity = event.get("userIdentity")
        resources = event.get("resources")
        if (
            not isinstance(request_parameters, dict)
            or not isinstance(identity, dict)
            or not isinstance(resources, list)
        ):
            raise NormalizationError("ECR event lacks request identity or resource details")
        registry_id = request_parameters.get("registryId", account_id)
        repository_name = text(
            request_parameters.get("repositoryName"), "ECR event repository name"
        )
        requested_policy = policy(
            request_parameters.get("policyText"), "ECR requested repository policy"
        )
        force = request_parameters.get("force", False)
        if not isinstance(force, bool):
            raise NormalizationError("ECR force parameter must be boolean")
        session_context = identity.get("sessionContext")
        if not isinstance(session_context, dict):
            raise NormalizationError("ECR assumed-role event lacks session context")
        issuer = session_context.get("sessionIssuer")
        attributes = session_context.get("attributes")
        if not isinstance(issuer, dict) or not isinstance(attributes, dict):
            raise NormalizationError("ECR session issuer or attributes are absent")
        session = session_index.get(
            text(identity.get("principalId"), "ECR session principal ID")
        )
        change = change_index.get((event_id, request_id))
        if session is None or change is None:
            raise NormalizationError("ECR event lacks an exact session or change-register join")
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
                "ECR CloudTrail identity does not resolve to one current attributed session"
            )
        repository_arn = current_repository["repository_arn"]
        resource_arns = [
            resource.get("ARN") for resource in resources if isinstance(resource, dict)
        ]
        if (
            registry_id != current_repository["registry_id"]
            or repository_name != current_repository["repository_name"]
            or repository_arn not in resource_arns
            or change.get("repository_arn") != repository_arn
            or change.get("repository_created_at") != current_repository["created_at"]
            or change.get("force") is not force
        ):
            raise NormalizationError(
                "ECR event register and snapshot do not name one repository generation"
            )
        if force:
            raise NormalizationError(
                "forced ECR repository-policy changes require a separate emergency adapter"
            )
        if not event_time <= repository_collected_at <= event_time + SNAPSHOT_MAX_DELAY:
            raise NormalizationError("ECR repository snapshot is stale or precedes the event")
        later_events = [
            candidate
            for candidate in events
            if candidate.get("eventName") == TARGET_EVENT
            and isinstance(candidate.get("requestParameters"), dict)
            and candidate["requestParameters"].get("repositoryName") == repository_name
            and candidate["requestParameters"].get("registryId", account_id) == registry_id
            and event_time
            < instant(candidate.get("eventTime"), "later ECR event time")
            <= repository_collected_at
        ]
        if later_events:
            raise NormalizationError(
                "ECR repository snapshot is ambiguous because a later policy update exists"
            )
        current_policy = current_repository["repository_policy"]
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
                "ECR requested current and reviewed repository-policy digests do not match"
            )
        approvals = objects(change.get("approvals"), "ECR change approvals")
        emergency = change.get("emergency")
        if not isinstance(emergency, dict):
            raise NormalizationError("ECR emergency record must be an object")
        principal_id = text(session.get("principal_id"), "principal ID")
        normalized_session_id = text(session.get("session_id"), "session ID")
        normalized_request_id = text(change.get("request_id"), "change request ID")
        target_id = f"{repository_arn}@{current_repository['created_at']}"
        changes.append(
            {
                "change_id": text(change.get("change_id"), "change ID"),
                "service": "artifact-registry",
                "change_type": "registry-protection",
                "target": {"type": "aws-ecr-repository-policy", "id": target_id},
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
        raise NormalizationError("ECR export contains no reviewed repository-policy changes")
    collected_at = max(
        instant(source.get("collected_at"), "source collected_at")
        for source in (cloudtrail, sessions, register, repositories)
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
            "identity": "aws-ecr-policy-normalizer@sha256:ae13ed4bd0ab76cb7997b4f68b4065d42e753b35340365069d99919176f81793",
            "covered_services": ["artifact-registry"],
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
        raise NormalizationError("cannot write normalized ECR evidence") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cloudtrail-events", type=Path, required=True)
    parser.add_argument("--identity-sessions", type=Path, required=True)
    parser.add_argument("--change-register", type=Path, required=True)
    parser.add_argument("--repositories", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = normalize(
            load(args.cloudtrail_events, "ECR CloudTrail events"),
            load(args.identity_sessions, "AWS identity sessions"),
            load(args.change_register, "ECR change register"),
            load(args.repositories, "ECR repository snapshot"),
        )
        write_output(args.output, output)
    except NormalizationError as error:
        print(f"ERROR ECR control-plane normalization unavailable: {error}", file=sys.stderr)
        return 2
    print(f"NORMALIZED {len(output['changes'])} ECR repository-policy change event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
