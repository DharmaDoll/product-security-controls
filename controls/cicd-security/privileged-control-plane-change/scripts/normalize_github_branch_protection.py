#!/usr/bin/env python3
"""Join one reviewed GitHub legacy branch-protection setting update."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


AUDIT_SCHEMA = "psb-github-audit-export/v1"
SESSION_SCHEMA = "psb-github-admin-session-export/v1"
REGISTER_SCHEMA = "psb-github-privileged-change-register/v1"
SNAPSHOT_SCHEMA = "psb-github-branch-protection-snapshot/v4"
OUTPUT_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
SETTING_CONTRACTS = {
    "protected_branch.update_allow_force_pushes_enforcement_level": {
        "event_field": "allow_force_pushes_enforcement_level",
        "snapshot_field": "allow_force_pushes",
        "register_before_field": "before_allow_force_pushes",
        "value_type": "level",
    },
    "protected_branch.update_allow_deletions_enforcement_level": {
        "event_field": "allow_deletions_enforcement_level",
        "snapshot_field": "allow_deletions",
        "register_before_field": "before_allow_deletions",
        "value_type": "level",
    },
    "protected_branch.update_admin_enforced": {
        "event_field": "admin_enforced",
        "snapshot_field": "enforce_admins",
        "register_before_field": "before_enforce_admins",
        "value_type": "boolean",
    },
    "protected_branch.update_require_code_owner_review": {
        "event_field": "require_code_owner_review",
        "snapshot_field": "require_code_owner_reviews",
        "register_before_field": "before_require_code_owner_reviews",
        "value_type": "boolean",
    },
}
API_VERSION = "2026-03-10"
SNAPSHOT_MAX_DELAY = timedelta(minutes=5)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SENSITIVE_FIELDS = {
    "access_token",
    "actor_ip",
    "authorization",
    "hashed_token",
    "password",
    "private_key",
    "secret",
    "token",
    "token_id",
    "token_scopes",
    "user_agent",
}


class NormalizationError(ValueError):
    """GitHub branch-protection fragments cannot create trusted SCM evidence."""


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


def positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise NormalizationError(f"{label} must be a positive integer")
    return value


def instant(value: Any, label: str) -> datetime:
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        except (OSError, OverflowError, ValueError) as error:
            raise NormalizationError(f"{label} must be a valid timestamp") from error
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


def ensure_no_sensitive_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SENSITIVE_FIELDS:
                raise NormalizationError(
                    f"branch-protection evidence contains forbidden field {key}"
                )
            ensure_no_sensitive_fields(child)
    elif isinstance(value, list):
        for child in value:
            ensure_no_sensitive_fields(child)


def canonical_state(
    repository_id: int,
    repository_node_id: str,
    repository_name: str,
    branch: str,
    setting: str,
    enabled: bool,
) -> dict[str, Any]:
    return {
        "repository_id": repository_id,
        "repository_node_id": repository_node_id,
        "repository": repository_name,
        "branch": branch,
        setting: enabled,
    }


def validate_audit_receipt(
    audit: dict[str, Any], organization: str, events: list[dict[str, Any]]
) -> tuple[datetime, datetime]:
    collection = audit.get("collection")
    if not isinstance(collection, dict):
        raise NormalizationError("GitHub audit collection receipt must be an object")
    if (
        collection.get("api_endpoint")
        != f"https://api.github.com/orgs/{organization}/audit-log"
        or collection.get("api_version") != API_VERSION
        or collection.get("include") != "all"
        or collection.get("order") != "asc"
        or collection.get("per_page") != 100
        or collection.get("pagination_complete") is not True
        or not isinstance(collection.get("pages"), int)
        or isinstance(collection.get("pages"), bool)
        or collection.get("pages", 0) < 1
        or collection.get("selected_events") != len(events)
        or not isinstance(collection.get("raw_events"), int)
        or isinstance(collection.get("raw_events"), bool)
        or collection.get("raw_events", -1) < len(events)
    ):
        raise NormalizationError("GitHub audit collection receipt is incomplete or mismatched")
    window_start = instant(collection.get("window_start"), "audit window_start")
    window_end = instant(collection.get("window_end"), "audit window_end")
    if not window_start < window_end <= instant(
        audit.get("collected_at"), "audit collected_at"
    ):
        raise NormalizationError("GitHub audit collection window is invalid")
    return window_start, window_end


def normalize(
    audit: dict[str, Any],
    sessions: dict[str, Any],
    register: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    if audit.get("schema") != AUDIT_SCHEMA:
        raise NormalizationError("unsupported GitHub audit schema")
    if sessions.get("schema") != SESSION_SCHEMA:
        raise NormalizationError("unsupported GitHub session schema")
    if register.get("schema") != REGISTER_SCHEMA:
        raise NormalizationError("unsupported GitHub change-register schema")
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise NormalizationError("unsupported GitHub branch-protection snapshot schema")
    sources = (audit, sessions, register, snapshot)
    if not all(source.get("complete") is True for source in sources):
        raise NormalizationError(
            "one or more GitHub branch-protection evidence sources are incomplete"
        )
    for source in sources:
        ensure_no_sensitive_fields(source)

    organization = text(audit.get("organization"), "GitHub organization")
    if snapshot.get("organization") != organization:
        raise NormalizationError("GitHub branch-protection organization is mismatched")
    audit_events = objects(audit.get("events"), "GitHub audit events")
    window_start, window_end = validate_audit_receipt(audit, organization, audit_events)

    repository = snapshot.get("repository")
    branch_record = snapshot.get("branch")
    protection = snapshot.get("protection")
    collection = snapshot.get("collection")
    if not all(
        isinstance(value, dict)
        for value in (repository, branch_record, protection, collection)
    ):
        raise NormalizationError("GitHub branch-protection snapshot is incomplete")
    repository_id = positive_integer(repository.get("id"), "repository ID")
    repository_node_id = text(repository.get("node_id"), "repository node ID")
    repository_name = text(repository.get("full_name"), "repository full name")
    branch = text(branch_record.get("name"), "protected branch name")
    if (
        not repository_name.lower().startswith(organization.lower() + "/")
        or "*" in branch
        or protection.keys()
        != {
            "allow_force_pushes",
            "allow_deletions",
            "enforce_admins",
            "require_code_owner_reviews",
        }
        or not isinstance(protection.get("allow_force_pushes"), bool)
        or not isinstance(protection.get("allow_deletions"), bool)
        or not isinstance(protection.get("enforce_admins"), bool)
        or not isinstance(protection.get("require_code_owner_reviews"), bool)
    ):
        raise NormalizationError("GitHub branch-protection target or state is unsupported")
    owner, repository_slug = repository_name.split("/", 1)
    base = f"https://api.github.com/repos/{owner}/{repository_slug}"
    expected_protection_endpoint = (
        base
        + "/branches/"
        + urllib.parse.quote(branch, safe="")
        + "/protection"
    )
    if (
        collection.get("api_version") != API_VERSION
        or collection.get("repository_endpoint") != base
        or collection.get("protection_endpoint") != expected_protection_endpoint
        or not all(
            isinstance(collection.get(field), str) and collection[field]
            for field in ("repository_request_id", "protection_request_id")
        )
    ):
        raise NormalizationError(
            "GitHub branch-protection collection receipt is incomplete or mismatched"
        )
    snapshot_time = instant(snapshot.get("collected_at"), "snapshot collected_at")
    if window_end < snapshot_time:
        raise NormalizationError(
            "GitHub branch-protection snapshot is not covered by a complete later audit window"
        )

    changes = objects(register.get("changes"), "GitHub change register")
    if len(changes) != 1:
        raise NormalizationError(
            "GitHub branch-protection register must contain one reviewed change"
        )
    change = changes[0]
    event_id = text(change.get("provider_event_id"), "provider event ID")
    github_request_id = text(change.get("github_request_id"), "GitHub request ID")
    matching = [
        event
        for event in audit_events
        if event.get("action") in SETTING_CONTRACTS
        and event.get("_document_id") == event_id
        and event.get("request_id") == github_request_id
    ]
    if len(matching) != 1:
        raise NormalizationError(
            "GitHub branch-protection change lacks one exact audit event"
        )
    event = matching[0]
    action = text(event.get("action"), "audit action")
    contract = SETTING_CONTRACTS[action]
    event_field = contract["event_field"]
    snapshot_field = contract["snapshot_field"]
    register_before_field = contract["register_before_field"]
    actor_id = positive_integer(event.get("actor_id"), "audit actor ID")
    event_time = instant(event.get("@timestamp"), "audit timestamp")
    enforcement = event.get(event_field)
    if contract["value_type"] == "level":
        valid_enforcement = (
            isinstance(enforcement, int)
            and not isinstance(enforcement, bool)
            and enforcement in {0, 1, 2}
        )
        after_enabled = enforcement != 0 if valid_enforcement else None
    else:
        valid_enforcement = isinstance(enforcement, bool)
        after_enabled = enforcement if valid_enforcement else None
    if (
        event.get("org") != organization
        or str(event.get("repo", "")).lower() != repository_name.lower()
        or event.get("repository_id") != repository_id
        or event.get("name") != branch
        or event.get("operation_type") != "modify"
        or event.get("actor_is_bot") is not False
        or not valid_enforcement
        or not window_start <= event_time <= window_end
        or not event_time <= snapshot_time <= event_time + SNAPSHOT_MAX_DELAY
        or protection[snapshot_field] is not after_enabled
    ):
        raise NormalizationError(
            "GitHub branch-protection event target state or snapshot time is mismatched"
        )
    for other in audit_events:
        if other is event or other.get("action") != action:
            continue
        other_time = instant(other.get("@timestamp"), "later audit timestamp")
        if (
            str(other.get("repo", "")).lower() == repository_name.lower()
            and other.get("repository_id") == repository_id
            and other.get("name") == branch
            and event_time < other_time <= snapshot_time
        ):
            raise NormalizationError(
                "GitHub branch-protection snapshot is ambiguous because a later update exists"
            )

    session_index: dict[tuple[int, str], dict[str, Any]] = {}
    for session in objects(sessions.get("sessions"), "GitHub sessions"):
        key = (
            positive_integer(session.get("github_actor_id"), "session actor ID"),
            text(session.get("request_id"), "session request ID"),
        )
        if key in session_index:
            raise NormalizationError(
                "GitHub branch-protection session join keys must be unique"
            )
        session_index[key] = session
    session = session_index.get((actor_id, github_request_id))
    if (
        session is None
        or session.get("github_actor") != event.get("actor")
        or session.get("organization_member") is not True
    ):
        raise NormalizationError(
            "GitHub branch-protection event lacks an exact human session join"
        )

    if (
        change.get("repository_id") != repository_id
        or change.get("repository_node_id") != repository_node_id
        or change.get("branch") != branch
        or not isinstance(change.get(register_before_field), bool)
    ):
        raise NormalizationError(
            "GitHub branch-protection register does not match the stable target"
        )
    before_enabled = change[register_before_field]
    after_enabled = protection[snapshot_field]
    before_state = canonical_state(
        repository_id,
        repository_node_id,
        repository_name,
        branch,
        snapshot_field,
        before_enabled,
    )
    after_state = canonical_state(
        repository_id,
        repository_node_id,
        repository_name,
        branch,
        snapshot_field,
        after_enabled,
    )
    before_digest = digest(before_state)
    after_digest = digest(after_state)
    if (
        DIGEST_RE.fullmatch(before_digest) is None
        or before_digest == after_digest
        or change.get("before_digest") != before_digest
        or change.get("after_digest") != after_digest
    ):
        raise NormalizationError(
            "GitHub branch-protection register does not match exact setting digests"
        )

    principal_id = text(session.get("principal_id"), "principal ID")
    session_id = text(session.get("session_id"), "session ID")
    request_id = text(change.get("request_id"), "change request ID")
    approvals = objects(change.get("approvals"), "GitHub branch-protection approvals")
    emergency = change.get("emergency")
    if not isinstance(emergency, dict):
        raise NormalizationError("GitHub branch-protection emergency record must be an object")
    target_id = (
        f"github:repository:{repository_id}:branch:"
        f"{urllib.parse.quote(branch, safe='')}:legacy-protection"
    )
    normalized_change = {
        "change_id": text(change.get("change_id"), "change ID"),
        "service": "scm",
        "change_type": "branch-protection",
        "target": {"type": "github-legacy-branch-protection", "id": target_id},
        "actor": {
            "id": principal_id,
            "kind": "human",
            "role": text(session.get("role"), "principal role"),
            "organization_member": session["organization_member"],
            "identity_assurance": text(
                session.get("identity_assurance"), "identity assurance"
            ),
            "session_id": session_id,
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
            "id": request_id,
            "requested_at": text(change.get("requested_at"), "requested_at"),
            "policy_version": text(change.get("policy_version"), "policy version"),
            "before_digest": before_digest,
            "after_digest": after_digest,
            "reason": text(change.get("reason"), "change reason"),
            "ticket": text(change.get("ticket"), "change ticket"),
        },
        "approvals": approvals,
        "execution": {
            "status": "applied",
            "executed_at": timestamp(event_time),
            "actor_id": principal_id,
            "session_id": session_id,
            "request_id": request_id,
            "before_digest": before_digest,
            "after_digest": after_digest,
        },
        "audit": {
            "provider_event_id": event_id,
            "recorded_at": timestamp(event_time),
            "actor_id": principal_id,
            "session_id": session_id,
            "request_id": request_id,
            "target_id": target_id,
            "after_digest": after_digest,
        },
        "emergency": emergency,
    }
    output = {
        "schema": OUTPUT_SCHEMA,
        "collected_at": timestamp(
            max(instant(source.get("collected_at"), "source collected_at") for source in sources)
        ),
        "window_start": timestamp(event_time),
        "window_end": timestamp(event_time),
        "collector": {
            "available": True,
            "complete": True,
            "identity": "github-branch-protection-normalizer@sha256:cb2bbe662437ee9ec3edd2a6bdc4f6455f0fba6808b42deff6247040e4429f8a",
            "covered_services": ["scm"],
        },
        "changes": [normalized_change],
    }
    ensure_no_sensitive_fields(output)
    return output


def write_output(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise NormalizationError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
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
        raise NormalizationError(
            "cannot write normalized GitHub branch-protection evidence"
        ) from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-events", type=Path, required=True)
    parser.add_argument("--identity-sessions", type=Path, required=True)
    parser.add_argument("--change-register", type=Path, required=True)
    parser.add_argument("--branch-protection-snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = normalize(
            load(args.audit_events, "GitHub branch-protection audit events"),
            load(args.identity_sessions, "GitHub identity sessions"),
            load(args.change_register, "GitHub branch-protection change register"),
            load(args.branch_protection_snapshot, "GitHub branch-protection snapshot"),
        )
        write_output(args.output, output)
    except NormalizationError as error:
        print(
            f"ERROR GitHub branch-protection normalization unavailable: {error}",
            file=sys.stderr,
        )
        return 2
    print("NORMALIZED 1 GitHub legacy branch-protection change event")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
