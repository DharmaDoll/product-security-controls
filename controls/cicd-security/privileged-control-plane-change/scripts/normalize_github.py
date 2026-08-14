#!/usr/bin/env python3
"""Join reviewed GitHub audit fragments into PSB-CICD-008 evidence."""

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


AUDIT_SCHEMA = "psb-github-audit-export/v1"
SESSION_SCHEMA = "psb-github-admin-session-export/v1"
REGISTER_SCHEMA = "psb-github-privileged-change-register/v1"
RUNNER_GROUP_SCHEMA = "psb-github-runner-group-snapshot/v1"
OUTPUT_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
ALLOWED_ACTIONS = {
    "environment.update_protection_rule": ("environment-protection", "github-environment"),
    "org.runner_group_updated": ("runner-registration-policy", "github-runner-group"),
}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RUNNER_GROUP_SNAPSHOT_MAX_DELAY = timedelta(minutes=5)
SENSITIVE_FIELDS = {
    "actor_ip",
    "authorization",
    "hashed_token",
    "password",
    "private_key",
    "secret",
    "token",
    "token_id",
    "token_scopes",
}


class NormalizationError(ValueError):
    """Input fragments cannot create complete trusted evidence."""


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


def items(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise NormalizationError(f"{label} must be an array")
    if not all(isinstance(item, dict) for item in value):
        raise NormalizationError(f"{label} must contain objects")
    return value


def instant(value: Any, label: str) -> datetime:
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        except (OSError, OverflowError, ValueError) as error:
            raise NormalizationError(f"{label} must be a valid Unix millisecond timestamp") from error
    raw = text(value, label)
    if not raw.endswith("Z"):
        raise NormalizationError(f"{label} must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise NormalizationError(f"{label} must be RFC3339 UTC") from error


def digest(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def ensure_no_sensitive_output(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SENSITIVE_FIELDS:
                raise NormalizationError(f"normalized output contains forbidden field {key}")
            ensure_no_sensitive_output(child)
    elif isinstance(value, list):
        for child in value:
            ensure_no_sensitive_output(child)


def event_target(event: dict[str, Any], target_type: str) -> str:
    action = text(event.get("action"), "audit action")
    if action == "environment.update_protection_rule":
        return f"{text(event.get('repo'), 'audit repo')}:{text(event.get('environment_name'), 'environment')}"
    if action == "org.runner_group_updated":
        runner_group_id = event.get("runner_group_id")
        if not isinstance(runner_group_id, int) or isinstance(runner_group_id, bool):
            raise NormalizationError("runner-group event lacks a stable group ID")
        return f"{text(event.get('org'), 'audit org')}:runner-group:{runner_group_id}"
    return f"{text(event.get('repo'), 'audit repo')}:{target_type}"


def runner_group_index(
    snapshot: dict[str, Any] | None, organization: str
) -> tuple[dict[int, dict[str, Any]], datetime | None]:
    if snapshot is None:
        return {}, None
    if snapshot.get("schema") != RUNNER_GROUP_SCHEMA:
        raise NormalizationError("unsupported GitHub runner-group snapshot schema")
    if snapshot.get("complete") is not True or snapshot.get("organization") != organization:
        raise NormalizationError("GitHub runner-group snapshot is incomplete or mismatched")
    collected_at = instant(snapshot.get("collected_at"), "runner-group collected_at")
    collection = snapshot.get("collection")
    if not isinstance(collection, dict):
        raise NormalizationError("GitHub runner-group collection receipt must be an object")
    groups = items(snapshot.get("runner_groups"), "runner groups")
    if len(groups) != 1:
        raise NormalizationError("runner-group snapshot must contain exactly one requested group")
    index: dict[int, dict[str, Any]] = {}
    for group in groups:
        configuration = group.get("configuration")
        if not isinstance(configuration, dict):
            raise NormalizationError("runner-group snapshot lacks canonical configuration")
        group_id = configuration.get("runner_group_id")
        if not isinstance(group_id, int) or isinstance(group_id, bool) or group_id < 1:
            raise NormalizationError("runner-group snapshot lacks a stable group ID")
        expected_group_endpoint = (
            f"https://api.github.com/orgs/{organization}/actions/runner-groups/{group_id}"
        )
        if (
            collection.get("api_version") != "2026-03-10"
            or collection.get("group_endpoint") != expected_group_endpoint
            or collection.get("repository_endpoint")
            != expected_group_endpoint + "/repositories"
            or collection.get("pagination_complete") is not True
            or not isinstance(collection.get("repository_pages"), int)
            or isinstance(collection.get("repository_pages"), bool)
            or collection.get("repository_pages", -1) < 0
        ):
            raise NormalizationError("runner-group collection receipt is incomplete or mismatched")
        required_types = {
            "name": str,
            "visibility": str,
            "default": bool,
            "inherited": bool,
            "allows_public_repositories": bool,
            "restricted_to_workflows": bool,
            "selected_workflows": list,
            "workflow_restrictions_read_only": bool,
            "selected_repository_ids": list,
        }
        if any(
            not isinstance(configuration.get(field), expected)
            for field, expected in required_types.items()
        ):
            raise NormalizationError("runner-group canonical configuration is malformed")
        if configuration["visibility"] not in {"all", "private", "selected"}:
            raise NormalizationError("runner-group visibility is unsupported")
        workflows = configuration["selected_workflows"]
        repositories = configuration["selected_repository_ids"]
        if (
            not configuration["name"]
            or not all(isinstance(value, str) and value for value in workflows)
            or workflows != sorted(set(workflows))
            or not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in repositories
            )
            or repositories != sorted(set(repositories))
        ):
            raise NormalizationError("runner-group workflows or repositories are not canonical")
        network_id = configuration.get("network_configuration_id")
        if network_id is not None and (not isinstance(network_id, str) or not network_id):
            raise NormalizationError("runner-group network configuration ID is malformed")
        if configuration["visibility"] == "selected":
            if collection["repository_pages"] < 1:
                raise NormalizationError("selected runner-group repository pagination is incomplete")
        elif repositories or collection["repository_pages"] != 0:
            raise NormalizationError("non-selected runner group must not claim repository pages")
        if group_id in index:
            raise NormalizationError("runner-group stable IDs must be unique")
        index[group_id] = configuration
    return index, collected_at


def normalize(
    audit: dict[str, Any],
    sessions: dict[str, Any],
    register: dict[str, Any],
    runner_groups: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if audit.get("schema") != AUDIT_SCHEMA:
        raise NormalizationError("unsupported GitHub audit schema")
    if sessions.get("schema") != SESSION_SCHEMA:
        raise NormalizationError("unsupported session schema")
    if register.get("schema") != REGISTER_SCHEMA:
        raise NormalizationError("unsupported change register schema")
    if not all(source.get("complete") is True for source in (audit, sessions, register)):
        raise NormalizationError("one or more GitHub evidence sources are incomplete")

    organization = text(audit.get("organization"), "organization")
    audit_events = items(audit.get("events"), "audit events")
    group_index, group_collected_at = runner_group_index(runner_groups, organization)
    collection = audit.get("collection")
    audit_window_start: datetime | None = None
    audit_window_end: datetime | None = None
    if collection is not None:
        if not isinstance(collection, dict):
            raise NormalizationError("GitHub collection receipt must be an object")
        if (
            collection.get("api_endpoint")
            != f"https://api.github.com/orgs/{organization}/audit-log"
            or collection.get("api_version") != "2026-03-10"
            or collection.get("include") != "all"
            or collection.get("order") != "asc"
            or collection.get("per_page") != 100
            or collection.get("pagination_complete") is not True
            or not isinstance(collection.get("pages"), int)
            or collection.get("pages", 0) < 1
            or not isinstance(collection.get("raw_events"), int)
            or collection.get("raw_events", -1) < len(audit_events)
            or collection.get("selected_events") != len(audit_events)
        ):
            raise NormalizationError("GitHub collection receipt is incomplete or mismatched")
        audit_window_start = instant(collection.get("window_start"), "audit window_start")
        audit_window_end = instant(collection.get("window_end"), "audit window_end")
        if not audit_window_start < audit_window_end:
            raise NormalizationError("GitHub audit collection window is invalid")
    if group_collected_at is not None and (
        audit_window_end is None or audit_window_end < group_collected_at
    ):
        raise NormalizationError(
            "runner-group snapshot is not covered by a complete later audit window"
        )
    session_index: dict[tuple[int, str], dict[str, Any]] = {}
    for session in items(sessions.get("sessions"), "sessions"):
        actor_id = session.get("github_actor_id")
        request_id = text(session.get("request_id"), "session request_id")
        if not isinstance(actor_id, int) or isinstance(actor_id, bool):
            raise NormalizationError("session actor ID must be integer")
        key = (actor_id, request_id)
        if key in session_index:
            raise NormalizationError("session join keys must be unique")
        session_index[key] = session

    change_index: dict[tuple[str, str], dict[str, Any]] = {}
    for change in items(register.get("changes"), "change register"):
        key = (
            text(change.get("provider_event_id"), "provider event ID"),
            text(change.get("github_request_id"), "GitHub request ID"),
        )
        if key in change_index:
            raise NormalizationError("change register join keys must be unique")
        change_index[key] = change

    changes: list[dict[str, Any]] = []
    seen_events: set[str] = set()
    for event in audit_events:
        action = text(event.get("action"), "audit action")
        if action not in ALLOWED_ACTIONS:
            continue
        event_id = text(event.get("_document_id"), "audit document ID")
        request_key = text(event.get("request_id"), "audit request ID")
        actor_id = event.get("actor_id")
        if not isinstance(actor_id, int) or isinstance(actor_id, bool):
            raise NormalizationError("audit actor ID must be integer")
        if event_id in seen_events:
            raise NormalizationError("audit event IDs must be unique")
        seen_events.add(event_id)
        if event.get("org") != organization or event.get("actor_is_bot") is not False:
            raise NormalizationError("audit event organization or human-actor marker is invalid")
        session = session_index.get((actor_id, request_key))
        change = change_index.get((event_id, request_key))
        if session is None or change is None:
            raise NormalizationError("privileged GitHub event lacks an exact session or change-register join")
        if session.get("github_actor") != event.get("actor"):
            raise NormalizationError("GitHub actor name and stable ID do not resolve to the same session")
        if session.get("organization_member") is not True:
            raise NormalizationError("GitHub session is not bound to current organization membership")
        change_type, target_type = ALLOWED_ACTIONS[action]
        target_id = event_target(event, target_type)
        event_time = instant(event.get("@timestamp"), "audit timestamp")
        if audit_window_start is not None and audit_window_end is not None and not (
            audit_window_start <= event_time <= audit_window_end
        ):
            raise NormalizationError("GitHub event falls outside the collection window")
        if action == "environment.update_protection_rule":
            old_value = event.get("old_value")
            new_value = event.get("new_value")
            if not isinstance(old_value, dict) or not isinstance(new_value, dict):
                raise NormalizationError(
                    "GitHub event lacks canonicalizable old or new configuration"
                )
            before_digest = digest(old_value)
            after_digest = digest(new_value)
            if (
                change.get("before_digest") != before_digest
                or change.get("after_digest") != after_digest
            ):
                raise NormalizationError(
                    "change register does not match GitHub before and after values"
                )
        else:
            group_id = event.get("runner_group_id")
            configuration = group_index.get(group_id)
            if configuration is None or group_collected_at is None:
                raise NormalizationError(
                    "runner-group event lacks an exact current-state snapshot join"
                )
            if not event_time <= group_collected_at <= event_time + RUNNER_GROUP_SNAPSHOT_MAX_DELAY:
                raise NormalizationError(
                    "runner-group current-state snapshot is stale or precedes the event"
                )
            later_events = [
                candidate
                for candidate in audit_events
                if candidate.get("action") == "org.runner_group_updated"
                and candidate.get("runner_group_id") == group_id
                and event_time
                < instant(candidate.get("@timestamp"), "runner-group audit timestamp")
                <= group_collected_at
            ]
            if later_events:
                raise NormalizationError(
                    "runner-group snapshot is ambiguous because a later update exists"
                )
            if (
                event.get("runner_group_name") != configuration["name"]
                or event.get("runner_group_allow_public")
                != configuration["allows_public_repositories"]
                or event.get("runner_group_restricted_to_workflows")
                != configuration["restricted_to_workflows"]
                or sorted(event.get("runner_group_selected_workflow_refs", []))
                != configuration["selected_workflows"]
                or event.get("network_configuration_id")
                != configuration["network_configuration_id"]
                or change.get("runner_group_id") != group_id
            ):
                raise NormalizationError(
                    "runner-group audit register and current state do not name one configuration"
                )
            before_digest = change.get("before_digest")
            after_digest = digest(configuration)
            if (
                not isinstance(before_digest, str)
                or SHA256_RE.fullmatch(before_digest) is None
                or change.get("after_digest") != after_digest
            ):
                raise NormalizationError(
                    "change register does not match the runner-group current-state digest"
                )
        approvals = items(change.get("approvals"), "change approvals")
        emergency = change.get("emergency")
        if not isinstance(emergency, dict):
            raise NormalizationError("change emergency record must be an object")
        changes.append(
            {
                "change_id": text(change.get("change_id"), "change ID"),
                "service": "ci",
                "change_type": change_type,
                "target": {"type": target_type, "id": target_id},
                "actor": {
                    "id": text(session.get("principal_id"), "principal ID"),
                    "kind": "human",
                    "role": text(session.get("role"), "principal role"),
                    "organization_member": session.get("organization_member"),
                    "identity_assurance": text(session.get("identity_assurance"), "identity assurance"),
                    "session_id": text(session.get("session_id"), "session ID"),
                    "session_issued_at": text(session.get("session_issued_at"), "session issued_at"),
                    "session_expires_at": text(session.get("session_expires_at"), "session expires_at"),
                    "reauthenticated_at": text(session.get("reauthenticated_at"), "reauthenticated_at"),
                },
                "request": {
                    "id": change["request_id"],
                    "requested_at": change["requested_at"],
                    "policy_version": change["policy_version"],
                    "before_digest": change["before_digest"],
                    "after_digest": change["after_digest"],
                    "reason": change["reason"],
                    "ticket": change["ticket"],
                },
                "approvals": approvals,
                "execution": {
                    "status": "applied",
                    "executed_at": event_time.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    "actor_id": session["principal_id"],
                    "session_id": session["session_id"],
                    "request_id": change["request_id"],
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                },
                "audit": {
                    "provider_event_id": event_id,
                    "recorded_at": event_time.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    "actor_id": session["principal_id"],
                    "session_id": session["session_id"],
                    "request_id": change["request_id"],
                    "target_id": target_id,
                    "after_digest": after_digest,
                },
                "emergency": emergency,
            }
        )

    if not changes:
        raise NormalizationError("GitHub export contains no reviewed privileged change events")
    collected_times = [
        instant(source.get("collected_at"), "source collected_at")
        for source in (audit, sessions, register)
    ]
    if group_collected_at is not None:
        collected_times.append(group_collected_at)
    event_times = [instant(change["execution"]["executed_at"], "execution time") for change in changes]
    output = {
        "schema": OUTPUT_SCHEMA,
        "collected_at": max(collected_times).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "window_start": min(event_times).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "window_end": max(event_times).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "collector": {
            "available": True,
            "complete": True,
            "identity": "github-control-plane-normalizer@sha256:ba1f50a0e90b709d0aa8d8ced4a010d566c3bb82744f7094c91c2b13b9cf6711",
            "covered_services": ["ci"],
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
        raise NormalizationError("cannot write normalized evidence") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-events", type=Path, required=True)
    parser.add_argument("--identity-sessions", type=Path, required=True)
    parser.add_argument("--change-register", type=Path, required=True)
    parser.add_argument("--runner-groups", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = normalize(
            load(args.audit_events, "GitHub audit events"),
            load(args.identity_sessions, "identity sessions"),
            load(args.change_register, "change register"),
            load(args.runner_groups, "runner-group snapshot")
            if args.runner_groups is not None
            else None,
        )
        write_output(args.output, output)
    except NormalizationError as error:
        print(f"ERROR GitHub control-plane normalization unavailable: {error}", file=sys.stderr)
        return 2
    print(f"NORMALIZED {len(output['changes'])} GitHub privileged change event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
