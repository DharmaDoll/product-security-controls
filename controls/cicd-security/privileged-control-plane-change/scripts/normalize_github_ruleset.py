#!/usr/bin/env python3
"""Join one reviewed GitHub repository or organization ruleset update."""

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
RULESET_SCHEMA = "psb-github-repository-ruleset-snapshot/v1"
ORGANIZATION_RULESET_SCHEMA = "psb-github-organization-ruleset-snapshot/v1"
FORK_NETWORK_SCHEMA = "psb-github-fork-network-snapshot/v1"
OUTPUT_SCHEMA = "psb-cicd-control-plane-change-evidence/v1"
ACTION = "repository_ruleset.update"
SNAPSHOT_MAX_DELAY = timedelta(minutes=5)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
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
    "user_agent",
}


class NormalizationError(ValueError):
    """GitHub ruleset fragments cannot create trusted SCM evidence."""


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


def ensure_no_sensitive_output(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SENSITIVE_FIELDS:
                raise NormalizationError(f"normalized output contains forbidden field {key}")
            ensure_no_sensitive_output(child)
    elif isinstance(value, list):
        for child in value:
            ensure_no_sensitive_output(child)


def canonical_state(
    value: Any,
    ruleset_id: int,
    node_id: str,
    source_name: str,
    source_type: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NormalizationError("GitHub ruleset state must be an object")
    required = {
        "id": int,
        "node_id": str,
        "name": str,
        "target": str,
        "source_type": str,
        "source": str,
        "enforcement": str,
        "bypass_actors": list,
        "rules": list,
        "created_at": str,
        "updated_at": str,
    }
    if (
        any(not isinstance(value.get(key), kind) for key, kind in required.items())
        or not (isinstance(value.get("conditions"), dict) or value.get("conditions") is None)
    ):
        raise NormalizationError("GitHub ruleset state is incomplete")
    if (
        value["id"] != ruleset_id
        or value["node_id"] != node_id
        or value["target"] not in {"branch", "tag", "push"}
        or value["source_type"] != source_type
        or value["source"].lower() != source_name.lower()
        or value["enforcement"] not in {"active", "evaluate", "disabled"}
        or not value["name"]
    ):
        raise NormalizationError("GitHub ruleset state identity or target is mismatched")
    instant(value["created_at"], "ruleset state created_at")
    instant(value["updated_at"], "ruleset state updated_at")
    return value


def normalize(
    audit: dict[str, Any],
    sessions: dict[str, Any],
    register: dict[str, Any],
    snapshot: dict[str, Any],
    fork_network: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if audit.get("schema") != AUDIT_SCHEMA:
        raise NormalizationError("unsupported GitHub audit schema")
    if sessions.get("schema") != SESSION_SCHEMA:
        raise NormalizationError("unsupported GitHub session schema")
    if register.get("schema") != REGISTER_SCHEMA:
        raise NormalizationError("unsupported GitHub change-register schema")
    snapshot_schema = snapshot.get("schema")
    if snapshot_schema not in {RULESET_SCHEMA, ORGANIZATION_RULESET_SCHEMA}:
        raise NormalizationError("unsupported GitHub ruleset snapshot schema")
    if not all(source.get("complete") is True for source in (audit, sessions, register, snapshot)):
        raise NormalizationError("one or more GitHub ruleset evidence sources are incomplete")

    organization = text(audit.get("organization"), "GitHub organization")
    if snapshot.get("organization") != organization:
        raise NormalizationError("GitHub ruleset organization is mismatched")
    audit_events = objects(audit.get("events"), "GitHub audit events")
    collection = audit.get("collection")
    if not isinstance(collection, dict):
        raise NormalizationError("GitHub audit collection receipt must be an object")
    if (
        collection.get("api_endpoint") != f"https://api.github.com/orgs/{organization}/audit-log"
        or collection.get("api_version") != "2026-03-10"
        or collection.get("include") != "all"
        or collection.get("order") != "asc"
        or collection.get("per_page") != 100
        or collection.get("pagination_complete") is not True
        or not isinstance(collection.get("pages"), int)
        or isinstance(collection.get("pages"), bool)
        or collection.get("pages", 0) < 1
        or collection.get("selected_events") != len(audit_events)
        or not isinstance(collection.get("raw_events"), int)
        or isinstance(collection.get("raw_events"), bool)
        or collection.get("raw_events", -1) < len(audit_events)
    ):
        raise NormalizationError("GitHub audit collection receipt is incomplete or mismatched")
    window_start = instant(collection.get("window_start"), "audit window_start")
    window_end = instant(collection.get("window_end"), "audit window_end")
    if not window_start < window_end <= instant(audit.get("collected_at"), "audit collected_at"):
        raise NormalizationError("GitHub audit collection window is invalid")

    repository_scope = snapshot_schema == RULESET_SCHEMA
    source_identity = (
        snapshot.get("repository")
        if repository_scope
        else snapshot.get("organization_identity")
    )
    ruleset = snapshot.get("ruleset")
    ruleset_collection = snapshot.get("collection")
    if not all(
        isinstance(value, dict) for value in (source_identity, ruleset, ruleset_collection)
    ):
        raise NormalizationError("GitHub ruleset snapshot lacks identity or receipt")
    source_id = positive_integer(
        source_identity.get("id"),
        "repository ID" if repository_scope else "organization ID",
    )
    source_node_id = text(
        source_identity.get("node_id"),
        "repository node ID" if repository_scope else "organization node ID",
    )
    source_name = text(
        source_identity.get("full_name")
        if repository_scope
        else source_identity.get("login"),
        "repository full name" if repository_scope else "organization login",
    )
    if repository_scope and not source_name.lower().startswith(
        organization.lower() + "/"
    ):
        raise NormalizationError("GitHub repository is outside the audited organization")
    if not repository_scope and source_name.lower() != organization.lower():
        raise NormalizationError("GitHub organization identity is mismatched")
    ruleset_id = positive_integer(ruleset.get("id"), "ruleset ID")
    ruleset_node_id = text(ruleset.get("node_id"), "ruleset node ID")
    before_version_id = positive_integer(ruleset.get("before_version_id"), "before version ID")
    after_version_id = positive_integer(ruleset.get("after_version_id"), "after version ID")
    if before_version_id >= after_version_id:
        raise NormalizationError("GitHub ruleset version order is invalid")
    if repository_scope:
        owner, repository_slug = source_name.split("/", 1)
        base = f"https://api.github.com/repos/{owner}/{repository_slug}"
        source_endpoint_field = "repository_endpoint"
        source_request_field = "repository_request_id"
        expected_ruleset_endpoint = base + f"/rulesets/{ruleset_id}?includes_parents=false"
    else:
        base = f"https://api.github.com/orgs/{organization}"
        source_endpoint_field = "organization_endpoint"
        source_request_field = "organization_request_id"
        expected_ruleset_endpoint = base + f"/rulesets/{ruleset_id}"
    if (
        ruleset_collection.get("api_version") != "2026-03-10"
        or ruleset_collection.get(source_endpoint_field) != base
        or ruleset_collection.get("ruleset_endpoint")
        != expected_ruleset_endpoint
        or ruleset_collection.get("history_endpoint")
        != base + f"/rulesets/{ruleset_id}/history?per_page=100"
        or ruleset_collection.get("history_complete") is not True
        or not isinstance(ruleset_collection.get("history_pages"), int)
        or isinstance(ruleset_collection.get("history_pages"), bool)
        or ruleset_collection.get("history_pages", 0) < 1
        or not all(
            isinstance(ruleset_collection.get(field), str) and ruleset_collection[field]
            for field in (source_request_field, "ruleset_request_id")
        )
        or not all(
            isinstance(ruleset_collection.get(field), list)
            and ruleset_collection[field]
            and all(isinstance(item, str) and item for item in ruleset_collection[field])
            for field in ("history_request_ids", "version_request_ids")
        )
        or len(ruleset_collection.get("history_request_ids", []))
        != ruleset_collection.get("history_pages")
        or len(ruleset_collection.get("version_request_ids", [])) != 2
    ):
        raise NormalizationError("GitHub ruleset collection receipt is incomplete or mismatched")
    snapshot_time = instant(snapshot.get("collected_at"), "ruleset collected_at")
    if window_end < snapshot_time:
        raise NormalizationError(
            "GitHub ruleset snapshot is not covered by a complete later audit window"
        )

    history = objects(ruleset.get("history"), "ruleset history")
    versions = objects(ruleset.get("versions"), "ruleset versions")
    if len(versions) != 2:
        raise NormalizationError("GitHub ruleset snapshot must contain exact before and after versions")
    history_index: dict[int, dict[str, Any]] = {}
    for entry in history:
        version_id = positive_integer(entry.get("version_id"), "history version ID")
        if version_id in history_index:
            raise NormalizationError("GitHub ruleset history version IDs must be unique")
        positive_integer(entry.get("actor_id"), "history actor ID")
        instant(entry.get("updated_at"), "history updated_at")
        history_index[version_id] = entry
    if (
        before_version_id not in history_index
        or after_version_id not in history_index
        or max(history_index) != after_version_id
    ):
        raise NormalizationError("GitHub ruleset history is incomplete or has a later version")
    version_index: dict[int, dict[str, Any]] = {}
    for version in versions:
        version_id = positive_integer(version.get("version_id"), "ruleset version ID")
        history_entry = history_index.get(version_id)
        if (
            history_entry is None
            or version.get("actor_id") != history_entry["actor_id"]
            or version.get("updated_at") != history_entry["updated_at"]
        ):
            raise NormalizationError("GitHub ruleset version does not match history")
        version_index[version_id] = version
    if set(version_index) != {before_version_id, after_version_id}:
        raise NormalizationError("GitHub ruleset before and after versions are mismatched")
    before_state = canonical_state(
        version_index[before_version_id].get("state"),
        ruleset_id,
        ruleset_node_id,
        source_name,
        "Repository" if repository_scope else "Organization",
    )
    after_state = canonical_state(
        version_index[after_version_id].get("state"),
        ruleset_id,
        ruleset_node_id,
        source_name,
        "Repository" if repository_scope else "Organization",
    )
    current_state = canonical_state(
        ruleset.get("current"),
        ruleset_id,
        ruleset_node_id,
        source_name,
        "Repository" if repository_scope else "Organization",
    )
    if current_state != after_state:
        raise NormalizationError("GitHub ruleset current state does not match the latest version")
    if (
        before_state["updated_at"] != version_index[before_version_id]["updated_at"]
        or after_state["updated_at"] != version_index[after_version_id]["updated_at"]
        or before_state["created_at"] != after_state["created_at"]
    ):
        raise NormalizationError("GitHub ruleset state timestamps or generation are mismatched")
    if before_state["target"] != after_state["target"]:
        raise NormalizationError("GitHub ruleset target changed across requested versions")
    ruleset_target = after_state["target"]
    if ruleset_target == "push" and not repository_scope:
        raise NormalizationError("organization push ruleset scope is not implemented")
    if ruleset_target != "push" and fork_network is not None:
        raise NormalizationError("fork-network evidence is only valid for a push ruleset")

    network_digest: str | None = None
    if ruleset_target == "push":
        if fork_network is None or fork_network.get("schema") != FORK_NETWORK_SCHEMA:
            raise NormalizationError("push ruleset lacks a supported fork-network snapshot")
        if fork_network.get("complete") is not True:
            raise NormalizationError("push ruleset fork-network snapshot is incomplete")
        network_collection = fork_network.get("collection")
        network_root = fork_network.get("root")
        network_forks = fork_network.get("forks")
        if (
            fork_network.get("organization") != organization
            or not isinstance(network_collection, dict)
            or not isinstance(network_root, dict)
            or not isinstance(network_forks, list)
            or not all(isinstance(item, dict) for item in network_forks)
            or network_collection.get("api_version") != "2026-03-10"
            or network_collection.get("root_endpoint") != base
            or network_collection.get("forks_endpoint")
            != base + "/forks?per_page=100&sort=oldest"
            or network_collection.get("forks_complete") is not True
            or not isinstance(network_collection.get("fork_pages"), int)
            or isinstance(network_collection.get("fork_pages"), bool)
            or network_collection.get("fork_pages", 0) < 1
            or not isinstance(network_collection.get("root_request_id"), str)
            or not network_collection.get("root_request_id")
            or not isinstance(network_collection.get("fork_request_ids"), list)
            or len(network_collection.get("fork_request_ids", []))
            != network_collection.get("fork_pages")
            or not all(
                isinstance(item, str) and item
                for item in network_collection.get("fork_request_ids", [])
            )
        ):
            raise NormalizationError("push ruleset fork-network receipt is mismatched")
        if (
            network_root.get("id") != source_id
            or network_root.get("node_id") != source_node_id
            or str(network_root.get("full_name", "")).lower() != source_name.lower()
            or network_root.get("visibility") not in {"private", "internal"}
            or network_root.get("network_count") != len(network_forks)
        ):
            raise NormalizationError("push ruleset fork-network root identity is mismatched")
        fork_ids: set[int] = set()
        canonical_forks: list[dict[str, Any]] = []
        for item in network_forks:
            fork_id = positive_integer(item.get("id"), "fork repository ID")
            fork_node_id = text(item.get("node_id"), "fork repository node ID")
            fork_name = text(item.get("full_name"), "fork repository full name")
            if (
                fork_id == source_id
                or fork_id in fork_ids
                or "/" not in fork_name
                or item.get("root_id") != source_id
                or item.get("root_node_id") != source_node_id
            ):
                raise NormalizationError("push ruleset fork-network members are not unique")
            fork_ids.add(fork_id)
            canonical_forks.append(
                {
                    "id": fork_id,
                    "node_id": fork_node_id,
                    "full_name": fork_name,
                    "root_id": source_id,
                    "root_node_id": source_node_id,
                }
            )
        if canonical_forks != sorted(canonical_forks, key=lambda item: item["id"]):
            raise NormalizationError("push ruleset fork-network members are not canonical")
        network_time = instant(fork_network.get("collected_at"), "fork-network collected_at")
        network_digest = digest({"root": network_root, "forks": canonical_forks})

    session_index: dict[tuple[int, str], dict[str, Any]] = {}
    for session in objects(sessions.get("sessions"), "GitHub sessions"):
        key = (
            positive_integer(session.get("github_actor_id"), "session actor ID"),
            text(session.get("request_id"), "session request ID"),
        )
        if key in session_index:
            raise NormalizationError("GitHub ruleset session join keys must be unique")
        session_index[key] = session
    change_index: dict[tuple[str, str], dict[str, Any]] = {}
    for change in objects(register.get("changes"), "GitHub change register"):
        key = (
            text(change.get("provider_event_id"), "provider event ID"),
            text(change.get("github_request_id"), "GitHub request ID"),
        )
        if key in change_index:
            raise NormalizationError("GitHub ruleset change-register join keys must be unique")
        change_index[key] = change

    matching = [event for event in audit_events if event.get("action") == ACTION]
    if len(matching) != 1:
        raise NormalizationError("GitHub ruleset export must contain one update event")
    event = matching[0]
    event_id = text(event.get("_document_id"), "audit document ID")
    github_request_id = text(event.get("request_id"), "audit request ID")
    actor_id = positive_integer(event.get("actor_id"), "audit actor ID")
    event_time = instant(event.get("@timestamp"), "audit timestamp")
    if ruleset_target == "push" and (
        not event_time <= network_time <= event_time + SNAPSHOT_MAX_DELAY
        or window_end < network_time
    ):
        raise NormalizationError("push ruleset fork-network snapshot time is not covered")
    session = session_index.get((actor_id, github_request_id))
    change = change_index.get((event_id, github_request_id))
    if session is None or change is None:
        raise NormalizationError("GitHub ruleset event lacks an exact session or change-register join")
    if (
        event.get("org") != organization
        or event.get("ruleset_id") != ruleset_id
        or event.get("ruleset_source_type")
        != ("Repository" if repository_scope else "Organization")
        or event.get("operation_type") != "modify"
        or event.get("actor_is_bot") is not False
        or session.get("github_actor") != event.get("actor")
        or session.get("organization_member") is not True
        or history_index[after_version_id]["actor_id"] != actor_id
        or instant(history_index[after_version_id]["updated_at"], "after version updated_at")
        != event_time
        or not window_start <= event_time <= window_end
        or not event_time <= snapshot_time <= event_time + SNAPSHOT_MAX_DELAY
    ):
        raise NormalizationError("GitHub ruleset event identity history or snapshot time is mismatched")
    if repository_scope and (
        event.get("repo", "").lower() != source_name.lower()
        or event.get("repository_id") != source_id
    ):
        raise NormalizationError("GitHub repository ruleset event source is mismatched")
    if not repository_scope and (
        event.get("org_id") != source_id
        or "repo" in event
        or "repository_id" in event
    ):
        raise NormalizationError("GitHub organization ruleset event source is mismatched")
    if (
        event.get("ruleset_old_enforcement") != before_state["enforcement"]
        or event.get("ruleset_enforcement") != after_state["enforcement"]
        or event.get("ruleset_old_name") != before_state["name"]
        or event.get("ruleset_name") != after_state["name"]
    ):
        raise NormalizationError("GitHub ruleset audit delta does not match version history")

    before_digest = digest(before_state)
    after_digest = digest(after_state)
    if (
        DIGEST_RE.fullmatch(before_digest) is None
        or before_digest == after_digest
        or change.get("ruleset_id") != ruleset_id
        or change.get("ruleset_node_id") != ruleset_node_id
        or change.get("before_version_id") != before_version_id
        or change.get("after_version_id") != after_version_id
        or change.get("ruleset_target") != ruleset_target
        or change.get("before_digest") != before_digest
        or change.get("after_digest") != after_digest
    ):
        raise NormalizationError("GitHub ruleset register does not match exact history digests")
    if repository_scope and (
        change.get("repository_id") != source_id
        or change.get("repository_node_id") != source_node_id
    ):
        raise NormalizationError("GitHub ruleset register does not match repository identity")
    if not repository_scope and (
        change.get("organization_id") != source_id
        or change.get("organization_node_id") != source_node_id
    ):
        raise NormalizationError("GitHub ruleset register does not match organization identity")
    if ruleset_target == "push" and change.get("network_digest") != network_digest:
        raise NormalizationError("GitHub push ruleset register does not match fork-network identity")
    if ruleset_target != "push" and "network_digest" in change:
        raise NormalizationError("non-push ruleset register unexpectedly includes fork-network identity")
    approvals = objects(change.get("approvals"), "GitHub ruleset approvals")
    emergency = change.get("emergency")
    if not isinstance(emergency, dict):
        raise NormalizationError("GitHub ruleset emergency record must be an object")

    principal_id = text(session.get("principal_id"), "principal ID")
    session_id = text(session.get("session_id"), "session ID")
    request_id = text(change.get("request_id"), "change request ID")
    target_id = (
        f"github:repository:{source_id}:ruleset:{ruleset_id}@{ruleset_node_id}"
        if repository_scope
        else f"github:organization:{source_id}:ruleset:{ruleset_id}@{ruleset_node_id}"
    )
    if network_digest is not None:
        target_id += f":network@{network_digest}"
    normalized_change = {
        "change_id": text(change.get("change_id"), "change ID"),
        "service": "scm",
        "change_type": {
            "branch": "branch-protection",
            "tag": "tag-protection",
            "push": "push-protection",
        }[ruleset_target],
        "target": {
            "type": "github-repository-ruleset"
            if repository_scope
            else "github-organization-ruleset",
            "id": target_id,
        },
        "actor": {
            "id": principal_id,
            "kind": "human",
            "role": text(session.get("role"), "principal role"),
            "organization_member": session["organization_member"],
            "identity_assurance": text(session.get("identity_assurance"), "identity assurance"),
            "session_id": session_id,
            "session_issued_at": text(session.get("session_issued_at"), "session issued_at"),
            "session_expires_at": text(session.get("session_expires_at"), "session expires_at"),
            "reauthenticated_at": text(session.get("reauthenticated_at"), "reauthenticated_at"),
        },
        "request": {
            "id": request_id,
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
            max(
                instant(source.get("collected_at"), "source collected_at")
                for source in (
                    (audit, sessions, register, snapshot)
                    + (() if fork_network is None else (fork_network,))
                )
            )
        ),
        "window_start": timestamp(event_time),
        "window_end": timestamp(event_time),
        "collector": {
            "available": True,
            "complete": True,
            "identity": "github-ruleset-normalizer@sha256:b1b2c687aff553470fd53e6ae02d912ea411ec38f0c998ea53a6d49de9850357",
            "covered_services": ["scm"],
        },
        "changes": [normalized_change],
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
        raise NormalizationError("cannot write normalized GitHub ruleset evidence") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-events", type=Path, required=True)
    parser.add_argument("--identity-sessions", type=Path, required=True)
    parser.add_argument("--change-register", type=Path, required=True)
    parser.add_argument("--ruleset-snapshot", type=Path, required=True)
    parser.add_argument("--fork-network-snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = normalize(
            load(args.audit_events, "GitHub ruleset audit events"),
            load(args.identity_sessions, "GitHub identity sessions"),
            load(args.change_register, "GitHub ruleset change register"),
            load(args.ruleset_snapshot, "GitHub ruleset snapshot"),
            (
                load(args.fork_network_snapshot, "GitHub fork-network snapshot")
                if args.fork_network_snapshot is not None
                else None
            ),
        )
        write_output(args.output, output)
    except NormalizationError as error:
        print(f"ERROR GitHub ruleset normalization unavailable: {error}", file=sys.stderr)
        return 2
    target = output["changes"][0]["target"]["type"]
    scope = "repository-ruleset" if target == "github-repository-ruleset" else "organization-ruleset"
    print(f"NORMALIZED 1 GitHub {scope} change event")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
