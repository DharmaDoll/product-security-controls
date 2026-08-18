#!/usr/bin/env python3
"""Verify repository mass-deletion prevention and recoverability evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-repository-destruction-recovery-policy/v1"
EVIDENCE_SCHEMA = "psb-repository-destruction-recovery-evidence/v1"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSIONED_ID_RE = re.compile(r"^[a-z0-9-]+@sha256:[0-9a-f]{64}$")
SNAPSHOT_ID_RE = re.compile(r"^repository-snapshot@sha256:[0-9a-f]{64}$")
REPOSITORY_ID_RE = re.compile(r"^[1-9][0-9]*$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DOMAIN_RE = re.compile(r"^[a-z][a-z0-9-]+-[0-9]+$")
SENSITIVE_FIELDS = {
    "access_key",
    "credential",
    "customer_data",
    "password",
    "payload",
    "private_key",
    "secret",
    "source_content",
    "token",
}
CHECK_MESSAGES = {
    "RDR-001": "critical repository inventory and collector scope are exact and complete",
    "RDR-002": "bulk deletion is default denied and independently authorized",
    "RDR-003": "current repository backups are immutable and attacker separated",
    "RDR-004": "destructive activity has complete audit and bounded external alert delivery",
    "RDR-005": "destructive actor authority is contained before recovery",
    "RDR-006": "isolated restore drill meets coverage RPO RTO and exact-state requirements",
    "RDR-007": "evidence evaluation is strict metadata only and fail closed",
}

POLICY_FIELDS = {
    "schema",
    "policy_id",
    "required_repository_ids",
    "max_bulk_delete_targets",
    "deletion_controls",
    "backup",
    "detection",
    "containment",
    "recovery",
    "max_evidence_age_seconds",
    "max_document_bytes",
    "evidence_mode",
}
EVIDENCE_FIELDS = {
    "schema",
    "policy_id",
    "collector",
    "repositories",
    "deletion_request",
    "audit",
    "containment",
    "recovery_drill",
}


class EvidenceError(ValueError):
    """Evidence cannot support a safe decision."""


def require_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise EvidenceError(f"{label} fields are incomplete or unknown")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str, *, nonempty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        raise EvidenceError(f"{label} must be a{' non-empty' if nonempty else ''} list")
    return value


def require_text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be non-empty text")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label} has invalid identity syntax")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{label} must be boolean")
    return value


def require_int(value: Any, label: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise EvidenceError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def require_unique_text_list(value: Any, label: str) -> list[str]:
    items = require_list(value, label)
    if any(not isinstance(item, str) or not item for item in items):
        raise EvidenceError(f"{label} must contain non-empty text")
    if len(items) != len(set(items)):
        raise EvidenceError(f"{label} contains duplicates")
    return items


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{label} must be an RFC 3339 UTC timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise EvidenceError(f"{label} must use UTC")
    return parsed


def read_json(path: Path, label: str, maximum: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"{label} is unavailable or symbolic")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"{label} cannot be read") from error
    if not raw or len(raw) > maximum:
        raise EvidenceError(f"{label} is empty or exceeds the size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} root must be an object")
    return value


def find_sensitive(value: Any, path: str = "evidence") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SENSITIVE_FIELDS:
                return f"{path}.{key}"
            found = find_sensitive(child, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = find_sensitive(child, f"{path}[{index}]")
            if found:
                return found
    return None


def validate_policy(policy: dict[str, Any]) -> None:
    require_fields(policy, POLICY_FIELDS, "policy")
    if policy.get("schema") != POLICY_SCHEMA:
        raise EvidenceError("policy schema is unsupported")
    policy_id = require_text(policy.get("policy_id"), "policy.policy_id", VERSIONED_ID_RE)
    canonical_policy = dict(policy)
    canonical_policy.pop("policy_id")
    canonical = json.dumps(
        canonical_policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    expected_policy_id = f"repository-recovery-policy@sha256:{hashlib.sha256(canonical).hexdigest()}"
    if policy_id != expected_policy_id:
        raise EvidenceError("policy_id does not match canonical policy content")
    for repository_id in require_unique_text_list(
        policy.get("required_repository_ids"), "policy.required_repository_ids"
    ):
        require_text(repository_id, "policy repository ID", REPOSITORY_ID_RE)
    require_int(policy.get("max_bulk_delete_targets"), "policy.max_bulk_delete_targets")
    require_int(policy.get("max_evidence_age_seconds"), "policy.max_evidence_age_seconds")
    require_int(policy.get("max_document_bytes"), "policy.max_document_bytes")
    if policy["max_document_bytes"] > 1048576:
        raise EvidenceError("policy.max_document_bytes exceeds the verifier limit")
    require_text(policy.get("evidence_mode"), "policy.evidence_mode")

    deletion = require_object(policy.get("deletion_controls"), "policy.deletion_controls")
    require_fields(
        deletion,
        {
            "default_deny",
            "independent_approval",
            "phishing_resistant_reauthentication",
            "approval_max_age_seconds",
        },
        "policy.deletion_controls",
    )
    for field in (
        "default_deny",
        "independent_approval",
        "phishing_resistant_reauthentication",
    ):
        require_bool(deletion.get(field), f"policy.deletion_controls.{field}")
    require_int(deletion.get("approval_max_age_seconds"), "policy deletion approval age")

    backup = require_object(policy.get("backup"), "policy.backup")
    require_fields(
        backup,
        {
            "max_rpo_seconds",
            "minimum_retention_days",
            "cross_security_domain",
            "object_lock",
            "source_admin_delete_denied",
        },
        "policy.backup",
    )
    require_int(backup.get("max_rpo_seconds"), "policy backup RPO")
    require_int(backup.get("minimum_retention_days"), "policy backup retention")
    require_bool(backup.get("cross_security_domain"), "policy backup domain separation")
    require_bool(backup.get("source_admin_delete_denied"), "policy backup deletion denial")
    require_text(backup.get("object_lock"), "policy backup object lock")

    detection = require_object(policy.get("detection"), "policy.detection")
    require_fields(
        detection,
        {
            "complete_audit_required",
            "max_alert_delay_seconds",
            "external_delivery_required",
        },
        "policy.detection",
    )
    require_bool(detection.get("complete_audit_required"), "policy complete audit")
    require_int(detection.get("max_alert_delay_seconds"), "policy alert delay")
    require_bool(detection.get("external_delivery_required"), "policy external alert")

    containment = require_object(policy.get("containment"), "policy.containment")
    require_fields(
        containment,
        {
            "actor_session_revocation_required",
            "token_revocation_required",
            "before_recovery_required",
        },
        "policy.containment",
    )
    for field in containment:
        require_bool(containment[field], f"policy.containment.{field}")

    recovery = require_object(policy.get("recovery"), "policy.recovery")
    require_fields(
        recovery,
        {
            "max_rto_seconds",
            "max_drill_age_seconds",
            "isolated_target_required",
            "complete_refs_required",
            "settings_restore_required",
        },
        "policy.recovery",
    )
    require_int(recovery.get("max_rto_seconds"), "policy recovery RTO")
    require_int(recovery.get("max_drill_age_seconds"), "policy recovery drill age")
    for field in ("isolated_target_required", "complete_refs_required", "settings_restore_required"):
        require_bool(recovery.get(field), f"policy.recovery.{field}")


def validate_evidence_structure(evidence: dict[str, Any]) -> None:
    require_fields(evidence, EVIDENCE_FIELDS, "evidence")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise EvidenceError("evidence schema is unsupported")
    require_text(evidence.get("policy_id"), "evidence.policy_id", VERSIONED_ID_RE)

    collector = require_object(evidence.get("collector"), "evidence.collector")
    require_fields(
        collector,
        {"status", "collector_id", "collected_at", "repository_ids", "pagination_complete"},
        "evidence.collector",
    )
    require_text(collector.get("status"), "collector.status")
    require_text(collector.get("collector_id"), "collector.collector_id", VERSIONED_ID_RE)
    parse_time(collector.get("collected_at"), "collector.collected_at")
    for repository_id in require_unique_text_list(collector.get("repository_ids"), "collector.repository_ids"):
        require_text(repository_id, "collector repository ID", REPOSITORY_ID_RE)
    require_bool(collector.get("pagination_complete"), "collector.pagination_complete")

    repositories = require_list(evidence.get("repositories"), "evidence.repositories")
    for index, repository_value in enumerate(repositories):
        repository = require_object(repository_value, f"repositories[{index}]")
        require_fields(
            repository,
            {"repository_id", "repository", "security_domain", "criticality", "backup"},
            f"repositories[{index}]",
        )
        require_text(repository.get("repository_id"), "repository.repository_id", REPOSITORY_ID_RE)
        require_text(repository.get("repository"), "repository.repository", REPOSITORY_RE)
        require_text(repository.get("security_domain"), "repository.security_domain", DOMAIN_RE)
        require_text(repository.get("criticality"), "repository.criticality")
        backup = require_object(repository.get("backup"), "repository.backup")
        require_fields(
            backup,
            {
                "snapshot_id",
                "captured_at",
                "security_domain",
                "object_lock",
                "retained_until",
                "source_admin_delete_denied",
                "content_digest",
                "refs_digest",
                "settings_digest",
            },
            "repository.backup",
        )
        require_text(backup.get("snapshot_id"), "backup.snapshot_id", SNAPSHOT_ID_RE)
        parse_time(backup.get("captured_at"), "backup.captured_at")
        require_text(backup.get("security_domain"), "backup.security_domain", DOMAIN_RE)
        require_text(backup.get("object_lock"), "backup.object_lock")
        parse_time(backup.get("retained_until"), "backup.retained_until")
        require_bool(backup.get("source_admin_delete_denied"), "backup source-admin denial")
        for field in ("content_digest", "refs_digest", "settings_digest"):
            require_text(backup.get(field), f"backup.{field}", SHA256_RE)

    request = require_object(evidence.get("deletion_request"), "evidence.deletion_request")
    require_fields(
        request,
        {
            "request_id",
            "requested_at",
            "actor_id",
            "session_id",
            "target_repository_ids",
            "approval_status",
            "approver_id",
            "reauthenticated_at",
            "decision",
            "decision_reason",
        },
        "evidence.deletion_request",
    )
    for field in ("request_id", "actor_id", "session_id", "approval_status", "decision", "decision_reason"):
        require_text(request.get(field), f"deletion_request.{field}")
    parse_time(request.get("requested_at"), "deletion_request.requested_at")
    for repository_id in require_unique_text_list(request.get("target_repository_ids"), "deletion request targets"):
        require_text(repository_id, "deletion request repository ID", REPOSITORY_ID_RE)
    if request.get("approver_id") is not None:
        require_text(request.get("approver_id"), "deletion_request.approver_id")
    if request.get("reauthenticated_at") is not None:
        parse_time(request.get("reauthenticated_at"), "deletion_request.reauthenticated_at")

    audit = require_object(evidence.get("audit"), "evidence.audit")
    require_fields(audit, {"status", "window_start", "window_end", "pagination_complete", "events", "alert"}, "evidence.audit")
    require_text(audit.get("status"), "audit.status")
    parse_time(audit.get("window_start"), "audit.window_start")
    parse_time(audit.get("window_end"), "audit.window_end")
    require_bool(audit.get("pagination_complete"), "audit.pagination_complete")
    for index, event_value in enumerate(require_list(audit.get("events"), "audit.events")):
        event = require_object(event_value, f"audit.events[{index}]")
        require_fields(event, {"event_id", "request_id", "actor_id", "session_id", "target_repository_ids", "decision", "occurred_at"}, f"audit.events[{index}]")
        for field in ("event_id", "request_id", "actor_id", "session_id", "decision"):
            require_text(event.get(field), f"audit event {field}")
        require_unique_text_list(event.get("target_repository_ids"), "audit event targets")
        parse_time(event.get("occurred_at"), "audit event occurred_at")
    alert = require_object(audit.get("alert"), "audit.alert")
    require_fields(alert, {"alert_id", "event_id", "delivered_at", "receiver_security_domain", "status"}, "audit.alert")
    for field in ("alert_id", "event_id", "status"):
        require_text(alert.get(field), f"audit.alert.{field}")
    parse_time(alert.get("delivered_at"), "audit.alert.delivered_at")
    require_text(alert.get("receiver_security_domain"), "audit alert receiver domain", DOMAIN_RE)

    containment = require_object(evidence.get("containment"), "evidence.containment")
    require_fields(containment, {"incident_id", "actor_id", "session_id", "contained_at", "actor_session_revoked", "tokens_revoked", "owner", "recovery_authorized_at"}, "evidence.containment")
    for field in ("incident_id", "actor_id", "session_id", "owner"):
        require_text(containment.get(field), f"containment.{field}")
    parse_time(containment.get("contained_at"), "containment.contained_at")
    parse_time(containment.get("recovery_authorized_at"), "containment.recovery_authorized_at")
    require_bool(containment.get("actor_session_revoked"), "containment actor session state")
    require_bool(containment.get("tokens_revoked"), "containment token state")

    drill = require_object(evidence.get("recovery_drill"), "evidence.recovery_drill")
    require_fields(drill, {"drill_id", "status", "mode", "target_security_domain", "started_at", "completed_at", "repository_ids", "restores"}, "evidence.recovery_drill")
    for field in ("drill_id", "status", "mode"):
        require_text(drill.get(field), f"recovery_drill.{field}")
    require_text(drill.get("target_security_domain"), "recovery drill target domain", DOMAIN_RE)
    parse_time(drill.get("started_at"), "recovery_drill.started_at")
    parse_time(drill.get("completed_at"), "recovery_drill.completed_at")
    require_unique_text_list(drill.get("repository_ids"), "recovery drill repository IDs")
    for index, restore_value in enumerate(require_list(drill.get("restores"), "recovery_drill.restores")):
        restore = require_object(restore_value, f"recovery_drill.restores[{index}]")
        require_fields(restore, {"source_repository_id", "restored_repository_id", "snapshot_id", "content_digest", "refs_digest", "settings_digest", "refs_complete", "settings_applied", "verification_status"}, f"recovery_drill.restores[{index}]")
        require_text(restore.get("source_repository_id"), "restore source repository ID", REPOSITORY_ID_RE)
        require_text(restore.get("restored_repository_id"), "restore target repository ID")
        require_text(restore.get("snapshot_id"), "restore snapshot ID", SNAPSHOT_ID_RE)
        for field in ("content_digest", "refs_digest", "settings_digest"):
            require_text(restore.get(field), f"restore.{field}", SHA256_RE)
        require_bool(restore.get("refs_complete"), "restore refs completeness")
        require_bool(restore.get("settings_applied"), "restore settings state")
        require_text(restore.get("verification_status"), "restore verification status")


def add(findings: dict[str, list[str]], check: str, message: str) -> None:
    if message not in findings[check]:
        findings[check].append(message)


def validate_health(evidence: dict[str, Any], policy: dict[str, Any], as_of: datetime) -> None:
    collector = evidence["collector"]
    expected = set(policy["required_repository_ids"])
    if collector["status"] != "COMPLETE" or collector["pagination_complete"] is not True:
        raise EvidenceError("repository collector is incomplete or unavailable")
    if set(collector["repository_ids"]) != expected:
        raise EvidenceError("repository collector coverage is incomplete")
    repository_ids = [item["repository_id"] for item in evidence["repositories"]]
    if len(repository_ids) != len(set(repository_ids)) or set(repository_ids) != expected:
        raise EvidenceError("repository inventory evidence is incomplete or duplicate")
    collected_at = parse_time(collector["collected_at"], "collector.collected_at")
    age = (as_of - collected_at).total_seconds()
    if age < 0 or age > policy["max_evidence_age_seconds"]:
        raise EvidenceError("repository collector evidence is stale or from the future")
    audit = evidence["audit"]
    if audit["status"] != "COMPLETE" or audit["pagination_complete"] is not True:
        raise EvidenceError("repository deletion audit is incomplete or unavailable")


def evaluate(policy: dict[str, Any], evidence: dict[str, Any], as_of: datetime) -> dict[str, list[str]]:
    findings = {check: [] for check in CHECK_MESSAGES}
    required = set(policy["required_repository_ids"])
    repositories = evidence["repositories"]
    observed_ids = [repository["repository_id"] for repository in repositories]
    observed_names = [repository["repository"] for repository in repositories]
    if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != required:
        add(findings, "RDR-001", "repository inventory does not exactly cover required stable IDs")
    if len(observed_names) != len(set(observed_names)):
        add(findings, "RDR-001", "repository inventory contains duplicate logical names")
    for repository in repositories:
        if repository["criticality"] != "critical":
            add(findings, "RDR-001", f"repository {repository['repository_id']} is not classified critical")

    deletion_policy = policy["deletion_controls"]
    if policy["max_bulk_delete_targets"] != 1:
        add(findings, "RDR-002", "policy permits more than one repository deletion per request")
    if deletion_policy != {
        "default_deny": True,
        "independent_approval": True,
        "phishing_resistant_reauthentication": True,
        "approval_max_age_seconds": 900,
    }:
        add(findings, "RDR-002", "deletion authorization policy is weakened")
    request = evidence["deletion_request"]
    targets = set(request["target_repository_ids"])
    if not targets.issubset(required):
        add(findings, "RDR-002", "deletion request contains an unknown repository ID")
    requested_at = parse_time(request["requested_at"], "deletion_request.requested_at")
    if len(targets) > policy["max_bulk_delete_targets"]:
        if request["decision"] != "DENIED" or request["decision_reason"] != "bulk-target-limit":
            add(findings, "RDR-002", "bulk repository deletion request was not denied")
    if request["decision"] == "ALLOWED":
        reauthenticated = request["reauthenticated_at"]
        if request["approval_status"] != "APPROVED" or request["approver_id"] in {None, request["actor_id"]}:
            add(findings, "RDR-002", "allowed deletion lacks independent approval")
        if reauthenticated is None:
            add(findings, "RDR-002", "allowed deletion lacks phishing-resistant reauthentication evidence")
        else:
            reauthenticated_at = parse_time(reauthenticated, "deletion request reauthentication")
            age = (requested_at - reauthenticated_at).total_seconds()
            if age < 0 or age > deletion_policy["approval_max_age_seconds"]:
                add(findings, "RDR-002", "allowed deletion reauthentication is stale or from the future")

    backup_policy = policy["backup"]
    if backup_policy != {
        "max_rpo_seconds": 86400,
        "minimum_retention_days": 30,
        "cross_security_domain": True,
        "object_lock": "compliance",
        "source_admin_delete_denied": True,
    }:
        add(findings, "RDR-003", "backup protection policy is weakened")
    backups: dict[str, dict[str, Any]] = {}
    source_domains: set[str] = set()
    for repository in repositories:
        repository_id = repository["repository_id"]
        backup = repository["backup"]
        backups[repository_id] = backup
        source_domains.add(repository["security_domain"])
        captured = parse_time(backup["captured_at"], "backup.captured_at")
        retained = parse_time(backup["retained_until"], "backup.retained_until")
        rpo = (requested_at - captured).total_seconds()
        if rpo < 0 or rpo > backup_policy["max_rpo_seconds"]:
            add(findings, "RDR-003", f"repository {repository_id} backup exceeds the RPO")
        if backup["security_domain"] == repository["security_domain"]:
            add(findings, "RDR-003", f"repository {repository_id} backup shares the source security domain")
        if backup["object_lock"] != backup_policy["object_lock"]:
            add(findings, "RDR-003", f"repository {repository_id} backup lacks compliance object lock")
        if backup["source_admin_delete_denied"] is not True:
            add(findings, "RDR-003", f"repository {repository_id} source administrator can delete its backup")
        if retained < captured + timedelta(days=backup_policy["minimum_retention_days"]):
            add(findings, "RDR-003", f"repository {repository_id} backup retention is too short")

    detection_policy = policy["detection"]
    if detection_policy != {
        "complete_audit_required": True,
        "max_alert_delay_seconds": 300,
        "external_delivery_required": True,
    }:
        add(findings, "RDR-004", "deletion detection policy is weakened")
    audit = evidence["audit"]
    window_start = parse_time(audit["window_start"], "audit.window_start")
    window_end = parse_time(audit["window_end"], "audit.window_end")
    matching_events: list[dict[str, Any]] = []
    for event in audit["events"]:
        occurred = parse_time(event["occurred_at"], "audit event occurred_at")
        if not window_start <= occurred <= window_end:
            add(findings, "RDR-004", "deletion audit event falls outside the complete window")
        if event["request_id"] == request["request_id"]:
            matching_events.append(event)
    if len(matching_events) != 1:
        add(findings, "RDR-004", "deletion request lacks one unique audit event")
        event = audit["events"][0]
    else:
        event = matching_events[0]
        for field in ("actor_id", "session_id", "decision"):
            if event[field] != request[field]:
                add(findings, "RDR-004", f"audit event {field} does not match deletion request")
        if set(event["target_repository_ids"]) != targets:
            add(findings, "RDR-004", "audit event target scope does not match deletion request")
    alert = audit["alert"]
    event_time = parse_time(event["occurred_at"], "audit event occurred_at")
    delivered = parse_time(alert["delivered_at"], "audit alert delivered_at")
    if alert["event_id"] != event["event_id"] or alert["status"] != "DELIVERED":
        add(findings, "RDR-004", "deletion alert was not delivered for the exact audit event")
    delay = (delivered - event_time).total_seconds()
    if delay < 0 or delay > detection_policy["max_alert_delay_seconds"]:
        add(findings, "RDR-004", "deletion alert delivery exceeded the policy deadline")
    if alert["receiver_security_domain"] in source_domains:
        add(findings, "RDR-004", "deletion alert receiver is not independent from the source domain")

    containment_policy = policy["containment"]
    if containment_policy != {
        "actor_session_revocation_required": True,
        "token_revocation_required": True,
        "before_recovery_required": True,
    }:
        add(findings, "RDR-005", "containment policy is weakened")
    containment = evidence["containment"]
    contained = parse_time(containment["contained_at"], "containment.contained_at")
    authorized = parse_time(containment["recovery_authorized_at"], "containment.recovery_authorized_at")
    if containment["actor_id"] != request["actor_id"] or containment["session_id"] != request["session_id"]:
        add(findings, "RDR-005", "containment does not identify the destructive actor session")
    if containment["actor_session_revoked"] is not True or containment["tokens_revoked"] is not True:
        add(findings, "RDR-005", "destructive actor session and tokens are not revoked")
    if containment["owner"] != "incident-response":
        add(findings, "RDR-005", "containment lacks the independent incident-response owner")
    if contained < requested_at or authorized < contained:
        add(findings, "RDR-005", "containment and recovery authorization order is unsafe")

    recovery_policy = policy["recovery"]
    if recovery_policy != {
        "max_rto_seconds": 14400,
        "max_drill_age_seconds": 2592000,
        "isolated_target_required": True,
        "complete_refs_required": True,
        "settings_restore_required": True,
    }:
        add(findings, "RDR-006", "recovery policy is weakened")
    drill = evidence["recovery_drill"]
    started = parse_time(drill["started_at"], "recovery_drill.started_at")
    completed = parse_time(drill["completed_at"], "recovery_drill.completed_at")
    if drill["status"] != "COMPLETE" or drill["mode"] != "isolated-destructive-simulation":
        add(findings, "RDR-006", "restore drill is not a complete isolated destructive simulation")
    if drill["target_security_domain"] in source_domains:
        add(findings, "RDR-006", "restore drill target is not isolated from the source domain")
    if started < authorized:
        add(findings, "RDR-006", "restore drill started before recovery authorization")
    duration = (completed - started).total_seconds()
    if duration <= 0 or duration > recovery_policy["max_rto_seconds"]:
        add(findings, "RDR-006", "restore drill exceeds the recovery time objective")
    drill_age = (as_of - completed).total_seconds()
    if drill_age < 0 or drill_age > recovery_policy["max_drill_age_seconds"]:
        add(findings, "RDR-006", "restore drill is stale or from the future")
    if set(drill["repository_ids"]) != required:
        add(findings, "RDR-006", "restore drill does not cover every required repository")
    restores = {restore["source_repository_id"]: restore for restore in drill["restores"]}
    if len(restores) != len(drill["restores"]) or set(restores) != required:
        add(findings, "RDR-006", "restore receipts do not exactly cover every required repository")
    for repository_id in sorted(required & set(restores) & set(backups)):
        restore = restores[repository_id]
        backup = backups[repository_id]
        if restore["restored_repository_id"] == repository_id:
            add(findings, "RDR-006", f"repository {repository_id} drill overwrites the source target")
        for field in ("snapshot_id", "content_digest", "refs_digest", "settings_digest"):
            if restore[field] != backup[field]:
                add(findings, "RDR-006", f"repository {repository_id} restored {field} does not match backup")
        if restore["refs_complete"] is not True or restore["settings_applied"] is not True or restore["verification_status"] != "PASSED":
            add(findings, "RDR-006", f"repository {repository_id} restore verification is incomplete")

    if evidence["policy_id"] != policy["policy_id"]:
        add(findings, "RDR-007", "evidence policy identity does not match the reviewed policy")
    if policy["max_evidence_age_seconds"] != 900 or policy["max_document_bytes"] != 1048576 or policy["evidence_mode"] != "metadata-only":
        add(findings, "RDR-007", "fail-closed metadata-only evidence policy is weakened")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    try:
        policy = read_json(args.policy, "policy", 1048576)
        validate_policy(policy)
        evidence = read_json(args.evidence, "evidence", policy["max_document_bytes"])
        sensitive_path = find_sensitive(evidence)
        if sensitive_path:
            raise EvidenceError(f"evidence contains forbidden sensitive field {sensitive_path}")
        validate_evidence_structure(evidence)
        as_of = parse_time(args.as_of, "evaluation time")
        validate_health(evidence, policy, as_of)
        findings = evaluate(policy, evidence, as_of)
    except EvidenceError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    print(f"POLICY id={policy['policy_id']}")
    finding_count = 0
    for check, message in CHECK_MESSAGES.items():
        if findings[check]:
            for finding in findings[check]:
                print(f"FAIL {check} {finding}")
                finding_count += 1
        else:
            print(f"PASS {check} {message}")
    if finding_count:
        print(f"REJECTED {finding_count} finding(s); repository recovery assurance denied")
        return 1
    print("ACCEPTED repositories=2 bulk-deletion-denied restore-drill=complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
