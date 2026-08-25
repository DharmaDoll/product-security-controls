#!/usr/bin/env python3
"""Assess normalized critical-repository destruction and recovery evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-repository-destruction-recovery-policy/v2"
EVIDENCE_SCHEMA = "psb-repository-destruction-recovery-evidence/v2"
POLICY_ID_RE = re.compile(r"^repository-recovery-policy@sha256:[0-9a-f]{64}$")
VERSIONED_ID_RE = re.compile(r"^[a-z0-9-]+@sha256:[0-9a-f]{64}$")
SNAPSHOT_ID_RE = re.compile(r"^repository-snapshot@sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STABLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
DOMAIN_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
REASON_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")

CHECK_MESSAGES = {
    "RDR-001": "critical repository scope is exact complete and stable-ID bound",
    "RDR-002": "destructive repository actions have a bounded blast radius",
    "RDR-003": "critical repositories have current attacker-separated recovery copies",
    "RDR-006": "an isolated restore drill proves complete recovery within RPO and RTO",
}

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

POLICY_FIELDS = {
    "schema",
    "policy_id",
    "required_repository_ids",
    "max_bulk_delete_targets",
    "deletion_control",
    "recovery_copy",
    "restore",
    "max_evidence_age_seconds",
    "max_document_bytes",
    "evidence_mode",
}

SECTION_NAMES = {
    "RDR-001": "inventory",
    "RDR-002": "deletion_control",
    "RDR-003": "recovery_copies",
    "RDR-006": "restore_drill",
}


class EvidenceError(ValueError):
    """Evidence cannot be safely evaluated."""


def require_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise EvidenceError(f"{label} fields are incomplete or unknown")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str, *, nonempty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        suffix = " non-empty" if nonempty else ""
        raise EvidenceError(f"{label} must be a{suffix} list")
    return value


def require_text(
    value: Any, label: str, pattern: re.Pattern[str] | None = None
) -> str:
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
        raise EvidenceError(
            f"{label} must be an integer greater than or equal to {minimum}"
        )
    return value


def require_unique_ids(value: Any, label: str) -> list[str]:
    items = require_list(value, label)
    for item in items:
        require_text(item, f"{label} item", STABLE_ID_RE)
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


def expected_policy_id(policy: dict[str, Any]) -> str:
    normalized = dict(policy)
    normalized.pop("policy_id", None)
    canonical = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return f"repository-recovery-policy@sha256:{hashlib.sha256(canonical).hexdigest()}"


def validate_policy(policy: dict[str, Any]) -> None:
    require_fields(policy, POLICY_FIELDS, "policy")
    if policy.get("schema") != POLICY_SCHEMA:
        raise EvidenceError("policy schema is unsupported")
    policy_id = require_text(policy.get("policy_id"), "policy.policy_id", POLICY_ID_RE)
    if policy_id != expected_policy_id(policy):
        raise EvidenceError("policy_id does not match canonical policy content")
    require_unique_ids(policy.get("required_repository_ids"), "policy repository IDs")
    require_int(policy.get("max_bulk_delete_targets"), "policy bulk target limit")
    require_int(policy.get("max_evidence_age_seconds"), "policy evidence age")
    require_int(policy.get("max_document_bytes"), "policy document size")
    if policy["max_document_bytes"] > 1048576:
        raise EvidenceError("policy document size exceeds the verifier limit")
    if policy["max_evidence_age_seconds"] > 86400:
        raise EvidenceError("policy evidence freshness safeguard is weakened")
    if policy.get("evidence_mode") != "metadata-only":
        raise EvidenceError("policy evidence mode must be metadata-only")

    deletion = require_object(policy.get("deletion_control"), "policy.deletion_control")
    require_fields(
        deletion,
        {
            "default_deny",
            "independent_approval",
            "phishing_resistant_reauthentication",
            "reauthentication_max_age_seconds",
        },
        "policy.deletion_control",
    )
    for field in (
        "default_deny",
        "independent_approval",
        "phishing_resistant_reauthentication",
    ):
        require_bool(deletion.get(field), f"policy.deletion_control.{field}")
    require_int(
        deletion.get("reauthentication_max_age_seconds"),
        "policy reauthentication age",
    )

    copy_policy = require_object(policy.get("recovery_copy"), "policy.recovery_copy")
    require_fields(
        copy_policy,
        {
            "max_rpo_seconds",
            "minimum_retention_days",
            "separate_security_domain",
            "lock_mode",
            "source_admin_delete_denied",
        },
        "policy.recovery_copy",
    )
    require_int(copy_policy.get("max_rpo_seconds"), "policy recovery-copy RPO")
    require_int(
        copy_policy.get("minimum_retention_days"), "policy recovery-copy retention"
    )
    require_bool(
        copy_policy.get("separate_security_domain"),
        "policy recovery-copy domain separation",
    )
    require_text(copy_policy.get("lock_mode"), "policy recovery-copy lock mode")
    require_bool(
        copy_policy.get("source_admin_delete_denied"),
        "policy source-admin delete denial",
    )

    restore = require_object(policy.get("restore"), "policy.restore")
    require_fields(
        restore,
        {
            "max_rto_seconds",
            "max_drill_age_seconds",
            "isolated_target_required",
            "complete_refs_required",
            "protected_settings_required",
        },
        "policy.restore",
    )
    require_int(restore.get("max_rto_seconds"), "policy restore RTO")
    require_int(restore.get("max_drill_age_seconds"), "policy restore drill age")
    for field in (
        "isolated_target_required",
        "complete_refs_required",
        "protected_settings_required",
    ):
        require_bool(restore.get(field), f"policy.restore.{field}")


def validate_unavailable_section(section: dict[str, Any], label: str) -> None:
    require_fields(section, {"status", "reason_code"}, label)
    require_text(section.get("reason_code"), f"{label}.reason_code", REASON_RE)


def validate_inventory(section: dict[str, Any]) -> None:
    require_fields(
        section,
        {
            "status",
            "collector_id",
            "collected_at",
            "pagination_complete",
            "repositories",
        },
        "evidence.sections.inventory",
    )
    require_text(section.get("collector_id"), "inventory.collector_id", VERSIONED_ID_RE)
    parse_time(section.get("collected_at"), "inventory.collected_at")
    require_bool(section.get("pagination_complete"), "inventory.pagination_complete")
    repositories = require_list(section.get("repositories"), "inventory.repositories")
    for index, item in enumerate(repositories):
        repository = require_object(item, f"inventory.repositories[{index}]")
        require_fields(
            repository,
            {"repository_id", "criticality"},
            f"inventory.repositories[{index}]",
        )
        require_text(
            repository.get("repository_id"), "inventory repository ID", STABLE_ID_RE
        )
        require_text(repository.get("criticality"), "inventory criticality")


def validate_deletion_control(section: dict[str, Any]) -> None:
    require_fields(
        section,
        {
            "status",
            "collected_at",
            "default_deny",
            "max_targets_per_request",
            "independent_approval",
            "phishing_resistant_reauthentication",
            "reauthentication_max_age_seconds",
            "dry_run",
        },
        "evidence.sections.deletion_control",
    )
    parse_time(section.get("collected_at"), "deletion_control.collected_at")
    require_bool(section.get("default_deny"), "deletion_control.default_deny")
    require_int(
        section.get("max_targets_per_request"),
        "deletion_control.max_targets_per_request",
    )
    require_bool(
        section.get("independent_approval"), "deletion_control.independent_approval"
    )
    require_bool(
        section.get("phishing_resistant_reauthentication"),
        "deletion_control.phishing_resistant_reauthentication",
    )
    require_int(
        section.get("reauthentication_max_age_seconds"),
        "deletion_control.reauthentication_max_age_seconds",
    )
    dry_run = require_object(section.get("dry_run"), "deletion_control.dry_run")
    require_fields(dry_run, {"target_count", "decision"}, "deletion_control.dry_run")
    require_int(dry_run.get("target_count"), "deletion_control dry-run target count")
    require_text(dry_run.get("decision"), "deletion_control dry-run decision")


def validate_recovery_copies(section: dict[str, Any]) -> None:
    require_fields(
        section,
        {"status", "collector_id", "collected_at", "repositories"},
        "evidence.sections.recovery_copies",
    )
    require_text(
        section.get("collector_id"), "recovery_copies.collector_id", VERSIONED_ID_RE
    )
    parse_time(section.get("collected_at"), "recovery_copies.collected_at")
    repositories = require_list(
        section.get("repositories"), "recovery_copies.repositories"
    )
    for index, item in enumerate(repositories):
        repository = require_object(item, f"recovery_copies.repositories[{index}]")
        require_fields(
            repository,
            {
                "repository_id",
                "source_security_domain",
                "snapshot_id",
                "captured_at",
                "backup_security_domain",
                "lock_mode",
                "retained_until",
                "source_admin_delete_denied",
                "content_digest",
                "refs_digest",
                "settings_digest",
            },
            f"recovery_copies.repositories[{index}]",
        )
        require_text(
            repository.get("repository_id"), "recovery-copy repository ID", STABLE_ID_RE
        )
        require_text(
            repository.get("source_security_domain"),
            "recovery-copy source domain",
            DOMAIN_RE,
        )
        require_text(
            repository.get("snapshot_id"), "recovery-copy snapshot ID", SNAPSHOT_ID_RE
        )
        parse_time(repository.get("captured_at"), "recovery-copy captured_at")
        require_text(
            repository.get("backup_security_domain"),
            "recovery-copy backup domain",
            DOMAIN_RE,
        )
        require_text(repository.get("lock_mode"), "recovery-copy lock mode")
        parse_time(repository.get("retained_until"), "recovery-copy retained_until")
        require_bool(
            repository.get("source_admin_delete_denied"),
            "recovery-copy source-admin delete state",
        )
        for field in ("content_digest", "refs_digest", "settings_digest"):
            require_text(
                repository.get(field), f"recovery-copy {field}", SHA256_RE
            )


def validate_restore_drill(section: dict[str, Any]) -> None:
    require_fields(
        section,
        {"status", "collector_id", "collected_at", "drill"},
        "evidence.sections.restore_drill",
    )
    require_text(
        section.get("collector_id"), "restore_drill.collector_id", VERSIONED_ID_RE
    )
    parse_time(section.get("collected_at"), "restore_drill.collected_at")
    drill = require_object(section.get("drill"), "restore_drill.drill")
    require_fields(
        drill,
        {
            "drill_id",
            "result",
            "isolated_target",
            "target_security_domain",
            "started_at",
            "completed_at",
            "repository_ids",
            "restores",
        },
        "restore_drill.drill",
    )
    require_text(drill.get("drill_id"), "restore drill ID")
    require_text(drill.get("result"), "restore drill result")
    require_bool(drill.get("isolated_target"), "restore drill isolation")
    require_text(
        drill.get("target_security_domain"), "restore drill target domain", DOMAIN_RE
    )
    parse_time(drill.get("started_at"), "restore drill started_at")
    parse_time(drill.get("completed_at"), "restore drill completed_at")
    require_unique_ids(drill.get("repository_ids"), "restore drill repository IDs")
    restores = require_list(drill.get("restores"), "restore drill restores")
    for index, item in enumerate(restores):
        restore = require_object(item, f"restore_drill.restores[{index}]")
        require_fields(
            restore,
            {
                "source_repository_id",
                "restored_repository_id",
                "snapshot_id",
                "content_digest",
                "refs_digest",
                "settings_digest",
                "refs_complete",
                "settings_applied",
                "verification_status",
            },
            f"restore_drill.restores[{index}]",
        )
        require_text(
            restore.get("source_repository_id"), "restore source ID", STABLE_ID_RE
        )
        require_text(restore.get("restored_repository_id"), "restore target ID")
        require_text(restore.get("snapshot_id"), "restore snapshot ID", SNAPSHOT_ID_RE)
        for field in ("content_digest", "refs_digest", "settings_digest"):
            require_text(restore.get(field), f"restore {field}", SHA256_RE)
        require_bool(restore.get("refs_complete"), "restore refs completeness")
        require_bool(restore.get("settings_applied"), "restore settings state")
        require_text(restore.get("verification_status"), "restore verification status")


SECTION_VALIDATORS = {
    "inventory": validate_inventory,
    "deletion_control": validate_deletion_control,
    "recovery_copies": validate_recovery_copies,
    "restore_drill": validate_restore_drill,
}


def validate_evidence(evidence: dict[str, Any]) -> None:
    require_fields(evidence, {"schema", "policy_id", "sections"}, "evidence")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise EvidenceError("evidence schema is unsupported")
    require_text(evidence.get("policy_id"), "evidence.policy_id", POLICY_ID_RE)
    sections = require_object(evidence.get("sections"), "evidence.sections")
    require_fields(sections, set(SECTION_VALIDATORS), "evidence.sections")
    for name, validator in SECTION_VALIDATORS.items():
        section = require_object(sections.get(name), f"evidence.sections.{name}")
        status = require_text(section.get("status"), f"evidence.sections.{name}.status")
        if status == "AVAILABLE":
            validator(section)
        elif status in {"NOT_PROVIDED", "ERROR"}:
            validate_unavailable_section(section, f"evidence.sections.{name}")
        else:
            raise EvidenceError(f"evidence.sections.{name}.status is unsupported")


def result(status: str, *messages: str) -> dict[str, Any]:
    return {"status": status, "messages": list(messages)}


def section_result(section: dict[str, Any]) -> dict[str, Any] | None:
    if section["status"] == "NOT_PROVIDED":
        return result("NOT_CHECKED", f"organization evidence not provided: {section['reason_code']}")
    if section["status"] == "ERROR":
        return result("ERROR", f"evidence collector failed: {section['reason_code']}")
    return None


def merge_unavailable(
    unavailable: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    if unavailable["status"] == "ERROR":
        return result("ERROR", *(findings + unavailable["messages"]))
    if findings:
        return result("FAIL", *findings)
    return unavailable


def stale_result(
    section: dict[str, Any], policy: dict[str, Any], as_of: datetime, label: str
) -> dict[str, Any] | None:
    collected = parse_time(section["collected_at"], f"{label}.collected_at")
    age = (as_of - collected).total_seconds()
    if age < 0 or age > policy["max_evidence_age_seconds"]:
        return result("ERROR", f"{label} evidence is stale or from the future")
    return None


def evaluate_inventory(
    policy: dict[str, Any], section: dict[str, Any], as_of: datetime
) -> dict[str, Any]:
    unavailable = section_result(section)
    if unavailable:
        return unavailable
    stale = stale_result(section, policy, as_of, "inventory")
    if stale:
        return stale
    if section["pagination_complete"] is not True:
        return result("ERROR", "inventory pagination is incomplete")
    expected = set(policy["required_repository_ids"])
    repositories = section["repositories"]
    observed = [item["repository_id"] for item in repositories]
    findings: list[str] = []
    if len(observed) != len(set(observed)) or set(observed) != expected:
        findings.append("inventory does not exactly cover required stable repository IDs")
    for item in repositories:
        if item["criticality"] != "critical":
            findings.append(
                f"repository {item['repository_id']} is not classified critical"
            )
    return result("FAIL", *findings) if findings else result("PASS", CHECK_MESSAGES["RDR-001"])


def evaluate_deletion_control(
    policy: dict[str, Any], section: dict[str, Any], as_of: datetime
) -> dict[str, Any]:
    policy_state = policy["deletion_control"]
    findings: list[str] = []
    if policy["max_bulk_delete_targets"] != 1:
        findings.append("policy permits more than one repository target per destructive request")
    if (
        policy_state["default_deny"] is not True
        or policy_state["independent_approval"] is not True
        or policy_state["phishing_resistant_reauthentication"] is not True
        or policy_state["reauthentication_max_age_seconds"] > 900
    ):
        findings.append("destructive-action policy is weaker than the reference baseline")
    unavailable = section_result(section)
    if unavailable:
        return merge_unavailable(unavailable, findings)
    stale = stale_result(section, policy, as_of, "deletion-control")
    if stale:
        return merge_unavailable(stale, findings)
    if section["default_deny"] is not True:
        findings.append("destructive actions are not default denied")
    if section["max_targets_per_request"] > policy["max_bulk_delete_targets"]:
        findings.append("destructive request target limit exceeds policy")
    if section["independent_approval"] is not True:
        findings.append("single-repository deletion lacks independent approval")
    if section["phishing_resistant_reauthentication"] is not True:
        findings.append("single-repository deletion lacks phishing-resistant reauthentication")
    if (
        section["reauthentication_max_age_seconds"]
        > policy_state["reauthentication_max_age_seconds"]
    ):
        findings.append("destructive-action reauthentication window exceeds policy")
    dry_run = section["dry_run"]
    if dry_run["target_count"] <= policy["max_bulk_delete_targets"]:
        findings.append("harmless dry-run does not exercise a bulk request")
    if dry_run["decision"] != "DENIED":
        findings.append("harmless bulk destructive-action dry-run was not denied")
    return result("FAIL", *findings) if findings else result("PASS", CHECK_MESSAGES["RDR-002"])


def recovery_copy_index(section: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if section["status"] != "AVAILABLE":
        return {}
    return {
        item["repository_id"]: item for item in section["repositories"]
    }


def evaluate_recovery_copies(
    policy: dict[str, Any], section: dict[str, Any], as_of: datetime
) -> dict[str, Any]:
    copy_policy = policy["recovery_copy"]
    findings: list[str] = []
    if (
        copy_policy["max_rpo_seconds"] > 86400
        or copy_policy["minimum_retention_days"] < 30
        or copy_policy["separate_security_domain"] is not True
        or copy_policy["lock_mode"] != "compliance"
        or copy_policy["source_admin_delete_denied"] is not True
    ):
        findings.append("recovery-copy policy is weaker than the reference baseline")
    unavailable = section_result(section)
    if unavailable:
        return merge_unavailable(unavailable, findings)
    stale = stale_result(section, policy, as_of, "recovery-copy")
    if stale:
        return merge_unavailable(stale, findings)
    required = set(policy["required_repository_ids"])
    repositories = section["repositories"]
    observed = [item["repository_id"] for item in repositories]
    if len(observed) != len(set(observed)) or set(observed) != required:
        findings.append("recovery copies do not exactly cover required stable repository IDs")
    for item in repositories:
        repository_id = item["repository_id"]
        captured = parse_time(item["captured_at"], "recovery-copy captured_at")
        retained = parse_time(item["retained_until"], "recovery-copy retained_until")
        age = (as_of - captured).total_seconds()
        if age < 0 or age > copy_policy["max_rpo_seconds"]:
            findings.append(f"repository {repository_id} recovery copy exceeds the RPO")
        if item["backup_security_domain"] == item["source_security_domain"]:
            findings.append(f"repository {repository_id} recovery copy shares the source security domain")
        if item["lock_mode"] != copy_policy["lock_mode"]:
            findings.append(f"repository {repository_id} recovery copy lacks the required retention lock")
        if item["source_admin_delete_denied"] is not True:
            findings.append(f"repository {repository_id} source administrator can delete the recovery copy")
        if retained < captured + timedelta(days=copy_policy["minimum_retention_days"]):
            findings.append(f"repository {repository_id} recovery-copy retention is too short")
    return result("FAIL", *findings) if findings else result("PASS", CHECK_MESSAGES["RDR-003"])


def evaluate_restore_drill(
    policy: dict[str, Any],
    section: dict[str, Any],
    recovery_section: dict[str, Any],
    as_of: datetime,
) -> dict[str, Any]:
    restore_policy = policy["restore"]
    findings: list[str] = []
    if (
        restore_policy["max_rto_seconds"] > 14400
        or restore_policy["max_drill_age_seconds"] > 2592000
        or restore_policy["isolated_target_required"] is not True
        or restore_policy["complete_refs_required"] is not True
        or restore_policy["protected_settings_required"] is not True
    ):
        findings.append("restore policy is weaker than the reference baseline")
    unavailable = section_result(section)
    if unavailable:
        return merge_unavailable(unavailable, findings)
    stale = stale_result(section, policy, as_of, "restore-drill")
    if stale:
        return merge_unavailable(stale, findings)
    if recovery_section["status"] == "NOT_PROVIDED":
        unavailable = result(
            "NOT_CHECKED",
            "recovery-copy evidence is required to compare restore results",
        )
        return merge_unavailable(unavailable, findings)
    if recovery_section["status"] == "ERROR":
        unavailable = result(
            "ERROR", "recovery-copy collector failed before restore comparison"
        )
        return merge_unavailable(unavailable, findings)

    required = set(policy["required_repository_ids"])
    copies = recovery_copy_index(recovery_section)
    source_domains = {item["source_security_domain"] for item in copies.values()}
    drill = section["drill"]
    started = parse_time(drill["started_at"], "restore drill started_at")
    completed = parse_time(drill["completed_at"], "restore drill completed_at")
    if drill["result"] != "COMPLETE":
        findings.append("restore drill is not complete")
    if drill["isolated_target"] is not True:
        findings.append("restore drill target is not declared isolated")
    if drill["target_security_domain"] in source_domains:
        findings.append("restore drill target shares a source security domain")
    duration = (completed - started).total_seconds()
    if duration <= 0 or duration > restore_policy["max_rto_seconds"]:
        findings.append("restore drill exceeds the recovery time objective")
    drill_age = (as_of - completed).total_seconds()
    if drill_age < 0 or drill_age > restore_policy["max_drill_age_seconds"]:
        findings.append("restore drill is stale or from the future")
    if set(drill["repository_ids"]) != required:
        findings.append("restore drill does not cover every required repository")
    restores_list = drill["restores"]
    restores = {item["source_repository_id"]: item for item in restores_list}
    if len(restores) != len(restores_list) or set(restores) != required:
        findings.append("restore receipts do not exactly cover every required repository")
    for repository_id in sorted(required & set(restores) & set(copies)):
        restore = restores[repository_id]
        copy = copies[repository_id]
        if restore["restored_repository_id"] == repository_id:
            findings.append(f"repository {repository_id} restore drill overwrites the source target")
        for field in ("snapshot_id", "content_digest", "refs_digest", "settings_digest"):
            if restore[field] != copy[field]:
                findings.append(f"repository {repository_id} restored {field} does not match the recovery copy")
        if (
            restore["refs_complete"] is not True
            or restore["settings_applied"] is not True
            or restore["verification_status"] != "PASSED"
        ):
            findings.append(f"repository {repository_id} restore verification is incomplete")
    return result("FAIL", *findings) if findings else result("PASS", CHECK_MESSAGES["RDR-006"])


def evaluate(
    policy: dict[str, Any], evidence: dict[str, Any], as_of: datetime
) -> dict[str, dict[str, Any]]:
    sections = evidence["sections"]
    return {
        "RDR-001": evaluate_inventory(policy, sections["inventory"], as_of),
        "RDR-002": evaluate_deletion_control(
            policy, sections["deletion_control"], as_of
        ),
        "RDR-003": evaluate_recovery_copies(
            policy, sections["recovery_copies"], as_of
        ),
        "RDR-006": evaluate_restore_drill(
            policy,
            sections["restore_drill"],
            sections["recovery_copies"],
            as_of,
        ),
    }


def assess_files(
    policy_path: Path, evidence_path: Path, as_of: datetime
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    policy = read_json(policy_path, "policy", 1048576)
    validate_policy(policy)
    evidence = read_json(evidence_path, "evidence", policy["max_document_bytes"])
    sensitive_path = find_sensitive(evidence)
    if sensitive_path:
        raise EvidenceError(f"evidence contains forbidden sensitive field {sensitive_path}")
    validate_evidence(evidence)
    if evidence["policy_id"] != policy["policy_id"]:
        raise EvidenceError("evidence policy identity does not match the reviewed policy")
    return policy, evaluate(policy, evidence, as_of)


def exit_code(results: dict[str, dict[str, Any]]) -> int:
    statuses = {item["status"] for item in results.values()}
    if "ERROR" in statuses:
        return 2
    if "FAIL" in statuses:
        return 1
    if "NOT_CHECKED" in statuses:
        return 3
    return 0


def render_results(policy_id: str, results: dict[str, dict[str, Any]]) -> list[str]:
    lines = [f"POLICY id={policy_id}"]
    finding_count = 0
    for check_id in CHECK_MESSAGES:
        item = results[check_id]
        status = item["status"]
        for message in item["messages"]:
            lines.append(f"{status} {check_id} {message}")
            if status == "FAIL":
                finding_count += 1
    code = exit_code(results)
    if code == 0:
        lines.append("ACCEPTED checks=4 critical-repository-recovery-assurance=verified")
    elif code == 1:
        lines.append(f"REJECTED {finding_count} finding(s); recovery assurance denied")
    elif code == 2:
        count = sum(item["status"] == "ERROR" for item in results.values())
        lines.append(f"ERROR {count} check(s) could not be evaluated")
    else:
        count = sum(item["status"] == "NOT_CHECKED" for item in results.values())
        lines.append(f"INCOMPLETE {count} check(s) require organization evidence")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    try:
        as_of = parse_time(args.as_of, "evaluation time")
        policy, results = assess_files(args.policy, args.evidence, as_of)
    except EvidenceError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    for line in render_results(policy["policy_id"], results):
        print(line)
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
