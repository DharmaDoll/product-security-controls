#!/usr/bin/env python3
"""Verify independent rogue-agent containment, fallback, and recovery evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CHECKS = {
    "RRC-001": "control plane and cross-control contracts are independent and immutable",
    "RRC-002": "trigger evidence is attributable complete fresh and policy-bound",
    "RRC-003": "containment command is authenticated fresh and exactly scoped",
    "RRC-004": "agent model tool delegation and memory activity stop within the deadline",
    "RRC-005": "session authority keys approvals and access grants are revoked",
    "RRC-006": "pending and unknown actions are quarantined before evidence cleanup",
    "RRC-007": "fallback is model-free read-only time-bounded and exercised",
    "RRC-008": "recovery readiness requires root cause clean identity and replay denial",
    "RRC-009": "recovery authorization has independent authenticated dual control",
    "RRC-010": "recovery uses a new read-only canary without restoring old authority",
    "RRC-011": "evidence is ordered sanitized and live enforcement remains NOT_CHECKED",
}


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"{label} is unavailable or malformed: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp requires a timezone")
    return parsed.astimezone(timezone.utc)


def resolve(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} path is missing")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} path escapes its allowed root") from exc
    if not path.is_file():
        raise ValueError(f"{label} is unavailable")
    return path


def exact_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def exact_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def forbidden_field(value: Any, forbidden: set[str], path: str = "$") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in forbidden:
                return f"{path}.{key}"
            found = forbidden_field(child, forbidden, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = forbidden_field(child, forbidden, f"{path}[{index}]")
            if found:
                return found
    return None


def keyed(records: Any, key: str, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} records are malformed")
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get(key), str):
            raise ValueError(f"{label} record is malformed")
        identity = record[key]
        if not identity or identity in result:
            raise ValueError(f"duplicate or empty {label} identity")
        result[identity] = record
    return result


def verify_cross_control_bindings(root: Path, policy: dict[str, Any]) -> bool:
    expected = {"PSB-AI-006", "PSB-AI-007", "PSB-AI-008"}
    observed: set[str] = set()
    for binding in policy.get("cross_control_bindings", []):
        if not isinstance(binding, dict):
            raise ValueError("cross-control binding is malformed")
        control_id = binding.get("control_id")
        if not isinstance(control_id, str) or control_id in observed:
            raise ValueError("cross-control identity is missing or duplicated")
        path = resolve(root, binding.get("path"), f"{control_id} binding")
        if digest_bytes(path.read_bytes()) != binding.get("sha256"):
            raise ValueError(f"{control_id} binding digest mismatch")
        document = load_json(path, f"{control_id} binding")
        if document.get(binding.get("identity_field")) != binding.get("identity"):
            raise ValueError(f"{control_id} binding identity mismatch")
        observed.add(control_id)
    return observed == expected


def load_operator_trust(
    root: Path, policy: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], Path]:
    binding = policy.get("operator_trust", {})
    if not isinstance(binding, dict):
        raise ValueError("operator trust binding is malformed")
    path = resolve(root, binding.get("path"), "operator trust manifest")
    if digest_bytes(path.read_bytes()) != binding.get("sha256"):
        raise ValueError("operator trust manifest digest mismatch")
    manifest = load_json(path, "operator trust manifest")
    if (
        manifest.get("schema_version") != "psb-ai-incident-operator-trust/v1"
        or manifest.get("manifest_id") != binding.get("manifest_id")
    ):
        raise ValueError("operator trust manifest identity is unsupported")
    operators = keyed(manifest.get("operators"), "operator_id", "operator")
    key_ids: set[str] = set()
    for operator in operators.values():
        key_id = operator.get("key_id")
        if not isinstance(key_id, str) or not key_id or key_id in key_ids:
            raise ValueError("operator key identity is missing or duplicated")
        key_ids.add(key_id)
        key_path = resolve(path.parent, operator.get("public_key_path"), key_id)
        if digest_bytes(key_path.read_bytes()) != operator.get("public_key_sha256"):
            raise ValueError(f"{key_id} public key digest mismatch")
        if operator.get("algorithm") != "Ed25519" or operator.get("status") != "active":
            raise ValueError(f"{key_id} operator trust state is unsupported")
    return operators, path.parent


def verify_signature(
    openssl: Path, key_path: Path, payload: Any, signature_text: Any
) -> bool:
    if not isinstance(signature_text, str):
        return False
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        with tempfile.NamedTemporaryFile() as payload_file, tempfile.NamedTemporaryFile() as signature_file:
            payload_file.write(canonical_bytes(payload))
            payload_file.flush()
            signature_file.write(signature)
            signature_file.flush()
            completed = subprocess.run(
                [
                    str(openssl),
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    payload_file.name,
                    "-sigfile",
                    signature_file.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    except OSError as exc:
        raise ValueError("cryptographic verifier is unavailable") from exc
    if completed.returncode not in {0, 1}:
        raise ValueError("cryptographic verifier failed")
    return completed.returncode == 0


def operator_signature_valid(
    envelope: dict[str, Any],
    operator_id: Any,
    authority: str,
    operators: dict[str, dict[str, Any]],
    trust_root: Path,
    openssl: Path,
) -> bool:
    operator = operators.get(operator_id) if isinstance(operator_id, str) else None
    if not isinstance(operator, dict):
        return False
    if authority not in operator.get("authorities", []):
        return False
    if (
        envelope.get("key_id") != operator.get("key_id")
        or envelope.get("algorithm") != "Ed25519"
    ):
        return False
    key_path = resolve(trust_root, operator.get("public_key_path"), "operator public key")
    return verify_signature(
        openssl, key_path, envelope.get("payload"), envelope.get("signature")
    )


def recovery_signatures_valid(
    authorization: dict[str, Any],
    required_roles: set[str],
    operators: dict[str, dict[str, Any]],
    trust_root: Path,
    openssl: Path,
) -> bool:
    signatures = authorization.get("signatures")
    if not isinstance(signatures, list):
        return False
    observed_ids: set[str] = set()
    observed_roles: set[str] = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            return False
        operator_id = signature.get("operator_id")
        operator = operators.get(operator_id) if isinstance(operator_id, str) else None
        if not isinstance(operator, dict) or operator_id in observed_ids:
            return False
        role = operator.get("role")
        if role not in required_roles:
            return False
        authority = (
            "agent-session.recover.propose"
            if role == "incident-commander"
            else "agent-session.recover.approve"
        )
        if authority not in operator.get("authorities", []):
            return False
        if (
            signature.get("key_id") != operator.get("key_id")
            or signature.get("algorithm") != "Ed25519"
        ):
            return False
        key_path = resolve(
            trust_root, operator.get("public_key_path"), "recovery operator key"
        )
        if not verify_signature(
            openssl,
            key_path,
            authorization.get("payload"),
            signature.get("signature"),
        ):
            return False
        observed_ids.add(operator_id)
        observed_roles.add(role)
    return observed_roles == required_roles and len(observed_ids) == len(required_roles)


def evaluate(
    root: Path,
    policy_path: Path,
    policy: dict[str, Any],
    trigger: dict[str, Any],
    containment_command: dict[str, Any],
    recovery_authorization: dict[str, Any],
    evidence: dict[str, Any],
    openssl: Path,
) -> dict[str, bool]:
    if policy.get("schema_version") != "psb-ai-rogue-containment-policy/v1":
        raise ValueError("policy schema is unsupported")
    if policy.get("policy_id") != "PSB-AI-009-FIRST-SLICE":
        raise ValueError("policy identity is unsupported")
    if evidence.get("schema_version") != "psb-ai-rogue-incident-evidence/v1":
        raise ValueError("incident evidence schema is unsupported")
    if evidence.get("collection_status") != "complete":
        raise ValueError("incident evidence collection is incomplete or unavailable")
    if evidence.get("evaluator_status") != "available":
        raise ValueError("incident evidence evaluator is unavailable")
    if trigger.get("schema_version") != "psb-ai-rogue-trigger/v1":
        raise ValueError("trigger evidence schema is unsupported")
    if trigger.get("collection_status") != "complete":
        raise ValueError("trigger collection is incomplete or unavailable")
    if trigger.get("evaluator_status") != "available":
        raise ValueError("trigger evaluator is unavailable")

    forbidden = set(policy.get("evidence", {}).get("forbidden_fields", []))
    if not forbidden:
        raise ValueError("evidence forbidden-field policy is empty")
    for label, document in (
        ("trigger", trigger),
        ("containment command", containment_command),
        ("recovery authorization", recovery_authorization),
        ("incident evidence", evidence),
    ):
        found = forbidden_field(document, forbidden)
        if found:
            raise ValueError(f"{label} contains forbidden sensitive field {found}")

    policy_sha = digest_bytes(policy_path.read_bytes())
    cross_controls_ok = verify_cross_control_bindings(root, policy)
    operators, trust_root = load_operator_trust(root, policy)
    authority = policy.get("authority_plane", {})
    control_plane = evidence.get("control_plane", {})
    decisions: dict[str, bool] = {}

    decisions["RRC-001"] = bool(
        cross_controls_ok
        and authority
        == {
            "type": "out-of-band-security-control-plane",
            "administered_by": "incident-response",
            "mutable_by_agent": False,
            "depends_on_agent_process": False,
            "depends_on_model_output": False,
            "depends_on_repository_content": False,
            "depends_on_extension_runtime": False,
        }
        and control_plane.get("type") == authority.get("type")
        and control_plane.get("health") == "available"
        and control_plane.get("policy_sha256") == policy_sha
        and control_plane.get("agent_can_disable") is False
        and control_plane.get("repository_can_override") is False
    )

    containment_payload = containment_command.get("payload", {})
    if not isinstance(containment_payload, dict):
        containment_payload = {}
    trigger_binding = policy.get("trigger", {})
    signals = keyed(trigger.get("signals"), "signal_id", "trigger signal")
    required_signals = set(trigger_binding.get("required_signal_ids", []))
    trigger_time = parse_time(trigger.get("observed_at"), "trigger")
    containment_issued = parse_time(containment_payload.get("issued_at"), "containment issued")
    trigger_age = (containment_issued - trigger_time).total_seconds()
    decisions["RRC-002"] = bool(
        trigger.get("evidence_source") == "synthetic-fixture"
        and trigger.get("incident_id") == evidence.get("incident_id")
        and trigger.get("tenant_id") == evidence.get("tenant_id")
        and trigger.get("agent_id") == evidence.get("agent_id")
        and trigger.get("session_id") == evidence.get("session_id")
        and set(signals) == required_signals
        and signals.get("approval-replay", {}).get("source_control") == "PSB-AI-007"
        and signals.get("approval-replay", {}).get("decision") == "block"
        and signals.get("approval-replay", {}).get("circuit_breaker") == "open"
        and signals.get("approval-replay", {}).get("alert_receipt") == "verified"
        and signals.get("invalid-delegation-attempt", {}).get("source_control")
        == "PSB-AI-008"
        and signals.get("invalid-delegation-attempt", {}).get("decision") == "reject"
        and signals.get("invalid-delegation-attempt", {}).get("downstream_dispatched")
        is False
        and 0 <= trigger_age <= trigger_binding.get("maximum_age_seconds", -1)
        and trigger.get("live_trigger_adoption") == "NOT_CHECKED"
    )

    containment_expires = parse_time(
        containment_payload.get("expires_at"), "containment expiry"
    )
    containment_ttl = (containment_expires - containment_issued).total_seconds()
    containment_policy = policy.get("containment", {})
    containment_signature_ok = operator_signature_valid(
        containment_command,
        containment_payload.get("operator_id"),
        "agent-session.contain",
        operators,
        trust_root,
        openssl,
    )
    decisions["RRC-003"] = bool(
        containment_command.get("schema_version") == "psb-ai-containment-command/v1"
        and containment_signature_ok
        and containment_payload.get("incident_id") == evidence.get("incident_id")
        and containment_payload.get("tenant_id") == evidence.get("tenant_id")
        and containment_payload.get("agent_id") == evidence.get("agent_id")
        and containment_payload.get("session_id") == evidence.get("session_id")
        and containment_payload.get("scope") == "exact-agent-session"
        and containment_payload.get("action") == "contain"
        and set(containment_payload.get("reason_ids", [])) == required_signals
        and containment_payload.get("policy_id") == policy.get("policy_id")
        and containment_payload.get("policy_sha256") == policy_sha
        and containment_payload.get("trigger_sha256") == trigger_binding.get("sha256")
        and 0 < containment_ttl
        <= containment_policy.get("maximum_command_ttl_seconds", -1)
        and isinstance(containment_payload.get("nonce"), str)
        and exact_positive_int(containment_payload.get("sequence"))
    )

    containment = evidence.get("containment", {})
    applied_at = parse_time(containment.get("applied_at"), "containment applied")
    containment_latency = (applied_at - containment_issued).total_seconds()
    decisions["RRC-004"] = bool(
        containment.get("command_id") == containment_payload.get("command_id")
        and 0 <= containment_latency
        <= containment_policy.get("maximum_application_latency_seconds", -1)
        and applied_at <= containment_expires
        and containment.get("model_calls_allowed") is False
        and containment.get("tool_dispatch_allowed") is False
        and containment.get("delegation_allowed") is False
        and containment.get("memory_writes_allowed") is False
        and containment.get("agent_process_state") == "stopped"
    )

    revocations = keyed(
        containment.get("revocations"), "authority_type", "revocation"
    )
    allowed_terminal_states = {"revoked", "invalidated"}
    decisions["RRC-005"] = bool(
        set(revocations) == set(containment_policy.get("required_revocations", []))
        and all(
            record.get("state") in allowed_terminal_states
            and isinstance(record.get("authority_id"), str)
            and record.get("authority_id")
            for record in revocations.values()
        )
    )

    quarantine_policy = policy.get("quarantine", {})
    quarantine = evidence.get("quarantine", {})
    quarantine_records = keyed(
        quarantine.get("records"), "request_id", "quarantine"
    )
    observed_original_states = {
        record.get("original_state") for record in quarantine_records.values()
    }
    decisions["RRC-006"] = bool(
        observed_original_states
        == set(quarantine_policy.get("required_states", []))
        and all(
            record.get("state") == "quarantined"
            and record.get("automatic_retry") is False
            for record in quarantine_records.values()
        )
        and quarantine_policy.get("automatic_retry") is False
        and quarantine_policy.get("preserve_evidence_before_cleanup") is True
        and quarantine.get("evidence_preserved_before_cleanup") is True
        and isinstance(quarantine.get("snapshot_id"), str)
        and quarantine.get("snapshot_id")
        and exact_sha(quarantine.get("snapshot_sha256"))
    )

    fallback_policy = policy.get("fallback", {})
    fallback = evidence.get("fallback_exercise", {})
    fallback_start = parse_time(fallback.get("started_at"), "fallback start")
    fallback_end = parse_time(fallback.get("ended_at"), "fallback end")
    fallback_duration = (fallback_end - fallback_start).total_seconds()
    decisions["RRC-007"] = bool(
        fallback.get("mode") == fallback_policy.get("mode")
        and 0 < fallback_duration
        <= fallback_policy.get("maximum_duration_seconds", -1)
        and fallback.get("agent_process_used") is False
        and fallback.get("model_calls_used") is False
        and fallback.get("tool_dispatch_used") is False
        and fallback.get("mutation_used") is False
        and set(fallback.get("operations", []))
        == set(fallback_policy.get("allowed_operations", []))
        and fallback.get("result") == "passed"
    )

    readiness = evidence.get("recovery_readiness", {})
    recovery_payload = recovery_authorization.get("payload", {})
    if not isinstance(recovery_payload, dict):
        recovery_payload = {}
    required_negative_tests = {
        "OLD-SESSION-REPLAY",
        "OLD-KEY-REPLAY",
        "OLD-APPROVAL-REPLAY",
        "OLD-DELEGATION-REPLAY",
    }
    negative_tests = keyed(
        readiness.get("negative_tests"), "test_id", "recovery negative test"
    )
    decisions["RRC-008"] = bool(
        readiness.get("readiness_id") == recovery_payload.get("recovery_readiness_id")
        and isinstance(readiness.get("root_cause_id"), str)
        and readiness.get("root_cause_id") not in {"", "unknown"}
        and readiness.get("root_cause_status") == "reviewed"
        and readiness.get("old_agent_key_state") == "revoked"
        and readiness.get("old_session_authority_state") == "invalid"
        and readiness.get("new_agent_id") != evidence.get("agent_id")
        and readiness.get("new_session_id") != evidence.get("session_id")
        and readiness.get("new_key_id") != "AGENT-KEY-OLD-001"
        and readiness.get("clean_runtime_revision") == "RUNTIME-REVISION-REVIEWED-002"
        and readiness.get("evidence_preserved") is True
        and readiness.get("fallback_exercise_result") == "passed"
        and set(negative_tests) == required_negative_tests
        and all(record.get("result") == "denied" for record in negative_tests.values())
    )

    recovery_policy = policy.get("recovery", {})
    recovery_issued = parse_time(recovery_payload.get("issued_at"), "recovery issued")
    recovery_expires = parse_time(recovery_payload.get("expires_at"), "recovery expiry")
    recovery_ttl = (recovery_expires - recovery_issued).total_seconds()
    recovery_signature_ok = recovery_signatures_valid(
        recovery_authorization,
        set(recovery_policy.get("required_roles", [])),
        operators,
        trust_root,
        openssl,
    )
    decisions["RRC-009"] = bool(
        recovery_authorization.get("schema_version")
        == "psb-ai-recovery-authorization/v1"
        and recovery_signature_ok
        and recovery_payload.get("incident_id") == evidence.get("incident_id")
        and recovery_payload.get("tenant_id") == evidence.get("tenant_id")
        and recovery_payload.get("old_agent_id") == evidence.get("agent_id")
        and recovery_payload.get("old_session_id") == evidence.get("session_id")
        and recovery_payload.get("new_agent_id") == readiness.get("new_agent_id")
        and recovery_payload.get("new_session_id") == readiness.get("new_session_id")
        and recovery_payload.get("new_key_id") == readiness.get("new_key_id")
        and recovery_payload.get("policy_id") == policy.get("policy_id")
        and recovery_payload.get("policy_sha256") == policy_sha
        and recovery_payload.get("canary_mode")
        == recovery_policy.get("canary", {}).get("mode")
        and 0 < recovery_ttl
        <= recovery_policy.get("maximum_authorization_ttl_seconds", -1)
        and recovery_payload.get("sequence", 0)
        > containment_payload.get("sequence", 0)
    )

    recovery = evidence.get("recovery", {})
    recovery_applied = parse_time(recovery.get("applied_at"), "recovery applied")
    canary_policy = recovery_policy.get("canary", {})
    decisions["RRC-010"] = bool(
        recovery.get("authorization_id")
        == recovery_payload.get("authorization_id")
        and recovery_issued <= recovery_applied <= recovery_expires
        and recovery.get("new_agent_id") == recovery_payload.get("new_agent_id")
        and recovery.get("new_session_id") == recovery_payload.get("new_session_id")
        and recovery.get("new_key_id") == recovery_payload.get("new_key_id")
        and recovery.get("old_session_state") == "stopped"
        and recovery.get("old_authority_restored") is False
        and recovery.get("canary_mode") == canary_policy.get("mode")
        and exact_positive_int(recovery.get("canary_duration_seconds"))
        and recovery.get("canary_duration_seconds")
        <= canary_policy.get("maximum_duration_seconds", -1)
        and recovery.get("canary_health") == "passed"
        and recovery.get("automatic_full_restore") is False
        and recovery.get("final_state") == "RECOVERED_READ_ONLY"
    )

    transitions = evidence.get("state_transitions")
    if not isinstance(transitions, list):
        transitions = []
    transition_sequences = [record.get("sequence") for record in transitions if isinstance(record, dict)]
    transition_states = [record.get("state") for record in transitions if isinstance(record, dict)]
    audit = evidence.get("audit", {})
    audit_events = audit.get("events") if isinstance(audit, dict) else []
    if not isinstance(audit_events, list):
        audit_events = []
    audit_sequences = [record.get("sequence") for record in audit_events if isinstance(record, dict)]
    live = evidence.get("live_enforcement", {})
    required_live = {
        "control_plane",
        "model_gateway",
        "tool_gateway",
        "delegation_gateway",
        "memory_gateway",
        "authority_revocation",
        "incident_receiver",
    }
    decisions["RRC-011"] = bool(
        evidence.get("evidence_source") == "synthetic-fixture"
        and transition_sequences == list(range(1, len(transitions) + 1))
        and transition_states
        == [
            "DETECTED",
            "CONTAINMENT_AUTHORIZED",
            "CONTAINED",
            "QUARANTINED",
            "RECOVERY_PENDING",
            "RECOVERED_READ_ONLY",
        ]
        and audit_sequences == list(range(1, len(audit_events) + 1))
        and len(audit_events) == 7
        and all(record.get("status") == "recorded" for record in audit_events)
        and audit.get("incident_handoff")
        == "organization-owned-live-workflow-NOT_CHECKED"
        and isinstance(live, dict)
        and set(live) == required_live
        and all(value == "NOT_CHECKED" for value in live.values())
    )
    return decisions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trigger", type=Path, required=True)
    parser.add_argument("--containment-command", type=Path, required=True)
    parser.add_argument("--recovery-authorization", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = args.repository_root.resolve()
        policy_path = args.policy.resolve()
        policy = load_json(policy_path, "policy")
        trigger = load_json(args.trigger, "trigger evidence")
        containment_command = load_json(
            args.containment_command, "containment command"
        )
        recovery_authorization = load_json(
            args.recovery_authorization, "recovery authorization"
        )
        evidence = load_json(args.evidence, "incident evidence")
        decisions = evaluate(
            root,
            policy_path,
            policy,
            trigger,
            containment_command,
            recovery_authorization,
            evidence,
            args.openssl,
        )
    except (KeyError, TypeError, ValueError) as exc:
        print(f"ERROR PSB-AI-009/EVIDENCE {exc}")
        return 2

    failures = 0
    for check_id, description in CHECKS.items():
        passed = decisions.get(check_id, False)
        print(f"{'PASS' if passed else 'FAIL'} PSB-AI-009/{check_id} {description}")
        failures += 0 if passed else 1
    if failures:
        print(f"REJECTED rogue-agent containment and recovery evidence with {failures} failure(s)")
        return 1
    print("ACCEPTED rogue-agent containment and recovery evidence; live enforcement NOT_CHECKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
