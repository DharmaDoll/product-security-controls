#!/usr/bin/env python3
"""Verify an authenticated, fail-closed AI application egress gateway."""

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
    "AIG-001": "gateway route workload trust and policy identity are immutable",
    "AIG-002": "workload session is authenticated audience-bound fresh and exact",
    "AIG-003": "application traffic cannot bypass the mandatory gateway route",
    "AIG-004": "provider model tenant region training and retention are allowlisted",
    "AIG-005": "outbound data is classified minimized and size bounded",
    "AIG-006": "secret credential source and regulated classes are denied before dispatch",
    "AIG-007": "personal data is locally redacted for a zero-retention target",
    "AIG-008": "decision telemetry is content-free complete and committed before dispatch",
    "AIG-009": "gateway decisions are independently derived and fail closed before egress",
    "AIG-010": "gateway identity policy enforcement and telemetry health are complete and fresh",
    "AIG-011": "synthetic evidence leaves every live enforcement point NOT_CHECKED",
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


def nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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


def load_workload_trust(
    root: Path, policy: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], Path]:
    binding = policy.get("workload_trust", {})
    if not isinstance(binding, dict):
        raise ValueError("workload trust binding is malformed")
    path = resolve(root, binding.get("path"), "workload trust manifest")
    if digest_bytes(path.read_bytes()) != binding.get("sha256"):
        raise ValueError("workload trust manifest digest mismatch")
    manifest = load_json(path, "workload trust manifest")
    if (
        manifest.get("schema_version") != "psb-ai-workload-trust/v1"
        or manifest.get("manifest_id") != binding.get("manifest_id")
    ):
        raise ValueError("workload trust manifest identity is unsupported")
    workloads = keyed(manifest.get("workloads"), "workload_id", "workload")
    for workload in workloads.values():
        key_path = resolve(
            path.parent, workload.get("public_key_path"), "workload public key"
        )
        if digest_bytes(key_path.read_bytes()) != workload.get("public_key_sha256"):
            raise ValueError("workload public key digest mismatch")
        if workload.get("algorithm") != "Ed25519" or workload.get("status") != "active":
            raise ValueError("workload trust state is unsupported")
    return workloads, path.parent


def evaluate_session(
    root: Path,
    policy_path: Path,
    policy: dict[str, Any],
    session: dict[str, Any],
    evaluated_at: datetime,
    openssl: Path,
) -> tuple[bool, dict[str, Any], str]:
    workloads, trust_root = load_workload_trust(root, policy)
    payload = session.get("payload")
    if not isinstance(payload, dict):
        return False, {}, ""
    workload = workloads.get(payload.get("workload_id"))
    if not isinstance(workload, dict):
        return False, {}, ""
    key_path = resolve(
        trust_root, workload.get("public_key_path"), "workload public key"
    )
    signature_ok = (
        session.get("schema_version") == "psb-ai-workload-session/v1"
        and session.get("key_id") == workload.get("key_id")
        and session.get("algorithm") == "Ed25519"
        and verify_signature(
            openssl, key_path, payload, session.get("signature")
        )
    )
    issued_at = parse_time(payload.get("issued_at"), "workload session issued")
    expires_at = parse_time(payload.get("expires_at"), "workload session expiry")
    ttl = (expires_at - issued_at).total_seconds()
    binding = policy.get("workload_trust", {})
    session_ok = bool(
        signature_ok
        and payload.get("service_account") == workload.get("service_account")
        and payload.get("tenant_id") == workload.get("tenant_id")
        and payload.get("audience") == binding.get("audience")
        and payload.get("policy_id") == policy.get("policy_id")
        and payload.get("policy_sha256") == digest_bytes(policy_path.read_bytes())
        and 0 < ttl <= binding.get("maximum_session_ttl_seconds", -1)
        and issued_at <= evaluated_at <= expires_at
        and isinstance(payload.get("nonce"), str)
        and payload.get("nonce")
        and isinstance(payload.get("sequence"), int)
        and not isinstance(payload.get("sequence"), bool)
        and payload.get("sequence") > 0
    )
    return session_ok, workload, payload.get("session_authorization_id", "")


def route_matches(route: Any, expected: dict[str, Any]) -> bool:
    return isinstance(route, dict) and route == {
        "mode": expected.get("mode"),
        "scheme": expected.get("scheme"),
        "host": expected.get("host"),
        "port": expected.get("port"),
        "path": expected.get("path"),
    }


def target_matches(target: Any, approved: dict[str, Any]) -> bool:
    return bool(
        isinstance(target, dict)
        and target.get("provider_id") == approved.get("provider_id")
        and target.get("model_id") == approved.get("model_id")
        and target.get("provider_tenant_id") == approved.get("provider_tenant_id")
        and target.get("region") == approved.get("region")
        and target.get("training_on_inputs")
        == approved.get("training_on_inputs")
        and nonnegative_int(target.get("retention_seconds"))
        and target.get("retention_seconds")
        <= approved.get("maximum_retention_seconds", -1)
    )


def derive_reasons(
    scenario: dict[str, Any],
    policy: dict[str, Any],
    valid_session_id: str,
    workload: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if scenario.get("workload_session_id") != valid_session_id:
        reasons.append("workload-identity-invalid")
    if not route_matches(scenario.get("route"), policy.get("application_route", {})):
        reasons.append("gateway-bypass")
    targets = policy.get("approved_inference_targets")
    if not isinstance(targets, list) or len(targets) != 1:
        raise ValueError("approved inference target policy is malformed")
    if not target_matches(scenario.get("target"), targets[0]):
        reasons.append("inference-target-unapproved")

    for field in (
        "input_bytes",
        "outbound_bytes",
        "received_field_count",
        "forwarded_field_count",
        "personal_data_detected_count",
        "redacted_count",
        "secret_detected_count",
    ):
        if not nonnegative_int(scenario.get(field)):
            raise ValueError(f"{scenario.get('request_id')} {field} is malformed")
    if not exact_sha(scenario.get("content_sha256")):
        raise ValueError(f"{scenario.get('request_id')} content digest is malformed")
    if (
        scenario.get("outbound_bytes") > scenario.get("input_bytes")
        or scenario.get("forwarded_field_count") > scenario.get("received_field_count")
    ):
        reasons.append("data-minimization-failed")

    data_policy = policy.get("data_egress", {})
    input_class = scenario.get("input_classification")
    output_class = scenario.get("output_classification")
    if input_class in set(data_policy.get("deny_input_classes", [])):
        reasons.append("data-class-denied")
    elif input_class == data_policy.get("personal_data_input_class"):
        if (
            output_class != data_policy.get("personal_data_required_output_class")
            or scenario.get("personal_data_detected_count") <= 0
            or scenario.get("redacted_count")
            != scenario.get("personal_data_detected_count")
        ):
            reasons.append("personal-data-redaction-failed")
    allow_policy = data_policy.get("allow", {}).get(output_class)
    if input_class not in set(data_policy.get("deny_input_classes", [])):
        if not isinstance(allow_policy, dict):
            reasons.append("data-class-unapproved")
        elif scenario.get("outbound_bytes") > allow_policy.get("maximum_bytes", -1):
            reasons.append("data-size-exceeded")
    if not reasons and output_class not in set(workload.get("allowed_data_classes", [])):
        reasons.append("workload-data-class-unapproved")
    return sorted(set(reasons))


def evaluate(
    root: Path,
    policy_path: Path,
    policy: dict[str, Any],
    session: dict[str, Any],
    corpus: dict[str, Any],
    evidence: dict[str, Any],
    openssl: Path,
) -> dict[str, bool]:
    if policy.get("schema_version") != "psb-ai-application-gateway-policy/v1":
        raise ValueError("policy schema is unsupported")
    if policy.get("policy_id") != "PSB-AI-010-FIRST-SLICE":
        raise ValueError("policy identity is unsupported")
    if corpus.get("schema_version") != "psb-ai-application-egress-corpus/v1":
        raise ValueError("scenario corpus schema is unsupported")
    if evidence.get("schema_version") != "psb-ai-application-gateway-evidence/v1":
        raise ValueError("gateway evidence schema is unsupported")
    if evidence.get("collection_status") != "complete":
        raise ValueError("gateway evidence collection is incomplete or unavailable")
    if evidence.get("evaluator_status") != "available":
        raise ValueError("gateway evidence evaluator is unavailable")

    forbidden = set(policy.get("evidence", {}).get("forbidden_fields", []))
    if not forbidden:
        raise ValueError("evidence forbidden-field policy is empty")
    for label, document in (
        ("session", session),
        ("scenario corpus", corpus),
        ("gateway evidence", evidence),
    ):
        found = forbidden_field(document, forbidden)
        if found:
            raise ValueError(f"{label} contains forbidden sensitive field {found}")

    evaluated_at = parse_time(corpus.get("evaluated_at"), "corpus evaluation")
    session_ok, workload, valid_session_id = evaluate_session(
        root, policy_path, policy, session, evaluated_at, openssl
    )
    scenarios = keyed(corpus.get("scenarios"), "request_id", "scenario")
    decisions = keyed(evidence.get("decisions"), "request_id", "gateway decision")
    expected_scenarios = {
        "REQ-ALLOW-PUBLIC",
        "REQ-ALLOW-PERSONAL-REDACTED",
        "REQ-DENY-SECRET",
        "REQ-DENY-UNAPPROVED-MODEL",
        "REQ-DENY-WRONG-TENANT-REGION",
        "REQ-DENY-DIRECT-BYPASS",
        "REQ-DENY-UNKNOWN-WORKLOAD",
        "REQ-DENY-OVERSIZED",
    }
    if set(scenarios) != expected_scenarios or set(decisions) != expected_scenarios:
        raise ValueError("scenario or decision coverage is incomplete")

    derived: dict[str, tuple[str, list[str]]] = {}
    for request_id, scenario in scenarios.items():
        reasons = derive_reasons(scenario, policy, valid_session_id, workload)
        decision = "deny" if reasons else "allow"
        if (
            scenario.get("expected_decision") != decision
            or sorted(scenario.get("expected_reasons", [])) != reasons
        ):
            raise ValueError(f"{request_id} corpus expectation is inconsistent")
        derived[request_id] = (decision, reasons)

    policy_route = policy.get("application_route", {})
    trust_binding = policy.get("workload_trust", {})
    decisions_out: dict[str, bool] = {}
    decisions_out["AIG-001"] = bool(
        policy_route
        == {
            "mode": "mandatory-gateway",
            "scheme": "https",
            "host": "ai-gateway.example.invalid",
            "port": 443,
            "path": "/v1/inference",
            "direct_provider_access": False,
            "fail_closed_when_unavailable": True,
        }
        and exact_sha(trust_binding.get("sha256"))
        and trust_binding.get("manifest_id") == "PSB-AI-010-WORKLOADS-001"
        and evidence.get("policy_id") == policy.get("policy_id")
    )
    decisions_out["AIG-002"] = bool(
        session_ok
        and evidence.get("workload_session_id") == valid_session_id
        and decisions["REQ-DENY-UNKNOWN-WORKLOAD"].get("identity_enforced") is True
        and derived["REQ-DENY-UNKNOWN-WORKLOAD"]
        == ("deny", ["workload-identity-invalid"])
    )

    bypass = decisions["REQ-DENY-DIRECT-BYPASS"]
    decisions_out["AIG-003"] = bool(
        derived["REQ-DENY-DIRECT-BYPASS"] == ("deny", ["gateway-bypass"])
        and bypass.get("decision") == "deny"
        and bypass.get("reasons") == ["gateway-bypass"]
        and bypass.get("route_enforced") is True
        and bypass.get("dispatch_decision") == "blocked"
        and bypass.get("upstream_dispatched") is False
    )

    target_ids = {"REQ-DENY-UNAPPROVED-MODEL", "REQ-DENY-WRONG-TENANT-REGION"}
    decisions_out["AIG-004"] = all(
        derived[request_id] == ("deny", ["inference-target-unapproved"])
        and decisions[request_id].get("decision") == "deny"
        and decisions[request_id].get("reasons")
        == ["inference-target-unapproved"]
        and decisions[request_id].get("target_enforced") is True
        and decisions[request_id].get("retention_enforced") is True
        and decisions[request_id].get("dispatch_decision") == "blocked"
        for request_id in target_ids
    )

    allow_public = decisions["REQ-ALLOW-PUBLIC"]
    oversized = decisions["REQ-DENY-OVERSIZED"]
    decisions_out["AIG-005"] = bool(
        derived["REQ-ALLOW-PUBLIC"] == ("allow", [])
        and allow_public.get("decision") == "allow"
        and allow_public.get("classification_enforced") is True
        and allow_public.get("minimization_enforced") is True
        and derived["REQ-DENY-OVERSIZED"] == ("deny", ["data-size-exceeded"])
        and oversized.get("decision") == "deny"
        and oversized.get("reasons") == ["data-size-exceeded"]
        and oversized.get("minimization_enforced") is True
        and oversized.get("dispatch_decision") == "blocked"
    )

    denied_secret = decisions["REQ-DENY-SECRET"]
    decisions_out["AIG-006"] = bool(
        derived["REQ-DENY-SECRET"] == ("deny", ["data-class-denied"])
        and denied_secret.get("decision") == "deny"
        and denied_secret.get("reasons") == ["data-class-denied"]
        and denied_secret.get("classification_enforced") is True
        and denied_secret.get("dispatch_decision") == "blocked"
        and denied_secret.get("upstream_dispatched") is False
    )

    personal = scenarios["REQ-ALLOW-PERSONAL-REDACTED"]
    personal_decision = decisions["REQ-ALLOW-PERSONAL-REDACTED"]
    decisions_out["AIG-007"] = bool(
        derived["REQ-ALLOW-PERSONAL-REDACTED"] == ("allow", [])
        and personal.get("redacted_count") == personal.get("personal_data_detected_count")
        and personal.get("forwarded_field_count") < personal.get("received_field_count")
        and personal_decision.get("decision") == "allow"
        and personal_decision.get("redaction_enforced") is True
        and personal_decision.get("minimization_enforced") is True
        and personal_decision.get("retention_enforced") is True
        and personal_decision.get("dispatch_decision") == "authorized"
    )

    sequences = [decisions[request_id].get("sequence") for request_id in scenarios]
    sequence_set_ok = set(sequences) == set(range(1, 9))
    decisions_out["AIG-008"] = bool(
        sequence_set_ok
        and all(
            record.get("audit_before_dispatch") is True
            and record.get("network_execution") == "not-performed-synthetic"
            for record in decisions.values()
        )
        and all(exact_sha(record.get("content_sha256")) for record in scenarios.values())
    )

    decisions_out["AIG-009"] = all(
        record.get("decision") == derived[request_id][0]
        and sorted(record.get("reasons", [])) == derived[request_id][1]
        and record.get("dispatch_decision")
        == ("authorized" if derived[request_id][0] == "allow" else "blocked")
        and record.get("upstream_dispatched") is False
        for request_id, record in decisions.items()
    )

    observed_at = parse_time(evidence.get("observed_at"), "gateway observation")
    health = evidence.get("gateway_health", {})
    health_time = parse_time(health.get("observed_at"), "gateway health")
    health_age = (observed_at - health_time).total_seconds()
    components = keyed(health.get("components"), "component_id", "health component")
    health_policy = policy.get("gateway_health", {})
    decisions_out["AIG-010"] = bool(
        health.get("complete") is True
        and set(components) == set(health_policy.get("required_components", []))
        and all(component.get("status") == "healthy" for component in components.values())
        and 0 <= health_age <= health_policy.get("maximum_age_seconds", -1)
    )

    live = evidence.get("live_enforcement", {})
    required_live = {
        "application-route",
        "gateway-decision",
        "identity-provider",
        "provider-tenant-policy",
        "telemetry-receiver",
    }
    decisions_out["AIG-011"] = bool(
        evidence.get("evidence_source") == "synthetic-fixture"
        and isinstance(live, dict)
        and set(live) == required_live
        and all(value == "NOT_CHECKED" for value in live.values())
    )
    return decisions_out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--workload-session", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = args.repository_root.resolve()
        policy_path = args.policy.resolve()
        decisions = evaluate(
            root,
            policy_path,
            load_json(policy_path, "policy"),
            load_json(args.workload_session, "workload session"),
            load_json(args.corpus, "scenario corpus"),
            load_json(args.evidence, "gateway evidence"),
            args.openssl,
        )
    except (KeyError, TypeError, ValueError) as exc:
        print(f"ERROR PSB-AI-010/EVIDENCE {exc}")
        return 2

    failures = 0
    for check_id, description in CHECKS.items():
        passed = decisions.get(check_id, False)
        print(f"{'PASS' if passed else 'FAIL'} PSB-AI-010/{check_id} {description}")
        failures += 0 if passed else 1
    if failures:
        print(f"REJECTED AI application gateway evidence with {failures} failure(s)")
        return 1
    print("ACCEPTED AI application gateway evidence; live enforcement NOT_CHECKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
