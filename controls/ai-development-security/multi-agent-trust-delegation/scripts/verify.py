#!/usr/bin/env python3
"""Verify authenticated, bounded multi-agent delegation and response evidence."""

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
    "MAD-001": "trust manifest and AI-004/006/007 bindings are exact",
    "MAD-002": "delegation and response signatures authenticate exact agent identities",
    "MAD-003": "delegation follows one explicit sender recipient purpose and parent task edge",
    "MAD-004": "delegated and runtime capabilities stay below both agent privilege ceilings",
    "MAD-005": "tenant resource path and data classification remain in scope",
    "MAD-006": "delegated and consumed resource budgets cannot amplify the parent ceiling",
    "MAD-007": "delegation and response are fresh monotonic and replay resistant",
    "MAD-008": "onward delegation is denied at the first bounded hop",
    "MAD-009": "recipient execution is isolated credential-free and fail-closed",
    "MAD-010": "signed response is bound to the exact delegation and AI-006 result schema",
    "MAD-011": "evidence is complete sanitized and live adoption remains NOT_CHECKED",
}
HARD_FORBIDDEN = {
    "prompt",
    "transcript",
    "message_body",
    "tool_arguments",
    "tool_output",
    "credential",
    "credential_value",
    "secret",
    "secret_value",
    "token",
    "token_value",
    "private_url",
}


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unavailable or malformed: {exc.__class__.__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


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
        raise ValueError(f"{label} path escapes repository root") from exc
    if not path.is_file():
        raise ValueError(f"{label} is unavailable")
    return path


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


def exact_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def exact_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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
    expected = {"PSB-AI-004", "PSB-AI-006", "PSB-AI-007"}
    observed: set[str] = set()
    for binding in policy.get("cross_control_bindings", []):
        control_id = binding.get("control_id")
        if control_id in observed:
            raise ValueError(f"duplicate cross-control binding {control_id}")
        path = resolve(root, binding.get("path"), f"{control_id} binding")
        if digest_bytes(path.read_bytes()) != binding.get("sha256"):
            raise ValueError(f"{control_id} binding digest mismatch")
        document = load_json(path, f"{control_id} binding")
        if document.get(binding.get("identity_field")) != binding.get("identity"):
            raise ValueError(f"{control_id} binding identity mismatch")
        observed.add(control_id)
    return observed == expected


def load_trust(root: Path, policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]], Path]:
    binding = policy.get("trust_manifest", {})
    path = resolve(root, binding.get("path"), "trust manifest")
    if digest_bytes(path.read_bytes()) != binding.get("sha256"):
        raise ValueError("trust manifest digest mismatch")
    manifest = load_json(path, "trust manifest")
    if (
        manifest.get("schema_version") != "psb-ai-agent-trust-manifest/v1"
        or manifest.get("manifest_id") != binding.get("manifest_id")
    ):
        raise ValueError("trust manifest identity is unsupported")
    agents = keyed(manifest.get("agents"), "agent_id", "agent")
    key_ids: set[str] = set()
    for agent in agents.values():
        key_id = agent.get("key_id")
        if not isinstance(key_id, str) or not key_id or key_id in key_ids:
            raise ValueError("agent key identity is missing or duplicated")
        key_ids.add(key_id)
        key_path = resolve(path.parent, agent.get("public_key_path"), f"{key_id} public key")
        if digest_bytes(key_path.read_bytes()) != agent.get("public_key_sha256"):
            raise ValueError(f"{key_id} public key digest mismatch")
        if agent.get("algorithm") != "Ed25519" or agent.get("status") != "active":
            raise ValueError(f"{key_id} trust state is unsupported")
    return manifest, agents, path.parent


def agent_for_envelope(
    envelope: dict[str, Any], agents: dict[str, dict[str, Any]], sender_id: Any
) -> dict[str, Any] | None:
    agent = agents.get(sender_id) if isinstance(sender_id, str) else None
    if not isinstance(agent, dict):
        return None
    if envelope.get("key_id") != agent.get("key_id") or envelope.get("algorithm") != "Ed25519":
        return None
    return agent


def verify_signature(
    openssl: Path,
    key_path: Path,
    payload: Any,
    signature_text: Any,
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
                timeout=10,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("cryptographic verifier is unavailable") from exc
    return completed.returncode == 0


def classification_within(value: Any, maximum: Any, order: Any) -> bool:
    if not isinstance(order, list) or len(order) != len(set(order)):
        raise ValueError("classification order is malformed")
    try:
        return order.index(value) <= order.index(maximum)
    except ValueError:
        return False


def budget_within(child: Any, ceiling: Any) -> bool:
    keys = {"tokens", "tool_calls", "duration_seconds"}
    if not isinstance(child, dict) or not isinstance(ceiling, dict):
        return False
    if set(child) != keys or set(ceiling) != keys:
        return False
    return all(
        exact_nonnegative_int(child[key])
        and exact_nonnegative_int(ceiling[key])
        and child[key] <= ceiling[key]
        for key in keys
    )


def render(check_id: str, passed: bool) -> None:
    print(f"{'PASS' if passed else 'FAIL'} PSB-AI-008/{check_id} {CHECKS[check_id]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--delegation", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    args = parser.parse_args()

    try:
        root = args.repository_root.resolve()
        policy = load_json(args.policy, "multi-agent policy")
        delegation_envelope = load_json(args.delegation, "delegation envelope")
        response_envelope = load_json(args.response, "response envelope")
        evidence = load_json(args.evidence, "multi-agent evidence")
        if policy.get("schema_version") != "psb-ai-multi-agent-policy/v1":
            raise ValueError("multi-agent policy schema is unsupported")
        if delegation_envelope.get("schema_version") != "psb-ai-signed-delegation-envelope/v1":
            raise ValueError("delegation envelope schema is unsupported")
        if response_envelope.get("schema_version") != "psb-ai-signed-delegation-response-envelope/v1":
            raise ValueError("response envelope schema is unsupported")
        if evidence.get("schema_version") != "psb-ai-multi-agent-evidence/v1":
            raise ValueError("multi-agent evidence schema is unsupported")
        if evidence.get("collection", {}).get("status") != "complete":
            raise ValueError("multi-agent collection is unavailable or incomplete")
        if evidence.get("evaluator", {}).get("status") != "complete":
            raise ValueError("multi-agent evaluator is unavailable or incomplete")
        delegation = delegation_envelope.get("payload")
        response = response_envelope.get("payload")
        if not isinstance(delegation, dict) or not isinstance(response, dict):
            raise ValueError("signed envelope payload is malformed")
        forbidden = set(policy.get("evidence", {}).get("forbidden_fields", [])) | HARD_FORBIDDEN
        for label, document in (
            ("policy", policy),
            ("delegation", delegation_envelope),
            ("response", response_envelope),
            ("evidence", evidence),
        ):
            found = forbidden_field(document, forbidden)
            if found:
                raise ValueError(f"{label} contains forbidden sensitive field {found}")
        bindings_ok = verify_cross_control_bindings(root, policy)
        _, agents, trust_root = load_trust(root, policy)
        parent_binding = policy.get("parent_request_binding", {})
        parent_path = resolve(root, parent_binding.get("path"), "parent request")
        if digest_bytes(parent_path.read_bytes()) != parent_binding.get("sha256"):
            raise ValueError("parent request binding digest mismatch")
        parent_request = load_json(parent_path, "parent request")
        if (
            parent_request.get("schema_version") != "psb-ai-006-parent-request-reference/v1"
            or parent_request.get("parent_request_id") != parent_binding.get("parent_request_id")
            or parent_request.get("authorization_status") != "authorized"
        ):
            raise ValueError("parent request identity or authorization is unsupported")
        evaluation_time = parse_time(policy.get("evaluation_time"), "evaluation")
        issued_at = parse_time(delegation.get("issued_at"), "delegation issue")
        expires_at = parse_time(delegation.get("expires_at"), "delegation expiry")
        response_issued_at = parse_time(response.get("issued_at"), "response issue")
    except ValueError as exc:
        print(f"ERROR PSB-AI-008/EVIDENCE {exc}")
        return 2

    sender = agent_for_envelope(delegation_envelope, agents, delegation.get("sender_agent_id"))
    responder = agent_for_envelope(response_envelope, agents, response.get("sender_agent_id"))
    signature_ok = False
    response_signature_ok = False
    try:
        if sender:
            signature_ok = verify_signature(
                args.openssl,
                resolve(trust_root, sender.get("public_key_path"), "sender public key"),
                delegation,
                delegation_envelope.get("signature_base64"),
            )
        if responder:
            response_signature_ok = verify_signature(
                args.openssl,
                resolve(trust_root, responder.get("public_key_path"), "responder public key"),
                response,
                response_envelope.get("signature_base64"),
            )
    except ValueError as exc:
        print(f"ERROR PSB-AI-008/EVIDENCE {exc}")
        return 2

    trust_ok = bindings_ok and len(agents) == 2
    authentication_ok = bool(sender and responder and signature_ok and response_signature_ok)

    schema = policy.get("delegation_schema", {})
    required_fields = set(schema.get("required_fields", []))
    edges = policy.get("delegation_edges", [])
    edge = edges[0] if isinstance(edges, list) and len(edges) == 1 and isinstance(edges[0], dict) else {}
    edge_ok = all(
        (
            set(delegation) == required_fields,
            delegation.get("schema_version") == schema.get("schema_version"),
            exact_sha(delegation.get("parent_request_digest")),
            delegation.get("parent_request_digest") == parent_request.get("request_digest"),
            delegation.get("sender_session_id") == parent_request.get("session_id"),
            delegation.get("tenant_id") == parent_request.get("tenant_id"),
            delegation.get("sender_agent_id") == edge.get("sender_agent_id"),
            delegation.get("recipient_agent_id") == edge.get("recipient_agent_id"),
            delegation.get("tenant_id") == edge.get("tenant_id"),
            delegation.get("purpose") in edge.get("purposes", []),
            isinstance(delegation.get("sender_session_id"), str),
            isinstance(delegation.get("task_id"), str),
            bool(sender and sender.get("can_delegate") is True),
            bool(sender and delegation.get("recipient_agent_id") in sender.get("allowed_recipients", [])),
        )
    )

    capabilities = delegation.get("capabilities")
    runtime = evidence.get("runtime", {})
    capability_ok = all(
        (
            isinstance(capabilities, list),
            len(capabilities) == len(set(capabilities or [])),
            set(capabilities or []).issubset(set(edge.get("capability_ceiling", []))),
            bool(sender and set(capabilities or []).issubset(set(sender.get("maximum_capabilities", [])))),
            bool(responder and set(capabilities or []).issubset(set(responder.get("maximum_capabilities", [])))),
            runtime.get("capabilities") == capabilities,
        )
    )

    scope = delegation.get("resource_scope", {})
    paths = scope.get("paths") if isinstance(scope, dict) else None
    scope_ok = all(
        (
            delegation.get("tenant_id") == runtime.get("tenant_id"),
            scope.get("repository") == edge.get("repository"),
            scope.get("repository") == runtime.get("repository"),
            scope.get("ref") == edge.get("ref"),
            scope.get("ref") == runtime.get("ref"),
            isinstance(paths, list) and bool(paths),
            paths == runtime.get("paths"),
            all(isinstance(path, str) and path.startswith(edge.get("path_prefix", "\0")) for path in paths or []),
            classification_within(
                delegation.get("data_classification"),
                edge.get("maximum_data_classification"),
                policy.get("classification_order"),
            ),
            bool(responder and classification_within(
                delegation.get("data_classification"),
                responder.get("maximum_data_classification"),
                policy.get("classification_order"),
            )),
        )
    )

    budget_ok = all(
        (
            budget_within(delegation.get("budget"), edge.get("budget_ceiling")),
            budget_within(response.get("budget_used"), delegation.get("budget")),
        )
    )

    replay_state = evidence.get("replay_state", {})
    response_replay = evidence.get("response_replay_state", {})
    age = (evaluation_time - issued_at).total_seconds()
    ttl = (expires_at - issued_at).total_seconds()
    response_age = (evaluation_time - response_issued_at).total_seconds()
    freshness_ok = all(
        (
            0 <= age <= schema.get("maximum_age_seconds", -1),
            0 < ttl <= schema.get("maximum_ttl_seconds", -1),
            issued_at <= response_issued_at <= expires_at,
            response_age >= 0,
            exact_nonnegative_int(delegation.get("sequence")),
            delegation.get("sequence", -1) > replay_state.get("last_consumed_sequence", -1),
            replay_state.get("sender_agent_id") == delegation.get("sender_agent_id"),
            delegation.get("nonce") not in replay_state.get("consumed_nonces", []),
            exact_nonnegative_int(response.get("sequence")),
            response.get("sequence", -1) > response_replay.get("last_consumed_sequence", -1),
            response_replay.get("sender_agent_id") == response.get("sender_agent_id"),
            response.get("nonce") not in response_replay.get("consumed_nonces", []),
        )
    )

    onward_ok = all(
        (
            delegation.get("hop") == 1,
            delegation.get("hop") <= schema.get("maximum_hops", 0),
            delegation.get("onward_delegation") is False,
            edge.get("onward_delegation") is False,
            bool(responder and responder.get("can_delegate") is False),
            runtime.get("onward_delegation_attempts") == 0,
        )
    )

    expected_allow = all(
        (authentication_ok, edge_ok, capability_ok, scope_ok, budget_ok, freshness_ok, onward_ok)
    )
    runtime_ok = all(
        (
            runtime.get("recipient_agent_id") == delegation.get("recipient_agent_id"),
            runtime.get("isolation") == "dedicated-context",
            runtime.get("ambient_credentials") is False,
            runtime.get("model_calls_stopped") is (not expected_allow),
            runtime.get("side_effects_stopped") is (not expected_allow),
            evidence.get("decision", {}).get("status") == ("allow" if expected_allow else "block"),
        )
    )

    response_schema = policy.get("response_schema", {})
    response_ok = all(
        (
            response.get("schema_version") == response_schema.get("schema_version"),
            response.get("delegation_id") == delegation.get("delegation_id"),
            response.get("delegation_payload_digest") == canonical_digest(delegation),
            response.get("sender_agent_id") == delegation.get("recipient_agent_id"),
            response.get("recipient_agent_id") == delegation.get("sender_agent_id"),
            response.get("status") in response_schema.get("statuses", []),
            response.get("result_schema") == response_schema.get("result_schema"),
            exact_sha(response.get("result_digest")),
            response_signature_ok,
        )
    )

    collection = evidence.get("collection", {})
    health_ok = all(
        (
            evidence.get("evidence_source") == policy.get("evidence", {}).get("source"),
            collection.get("status") == "complete",
            collection.get("gaps") == [],
            parse_time(collection.get("observed_at"), "collection observation") == evaluation_time,
            evidence.get("evaluator", {}).get("status") == "complete",
            evidence.get("live_enforcement") == policy.get("evidence", {}).get("live_enforcement") == "NOT_CHECKED",
        )
    )

    outcomes = [
        trust_ok,
        authentication_ok,
        edge_ok,
        capability_ok,
        scope_ok,
        budget_ok,
        freshness_ok,
        onward_ok,
        runtime_ok,
        response_ok,
        health_ok,
    ]
    for check_id, passed in zip(CHECKS, outcomes, strict=True):
        render(check_id, passed)
    if all(outcomes):
        print("ACCEPTED multi-agent delegation evidence; live enforcement NOT_CHECKED")
        return 0
    print(f"REJECTED multi-agent delegation evidence: {sum(not item for item in outcomes)} checks failed")
    return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except (KeyError, TypeError, ValueError) as error:
        print(f"ERROR PSB-AI-008/EVIDENCE malformed evaluation input: {error.__class__.__name__}")
        exit_code = 2
    raise SystemExit(exit_code)
