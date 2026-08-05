#!/usr/bin/env python3
"""Verify a deterministic agent action-integrity and output-validation contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HARD_FORBIDDEN = {
    "raw_model_output",
    "raw_prompt",
    "transcript",
    "credential_value",
    "secret_value",
    "token",
    "tool_arguments",
    "result_body",
}
CHECKS = {
    "AAI-001": "strict structured proposals reject unknown or free-form fields",
    "AAI-002": "canonical request digest binds normalized proposal content",
    "AAI-003": "independent policy constrains action target parameters and freshness",
    "AAI-004": "high-impact action uses an exact single-use PSB-AI-004 authorization",
    "AAI-005": "decision and execution retain exact request identity",
    "AAI-006": "idempotency prevents replay and duplicate dispatch",
    "AAI-007": "tool results match strict schema request and resource identity",
    "AAI-008": "uncertain outcomes quarantine without retry or authorization restoration",
    "AAI-009": "evidence is complete sanitized and evaluator-backed",
    "AAI-010": "fixture leaves live enforcement explicitly NOT_CHECKED",
}


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unavailable or malformed: {exc.__class__.__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_bytes(encoded)


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


def keyed(items: Any, key: str, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        raise ValueError(f"{label} collection is malformed")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get(key), str) or not item[key]:
            raise ValueError(f"{label} record is malformed")
        identity = item[key]
        if identity in result:
            raise ValueError(f"duplicate {label} identity {identity}")
        result[identity] = item
    return result


def exact_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str) and bool(value)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "sha256":
        return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)
    return False


def proposal_outcome(
    proposal: dict[str, Any], policy: dict[str, Any], evaluation_time: datetime
) -> tuple[str, str, str | None]:
    schema = policy.get("proposal_schema", {})
    required = set(schema.get("required_fields", []))
    if set(proposal) != required or proposal.get("schema_version") != schema.get("schema_version"):
        return "deny", "schema-invalid", None
    request_digest = canonical_digest(proposal)
    action = policy.get("actions", {}).get(proposal.get("action_id"))
    if not isinstance(action, dict):
        return "deny", "action-unknown", request_digest
    if proposal.get("target") not in action.get("allowed_targets", []):
        return "deny", "scope-violation", request_digest
    parameters = proposal.get("parameters")
    parameter_schema = action.get("parameter_schema", {})
    required_parameters = set(parameter_schema.get("required_fields", []))
    if not isinstance(parameters, dict) or set(parameters) != required_parameters:
        return "deny", "parameter-invalid", request_digest
    for name, expected_type in parameter_schema.get("types", {}).items():
        if not exact_type(parameters.get(name), expected_type):
            return "deny", "parameter-invalid", request_digest
    for name, exact_value in parameter_schema.get("exact_values", {}).items():
        if parameters.get(name) != exact_value:
            return "deny", "parameter-invalid", request_digest
    for name, maximum in parameter_schema.get("maximums", {}).items():
        if name.endswith("_bytes"):
            parameter_name = name[: -len("_bytes")]
            value = parameters.get(parameter_name)
            if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
                return "deny", "parameter-invalid", request_digest
        elif not isinstance(parameters.get(name), int) or parameters[name] > maximum:
            return "deny", "parameter-invalid", request_digest
    requested_at = parse_time(proposal.get("requested_at"), f"{proposal.get('proposal_id')} request")
    age = (evaluation_time - requested_at).total_seconds()
    if age < 0 or age > policy.get("maximum_proposal_age_seconds", 0):
        return "deny", "stale-proposal", request_digest
    reason = "policy-and-authorization-match" if action.get("authorization") == "PSB-AI-004-bound-single-use" else "policy-match"
    return "allow", reason, request_digest


def verify_bindings(repository_root: Path, policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for binding in policy.get("cross_control_bindings", []):
        control_id = binding.get("control_id")
        if control_id in documents:
            raise ValueError(f"duplicate cross-control binding {control_id}")
        path = resolve(repository_root, binding.get("path"), f"{control_id} binding")
        if sha256_bytes(path.read_bytes()) != binding.get("sha256"):
            raise ValueError(f"{control_id} binding digest mismatch")
        document = load_json(path, f"{control_id} binding")
        if document.get(binding.get("identity_field")) != binding.get("identity"):
            raise ValueError(f"{control_id} binding identity mismatch")
        documents[control_id] = document
    if set(documents) != {"PSB-AI-002", "PSB-AI-004"}:
        raise ValueError("required cross-control bindings are incomplete")
    return documents["PSB-AI-002"], documents["PSB-AI-004"]


def verify_action_inventory(policy: dict[str, Any], manifest: dict[str, Any], runtime: dict[str, Any]) -> None:
    dependencies = keyed(manifest.get("dependencies"), "id", "dependency")
    extensions = runtime.get("extension_capabilities", {}).get("extensions", {})
    for action_id, action in policy.get("actions", {}).items():
        dependency = dependencies.get(action.get("dependency_record_id"))
        extension = extensions.get(action.get("tool"))
        if not isinstance(dependency, dict) or not isinstance(extension, dict):
            raise ValueError(f"{action_id} reviewed tool identity is unavailable")
        if dependency.get("runtime_handoff", {}).get("extension_id") != action.get("tool"):
            raise ValueError(f"{action_id} dependency runtime handoff mismatch")
        if action.get("operation") not in dependency.get("capabilities", {}).get("tools", []):
            raise ValueError(f"{action_id} operation is absent from dependency capabilities")
        runtime_tool = extension.get("tools", {}).get(action.get("operation"))
        if not isinstance(runtime_tool, dict) or runtime_tool.get("effect") != action.get("effect"):
            raise ValueError(f"{action_id} runtime effect binding mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--proposals", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    try:
        repository_root = args.repository_root.resolve()
        policy = load_json(args.policy, "action policy")
        proposals_doc = load_json(args.proposals, "proposal set")
        evidence = load_json(args.evidence, "execution evidence")
        if policy.get("schema_version") != "psb-ai-action-integrity-policy/v1":
            raise ValueError("action policy schema is unsupported")
        proposal_binding = policy.get("proposal_set_binding", {})
        if sha256_bytes(args.proposals.read_bytes()) != proposal_binding.get("sha256"):
            raise ValueError("proposal set binding digest mismatch")
        if proposals_doc.get("proposal_set_id") != proposal_binding.get("proposal_set_id"):
            raise ValueError("proposal set binding identity mismatch")
        forbidden = set(policy.get("evidence", {}).get("forbidden_fields", [])) | HARD_FORBIDDEN
        for label, document in (("proposal set", proposals_doc), ("execution evidence", evidence)):
            found = forbidden_field(document, forbidden)
            if found:
                raise ValueError(f"{label} contains forbidden evidence field {found}")
        if evidence.get("collection_status") != "complete":
            raise ValueError("agent action evidence collection is incomplete")
        if evidence.get("evaluator_status") != "completed":
            raise ValueError("agent action evaluator is unavailable")
        if evidence.get("source_type") != policy.get("evidence", {}).get("required_source"):
            raise ValueError("agent action evidence source is untrusted")
        if evidence.get("schema_version") != "psb-ai-action-execution-evidence/v1":
            raise ValueError("execution evidence schema is unsupported")
        if proposals_doc.get("schema_version") != "psb-ai-action-proposal-set/v1" or proposals_doc.get("source_type") != "synthetic-fixture":
            raise ValueError("proposal set schema or source is unsupported")
        if evidence.get("policy_id") != policy.get("policy_id") or evidence.get("policy_revision") != policy.get("policy_revision"):
            raise ValueError("execution evidence policy identity mismatch")
        manifest, runtime = verify_bindings(repository_root, policy)
        verify_action_inventory(policy, manifest, runtime)
        evaluation_time = parse_time(policy.get("evaluation_time"), "policy evaluation")

        proposals = keyed(proposals_doc.get("proposals"), "proposal_id", "proposal")
        if set(proposals) != {"ACT-T001", "ACT-T002", "ACT-T003", "ACT-T004"}:
            raise ValueError("proposal scenario coverage is incomplete or contains unknown identities")
        decisions = keyed(evidence.get("decisions"), "proposal_id", "decision")
        executions = keyed(evidence.get("executions"), "proposal_id", "execution")
        results = keyed(evidence.get("results"), "execution_id", "result")
        replay_decisions = keyed(evidence.get("replay_decisions"), "proposal_id", "replay decision")
        if set(decisions) != set(proposals):
            raise ValueError("proposal decision evidence is incomplete or contains unknown identities")

        findings: dict[str, list[str]] = {check_id: [] for check_id in CHECKS}
        expected_allowed: set[str] = set()
        proposal_digests: dict[str, str | None] = {}
        for proposal_id, proposal in sorted(proposals.items()):
            expected_decision, expected_reason, request_digest = proposal_outcome(proposal, policy, evaluation_time)
            proposal_digests[proposal_id] = request_digest
            decision = decisions[proposal_id]
            expected_decision_fields = {
                "decision_id", "proposal_id", "decision", "reason", "request_digest", "evaluated_at"
            }
            if decision.get("decision") != expected_decision or decision.get("reason") != expected_reason:
                check_id = "AAI-001" if expected_reason == "schema-invalid" else "AAI-003"
                findings[check_id].append(f"{proposal_id} decision does not match the independent policy")
            if decision.get("request_digest") != request_digest:
                findings["AAI-002"].append(f"{proposal_id} decision request digest mismatch")
            if expected_decision == "allow":
                expected_allowed.add(proposal_id)
            action = policy.get("actions", {}).get(proposal.get("action_id"), {})
            if expected_decision == "allow" and action.get("authorization") == "PSB-AI-004-bound-single-use":
                expected_decision_fields.add("authorization")
                authorization = decision.get("authorization")
                valid = isinstance(authorization, dict)
                if valid:
                    try:
                        issued = parse_time(authorization.get("issued_at"), f"{proposal_id} authorization issue")
                        expires = parse_time(authorization.get("expires_at"), f"{proposal_id} authorization expiry")
                        consumed = parse_time(authorization.get("consumed_at"), f"{proposal_id} authorization consumption")
                        lifetime = (expires - issued).total_seconds()
                    except ValueError:
                        valid = False
                        lifetime = -1
                        consumed = evaluation_time
                    valid = valid and (
                        set(authorization) == {
                            "control_id", "status", "authorization_id", "request_digest",
                            "policy_sha256", "issued_at", "expires_at", "single_use",
                            "consumed", "consumed_at"
                        }
                        and authorization.get("control_id") == "PSB-AI-004"
                        and authorization.get("status") == "authorized"
                        and isinstance(authorization.get("authorization_id"), str)
                        and bool(authorization.get("authorization_id"))
                        and authorization.get("request_digest") == request_digest
                        and authorization.get("policy_sha256") == next(
                            item["sha256"] for item in policy["cross_control_bindings"] if item["control_id"] == "PSB-AI-004"
                        )
                        and authorization.get("single_use") is True
                        and authorization.get("consumed") is True
                        and issued <= evaluation_time < expires
                        and issued <= consumed <= evaluation_time
                        and 0 < lifetime <= policy.get("maximum_authorization_lifetime_seconds", 0)
                    )
                if not valid:
                    findings["AAI-004"].append(f"{proposal_id} authorization is missing stale reused or not request-bound")
            if set(decision) != expected_decision_fields or decision.get("evaluated_at") != policy.get("evaluation_time"):
                findings["AAI-003"].append(f"{proposal_id} decision schema or evaluation time is invalid")

        if set(executions) != expected_allowed:
            raise ValueError("execution evidence is incomplete or contains denied proposal identities")
        execution_by_id: dict[str, dict[str, Any]] = {}
        for proposal_id, execution in sorted(executions.items()):
            proposal = proposals[proposal_id]
            action = policy["actions"][proposal["action_id"]]
            execution_id = execution.get("execution_id")
            if not isinstance(execution_id, str) or execution_id in execution_by_id:
                raise ValueError("execution identity is missing or duplicated")
            execution_by_id[execution_id] = execution
            if set(execution) != {
                "execution_id", "proposal_id", "decision_id", "request_digest", "target",
                "parameters_sha256", "attempt", "dispatched_at", "idempotency_key_sha256",
                "result_id"
            }:
                findings["AAI-005"].append(f"{proposal_id} execution envelope contains an unexpected field")
            dispatched_at = evaluation_time
            try:
                dispatched_at = parse_time(execution.get("dispatched_at"), f"{proposal_id} dispatch")
                dispatch_delay = (dispatched_at - evaluation_time).total_seconds()
                if dispatch_delay < 0 or dispatch_delay > policy.get("maximum_dispatch_delay_seconds", 0):
                    findings["AAI-005"].append(f"{proposal_id} execution is outside the decision freshness window")
            except ValueError:
                findings["AAI-005"].append(f"{proposal_id} execution dispatch time is invalid")
            if (
                execution.get("decision_id") != decisions[proposal_id].get("decision_id")
                or execution.get("request_digest") != proposal_digests[proposal_id]
                or execution.get("target") != proposal.get("target")
                or execution.get("parameters_sha256") != canonical_digest(proposal.get("parameters"))
            ):
                findings["AAI-005"].append(f"{proposal_id} execution changed after decision")
            idempotency = proposal["parameters"].get("idempotency_key")
            expected_key_digest = sha256_bytes(idempotency.encode("utf-8")) if isinstance(idempotency, str) else None
            if execution.get("attempt") != 1 or execution.get("idempotency_key_sha256") != expected_key_digest:
                findings["AAI-006"].append(f"{proposal_id} dispatch attempt or idempotency identity is invalid")
            if action.get("idempotency") == "required":
                authorization = decisions[proposal_id].get("authorization", {})
                try:
                    consumed_at = parse_time(authorization.get("consumed_at"), f"{proposal_id} authorization consumption")
                    if consumed_at > dispatched_at:
                        findings["AAI-004"].append(f"{proposal_id} authorization was not consumed before dispatch")
                except ValueError:
                    findings["AAI-004"].append(f"{proposal_id} authorization consumption time is invalid")
                replay = replay_decisions.get(proposal_id)
                if not isinstance(replay, dict) or not (
                    set(replay) == {"proposal_id", "request_digest", "attempt", "decision", "reason"}
                    and replay.get("request_digest") == proposal_digests[proposal_id]
                    and replay.get("attempt") == 2
                    and replay.get("decision") == "deny"
                    and replay.get("reason") == "idempotency-key-already-dispatched"
                ):
                    findings["AAI-006"].append(f"{proposal_id} replay was not denied")
        if set(replay_decisions) != {"ACT-T002"}:
            raise ValueError("replay decision coverage is incomplete or contains unknown identities")
        if set(results) != set(execution_by_id):
            raise ValueError("result evidence is incomplete or contains unknown execution identities")

        for execution_id, result in sorted(results.items()):
            execution = execution_by_id[execution_id]
            proposal = proposals[execution["proposal_id"]]
            action = policy["actions"][proposal["action_id"]]
            if (
                result.get("result_id") != execution.get("result_id")
                or result.get("request_digest") != execution.get("request_digest")
                or result.get("resource_identity") != execution.get("target")
                or result.get("schema_version") != action.get("result_schema")
                or result.get("status") not in {"succeeded", "unknown"}
            ):
                findings["AAI-007"].append(f"{execution_id} result schema or identity is invalid")
            if result.get("status") == "succeeded":
                if set(result) != {
                    "result_id", "execution_id", "request_digest", "schema_version",
                    "status", "resource_identity", "output"
                }:
                    findings["AAI-007"].append(f"{execution_id} successful result contains an unexpected field")
                output = result.get("output")
                if not isinstance(output, dict) or set(output) != {"result_count", "resource_ids_sha256"} or not exact_type(output.get("result_count"), "integer") or not exact_type(output.get("resource_ids_sha256"), "sha256"):
                    findings["AAI-007"].append(f"{execution_id} successful result payload is malformed")
            if result.get("status") == "unknown":
                if set(result) != {
                    "result_id", "execution_id", "request_digest", "schema_version", "status",
                    "resource_identity", "outcome_state", "decision", "automatic_retry",
                    "authorization_restored"
                }:
                    findings["AAI-007"].append(f"{execution_id} unknown result contains an unexpected field")
                uncertain = policy.get("uncertain_outcome", {})
                if not (
                    result.get("outcome_state") == "unknown"
                    and result.get("decision") == uncertain.get("decision")
                    and result.get("automatic_retry") is uncertain.get("automatic_retry")
                    and result.get("authorization_restored") is uncertain.get("restore_authorization")
                    and "output" not in result
                ):
                    findings["AAI-008"].append(f"{execution_id} uncertain outcome was retried trusted or released")
        if evidence.get("live_enforcement") != "NOT_CHECKED":
            findings["AAI-010"].append("synthetic evidence overclaims live enforcement")

        for check_id, description in CHECKS.items():
            if findings[check_id]:
                print(f"FAIL {check_id} {description}")
            else:
                print(f"PASS {check_id} {description}")
        if any(findings.values()):
            return 1
        print("NOT_CHECKED live provider execution gateway and external side effects require adopted evidence")
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(f"ERROR {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
