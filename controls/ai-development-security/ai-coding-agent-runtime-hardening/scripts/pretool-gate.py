#!/usr/bin/env python3
"""Enforce PSB-AI-004 extension capabilities at a managed PreToolUse boundary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from approval_core import EvaluationError as ApprovalEvaluationError
from approval_core import canonical_request_digest
from approval_core import load_json as load_approval_json
from runtime_audit import AuditError, load_audit_policy, record_event
from signed_approval import (
    approval_envelope_path,
    authorize_and_consume,
    load_managed_actor,
    normalized_high_impact_request,
    utc_now_text,
)

POLICY_SCHEMA = "psb-ai-extension-capabilities/v1"
ENGINE_SCHEMA = "psb-ai-capability-engine-state/v1"
MCP_TOOL_NAME = re.compile(
    r"^mcp__(?P<extension>[A-Za-z0-9_-]{1,64})__(?P<tool>[A-Za-z0-9_-]{1,128})$"
)


class GateError(Exception):
    """The hook invocation could not be evaluated safely."""


@dataclass(frozen=True)
class GateDecision:
    decision: str
    reason: str
    reason_code: str
    request_ref: str | None = None
    approval_id: str | None = None


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"{label} is unavailable") from error
    if not isinstance(value, dict):
        raise GateError(f"{label} is not an object")
    return value


def load_event() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError("hook input is malformed") from error
    if not isinstance(value, dict):
        raise GateError("hook input is not an object")
    return value


def capability_policy(runtime_policy: dict[str, Any]) -> dict[str, Any]:
    policy = runtime_policy.get("extension_capabilities")
    if (
        not isinstance(policy, dict)
        or policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("default_decision") != "deny"
        or not isinstance(policy.get("extensions"), dict)
    ):
        raise GateError("capability policy is unavailable")
    return policy


def normalize_event(
    event: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    if event.get("hook_event_name") != "PreToolUse":
        raise GateError("hook event is unsupported")
    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")
    tool_use_id = event.get("tool_use_id")
    if (
        not isinstance(tool_name, str)
        or not isinstance(tool_input, dict)
        or not isinstance(tool_use_id, str)
        or not tool_use_id
    ):
        raise GateError("hook input fields are malformed")
    match = MCP_TOOL_NAME.fullmatch(tool_name)
    if match is None:
        raise GateError("hook tool name is unsupported")
    return match["extension"], match["tool"], tool_input


def bounded_write_matches(tool: dict[str, Any], arguments: dict[str, Any]) -> bool:
    constraints = tool.get("constraints")
    if not isinstance(constraints, dict):
        raise GateError("bounded-write policy is malformed")
    maximum_body_bytes = constraints.get("maximum_body_bytes")
    body = arguments.get("body")
    idempotency_key = arguments.get("idempotency_key")
    valid_body = (
        isinstance(body, str)
        and isinstance(maximum_body_bytes, int)
        and maximum_body_bytes >= 0
        and len(body.encode("utf-8")) <= maximum_body_bytes
    )
    valid_idempotency_key = (
        isinstance(idempotency_key, str)
        and bool(idempotency_key)
        and len(idempotency_key) <= 128
    )
    return all(
        (
            arguments.get("resource") == constraints.get("allowed_resource"),
            valid_body,
            constraints.get("require_idempotency_key") is True,
            valid_idempotency_key,
        )
    )


def evaluate(
    runtime_policy: dict[str, Any],
    engine_state: dict[str, Any],
    event: dict[str, Any],
) -> GateDecision:
    policy = capability_policy(runtime_policy)
    if (
        engine_state.get("schema_version") != ENGINE_SCHEMA
        or engine_state.get("available") is not True
    ):
        raise GateError("capability engine is unavailable")

    extension_id, tool_name, arguments = normalize_event(event)
    extension = policy["extensions"].get(extension_id)
    if not isinstance(extension, dict) or extension.get("kind") != "mcp":
        return GateDecision(
            "deny",
            "PSB-AI-004 denied an MCP invocation outside the reviewed inventory.",
            "unreviewed_extension",
        )
    tools = extension.get("tools")
    tool = tools.get(tool_name) if isinstance(tools, dict) else None
    if not isinstance(tool, dict):
        return GateDecision(
            "deny",
            "PSB-AI-004 denied an MCP invocation outside the reviewed tool set.",
            "unreviewed_tool",
        )

    effect = tool.get("effect")
    policy_decision = tool.get("decision")
    if effect == "bounded-reversible-write" and not bounded_write_matches(
        tool, arguments
    ):
        return GateDecision(
            "deny",
            "PSB-AI-004 denied an invocation whose bounded-write constraints did not match.",
            "bounded_write_mismatch",
        )
    if policy_decision == "allow" and effect in {
        "read-only",
        "bounded-reversible-write",
    }:
        return GateDecision(
            "allow",
            "PSB-AI-004 allowed an invocation matching the reviewed capability.",
            "reviewed_capability",
        )
    if (
        policy_decision == "require-bound-approval"
        and effect == "high-impact"
        and isinstance(tool.get("action_class"), str)
    ):
        action_classes = (
            runtime_policy.get("high_impact_approval", {}).get("action_classes")
        )
        if not isinstance(action_classes, dict) or tool["action_class"] not in action_classes:
            raise GateError("high-impact action policy is unavailable")
        return GateDecision(
            "require-bound-approval",
            "PSB-AI-004 requires the managed high-impact approval path.",
            "high_impact_approval_missing",
        )
    return GateDecision(
        "deny",
        "PSB-AI-004 denied an invocation prohibited by capability policy.",
        "prohibited_capability",
    )


def provider_output(provider: str, decision: GateDecision) -> dict[str, Any]:
    hook_output: dict[str, Any] = {"hookEventName": "PreToolUse"}
    if decision.decision in {"allow", "deny"}:
        hook_output["permissionDecision"] = decision.decision
        hook_output["permissionDecisionReason"] = decision.reason
        return {"hookSpecificOutput": hook_output}
    if provider == "claude-code":
        hook_output["permissionDecision"] = "ask"
        hook_output["permissionDecisionReason"] = decision.reason
        return {"hookSpecificOutput": hook_output}
    hook_output["permissionDecision"] = "deny"
    hook_output["permissionDecisionReason"] = decision.reason
    return {"hookSpecificOutput": hook_output}


def authorize_high_impact(
    runtime_policy: dict[str, Any],
    provider: str,
    event: dict[str, Any],
    actor_state: Path | None,
    approval_dir: Path | None,
    approval_trust: Path | None,
    approval_ledger: Path | None,
    openssl_path: Path,
    now_text: str,
) -> GateDecision:
    if any(
        value is None
        for value in (
            actor_state,
            approval_dir,
            approval_trust,
            approval_ledger,
        )
    ):
        raise GateError("signed approval integration is unavailable")
    try:
        actor_id = load_managed_actor(actor_state)
        request = normalized_high_impact_request(
            runtime_policy,
            provider,
            event,
            actor_id,
        )
        envelope_path = approval_envelope_path(approval_dir, request)
        if envelope_path is None:
            return GateDecision(
                "deny",
                "PSB-AI-004 requires a signed approval bound to this exact request.",
                "high_impact_approval_missing",
                canonical_request_digest(request),
            )
        result = authorize_and_consume(
            runtime_policy,
            request,
            load_approval_json(envelope_path, "signed approval envelope"),
            approval_trust,
            approval_ledger,
            openssl_path,
            now_text,
        )
    except ApprovalEvaluationError as error:
        raise GateError("signed approval evaluation failed") from error
    if result.allowed:
        return GateDecision(
            "allow",
            "PSB-AI-004 authenticated and consumed one exact bound approval.",
            "signed_approval_consumed",
            result.request_digest,
            result.approval_id,
        )
    return GateDecision(
        "deny",
        "PSB-AI-004 denied invalid expired or previously consumed approval evidence.",
        "signed_approval_invalid",
        result.request_digest,
        result.approval_id,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply the PSB-AI-004 managed PreToolUse capability gate."
    )
    parser.add_argument(
        "--provider", choices=("claude-code", "codex"), required=True
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--engine-state", type=Path, required=True)
    parser.add_argument("--actor-state", type=Path)
    parser.add_argument("--approval-dir", type=Path)
    parser.add_argument("--approval-trust", type=Path)
    parser.add_argument("--approval-ledger", type=Path)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    parser.add_argument("--audit-policy", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--now")
    args = parser.parse_args()

    now_text = args.now or utc_now_text()
    event: dict[str, Any] = {}
    audit_policy: dict[str, Any] | None = None
    try:
        audit_policy = load_audit_policy(args.audit_policy)
        event = load_event()
        runtime_policy = load_json(args.policy.resolve(), "runtime policy")
        decision = evaluate(
            runtime_policy,
            load_json(args.engine_state.resolve(), "capability engine state"),
            event,
        )
        if decision.decision == "require-bound-approval":
            decision = authorize_high_impact(
                runtime_policy,
                args.provider,
                event,
                args.actor_state,
                args.approval_dir,
                args.approval_trust,
                args.approval_ledger,
                args.openssl,
                now_text,
            )
        record_event(
            audit_policy,
            args.audit_log,
            args.provider,
            event,
            decision.decision,
            decision.reason_code,
            now_text,
            decision.request_ref,
            decision.approval_id,
        )
        print(
            json.dumps(
                provider_output(args.provider, decision),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except (AuditError, GateError):
        if audit_policy is not None:
            try:
                record_event(
                    audit_policy,
                    args.audit_log,
                    args.provider,
                    event,
                    "error",
                    "evaluation_error",
                    now_text,
                )
            except (AuditError, ApprovalEvaluationError):
                pass
        print(
            "PSB-AI-004 hook ERROR: capability evaluation unavailable; tool call blocked.",
            file=sys.stderr,
        )
        return 2
    except Exception:
        if audit_policy is not None:
            try:
                record_event(
                    audit_policy,
                    args.audit_log,
                    args.provider,
                    event,
                    "error",
                    "evaluation_error",
                    now_text,
                )
            except (AuditError, ApprovalEvaluationError):
                pass
        print(
            "PSB-AI-004 hook ERROR: unexpected evaluator failure; tool call blocked.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
