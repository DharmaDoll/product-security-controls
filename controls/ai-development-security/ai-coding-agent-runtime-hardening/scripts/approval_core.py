"""Provider-neutral PSB-AI-004 approval evaluation primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-high-impact-policy/v1"
REQUEST_SCHEMA = "psb-ai-action-request/v1"
APPROVAL_SCHEMA = "psb-ai-action-approval/v1"
REPLAY_SCHEMA = "psb-ai-approval-replay-state/v1"
VALIDATION_SCHEMA = "psb-ai-approval-validation-state/v1"

REQUEST_BINDING_FIELDS = (
    "actor_id",
    "agent_id",
    "action_class",
    "tool",
    "operation",
    "target",
    "parameters",
    "policy_id",
    "policy_revision",
)
REQUIRED_ACTION_CLASSES = {
    "dependency-installation",
    "source-commit",
    "source-publication",
    "source-history-rewrite",
    "package-publication",
    "database-mutation",
    "infrastructure-change",
    "cloud-administration",
    "deployment",
}


class EvaluationError(Exception):
    """Approval evidence could not be evaluated safely."""


@dataclass(frozen=True)
class ApprovalEvaluation:
    request_id: str
    approval_id: str
    request_digest: str
    action_class: str
    classified: bool
    binding_ok: bool
    time_ok: bool
    replay_ok: bool
    issuer_ok: bool

    @property
    def passed(self) -> bool:
        return all(
            (
                self.classified,
                self.binding_ok,
                self.time_ok,
                self.replay_ok,
                self.issuer_ok,
            )
        )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is missing") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return value


def require_schema(value: dict[str, Any], expected: str, label: str) -> None:
    if value.get("schema_version") != expected:
        raise EvaluationError(f"{label} schema is unsupported")


def require_string(value: dict[str, Any], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise EvaluationError(f"{label} {key} is missing or invalid")
    return item


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvaluationError(f"{label} timestamp is missing or invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise EvaluationError(f"{label} timestamp is missing or invalid") from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{label} timestamp is missing or invalid")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_request_digest(request: dict[str, Any]) -> str:
    payload: dict[str, Any] = {}
    for field in REQUEST_BINDING_FIELDS:
        if field not in request:
            raise EvaluationError(f"action request {field} is missing")
        payload[field] = request[field]
    if not isinstance(payload["target"], dict) or not isinstance(
        payload["parameters"], dict
    ):
        raise EvaluationError("action request target or parameters are invalid")
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def action_class_index(policy: dict[str, Any]) -> dict[tuple[str, str], str]:
    classes = policy.get("action_classes")
    if not isinstance(classes, dict) or not classes:
        raise EvaluationError("high-impact action classes are missing")
    if not REQUIRED_ACTION_CLASSES.issubset(classes):
        raise EvaluationError("required high-impact action classes are incomplete")
    index: dict[tuple[str, str], str] = {}
    for class_name, matchers in classes.items():
        if (
            not isinstance(class_name, str)
            or not class_name
            or not isinstance(matchers, list)
            or not matchers
        ):
            raise EvaluationError("high-impact action class is malformed")
        for matcher in matchers:
            if not isinstance(matcher, dict):
                raise EvaluationError("high-impact action matcher is malformed")
            tool = matcher.get("tool")
            operations = matcher.get("operations")
            if (
                not isinstance(tool, str)
                or not tool
                or not isinstance(operations, list)
                or not operations
                or not all(isinstance(item, str) and item for item in operations)
                or len(operations) != len(set(operations))
            ):
                raise EvaluationError("high-impact action operations are malformed")
            for operation in operations:
                pair = (tool, operation)
                if pair in index:
                    raise EvaluationError(
                        "high-impact action classification is ambiguous"
                    )
                index[pair] = class_name
    return index


def classify_action(policy: dict[str, Any], request: dict[str, Any]) -> tuple[bool, str]:
    tool = require_string(request, "tool", "action request")
    operation = require_string(request, "operation", "action request")
    declared = require_string(request, "action_class", "action request")
    resolved = action_class_index(policy).get((tool, operation))
    return resolved is not None and resolved == declared, declared


def validate_policy_identity(
    runtime_policy: dict[str, Any],
    approval_policy: dict[str, Any],
    request: dict[str, Any],
) -> None:
    require_schema(approval_policy, POLICY_SCHEMA, "high-impact policy")
    policy_id = require_string(approval_policy, "policy_id", "high-impact policy")
    revision = require_string(
        approval_policy, "policy_revision", "high-impact policy"
    )
    if request.get("policy_id") != policy_id:
        raise EvaluationError("action request policy_id is unsupported")
    if request.get("policy_revision") != revision:
        raise EvaluationError("action request policy_revision is unsupported")
    if runtime_policy.get("high_impact_approval") != approval_policy:
        raise EvaluationError("high-impact policy could not be resolved")


def evaluate_approval(
    runtime_policy: dict[str, Any],
    request: dict[str, Any],
    approval: dict[str, Any],
    replay: dict[str, Any],
    validation: dict[str, Any],
    now_text: str,
) -> ApprovalEvaluation:
    approval_policy = runtime_policy.get("high_impact_approval")
    if not isinstance(approval_policy, dict):
        raise EvaluationError("runtime policy has no high-impact approval policy")
    require_schema(request, REQUEST_SCHEMA, "action request")
    require_schema(approval, APPROVAL_SCHEMA, "action approval")
    require_schema(replay, REPLAY_SCHEMA, "approval replay state")
    require_schema(validation, VALIDATION_SCHEMA, "approval validation state")
    validate_policy_identity(runtime_policy, approval_policy, request)

    if validation.get("available") is not True:
        raise EvaluationError("approval validator is unavailable")
    trusted_issuers = validation.get("trusted_issuers")
    if not isinstance(trusted_issuers, list) or not all(
        isinstance(item, str) for item in trusted_issuers
    ):
        raise EvaluationError("approval validator trusted issuers are malformed")

    request_id = require_string(request, "request_id", "action request")
    approval_id = require_string(approval, "approval_id", "action approval")
    require_string(approval, "approver_id", "action approval")
    require_string(approval, "issuer", "action approval")
    digest = canonical_request_digest(request)
    classified, action_class = classify_action(approval_policy, request)

    required_fields = approval_policy.get("required_binding_fields")
    if not isinstance(required_fields, list) or not all(
        isinstance(item, str) for item in required_fields
    ):
        raise EvaluationError("required approval binding fields are malformed")
    fields_present = all(field in approval for field in required_fields)
    fields_match = fields_present and all(
        approval.get(field) == request.get(field) for field in REQUEST_BINDING_FIELDS
    )
    digest_matches = isinstance(approval.get("request_digest"), str) and (
        hmac.compare_digest(approval["request_digest"], digest)
    )
    independent = (
        approval_policy.get("require_independent_approver") is True
        and approval.get("approver_id") != request.get("actor_id")
    )
    binding_ok = fields_match and digest_matches and independent

    issued = parse_timestamp(approval.get("issued_at"), "approval issued_at")
    expires = parse_timestamp(approval.get("expires_at"), "approval expires_at")
    now = parse_timestamp(now_text, "evaluation now")
    maximum_ttl = approval_policy.get("maximum_ttl_seconds")
    if not isinstance(maximum_ttl, int) or maximum_ttl <= 0:
        raise EvaluationError("maximum approval TTL is invalid")
    lifetime = (expires - issued).total_seconds()
    time_ok = (
        approval.get("decision") == "approved"
        and 0 < lifetime <= maximum_ttl
        and issued <= now < expires
    )

    used_ids = replay.get("used_approval_ids")
    used_digests = replay.get("used_request_digests")
    if (
        not isinstance(used_ids, list)
        or not all(isinstance(item, str) for item in used_ids)
        or not isinstance(used_digests, list)
        or not all(isinstance(item, str) for item in used_digests)
    ):
        raise EvaluationError("approval replay state is malformed")
    replay_ok = approval_id not in used_ids and digest not in used_digests

    return ApprovalEvaluation(
        request_id=request_id,
        approval_id=approval_id,
        request_digest=digest,
        action_class=action_class,
        classified=classified,
        binding_ok=binding_ok,
        time_ok=time_ok,
        replay_ok=replay_ok,
        issuer_ok=approval.get("issuer") in trusted_issuers,
    )
