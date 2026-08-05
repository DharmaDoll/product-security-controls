#!/usr/bin/env python3
"""Verify deterministic AI agent resource budgets, anomaly rules, and breakers."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CHECKS = {
    "ARB-001": "telemetry contract and complete session identities are verified",
    "ARB-002": "input output and total token budgets are enforced",
    "ARB-003": "integer micro-unit cost budget is enforced",
    "ARB-004": "wall-clock session duration is bounded",
    "ARB-005": "tool-call and high-impact action budgets are enforced",
    "ARB-006": "automatic retry count is bounded",
    "ARB-007": "single-agent recursion depth is bounded",
    "ARB-008": "security anomaly thresholds trigger blocking",
    "ARB-009": "warning restriction circuit breaker and alerts are enforced",
    "ARB-010": "evidence is complete sanitized and evaluator-backed",
    "ARB-011": "fixture leaves live provider enforcement explicitly NOT_CHECKED",
}
HARD_FORBIDDEN = {
    "prompt", "raw_prompt", "transcript", "tool_input", "arguments",
    "parameters", "target", "body", "tool_output", "credential",
    "secret_value", "token", "private_url",
}
SESSION_FIELDS = {
    "session_id", "provider", "started_at", "observed_at", "first_sequence",
    "last_sequence", "event_count", "measurements", "decision", "enforcement",
}
MEASUREMENT_FIELDS = {
    "input_tokens", "output_tokens", "cost_currency", "cost_microunits",
    "tool_calls", "high_impact_actions", "retries", "maximum_recursion_depth",
    "unknown_tool_denials", "approval_replays", "hook_failures",
}
DECISION_FIELDS = {"decision", "reasons", "breaker_state", "permitted_mode", "evaluated_at"}
ENFORCEMENT_FIELDS = {
    "applied", "applied_at", "new_model_calls_allowed", "side_effects_allowed",
    "safe_summary_allowed",
}
ALERT_FIELDS = {
    "session_id", "rule_ids", "status", "emitted_at", "delivered_at",
    "delivery_latency_seconds", "receipt_verified",
}


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unavailable or malformed: {exc.__class__.__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} path is missing")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} path escapes its trust root") from exc
    if not path.is_file():
        raise ValueError(f"{label} is unavailable")
    return path


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


def load_evidence(path: Path, control_root: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    document = load_json(path, "resource evidence")
    if document.get("schema_version") != "psb-ai-resource-budget-insecure-overlay/v1":
        return document, None
    if set(document) != {
        "schema_version", "evidence_id", "source_type", "base_evidence_path",
        "base_evidence_sha256", "session_overrides", "alert_overrides",
    }:
        raise ValueError("insecure evidence overlay schema is malformed")
    base_path = resolve(control_root, document.get("base_evidence_path"), "insecure base evidence")
    if sha256(base_path) != document.get("base_evidence_sha256"):
        raise ValueError("insecure base evidence digest mismatch")
    evidence = copy.deepcopy(load_json(base_path, "insecure base evidence"))
    sessions = keyed(evidence.get("sessions"), "session_id", "base session")
    overrides = keyed(document.get("session_overrides"), "session_id", "session override")
    expected_overrides = set(sessions) - {"SESSION-NORMAL"}
    if set(overrides) != expected_overrides:
        raise ValueError("insecure session override coverage is incomplete")
    for session_id, override in overrides.items():
        if set(override) != {"session_id", "decision", "enforcement"}:
            raise ValueError("insecure session override schema is malformed")
        sessions[session_id]["decision"] = override["decision"]
        sessions[session_id]["enforcement"] = override["enforcement"]
    alerts = keyed(evidence.get("alerts"), "session_id", "base alert")
    alert_overrides = keyed(document.get("alert_overrides"), "session_id", "alert override")
    if set(alert_overrides) != set(alerts):
        raise ValueError("insecure alert override coverage is incomplete")
    for session_id, override in alert_overrides.items():
        if set(override) != {
            "session_id", "status", "delivered_at", "delivery_latency_seconds",
            "receipt_verified",
        }:
            raise ValueError("insecure alert override schema is malformed")
        alerts[session_id].update({key: value for key, value in override.items() if key != "session_id"})
    evidence["evidence_id"] = document["evidence_id"]
    evidence["source_type"] = document["source_type"]
    return evidence, document


def positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_policy(repository_root: Path, policy: dict[str, Any]) -> tuple[dict[str, int], set[str]]:
    if policy.get("schema_version") != "psb-ai-resource-budget-policy/v1":
        raise ValueError("resource budget policy schema is unsupported")
    binding = policy.get("telemetry_contract_binding", {})
    path = resolve(repository_root, binding.get("path"), "PSB-AI-004 telemetry policy")
    if sha256(path) != binding.get("sha256"):
        raise ValueError("PSB-AI-004 telemetry policy binding digest mismatch")
    upstream = load_json(path, "PSB-AI-004 telemetry policy")
    if (
        binding.get("control_id") != "PSB-AI-004"
        or upstream.get("policy_id") != binding.get("policy_id")
        or upstream.get("schema_version") != binding.get("schema_version")
    ):
        raise ValueError("PSB-AI-004 telemetry policy binding identity mismatch")
    providers = set(upstream.get("required_providers", []))
    if providers != {"claude-code", "codex"}:
        raise ValueError("PSB-AI-004 provider telemetry coverage is incomplete")
    budget = policy.get("budget")
    required_budget = {
        "maximum_input_tokens", "maximum_output_tokens", "maximum_total_tokens",
        "cost_currency", "maximum_cost_microunits", "maximum_duration_seconds",
        "maximum_tool_calls", "maximum_high_impact_actions", "maximum_retries",
        "maximum_recursion_depth", "warning_percent",
    }
    if not isinstance(budget, dict) or set(budget) != required_budget:
        raise ValueError("resource budget policy is malformed")
    numeric = {key: value for key, value in budget.items() if key != "cost_currency"}
    if not all(positive_int(value) for value in numeric.values()) or not 1 <= budget["warning_percent"] < 100:
        raise ValueError("resource budget values are unsafe")
    if not isinstance(budget.get("cost_currency"), str) or not budget["cost_currency"]:
        raise ValueError("resource cost currency is malformed")
    expected_anomalies = {"unknown_tool_denials", "approval_replays", "hook_failures"}
    rules = policy.get("anomaly_rules")
    if not isinstance(rules, dict) or set(rules) != expected_anomalies:
        raise ValueError("anomaly rule coverage is incomplete")
    for rule in rules.values():
        if not isinstance(rule, dict) or set(rule) != {"threshold", "reason"} or not positive_int(rule.get("threshold")) or not isinstance(rule.get("reason"), str):
            raise ValueError("anomaly rule is malformed")
    required_scenarios = policy.get("required_scenarios")
    if not isinstance(required_scenarios, list) or len(required_scenarios) != len(set(required_scenarios)):
        raise ValueError("required scenario policy is malformed")
    return budget, providers


def expected_outcome(session: dict[str, Any], policy: dict[str, Any], budget: dict[str, int]) -> tuple[str, list[str], str, str, int]:
    measurements = session["measurements"]
    started = parse_time(session.get("started_at"), f"{session.get('session_id')} start")
    observed = parse_time(session.get("observed_at"), f"{session.get('session_id')} observation")
    duration = int((observed - started).total_seconds())
    if duration < 0:
        raise ValueError(f"{session.get('session_id')} duration is negative")
    reasons: list[str] = []
    if measurements["input_tokens"] > budget["maximum_input_tokens"]:
        reasons.append("input-token-limit")
    if measurements["output_tokens"] > budget["maximum_output_tokens"]:
        reasons.append("output-token-limit")
    total_tokens = measurements["input_tokens"] + measurements["output_tokens"]
    if total_tokens > budget["maximum_total_tokens"]:
        reasons.append("total-token-limit")
    comparisons = (
        ("cost_microunits", "maximum_cost_microunits", "cost-limit"),
        ("tool_calls", "maximum_tool_calls", "tool-call-limit"),
        ("high_impact_actions", "maximum_high_impact_actions", "high-impact-action-limit"),
        ("retries", "maximum_retries", "retry-limit"),
        ("maximum_recursion_depth", "maximum_recursion_depth", "recursion-limit"),
    )
    for measurement, maximum, reason in comparisons:
        if measurements[measurement] > budget[maximum]:
            reasons.append(reason)
    if duration > budget["maximum_duration_seconds"]:
        reasons.append("duration-limit")
    for measurement, rule in policy["anomaly_rules"].items():
        if measurements[measurement] >= rule["threshold"]:
            reasons.append(rule["reason"])
    if reasons:
        state = policy["decision_policy"]["limit_or_anomaly"]
        return state["decision"], sorted(reasons), state["breaker_state"], state["permitted_mode"], duration
    warning_values = (
        (measurements["input_tokens"], budget["maximum_input_tokens"]),
        (measurements["output_tokens"], budget["maximum_output_tokens"]),
        (total_tokens, budget["maximum_total_tokens"]),
        (measurements["cost_microunits"], budget["maximum_cost_microunits"]),
        (duration, budget["maximum_duration_seconds"]),
        (measurements["tool_calls"], budget["maximum_tool_calls"]),
        (measurements["high_impact_actions"], budget["maximum_high_impact_actions"]),
        (measurements["retries"], budget["maximum_retries"]),
        (measurements["maximum_recursion_depth"], budget["maximum_recursion_depth"]),
    )
    if any(value * 100 >= maximum * budget["warning_percent"] for value, maximum in warning_values):
        state = policy["decision_policy"]["warning"]
        return state["decision"], ["budget-warning"], state["breaker_state"], state["permitted_mode"], duration
    state = policy["decision_policy"]["within_budget"]
    return state["decision"], ["within-budget"], state["breaker_state"], state["permitted_mode"], duration


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        repository_root = args.repository_root.resolve()
        control_root = args.control_root.resolve()
        policy = load_json(args.policy, "resource budget policy")
        evidence, overlay = load_evidence(args.evidence, control_root)
        forbidden = set(policy.get("evidence", {}).get("forbidden_fields", [])) | HARD_FORBIDDEN
        for label, document in (("resource evidence", evidence), ("insecure overlay", overlay)):
            if document is not None:
                found = forbidden_field(document, forbidden)
                if found:
                    raise ValueError(f"{label} contains forbidden evidence field {found}")
        budget, providers = validate_policy(repository_root, policy)
        if set(evidence) != {
            "schema_version", "evidence_id", "source_type", "collection_status",
            "evaluator_status", "captured_at", "policy_id", "policy_revision",
            "collector_health", "sessions", "alerts", "live_enforcement",
        } or evidence.get("schema_version") != "psb-ai-resource-budget-evidence/v1":
            raise ValueError("resource evidence schema is unsupported")
        if evidence.get("collection_status") != "complete":
            raise ValueError("resource evidence collection is incomplete")
        if evidence.get("evaluator_status") != "completed":
            raise ValueError("resource budget evaluator is unavailable")
        if evidence.get("source_type") != policy.get("evidence", {}).get("required_source"):
            raise ValueError("resource evidence source is untrusted")
        if evidence.get("policy_id") != policy.get("policy_id") or evidence.get("policy_revision") != policy.get("policy_revision"):
            raise ValueError("resource evidence policy identity mismatch")
        evaluation_time = parse_time(policy.get("evaluation_time"), "policy evaluation")
        captured_at = parse_time(evidence.get("captured_at"), "evidence capture")
        age = (evaluation_time - captured_at).total_seconds()
        if age < 0 or age > policy.get("maximum_snapshot_age_seconds", 0):
            raise ValueError("resource evidence snapshot is stale or future-dated")
        health = evidence.get("collector_health")
        if not isinstance(health, dict) or set(health) != {"available", "complete", "sequence_gap", "rejected_records", "providers"}:
            raise ValueError("resource collector health is malformed")
        if not (
            health.get("available") is True
            and health.get("complete") is True
            and health.get("sequence_gap") is False
            and health.get("rejected_records") == 0
            and set(health.get("providers", [])) == providers
        ):
            raise ValueError("resource telemetry collection is unavailable or incomplete")
        sessions = keyed(evidence.get("sessions"), "session_id", "session")
        required_sessions = set(policy.get("required_scenarios", []))
        if set(sessions) != required_sessions:
            raise ValueError("resource scenario coverage is incomplete or contains unknown identities")
        alerts = keyed(evidence.get("alerts"), "session_id", "alert")
        findings: dict[str, list[str]] = {check_id: [] for check_id in CHECKS}
        expected_alerts: dict[str, list[str]] = {}
        for session_id, session in sorted(sessions.items()):
            if set(session) != SESSION_FIELDS or session.get("provider") not in providers:
                raise ValueError(f"{session_id} session schema or provider is malformed")
            if not all(nonnegative_int(session.get(field)) for field in ("first_sequence", "last_sequence", "event_count")):
                raise ValueError(f"{session_id} sequence evidence is malformed")
            if session["first_sequence"] < 1 or session["last_sequence"] - session["first_sequence"] + 1 != session["event_count"]:
                raise ValueError(f"{session_id} sequence coverage is incomplete")
            measurements = session.get("measurements")
            if not isinstance(measurements, dict) or set(measurements) != MEASUREMENT_FIELDS:
                raise ValueError(f"{session_id} measurements are malformed")
            for field in MEASUREMENT_FIELDS - {"cost_currency"}:
                if not nonnegative_int(measurements.get(field)):
                    raise ValueError(f"{session_id} measurement value is malformed")
            if measurements.get("cost_currency") != budget["cost_currency"]:
                raise ValueError(f"{session_id} cost currency is unsupported")
            expected_decision, expected_reasons, expected_breaker, expected_mode, _ = expected_outcome(session, policy, budget)
            decision = session.get("decision")
            if not isinstance(decision, dict) or set(decision) != DECISION_FIELDS or not isinstance(decision.get("reasons"), list):
                raise ValueError(f"{session_id} decision evidence is malformed")
            decision_time = parse_time(decision.get("evaluated_at"), f"{session_id} decision")
            observed_at = parse_time(session.get("observed_at"), f"{session_id} observation")
            decision_matches = (
                decision.get("decision") == expected_decision
                and decision.get("reasons") == expected_reasons
                and decision.get("breaker_state") == expected_breaker
                and decision.get("permitted_mode") == expected_mode
                and observed_at <= decision_time <= evaluation_time
            )
            reason_checks = {
                "ARB-002": {"input-token-limit", "output-token-limit", "total-token-limit"},
                "ARB-003": {"cost-limit"},
                "ARB-004": {"duration-limit"},
                "ARB-005": {"tool-call-limit", "high-impact-action-limit"},
                "ARB-006": {"retry-limit"},
                "ARB-007": {"recursion-limit"},
                "ARB-008": {"unknown-tool-denial-spike", "approval-replay", "hook-failure"},
            }
            for check_id, reasons in reason_checks.items():
                if reasons & set(expected_reasons) and not decision_matches:
                    findings[check_id].append(f"{session_id} required resource or anomaly decision was not enforced")
            enforcement = session.get("enforcement")
            if not isinstance(enforcement, dict) or set(enforcement) != ENFORCEMENT_FIELDS:
                raise ValueError(f"{session_id} enforcement evidence is malformed")
            applied_at = parse_time(enforcement.get("applied_at"), f"{session_id} enforcement")
            expected_permissions = {
                "continue": (True, True),
                "restrict": (True, False),
                "block": (False, False),
            }[expected_decision]
            enforcement_matches = (
                enforcement.get("applied") is True
                and enforcement.get("new_model_calls_allowed") is expected_permissions[0]
                and enforcement.get("side_effects_allowed") is expected_permissions[1]
                and enforcement.get("safe_summary_allowed") is True
                and decision_time <= applied_at <= evaluation_time
            )
            if not decision_matches or not enforcement_matches:
                findings["ARB-009"].append(f"{session_id} breaker decision or enforcement does not match policy")
            if expected_decision in set(policy.get("alert_policy", {}).get("required_for_decisions", [])):
                expected_alerts[session_id] = expected_reasons
        if set(alerts) != set(expected_alerts):
            findings["ARB-009"].append("required alert coverage is incomplete or contains unknown sessions")
        for session_id, expected_reasons in sorted(expected_alerts.items()):
            alert = alerts.get(session_id)
            if not isinstance(alert, dict) or set(alert) != ALERT_FIELDS:
                findings["ARB-009"].append(f"{session_id} alert evidence is unavailable or malformed")
                continue
            delivered = alert.get("delivered_at")
            latency = alert.get("delivery_latency_seconds")
            valid = (
                alert.get("rule_ids") == expected_reasons
                and alert.get("status") == "delivered"
                and alert.get("receipt_verified") is True
                and nonnegative_int(latency)
                and latency <= policy["alert_policy"]["maximum_delivery_latency_seconds"]
            )
            try:
                emitted_at = parse_time(alert.get("emitted_at"), f"{session_id} alert emission")
                delivered_at = parse_time(delivered, f"{session_id} alert delivery")
                valid = valid and int((delivered_at - emitted_at).total_seconds()) == latency and delivered_at <= evaluation_time
            except ValueError:
                valid = False
            if not valid:
                findings["ARB-009"].append(f"{session_id} alert was not delivered with a valid receipt")
        if evidence.get("live_enforcement") != "NOT_CHECKED":
            findings["ARB-011"].append("synthetic evidence overclaims live provider enforcement")
        for check_id, description in CHECKS.items():
            status = "FAIL" if findings[check_id] else "PASS"
            print(f"{status} {check_id} {description}")
        if any(findings.values()):
            return 1
        print("NOT_CHECKED live provider usage collector budget gateway circuit breaker and receiver require adopted evidence")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
