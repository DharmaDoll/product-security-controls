#!/usr/bin/env python3
"""Evaluate runtime events, sensor health, alert delivery, and response policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from normalize import AdapterError, normalize


DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_EVIDENCE_FIELDS = [
    "check_id",
    "provider",
    "rule_id",
    "category",
    "event_id",
    "decision",
]
FORBIDDEN_EVIDENCE_FIELDS = [
    "command",
    "arguments",
    "file_content",
    "network_payload",
    "raw_output",
    "credential",
]
CHECK_BY_CATEGORY = {
    "process": "RTD-003",
    "file": "RTD-004",
    "privilege": "RTD-005",
    "runtime-boundary": "RTD-006",
    "network": "RTD-007",
    "resource": "RTD-008",
}


class EvaluationError(RuntimeError):
    """Runtime security state cannot be evaluated reliably."""

    def __init__(self, message: str, check_id: str = "RTD-009") -> None:
        super().__init__(message)
        self.check_id = check_id


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"cannot load {label}") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return value


def object_at(
    value: dict[str, Any], key: str, label: str, check_id: str = "RTD-009"
) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise EvaluationError(f"{label}.{key} must be an object", check_id)
    return child


def text_at(
    value: dict[str, Any], key: str, label: str, check_id: str = "RTD-009"
) -> str:
    child = value.get(key)
    if not isinstance(child, str) or not child:
        raise EvaluationError(f"{label}.{key} must be non-empty text", check_id)
    return child


def parse_time(value: Any, label: str, check_id: str) -> datetime:
    if not isinstance(value, str):
        raise EvaluationError(f"{label} must be an RFC3339 timestamp", check_id)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError(
            f"{label} must be an RFC3339 timestamp", check_id
        ) from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{label} must include a timezone", check_id)
    return parsed


def require_digest(value: Any, label: str, check_id: str = "RTD-001") -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise EvaluationError(f"{label} must be an exact SHA-256", check_id)
    return value


def check_fresh(
    value: Any,
    label: str,
    as_of: datetime,
    maximum_age: timedelta,
    check_id: str,
) -> None:
    observed = parse_time(value, label, check_id)
    if observed > as_of or as_of - observed > maximum_age:
        raise EvaluationError(f"{label} is stale or from the future", check_id)


def validate_policy(policy: dict[str, Any], provider: str) -> tuple[dict[str, Any], dict[str, str]]:
    if policy.get("schema") != "psb-runtime-threat-policy/1.0":
        raise EvaluationError("unsupported runtime policy schema", "RTD-001")
    maximum_age = policy.get("maximum_signal_age_seconds")
    if not isinstance(maximum_age, int) or isinstance(maximum_age, bool) or maximum_age <= 0:
        raise EvaluationError(
            "maximum_signal_age_seconds must be a positive integer", "RTD-009"
        )
    providers = object_at(policy, "providers", "policy", "RTD-001")
    provider_policy = object_at(providers, provider, "policy.providers", "RTD-001")
    for field in ("sensor_artifact_sha256", "config_sha256", "ruleset_sha256"):
        require_digest(provider_policy.get(field), f"provider policy {field}")
    required_rules = policy.get("required_rules")
    if not isinstance(required_rules, list) or not required_rules:
        raise EvaluationError("policy.required_rules must be a non-empty list")
    rule_categories: dict[str, str] = {}
    for index, rule in enumerate(required_rules):
        if not isinstance(rule, dict):
            raise EvaluationError(f"policy.required_rules[{index}] must be an object")
        rule_id = text_at(rule, "id", f"policy.required_rules[{index}]")
        category = text_at(rule, "category", f"policy.required_rules[{index}]")
        if category not in CHECK_BY_CATEGORY:
            raise EvaluationError(
                f"policy.required_rules[{index}] has unsupported category {category!r}"
            )
        if rule_id in rule_categories:
            raise EvaluationError(f"duplicate required runtime rule {rule_id!r}")
        rule_categories[rule_id] = category
    return provider_policy, rule_categories


def validate_health(
    health: dict[str, Any],
    provider: str,
    provider_policy: dict[str, Any],
    required_rules: dict[str, str],
    as_of: datetime,
    maximum_age: timedelta,
) -> tuple[int, int, int]:
    if health.get("schema") != "psb-runtime-sensor-health/1.0":
        raise EvaluationError("unsupported sensor health schema")
    for field in ("provider", "adapter_contract", "sensor_release"):
        if health.get(field) != provider_policy.get(field):
            raise EvaluationError(
                f"sensor health {field} does not match provider policy", "RTD-001"
            )
    if health.get("provider") != provider:
        raise EvaluationError("sensor health provider does not match adapter", "RTD-001")
    for field in ("sensor_artifact_sha256", "config_sha256", "ruleset_sha256"):
        actual = require_digest(health.get(field), f"health.{field}")
        if actual != provider_policy.get(field):
            raise EvaluationError(
                f"sensor health {field} does not match provider policy", "RTD-001"
            )
    check_fresh(health.get("observed_at"), "health.observed_at", as_of, maximum_age, "RTD-009")
    status = object_at(health, "status", "health")
    if (
        status.get("running") is not True
        or status.get("connected") is not True
        or status.get("licensed") is not True
    ):
        raise EvaluationError("runtime sensor is not healthy connected and licensed")
    enabled = health.get("enabled_rule_ids")
    if not isinstance(enabled, list) or set(enabled) != set(required_rules):
        raise EvaluationError("runtime sensor required rule inventory is incomplete")
    telemetry = object_at(health, "telemetry", "health")
    values: dict[str, int] = {}
    for field in (
        "batch_first_sequence",
        "batch_last_sequence",
        "batch_event_count",
        "events_dropped",
        "output_dropped",
    ):
        value = telemetry.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise EvaluationError(f"health.telemetry.{field} must be a non-negative integer")
        values[field] = value
    if values["events_dropped"] != 0 or values["output_dropped"] != 0:
        raise EvaluationError("runtime telemetry reports dropped events or alerts")
    source_metrics = object_at(health, "source_metrics", "health")
    if provider == "falco":
        for field in (
            "scap.n_drops",
            "falco.outputs_queue_num_drops",
            "falco.n_store_evts_drops",
        ):
            if source_metrics.get(field) != 0:
                raise EvaluationError(f"Falco metric {field} is non-zero")
    elif provider == "sysdig":
        if (
            source_metrics.get("sysdig_agent_healthy") != 1
            or source_metrics.get("sysdig_agent_connected") != 1
            or source_metrics.get("sysdig_agent_unlicensed") != 0
            or source_metrics.get("sysdig_agent_analyzer_dropped_evts") != 0
            or source_metrics.get("event_forwarding_status") != "CONNECTED"
        ):
            raise EvaluationError("Sysdig agent or event forwarding health is not clean")
    return (
        values["batch_first_sequence"],
        values["batch_last_sequence"],
        values["batch_event_count"],
    )


def validate_delivery(
    delivery: dict[str, Any], policy: dict[str, Any], as_of: datetime, maximum_age: timedelta
) -> None:
    if delivery.get("schema") != "psb-runtime-alert-delivery/1.0":
        raise EvaluationError("unsupported alert delivery schema", "RTD-010")
    alert_policy = object_at(policy, "alert_delivery", "policy", "RTD-010")
    if (
        delivery.get("receiver_id") != alert_policy.get("receiver_id")
        or delivery.get("owned_by") != alert_policy.get("owned_by")
        or delivery.get("delivered") is not True
        or delivery.get("tls_verified") is not True
        or delivery.get("authentication") != "signature"
        or delivery.get("failed_deliveries") != 0
    ):
        raise EvaluationError("runtime alert receiver delivery is not verified", "RTD-010")
    check_fresh(
        delivery.get("observed_at"),
        "delivery.observed_at",
        as_of,
        maximum_age,
        "RTD-010",
    )


def validate_response(
    response: dict[str, Any], policy: dict[str, Any]
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if response.get("schema") != "psb-runtime-response-policy/1.0":
        raise EvaluationError("unsupported response policy schema", "RTD-011")
    if (
        response.get("mode") != "authorization-bound-dry-run"
        or response.get("automatic_destructive_actions") is not False
        or response.get("require_independent_authorization") is not True
        or response.get("preserve_evidence_before_action") is not True
    ):
        findings.append(
            ("RTD-011", "response handoff is not authorization-bound and evidence-preserving")
        )
    evidence = object_at(policy, "evidence", "policy", "RTD-012")
    if (
        evidence.get("allowed_fields") != EXPECTED_EVIDENCE_FIELDS
        or evidence.get("forbidden_fields") != FORBIDDEN_EVIDENCE_FIELDS
        or evidence.get("include_raw_provider_event") is not False
    ):
        findings.append(("RTD-012", "runtime evidence policy is not sanitized"))
    return findings


def validate_events(
    events: list[dict[str, Any]],
    identity: dict[str, Any],
    required_rules: dict[str, str],
    sequence: tuple[int, int, int],
    as_of: datetime,
    maximum_age: timedelta,
) -> list[tuple[str, str, str]]:
    first, last, count = sequence
    if count != len(events):
        raise EvaluationError("sensor event count does not match normalized batch")
    expected_sequences = list(range(first, last + 1)) if count else []
    actual_sequences = [event.get("sequence") for event in events]
    if (
        (count == 0 and (first != 0 or last != 0))
        or (count > 0 and last - first + 1 != count)
        or actual_sequences != expected_sequences
    ):
        raise EvaluationError("runtime event sequence is incomplete or out of order")
    seen_ids: set[str] = set()
    detections: list[tuple[str, str, str]] = []
    expected_identity = object_at(identity, "identity", "workload identity", "RTD-002")
    if not IMAGE_DIGEST_RE.fullmatch(str(expected_identity.get("image_digest", ""))):
        raise EvaluationError("workload identity image digest is not immutable", "RTD-002")
    for event in events:
        event_id = text_at(event, "event_id", "normalized event")
        if event_id in seen_ids:
            raise EvaluationError("runtime event ID is duplicated")
        seen_ids.add(event_id)
        check_fresh(
            event.get("observed_at"),
            "event.observed_at",
            as_of,
            maximum_age,
            "RTD-009",
        )
        if event.get("identity") != expected_identity:
            raise EvaluationError(
                "runtime event is not bound to the expected workload and image digest",
                "RTD-002",
            )
        rule_id = text_at(event, "rule_id", "normalized event")
        category = text_at(event, "category", "normalized event")
        if required_rules.get(rule_id) != category:
            raise EvaluationError("runtime event rule or category is not in reviewed policy")
        detections.append((rule_id, category, event_id))
    return detections


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("falco", "sysdig"), required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--workload-identity", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--health", type=Path, required=True)
    parser.add_argument("--alert-delivery", type=Path, required=True)
    parser.add_argument("--response-policy", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    try:
        as_of = parse_time(args.as_of, "--as-of", "RTD-009")
        policy = load_json(args.policy, "runtime policy")
        identity = load_json(args.workload_identity, "workload identity")
        health = load_json(args.health, "sensor health")
        delivery = load_json(args.alert_delivery, "alert delivery")
        response = load_json(args.response_policy, "response policy")
        if identity.get("schema") != "psb-runtime-workload-identity/1.0":
            raise EvaluationError("unsupported workload identity schema", "RTD-002")
        provider_policy, required_rules = validate_policy(policy, args.provider)
        maximum_age = timedelta(seconds=policy["maximum_signal_age_seconds"])
        sequence = validate_health(
            health,
            args.provider,
            provider_policy,
            required_rules,
            as_of,
            maximum_age,
        )
        validate_delivery(delivery, policy, as_of, maximum_age)
        response_findings = validate_response(response, policy)
        events = normalize(args.provider, args.events)
        detections = validate_events(
            events,
            identity,
            required_rules,
            sequence,
            as_of,
            maximum_age,
        )
    except AdapterError as error:
        print(f"ERROR {error.check_id} runtime evaluation unavailable: {error}")
        print("RESULT ERROR; absence of events is not clean")
        return 2
    except EvaluationError as error:
        print(f"ERROR {error.check_id} runtime evaluation unavailable: {error}")
        print("RESULT ERROR; absence of events is not clean")
        return 2

    for check_id, finding in response_findings:
        print(f"FAIL {check_id} {finding}")
    for rule_id, category, _ in detections:
        print(
            f"DETECTED {CHECK_BY_CATEGORY[category]} "
            f"provider={args.provider} rule={rule_id} category={category}"
        )
    total = len(response_findings) + len(detections)
    if total:
        print(f"RESULT DETECTED_OR_BLOCKED {total} finding(s); response handoff required")
        return 1
    print("PASS RTD-001 provider adapter and sensor identity verified")
    print("PASS RTD-002 exact workload and image binding ready")
    print("PASS RTD-009 sensor health sequence and zero-drop telemetry verified")
    print("PASS RTD-010 alert receiver delivery verified")
    print("PASS RTD-011 authorization-bound response verified")
    print("PASS RTD-012 runtime evidence policy is sanitized")
    print("RESULT CLEAN no runtime policy events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
