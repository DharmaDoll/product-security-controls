#!/usr/bin/env python3
"""Verify adopted fleet telemetry ingestion and alert delivery offline."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-fleet-telemetry-policy/v1"
EVIDENCE_SCHEMA = "psb-ai-fleet-telemetry-evidence/v1"
EVIDENCE_FIELDS = {
    "schema_version",
    "profile",
    "collector_available",
    "captured_at",
    "endpoints",
    "ingestion",
    "alerts",
}
ENDPOINT_FIELDS = {
    "provider",
    "enrollment_status",
    "managed",
    "export_enabled",
    "last_export_at",
    "last_ingested_at",
    "sequence_gap",
    "rejected_records",
    "quarantine_accounted",
}
INGESTION_FIELDS = {
    "available",
    "immutable_to_developers",
    "access_controlled",
    "content_classification",
    "event_fields",
    "forbidden_fields_present",
}
ALERT_FIELDS = {
    "rule_id",
    "enabled",
    "test_status",
    "tested_at",
    "delivery_latency_seconds",
    "receipt_verified",
}


class EvaluationError(Exception):
    """Fleet telemetry evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Result:
    surface: str
    passed: bool
    pass_reason: str
    fail_reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        reason = self.pass_reason if self.passed else self.fail_reason
        return (
            f"{status} PSB-AI-004/AAR-025 "
            f"surface={self.surface} {reason}"
        )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is unavailable") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be an object")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvaluationError(f"{label} is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{label} has no timezone")
    return parsed.astimezone(timezone.utc)


def require_string_set(policy: dict[str, Any], field: str) -> set[str]:
    values = policy.get(field)
    if not isinstance(values, list) or not values or not all(
        isinstance(value, str) for value in values
    ):
        raise EvaluationError("fleet telemetry policy is malformed")
    return set(values)


def require_positive_int(policy: dict[str, Any], field: str) -> int:
    value = policy.get(field)
    if not isinstance(value, int) or value < 1:
        raise EvaluationError("fleet telemetry timing policy is malformed")
    return value


def require_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if (
        policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("required_enrollment_status") != "enrolled"
        or policy.get("required_content_classification") != "metadata-only"
    ):
        raise EvaluationError("fleet telemetry policy is unsafe")
    required_providers = require_string_set(policy, "required_providers")
    required_alerts = require_string_set(policy, "required_alert_rules")
    allowed_fields = require_string_set(policy, "allowed_event_fields")
    forbidden_fields = require_string_set(policy, "forbidden_content_fields")
    if required_providers != {"claude-code", "codex"} or required_alerts != {
        "unknown-extension",
        "hook-failure",
        "audit-sink-failure",
        "gateway-bypass",
        "approval-replay",
        "reconciliation-unknown",
        "command-broker-bypass",
    }:
        raise EvaluationError("fleet telemetry coverage policy is incomplete")
    if allowed_fields & forbidden_fields:
        raise EvaluationError("fleet telemetry field policy conflicts")
    return {
        "required_providers": required_providers,
        "required_alerts": required_alerts,
        "allowed_fields": allowed_fields,
        "forbidden_fields": forbidden_fields,
        "maximum_snapshot_age": require_positive_int(
            policy, "maximum_snapshot_age_seconds"
        ),
        "maximum_ingestion_lag": require_positive_int(
            policy, "maximum_ingestion_lag_seconds"
        ),
        "maximum_alert_test_age": require_positive_int(
            policy, "maximum_alert_test_age_seconds"
        ),
        "maximum_alert_delivery_latency": require_positive_int(
            policy, "maximum_alert_delivery_latency_seconds"
        ),
        "required_enrollment_status": policy["required_enrollment_status"],
        "required_content_classification": policy[
            "required_content_classification"
        ],
    }


def load_endpoints(
    evidence: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    values = evidence.get("endpoints")
    if not isinstance(values, list):
        raise EvaluationError("fleet endpoint evidence is malformed")
    endpoints: dict[str, dict[str, Any]] = {}
    for endpoint in values:
        if (
            not isinstance(endpoint, dict)
            or set(endpoint) != ENDPOINT_FIELDS
            or endpoint.get("provider") not in {"claude-code", "codex"}
            or endpoint["provider"] in endpoints
        ):
            raise EvaluationError("fleet endpoint evidence is malformed")
        for field in (
            "managed",
            "export_enabled",
            "sequence_gap",
            "quarantine_accounted",
        ):
            if not isinstance(endpoint.get(field), bool):
                raise EvaluationError("fleet endpoint state is malformed")
        if (
            not isinstance(endpoint.get("enrollment_status"), str)
            or not isinstance(endpoint.get("rejected_records"), int)
            or endpoint["rejected_records"] < 0
        ):
            raise EvaluationError("fleet endpoint state is malformed")
        parse_time(endpoint.get("last_export_at"), "last export time")
        parse_time(endpoint.get("last_ingested_at"), "last ingestion time")
        endpoints[endpoint["provider"]] = endpoint
    return endpoints


def endpoint_result(
    provider: str,
    endpoint: dict[str, Any] | None,
    policy: dict[str, Any],
    now: datetime,
) -> Result:
    passed = False
    if endpoint is not None:
        exported = parse_time(endpoint["last_export_at"], "last export time")
        ingested = parse_time(endpoint["last_ingested_at"], "last ingestion time")
        lag = (ingested - exported).total_seconds()
        age = (now - ingested).total_seconds()
        passed = all(
            (
                endpoint["enrollment_status"]
                == policy["required_enrollment_status"],
                endpoint["managed"],
                endpoint["export_enabled"],
                not endpoint["sequence_gap"],
                endpoint["rejected_records"] == 0
                or endpoint["quarantine_accounted"],
                0 <= lag <= policy["maximum_ingestion_lag"],
                0 <= age <= policy["maximum_snapshot_age"],
            )
        )
    return Result(
        provider,
        passed,
        "managed endpoint export is enrolled fresh complete and gap-free",
        "endpoint enrollment export freshness or sequence evidence is incomplete",
    )


def ingestion_result(
    evidence: dict[str, Any], policy: dict[str, Any]
) -> Result:
    ingestion = evidence.get("ingestion")
    if not isinstance(ingestion, dict) or set(ingestion) != INGESTION_FIELDS:
        raise EvaluationError("central ingestion evidence is malformed")
    if ingestion.get("available") is not True:
        raise EvaluationError("central ingestion verification is unavailable")
    event_fields = ingestion.get("event_fields")
    forbidden_present = ingestion.get("forbidden_fields_present")
    if (
        not isinstance(event_fields, list)
        or not all(isinstance(value, str) for value in event_fields)
        or not isinstance(forbidden_present, list)
        or not all(isinstance(value, str) for value in forbidden_present)
    ):
        raise EvaluationError("central ingestion field evidence is malformed")
    passed = all(
        (
            ingestion.get("immutable_to_developers") is True,
            ingestion.get("access_controlled") is True,
            ingestion.get("content_classification")
            == policy["required_content_classification"],
            set(event_fields) == policy["allowed_fields"],
            not forbidden_present,
            not (set(event_fields) & policy["forbidden_fields"]),
        )
    )
    return Result(
        "central-ingestion",
        passed,
        "central evidence is immutable access-controlled and metadata-only",
        "central evidence storage or content classification is unsafe",
    )


def alert_result(
    evidence: dict[str, Any],
    policy: dict[str, Any],
    now: datetime,
) -> Result:
    values = evidence.get("alerts")
    if not isinstance(values, list):
        raise EvaluationError("alert delivery evidence is malformed")
    alerts: dict[str, dict[str, Any]] = {}
    for alert in values:
        if (
            not isinstance(alert, dict)
            or set(alert) != ALERT_FIELDS
            or not isinstance(alert.get("rule_id"), str)
            or alert["rule_id"] in alerts
            or not isinstance(alert.get("enabled"), bool)
            or not isinstance(alert.get("receipt_verified"), bool)
            or not isinstance(alert.get("delivery_latency_seconds"), int)
            or alert["delivery_latency_seconds"] < 0
        ):
            raise EvaluationError("alert delivery evidence is malformed")
        tested = parse_time(alert.get("tested_at"), "alert test time")
        alert["test_age_seconds"] = (now - tested).total_seconds()
        alerts[alert["rule_id"]] = alert
    passed = set(alerts) == policy["required_alerts"] and all(
        (
            alert["enabled"],
            alert.get("test_status") == "delivered",
            alert["receipt_verified"],
            0 <= alert["test_age_seconds"] <= policy["maximum_alert_test_age"],
            alert["delivery_latency_seconds"]
            <= policy["maximum_alert_delivery_latency"],
        )
        for alert in alerts.values()
    )
    return Result(
        "alert-pipeline",
        passed,
        "all required synthetic alerts delivered within the reviewed window",
        "required alert coverage enablement freshness or delivery is incomplete",
    )


def evaluate(
    policy_document: dict[str, Any],
    evidence: dict[str, Any],
    now: datetime,
) -> list[Result]:
    policy = require_policy(policy_document)
    if set(evidence) != EVIDENCE_FIELDS:
        raise EvaluationError("fleet telemetry evidence fields are malformed")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvaluationError("fleet telemetry evidence schema is unsupported")
    if evidence.get("collector_available") is not True:
        raise EvaluationError("fleet collector is unavailable")
    captured = parse_time(evidence.get("captured_at"), "fleet snapshot time")
    if not 0 <= (now - captured).total_seconds() <= policy[
        "maximum_snapshot_age"
    ]:
        raise EvaluationError("fleet snapshot is stale or from the future")
    endpoints = load_endpoints(evidence)
    results = [
        endpoint_result(provider, endpoints.get(provider), policy, now)
        for provider in sorted(policy["required_providers"])
    ]
    results.append(ingestion_result(evidence, policy))
    results.append(alert_result(evidence, policy, now))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--now", default="2026-07-29T12:02:00Z")
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "fleet telemetry policy")
        evidence = load_json(args.evidence, "fleet telemetry evidence")
        if isinstance(evidence.get("profile"), str):
            profile = evidence["profile"]
        results = evaluate(
            policy,
            evidence,
            parse_time(args.now, "fleet assessment time"),
        )
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004/AAR-025 "
            f"profile={profile} fleet telemetry evaluation failed: {error}"
        )
        print(f"RESULT ERROR profile={profile} checks=0 failures=1")
        return 2
    for result in results:
        print(result.render())
    failures = sum(not result.passed for result in results)
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} profile={profile} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
