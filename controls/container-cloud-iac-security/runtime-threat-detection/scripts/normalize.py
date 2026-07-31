#!/usr/bin/env python3
"""Normalize Falco and Sysdig runtime policy events without retaining raw output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class AdapterError(ValueError):
    """Provider event input cannot be normalized safely."""

    def __init__(self, message: str, check_id: str = "RTD-009") -> None:
        super().__init__(message)
        self.check_id = check_id


def _read(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AdapterError(f"cannot read {label}") from error


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must be an object")
    return value


def _text(value: dict[str, Any], key: str, label: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise AdapterError(f"{label}.{key} must be non-empty text")
    return result


def _integer(value: dict[str, Any], key: str, label: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool) or result < 1:
        raise AdapterError(f"{label}.{key} must be a positive integer")
    return result


def _normalized_event(
    *,
    provider: str,
    event_id: str,
    observed_at: str,
    rule_id: str,
    category: str,
    severity: str,
    sequence: int,
    fields: dict[str, Any],
) -> dict[str, Any]:
    required_fields = {
        "psb.cluster": "cluster",
        "k8s.ns.name": "namespace",
        "psb.workload.kind": "workload_kind",
        "psb.workload.name": "workload_name",
        "k8s.pod.uid": "pod_uid",
        "container.full_id": "container_id",
        "container.image.digest": "image_digest",
        "psb.admission_policy_version": "admission_policy_version",
    }
    identity: dict[str, str] = {}
    for provider_field, normalized_field in required_fields.items():
        value = fields.get(provider_field)
        if not isinstance(value, str) or not value:
            raise AdapterError(
                f"{provider} event identity field {provider_field} is missing",
                "RTD-002",
            )
        identity[normalized_field] = value
    return {
        "schema": "psb-runtime-event/1.0",
        "provider": provider,
        "event_id": event_id,
        "observed_at": observed_at,
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "sequence": sequence,
        "identity": identity,
    }


def normalize_falco(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(_read(path, "Falco events").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = _object(json.loads(line), f"Falco event line {line_number}")
        except json.JSONDecodeError as error:
            raise AdapterError(
                f"Falco event line {line_number} is malformed"
            ) from error
        fields = _object(raw.get("output_fields"), "Falco output_fields")
        event_id = _text(fields, "psb.event_id", "Falco output_fields")
        rule_id = _text(fields, "psb.rule_id", "Falco output_fields")
        category = _text(fields, "psb.category", "Falco output_fields")
        sequence = _integer(fields, "psb.sequence", "Falco output_fields")
        events.append(
            _normalized_event(
                provider="falco",
                event_id=event_id,
                observed_at=_text(raw, "time", "Falco event"),
                rule_id=rule_id,
                category=category,
                severity=_text(raw, "priority", "Falco event").upper(),
                sequence=sequence,
                fields=fields,
            )
        )
    return events


def normalize_sysdig(path: Path) -> list[dict[str, Any]]:
    try:
        raw_events = json.loads(_read(path, "Sysdig events"))
    except json.JSONDecodeError as error:
        raise AdapterError("Sysdig event batch is malformed") from error
    if not isinstance(raw_events, list):
        raise AdapterError("Sysdig event batch must be a JSON array")
    severity_names = {
        0: "HIGH",
        1: "HIGH",
        2: "HIGH",
        3: "HIGH",
        4: "MEDIUM",
        5: "LOW",
        6: "INFO",
        7: "INFO",
    }
    events: list[dict[str, Any]] = []
    for index, item in enumerate(raw_events):
        raw = _object(item, f"Sysdig event {index}")
        if raw.get("type") != "policy" or raw.get("category") != "runtime":
            raise AdapterError("Sysdig event is not a runtime policy event")
        content = _object(raw.get("content"), "Sysdig event content")
        fields = _object(content.get("fields"), "Sysdig event content.fields")
        severity = raw.get("severity")
        if severity not in severity_names:
            raise AdapterError("Sysdig event severity is unsupported")
        events.append(
            _normalized_event(
                provider="sysdig",
                event_id=_text(raw, "id", "Sysdig event"),
                observed_at=_text(raw, "timestampRFC3339Nano", "Sysdig event"),
                rule_id=_text(fields, "psb.rule_id", "Sysdig content.fields"),
                category=_text(fields, "psb.category", "Sysdig content.fields"),
                severity=severity_names[severity],
                sequence=_integer(fields, "psb.sequence", "Sysdig content.fields"),
                fields=fields,
            )
        )
    return events


def normalize(provider: str, path: Path) -> list[dict[str, Any]]:
    if provider == "falco":
        return normalize_falco(path)
    if provider == "sysdig":
        return normalize_sysdig(path)
    raise AdapterError(f"unsupported runtime provider {provider!r}", "RTD-001")
