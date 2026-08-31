#!/usr/bin/env python3
"""Reconcile sanitized external observations with an approved asset inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-external-attack-surface-policy/v1"
INVENTORY_SCHEMA = "psb-external-attack-surface-inventory/v1"
OBSERVATION_SCHEMA = "psb-external-attack-surface-observations/v1"
STATE_SCHEMA = "psb-external-attack-surface-state/v1"
HASH_ID_RE = re.compile(r"^[a-z][a-z0-9-]*@sha256:[0-9a-f]{64}$")
SCOPE_ID_RE = re.compile(r"^external-surface@sha256:[0-9a-f]{64}$")
ROOT_ID_RE = re.compile(r"^ROOT-[A-Z0-9][A-Z0-9-]{2,62}$")
ASSET_ID_RE = re.compile(r"^AST-[A-Z0-9][A-Z0-9-]{2,62}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
EXPECTED_SOURCES = {
    "certificate-transparency",
    "https-metadata",
    "public-dns",
}
EXPECTED_RELATIONSHIPS = {"delegated-service", "owned-name"}
EXPECTED_FORBIDDEN_FIELDS = {
    "authorization",
    "banner",
    "body",
    "credential",
    "email",
    "header",
    "password",
    "secret",
    "snippet",
    "token",
}
EXPECTED_ALLOWED_OUTPUT_FIELDS = {"asset_id", "fingerprint", "reason", "state"}
MAX_DOCUMENT_BYTES = 1024 * 1024


class EvidenceError(ValueError):
    """The result cannot be established from trustworthy evidence."""


class PolicyFinding(ValueError):
    """A policy setting weakens the safe reconnaissance boundary."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("JSON contains duplicate object keys")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise EvidenceError(f"{label} exceeds the size limit")
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except EvidenceError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} cannot be loaded or parsed") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} root must be an object")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise EvidenceError(f"{label} fields are incomplete or unsupported")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be a list")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc)


def exact_id(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise EvidenceError(f"{label} has invalid immutable identity")
    return value


def safe_label(value: Any, label: str) -> str:
    if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
        raise EvidenceError(f"{label} is not a safe stable label")
    return value


def normalize_domain(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EvidenceError(f"{label} is not a normalized domain")
    if any(character in value for character in "/*:@?#\\"):
        raise EvidenceError(f"{label} is not a normalized domain")
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise EvidenceError(f"{label} is not a normalized domain") from exc
    labels = normalized.split(".")
    if normalized != value or len(labels) < 2 or len(normalized) > 253:
        raise EvidenceError(f"{label} is not a normalized domain")
    for part in labels:
        if (
            not part
            or len(part) > 63
            or part.startswith("-")
            or part.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", part)
        ):
            raise EvidenceError(f"{label} is not a normalized domain")
    return normalized


def find_forbidden_key(value: Any, path: str = "root") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in EXPECTED_FORBIDDEN_FIELDS:
                return f"{path}.{key}"
            found = find_forbidden_key(child, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = find_forbidden_key(child, f"{path}[{index}]")
            if found:
                return found
    return None


def ensure_age(timestamp: datetime, now: datetime, maximum: int, label: str) -> None:
    age = (now - timestamp).total_seconds()
    if age < 0:
        raise EvidenceError(f"{label} is from the future")
    if age > maximum:
        raise EvidenceError(f"{label} is stale")


def under_root(name: str, root: str) -> bool:
    return name == root or name.endswith(f".{root}")


def observation_fingerprint(name: str) -> str:
    return hashlib.sha256(f"hostname:v1:{name}".encode("utf-8")).hexdigest()


def validate_policy(policy: dict[str, Any]) -> tuple[datetime, dict[str, str]]:
    require_exact_keys(
        policy,
        {
            "active_validation",
            "as_of",
            "asset_review_max_days",
            "inventory_max_age_seconds",
            "observation_max_age_seconds",
            "output",
            "owned_roots",
            "policy_id",
            "required_relationships",
            "required_sources",
            "root_review_max_days",
            "schema",
            "state",
        },
        "policy",
    )
    if policy.get("schema") != POLICY_SCHEMA:
        raise EvidenceError("policy schema is unsupported")
    exact_id(policy.get("policy_id"), HASH_ID_RE, "policy.policy_id")
    now = parse_time(policy.get("as_of"), "policy.as_of")
    for field in ("inventory_max_age_seconds", "observation_max_age_seconds"):
        maximum = policy.get(field)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 60 <= maximum <= 86400:
            raise PolicyFinding("evidence-freshness-policy-is-weakened")
    for field, maximum in (("asset_review_max_days", 90), ("root_review_max_days", 365)):
        days = policy.get(field)
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= maximum:
            raise PolicyFinding("review-expiry-policy-is-weakened")
    source_policy = require_list(policy.get("required_sources"), "policy.required_sources")
    if len(source_policy) != len(set(source_policy)) or set(source_policy) != EXPECTED_SOURCES:
        raise PolicyFinding("required-observation-sources-are-incomplete")
    relationship_policy = require_list(policy.get("required_relationships"), "policy.required_relationships")
    if len(relationship_policy) != len(set(relationship_policy)) or set(relationship_policy) != EXPECTED_RELATIONSHIPS:
        raise PolicyFinding("asset-relationship-policy-is-incomplete")

    active = require_object(policy.get("active_validation"), "policy.active_validation")
    require_exact_keys(
        active,
        {
            "allow_login_attempts",
            "allow_third_party_ip_scanning",
            "allow_vulnerability_probes",
            "allowed_ports",
            "allowed_protocols",
        },
        "policy.active_validation",
    )
    expected_active = {
        "allow_login_attempts": False,
        "allow_third_party_ip_scanning": False,
        "allow_vulnerability_probes": False,
        "allowed_ports": [443],
        "allowed_protocols": ["dns", "https-metadata"],
    }
    if active != expected_active:
        raise PolicyFinding("unsafe-active-validation-policy")

    state_policy = require_object(policy.get("state"), "policy.state")
    require_exact_keys(
        state_policy,
        {"require_external_reobservation_for_closure", "require_reappearance_detection"},
        "policy.state",
    )
    if state_policy != {
        "require_external_reobservation_for_closure": True,
        "require_reappearance_detection": True,
    }:
        raise PolicyFinding("finding-state-policy-is-weakened")

    output = require_object(policy.get("output"), "policy.output")
    require_exact_keys(output, {"allowed_fields", "forbidden_fields"}, "policy.output")
    allowed_fields = require_list(output.get("allowed_fields"), "policy.output.allowed_fields")
    if len(allowed_fields) != len(set(allowed_fields)) or set(allowed_fields) != EXPECTED_ALLOWED_OUTPUT_FIELDS:
        raise PolicyFinding("output-allowlist-is-unsafe")
    forbidden_fields = require_list(output.get("forbidden_fields"), "policy.output.forbidden_fields")
    if len(forbidden_fields) != len(set(forbidden_fields)) or set(forbidden_fields) != EXPECTED_FORBIDDEN_FIELDS:
        raise PolicyFinding("output-redaction-policy-is-incomplete")

    roots: dict[str, str] = {}
    root_values: list[str] = []
    for index, raw_root in enumerate(require_list(policy.get("owned_roots"), "policy.owned_roots")):
        root = require_object(raw_root, f"policy.owned_roots[{index}]")
        require_exact_keys(
            root,
            {
                "id",
                "kind",
                "owner",
                "ownership_evidence",
                "review_expires_at",
                "reviewed_at",
                "value",
            },
            f"policy.owned_roots[{index}]",
        )
        root_id = exact_id(root.get("id"), ROOT_ID_RE, "owned root id")
        if root_id in roots or root.get("kind") != "domain":
            raise EvidenceError("owned root identity or kind is invalid")
        value = normalize_domain(root.get("value"), "owned root value")
        if any(under_root(value, existing) or under_root(existing, value) for existing in root_values):
            raise EvidenceError("owned roots overlap or duplicate")
        try:
            safe_label(root.get("owner"), "owned root owner")
        except EvidenceError:
            raise PolicyFinding("owned-root-owner-is-missing")
        exact_id(root.get("ownership_evidence"), HASH_ID_RE, "owned root ownership evidence")
        reviewed = parse_time(root.get("reviewed_at"), "owned root reviewed_at")
        expires = parse_time(root.get("review_expires_at"), "owned root review_expires_at")
        if reviewed > now or expires <= now:
            raise PolicyFinding("owned-root-review-is-not-current")
        if (expires - reviewed).total_seconds() > policy["root_review_max_days"] * 86400:
            raise PolicyFinding("owned-root-review-window-is-too-broad")
        roots[root_id] = value
        root_values.append(value)
    if not roots:
        raise EvidenceError("owned root inventory is empty")
    return now, roots


def validate_inventory(
    inventory: dict[str, Any], policy: dict[str, Any], now: datetime, roots: dict[str, str]
) -> tuple[str, dict[str, dict[str, Any]]]:
    require_exact_keys(
        inventory,
        {"assets", "collected_at", "inventory_id", "schema", "scope_id", "status"},
        "inventory",
    )
    if inventory.get("schema") != INVENTORY_SCHEMA:
        raise EvidenceError("inventory schema is unsupported")
    exact_id(inventory.get("inventory_id"), HASH_ID_RE, "inventory.inventory_id")
    scope_id = exact_id(inventory.get("scope_id"), SCOPE_ID_RE, "inventory.scope_id")
    if inventory.get("status") != "COMPLETE":
        raise EvidenceError("approved inventory is incomplete")
    ensure_age(
        parse_time(inventory.get("collected_at"), "inventory.collected_at"),
        now,
        policy["inventory_max_age_seconds"],
        "approved inventory",
    )

    assets: dict[str, dict[str, Any]] = {}
    asset_ids: set[str] = set()
    for index, raw_asset in enumerate(require_list(inventory.get("assets"), "inventory.assets")):
        asset = require_object(raw_asset, f"inventory.assets[{index}]")
        base_fields = {
            "asset_id",
            "environment",
            "expected_public",
            "expected_services",
            "name",
            "owner",
            "relationship",
            "review_expires_at",
            "reviewed_at",
            "root_id",
        }
        relationship = asset.get("relationship")
        expected_fields = base_fields | ({"delegated_target"} if relationship == "delegated-service" else set())
        require_exact_keys(asset, expected_fields, f"inventory.assets[{index}]")
        asset_id = exact_id(asset.get("asset_id"), ASSET_ID_RE, "asset id")
        name = normalize_domain(asset.get("name"), "asset name")
        root_id = asset.get("root_id")
        if root_id not in roots or not under_root(name, roots[root_id]):
            raise EvidenceError("asset is outside its verified owned root")
        if asset_id in asset_ids or name in assets:
            raise EvidenceError("approved inventory contains duplicate assets")
        if relationship not in EXPECTED_RELATIONSHIPS:
            raise EvidenceError("asset relationship is unsupported")
        try:
            safe_label(asset.get("owner"), "asset owner")
        except EvidenceError:
            raise PolicyFinding("approved-asset-owner-is-missing")
        safe_label(asset.get("environment"), "asset environment")
        if not isinstance(asset.get("expected_public"), bool):
            raise EvidenceError("asset expected_public state is invalid")
        services: set[tuple[str, int]] = set()
        for service_index, raw_service in enumerate(
            require_list(asset.get("expected_services"), "asset.expected_services")
        ):
            service = require_object(raw_service, f"asset.expected_services[{service_index}]")
            require_exact_keys(service, {"port", "protocol"}, "expected service")
            if service.get("protocol") != "https" or service.get("port") != 443:
                raise PolicyFinding("approved-inventory-permits-unsupported-public-service")
            services.add((service["protocol"], service["port"]))
        if len(services) != len(asset["expected_services"]):
            raise EvidenceError("asset expected services contain duplicates")
        if asset["expected_public"] is True and not services:
            raise EvidenceError("public asset has no expected service")
        if asset["expected_public"] is False and services:
            raise PolicyFinding("private-asset-has-public-service-policy")
        if relationship == "delegated-service":
            delegated = normalize_domain(asset.get("delegated_target"), "delegated target")
            if any(under_root(delegated, root) for root in roots.values()):
                raise EvidenceError("delegated target is not external to the owned roots")
        reviewed = parse_time(asset.get("reviewed_at"), "asset reviewed_at")
        expires = parse_time(asset.get("review_expires_at"), "asset review_expires_at")
        if reviewed > now or (expires - reviewed).total_seconds() > policy["asset_review_max_days"] * 86400:
            raise PolicyFinding("asset-review-window-is-invalid")
        normalized = dict(asset)
        normalized["name"] = name
        normalized["services"] = services
        normalized["review_expired"] = expires <= now
        assets[name] = normalized
        asset_ids.add(asset_id)
    return scope_id, assets


def validate_sources(
    observations: dict[str, Any], policy: dict[str, Any], now: datetime, observation_time: datetime
) -> None:
    sources: set[str] = set()
    for index, raw_source in enumerate(require_list(observations.get("sources"), "observations.sources")):
        source = require_object(raw_source, f"observations.sources[{index}]")
        require_exact_keys(source, {"collected_at", "complete", "id", "status", "window_id"}, "observation source")
        source_id = source.get("id")
        if source_id not in EXPECTED_SOURCES or source_id in sources:
            raise EvidenceError("observation source identity is missing duplicate or unsupported")
        if source.get("status") != "HEALTHY" or source.get("complete") is not True:
            raise EvidenceError("observation source is incomplete or unhealthy")
        exact_id(source.get("window_id"), HASH_ID_RE, "observation source window")
        source_time = parse_time(source.get("collected_at"), "observation source collected_at")
        if source_time > observation_time:
            raise EvidenceError("observation source time is later than the observation set")
        ensure_age(
            source_time,
            now,
            policy["observation_max_age_seconds"],
            "observation source",
        )
        sources.add(source_id)
    if sources != EXPECTED_SOURCES:
        raise EvidenceError("required observation source set is incomplete")


def validate_signal(signal: dict[str, Any]) -> tuple[str, tuple[str, int] | None, str | None]:
    source = signal.get("source")
    kind = signal.get("kind")
    if source == "certificate-transparency" and kind == "certificate-name":
        require_exact_keys(signal, {"kind", "record_id", "source"}, "certificate observation")
        exact_id(signal.get("record_id"), HASH_ID_RE, "certificate observation record")
        return source, None, None
    if source == "public-dns" and kind == "dns-record":
        record_type = signal.get("record_type")
        fields = {"kind", "record_id", "record_type", "source", "target_class"}
        if record_type == "CNAME":
            fields.add("target_name")
        require_exact_keys(signal, fields, "DNS observation")
        exact_id(signal.get("record_id"), HASH_ID_RE, "DNS observation record")
        if record_type not in {"A", "AAAA", "CNAME"}:
            raise EvidenceError("DNS observation record type is unsupported")
        if record_type == "CNAME":
            if signal.get("target_class") != "delegated-service":
                raise EvidenceError("CNAME target attribution is invalid")
            return source, None, normalize_domain(signal.get("target_name"), "CNAME target")
        if signal.get("target_class") not in {
            "address-redacted",
            "owned-infrastructure",
            "shared-infrastructure",
        }:
            raise EvidenceError("address target attribution is invalid")
        return source, None, None
    if source == "https-metadata" and kind == "https-service":
        require_exact_keys(
            signal,
            {"kind", "port", "protocol", "record_id", "source", "status_class", "tls"},
            "HTTPS observation",
        )
        exact_id(signal.get("record_id"), HASH_ID_RE, "HTTPS observation record")
        port = signal.get("port")
        status_class = signal.get("status_class")
        if (
            signal.get("protocol") != "https"
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not isinstance(status_class, int)
            or isinstance(status_class, bool)
            or status_class not in {1, 2, 3, 4, 5}
            or signal.get("tls") is not True
        ):
            raise EvidenceError("HTTPS observation metadata is invalid")
        return source, ("https", port), None
    raise EvidenceError("observation signal source or kind is unsupported")


def validate_observations(
    observations: dict[str, Any], policy: dict[str, Any], now: datetime, roots: dict[str, str], scope_id: str
) -> dict[str, dict[str, Any]]:
    require_exact_keys(
        observations,
        {"assets", "collected_at", "observation_set_id", "schema", "scope_id", "sources"},
        "observations",
    )
    if observations.get("schema") != OBSERVATION_SCHEMA:
        raise EvidenceError("observations schema is unsupported")
    exact_id(observations.get("observation_set_id"), HASH_ID_RE, "observations.observation_set_id")
    if observations.get("scope_id") != scope_id:
        raise EvidenceError("observations scope does not match the approved inventory")
    observation_time = parse_time(observations.get("collected_at"), "observations.collected_at")
    ensure_age(
        observation_time,
        now,
        policy["observation_max_age_seconds"],
        "observation set",
    )
    validate_sources(observations, policy, now, observation_time)

    candidates: dict[str, dict[str, Any]] = {}
    record_ids: set[str] = set()
    for index, raw_candidate in enumerate(require_list(observations.get("assets"), "observations.assets")):
        candidate = require_object(raw_candidate, f"observations.assets[{index}]")
        require_exact_keys(candidate, {"name", "root_id", "signals"}, "observed asset")
        name = normalize_domain(candidate.get("name"), "observed asset name")
        root_id = candidate.get("root_id")
        if root_id not in roots or not under_root(name, roots[root_id]):
            raise EvidenceError("observed asset is outside the authorized owned roots")
        if name in candidates:
            raise EvidenceError("observation set contains duplicate assets")
        signal_sources: set[str] = set()
        services: set[tuple[str, int]] = set()
        cname_targets: set[str] = set()
        signals = require_list(candidate.get("signals"), "observed asset signals")
        if not signals:
            raise EvidenceError("observed asset has no provenance signals")
        for raw_signal in signals:
            signal = require_object(raw_signal, "observed asset signal")
            record_id = signal.get("record_id")
            if record_id in record_ids:
                raise EvidenceError("observation record identity is duplicated")
            source, service, cname = validate_signal(signal)
            record_ids.add(record_id)
            signal_sources.add(source)
            if service:
                services.add(service)
            if cname:
                cname_targets.add(cname)
        if not signal_sources.intersection({"certificate-transparency", "public-dns"}):
            raise EvidenceError("observed asset lacks passive discovery provenance")
        candidates[name] = {
            "name": name,
            "root_id": root_id,
            "services": services,
            "cname_targets": cname_targets,
            "currently_exposed": bool(signal_sources.intersection({"public-dns", "https-metadata"})),
        }
    return candidates


def validate_state(state: dict[str, Any], now: datetime, scope_id: str) -> dict[str, dict[str, Any]]:
    require_exact_keys(state, {"entries", "schema", "scope_id", "updated_at"}, "state")
    if state.get("schema") != STATE_SCHEMA:
        raise EvidenceError("state schema is unsupported")
    if state.get("scope_id") != scope_id:
        raise EvidenceError("state scope does not match the approved inventory")
    updated = parse_time(state.get("updated_at"), "state.updated_at")
    if updated > now:
        raise EvidenceError("state update is from the future")
    entries: dict[str, dict[str, Any]] = {}
    for index, raw_entry in enumerate(require_list(state.get("entries"), "state.entries")):
        entry = require_object(raw_entry, f"state.entries[{index}]")
        status = entry.get("status")
        fields = {"fingerprint", "first_seen_at", "last_seen_at", "owner", "reason_class", "status"}
        if status == "remediated":
            fields |= {"closed_at", "closure_evidence_id"}
        require_exact_keys(entry, fields, "state entry")
        fingerprint = exact_id(entry.get("fingerprint"), FINGERPRINT_RE, "state fingerprint")
        if fingerprint in entries or status not in {"open", "remediated"}:
            raise EvidenceError("state entry identity or status is invalid")
        safe_label(entry.get("owner"), "state entry owner")
        safe_label(entry.get("reason_class"), "state entry reason class")
        first = parse_time(entry.get("first_seen_at"), "state first_seen_at")
        last = parse_time(entry.get("last_seen_at"), "state last_seen_at")
        if first > last or last > now:
            raise EvidenceError("state entry observation time is invalid")
        if status == "remediated":
            closed = parse_time(entry.get("closed_at"), "state closed_at")
            if closed < last or closed > now:
                raise EvidenceError("state remediation time is invalid")
            exact_id(entry.get("closure_evidence_id"), HASH_ID_RE, "state closure evidence")
        entries[fingerprint] = entry
    return entries


def reconcile(
    inventory_assets: dict[str, dict[str, Any]],
    candidates: dict[str, dict[str, Any]],
    state_entries: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, str]], int]:
    findings: list[dict[str, str]] = []
    known = 0
    for name in sorted(candidates):
        candidate = candidates[name]
        approved = inventory_assets.get(name)
        candidate_findings: list[dict[str, str]] = []
        if approved is None:
            fingerprint = observation_fingerprint(name)
            previous = state_entries.get(fingerprint)
            if previous is None:
                state = "NEW_UNATTRIBUTED"
                reason = "asset-not-in-approved-inventory"
            elif previous["status"] == "remediated":
                state = "REAPPEARED"
                reason = "previously-remediated-asset-observed"
            else:
                state = "UNATTRIBUTED"
                reason = "unowned-asset-remains-observed"
            candidate_findings.append(
                {"identity_kind": "fingerprint", "identity": fingerprint, "reason": reason, "state": state}
            )
        else:
            if candidate["root_id"] != approved["root_id"]:
                raise EvidenceError("observed asset root binding differs from inventory")
            if approved["review_expired"]:
                candidate_findings.append(
                    {
                        "identity_kind": "asset",
                        "identity": approved["asset_id"],
                        "reason": "inventory-review-expired",
                        "state": "FINDING",
                    }
                )
            if candidate["currently_exposed"] and approved["expected_public"] is False:
                candidate_findings.append(
                    {
                        "identity_kind": "asset",
                        "identity": approved["asset_id"],
                        "reason": "unexpected-public-exposure",
                        "state": "FINDING",
                    }
                )
            unexpected_services = candidate["services"] - approved["services"]
            if approved["expected_public"] is True and unexpected_services:
                candidate_findings.append(
                    {
                        "identity_kind": "asset",
                        "identity": approved["asset_id"],
                        "reason": "unexpected-public-service",
                        "state": "FINDING",
                    }
                )
            if approved["relationship"] == "delegated-service" and candidate["cname_targets"]:
                if candidate["cname_targets"] != {approved["delegated_target"]}:
                    candidate_findings.append(
                        {
                            "identity_kind": "asset",
                            "identity": approved["asset_id"],
                            "reason": "delegation-target-drift",
                            "state": "FINDING",
                        }
                    )
        if candidate_findings:
            findings.extend(candidate_findings)
        else:
            known += 1
    findings.sort(
        key=lambda item: (
            0 if item["identity_kind"] == "asset" else 1,
            item["identity"],
            item["state"],
            item["reason"],
        )
    )
    return findings, known


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy, "policy")
        inventory = load_json(args.inventory, "inventory")
        observations = load_json(args.observations, "observations")
        state = load_json(args.state, "state")
        for label, document in (
            ("policy", policy),
            ("inventory", inventory),
            ("observations", observations),
            ("state", state),
        ):
            forbidden = find_forbidden_key(document)
            if forbidden:
                raise EvidenceError(f"{label} contains forbidden sensitive field at {forbidden}")
        now, roots = validate_policy(policy)
        scope_id, inventory_assets = validate_inventory(inventory, policy, now, roots)
        candidates = validate_observations(observations, policy, now, roots, scope_id)
        state_entries = validate_state(state, now, scope_id)
        findings, known = reconcile(inventory_assets, candidates, state_entries)
    except PolicyFinding as exc:
        print(f"FINDING control reason={exc}")
        print("REJECTED findings=1")
        return 1
    except EvidenceError as exc:
        print(f"ERROR {exc}")
        return 2

    for finding in findings:
        print(
            f"{finding['state']} {finding['identity_kind']}={finding['identity']} "
            f"reason={finding['reason']}"
        )
    if findings:
        print(f"REJECTED findings={len(findings)} known={known} observed={len(candidates)}")
        return 1
    print(f"PASS scope={scope_id} observed={len(candidates)} known={known} findings=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
