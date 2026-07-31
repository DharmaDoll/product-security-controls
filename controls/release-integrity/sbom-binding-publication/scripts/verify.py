#!/usr/bin/env python3
"""Verify artifact-bound SBOM publication and a normalized Dependency-Track receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import UUID


DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SERIAL_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MUTABLE_VALUES = {"", "latest", "main", "master"}
EXPECTED_ERROR_EVENTS = {"BOM_PROCESSING_FAILED", "BOM_VALIDATION_FAILED"}


class InputError(ValueError):
    """Input cannot be parsed or evaluated."""


class EvaluationError(RuntimeError):
    """External analysis did not complete reliably."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def sha256(path: Path, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise InputError(f"cannot read {label}: {error}") from error


def object_at(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise InputError(f"{label}.{key} must be an object")
    return child


def valid_uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise InputError(f"{label} must be an RFC3339 timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InputError(f"{label} must be an RFC3339 timestamp") from error


def components(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    values = sbom.get("components")
    if not isinstance(values, list):
        raise InputError("SBOM components must be a list")
    if not all(isinstance(item, dict) for item in values):
        raise InputError("SBOM components must contain objects")
    return values


def root_component(sbom: dict[str, Any]) -> dict[str, Any]:
    metadata = object_at(sbom, "metadata", "SBOM")
    return object_at(metadata, "component", "SBOM.metadata")


def check_sbom_identity(
    sbom: dict[str, Any], _: dict[str, Any], __: dict[str, Any], ___: dict[str, Any],
    ____: str, _____: str
) -> list[str]:
    issues: list[str] = []
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.7":
        issues.append("SBOM must be CycloneDX 1.7")
    serial = sbom.get("serialNumber")
    if not isinstance(serial, str) or not SERIAL_RE.fullmatch(serial):
        issues.append("SBOM serialNumber is invalid")
    if not isinstance(sbom.get("version"), int) or isinstance(sbom.get("version"), bool):
        issues.append("SBOM version must be an integer")
    root = root_component(sbom)
    for field in ("bom-ref", "name", "version", "purl"):
        if not isinstance(root.get(field), str) or not root[field]:
            issues.append(f"root component requires {field}")
    for index, component in enumerate(components(sbom)):
        for field in ("bom-ref", "name", "version", "purl"):
            value = component.get(field)
            if not isinstance(value, str) or not value or "*" in value:
                issues.append(f"component {index} requires exact {field}")
        if component.get("bom-ref") != component.get("purl"):
            issues.append(f"component {index} bom-ref must equal its exact purl")
    return issues


def check_artifact_binding(
    sbom: dict[str, Any], manifest: dict[str, Any], _: dict[str, Any],
    __: dict[str, Any], artifact_digest: str, sbom_digest: str
) -> list[str]:
    issues: list[str] = []
    artifact = object_at(manifest, "artifact", "manifest")
    sbom_record = object_at(manifest, "sbom", "manifest")
    if artifact.get("sha256") != artifact_digest:
        issues.append("manifest artifact digest does not match released bytes")
    if sbom_record.get("sha256") != sbom_digest:
        issues.append("manifest SBOM digest does not match published SBOM bytes")
    if sbom_record.get("serial_number") != sbom.get("serialNumber"):
        issues.append("manifest SBOM serial does not match the SBOM")
    if sbom_record.get("generated_from") != "release-artifact":
        issues.append("SBOM was not generated for the released artifact")
    hashes = root_component(sbom).get("hashes")
    bound = (
        isinstance(hashes, list)
        and any(
            isinstance(item, dict)
            and item.get("alg") == "SHA-256"
            and item.get("content") == artifact_digest
            for item in hashes
        )
    )
    if not bound:
        issues.append("SBOM root component is not bound to the artifact SHA-256")
    return issues


def check_completeness(
    sbom: dict[str, Any], manifest: dict[str, Any], _: dict[str, Any],
    __: dict[str, Any], ___: str, ____: str
) -> list[str]:
    issues: list[str] = []
    component_refs = {
        item.get("bom-ref") for item in components(sbom) if isinstance(item.get("bom-ref"), str)
    }
    required = manifest.get("required_components")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise InputError("manifest.required_components must be a string list")
    missing = sorted(set(required) - component_refs)
    if missing:
        issues.append(f"required components are missing: {', '.join(missing)}")
    dependency_rows = sbom.get("dependencies")
    if not isinstance(dependency_rows, list):
        raise InputError("SBOM dependencies must be a list")
    edges: set[tuple[str, str]] = set()
    for row in dependency_rows:
        if not isinstance(row, dict) or not isinstance(row.get("dependsOn"), list):
            raise InputError("SBOM dependency rows require ref and dependsOn")
        if isinstance(row.get("ref"), str):
            edges.update(
                (row["ref"], target)
                for target in row["dependsOn"]
                if isinstance(target, str)
            )
    relationships = manifest.get("required_relationships")
    if not isinstance(relationships, list):
        raise InputError("manifest.required_relationships must be a list")
    for item in relationships:
        if not isinstance(item, dict):
            raise InputError("required relationship must be an object")
        edge = (item.get("from"), item.get("to"))
        if not all(isinstance(value, str) for value in edge) or edge not in edges:
            issues.append(f"required relationship is missing: {edge[0]} -> {edge[1]}")
    compositions = sbom.get("compositions")
    if not (
        isinstance(compositions, list)
        and compositions
        and all(isinstance(item, dict) and item.get("aggregate") == "complete" for item in compositions)
    ):
        issues.append("SBOM composition is not complete")
    return issues


def check_publication(
    _: dict[str, Any], manifest: dict[str, Any], __: dict[str, Any],
    ___: dict[str, Any], ____: str, _____: str
) -> list[str]:
    issues: list[str] = []
    artifact = object_at(manifest, "artifact", "manifest")
    sbom_record = object_at(manifest, "sbom", "manifest")
    if sbom_record.get("required") is not True or manifest.get("protected_artifact_family") is not True:
        issues.append("protected artifact family can downgrade the SBOM requirement")
    location = sbom_record.get("location")
    parsed = urlsplit(location) if isinstance(location, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
    ):
        issues.append("SBOM location is not an exact authenticated HTTPS path")
    if sbom_record.get("immutable") is not True:
        issues.append("SBOM publication is mutable")
    retention = sbom_record.get("retention_days")
    if not isinstance(retention, int) or isinstance(retention, bool) or retention < 365:
        issues.append("SBOM retention is shorter than the reference policy")
    artifact_time = parse_time(artifact.get("published_at"), "artifact.published_at")
    sbom_time = parse_time(sbom_record.get("published_at"), "sbom.published_at")
    delay = (sbom_time - artifact_time).total_seconds()
    if delay < 0 or delay > 300:
        issues.append("SBOM is not published within five minutes of the artifact")
    return issues


def check_dependency_track_policy(
    _: dict[str, Any], __: dict[str, Any], policy: dict[str, Any],
    ___: dict[str, Any], ____: str, _____: str
) -> list[str]:
    issues: list[str] = []
    server = object_at(policy, "server", "Dependency-Track policy")
    release = server.get("release")
    digest = server.get("apiserver_sha256")
    if not isinstance(release, str) or release in MUTABLE_VALUES:
        issues.append("Dependency-Track server release is mutable")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        issues.append("Dependency-Track server artifact is not integrity pinned")
    endpoint = policy.get("endpoint")
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith("/api/v1/bom")
    ):
        issues.append("Dependency-Track endpoint is not an exact HTTPS BOM endpoint")
    if not valid_uuid(policy.get("project_uuid")):
        issues.append("Dependency-Track project UUID is not pre-bound")
    if policy.get("project_version") in MUTABLE_VALUES:
        issues.append("Dependency-Track project version is mutable")
    if policy.get("auto_create") is not False:
        issues.append("BOM upload can auto-create an unintended project")
    if policy.get("api_key_source") != "environment:DEPENDENCY_TRACK_API_KEY":
        issues.append("API key is not obtained from the approved environment boundary")
    if policy.get("api_permissions") != ["BOM_UPLOAD"]:
        issues.append("upload API key permissions exceed BOM_UPLOAD")
    if policy.get("transport") != "tls-server-authenticated":
        issues.append("Dependency-Track transport is not server-authenticated TLS")
    if policy.get("upload_response_semantics") != "accepted-only":
        issues.append("upload acceptance is treated as completed analysis")
    if policy.get("success_event") != "BOM_PROCESSED":
        issues.append("BOM_PROCESSED is not required for success")
    if set(policy.get("error_events", [])) != EXPECTED_ERROR_EVENTS:
        issues.append("Dependency-Track processing and validation failures are incomplete")
    if policy.get("timeout_state") != "ERROR" or policy.get("analyzer_unavailable_state") != "ERROR":
        issues.append("timeout or analyzer failure can appear clean")
    age = policy.get("max_vulnerability_data_age_hours")
    if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 24:
        issues.append("vulnerability data freshness limit exceeds 24 hours")
    return issues


def check_dependency_track_receipt(
    sbom: dict[str, Any], _: dict[str, Any], policy: dict[str, Any],
    receipt: dict[str, Any], __: str, sbom_digest: str
) -> list[str]:
    event = receipt.get("event")
    error_events = set(policy.get("error_events", []))
    if event in error_events:
        raise EvaluationError(f"Dependency-Track reported {event}")
    if event != policy.get("success_event"):
        raise EvaluationError("Dependency-Track processing is incomplete or timed out")
    issues: list[str] = []
    expected = {
        "server_release": object_at(policy, "server", "Dependency-Track policy").get("release"),
        "project_uuid": policy.get("project_uuid"),
        "project_version": policy.get("project_version"),
        "bom_serial_number": sbom.get("serialNumber"),
        "bom_sha256": sbom_digest,
        "component_count": len(components(sbom)),
        "composition": "complete",
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            issues.append(f"Dependency-Track receipt {field} does not match")
    return issues


def check_sanitized_fresh_evidence(
    _: dict[str, Any], __: dict[str, Any], policy: dict[str, Any],
    receipt: dict[str, Any], ___: str, ____: str
) -> list[str]:
    if receipt.get("contains_secrets") is not False:
        return ["Dependency-Track receipt contains secret-bearing evidence"]
    if policy.get("evidence") != "sanitized-metadata-only":
        return ["Dependency-Track evidence policy can retain requests or credentials"]
    data = object_at(receipt, "vulnerability_data", "Dependency-Track receipt")
    if data.get("status") != "healthy":
        raise EvaluationError("Dependency-Track vulnerability analyzer is unavailable")
    updated = parse_time(data.get("updated_at"), "vulnerability_data.updated_at")
    evaluated = parse_time(data.get("evaluated_at"), "vulnerability_data.evaluated_at")
    max_age = policy.get("max_vulnerability_data_age_hours")
    if not isinstance(max_age, int):
        raise InputError("max_vulnerability_data_age_hours must be an integer")
    if updated > evaluated or (evaluated - updated).total_seconds() > max_age * 3600:
        raise EvaluationError("Dependency-Track vulnerability data is stale")
    return []


Check = Callable[
    [dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str, str],
    list[str],
]
CHECKS: list[tuple[str, str, Check]] = [
    ("SBM-001", "CycloneDX identities are exact and machine readable", check_sbom_identity),
    ("SBM-002", "SBOM is bound to exact released bytes", check_artifact_binding),
    ("SBM-003", "direct transitive and relationship inventory is complete", check_completeness),
    ("SBM-004", "SBOM publication is immutable prompt and no-downgrade", check_publication),
    ("SBM-005", "Dependency-Track upload is pre-bound and least privileged", check_dependency_track_policy),
    ("SBM-006", "Dependency-Track completed receipt matches the release", check_dependency_track_receipt),
    ("SBM-007", "Dependency-Track evidence is sanitized and fresh", check_sanitized_fresh_evidence),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dependency-track-policy", type=Path, required=True)
    parser.add_argument("--dependency-track-receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        sbom = load_json(args.sbom, "SBOM")
        manifest = load_json(args.manifest, "release manifest")
        policy = load_json(args.dependency_track_policy, "Dependency-Track policy")
        receipt = load_json(args.dependency_track_receipt, "Dependency-Track receipt")
        artifact_digest = sha256(args.artifact, "artifact")
        sbom_digest = sha256(args.sbom, "SBOM")
        findings = 0
        for check_id, title, check in CHECKS:
            issues = check(
                sbom, manifest, policy, receipt, artifact_digest, sbom_digest
            )
            if issues:
                findings += 1
                print(f"FAIL {check_id} {title}: {'; '.join(issues)}")
            else:
                print(f"PASS {check_id} {title}")
    except (InputError, EvaluationError, TypeError) as error:
        print(f"ERROR {error}")
        return 2
    if findings:
        print(f"REJECTED SBOM release: {findings} control checks failed")
        return 1
    print("ACCEPTED SBOM release and Dependency-Track processing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
