#!/usr/bin/env python3
"""Verify RAG corpus admission, retrieval provenance, and deletion evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_EVIDENCE_KEYS = {
    "chunk_content",
    "content",
    "credential",
    "embedding_vector",
    "output",
    "prompt",
    "query_text",
    "raw_query",
    "secret",
    "token",
}


class EvaluationError(RuntimeError):
    """Evidence or trusted policy cannot be evaluated."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvaluationError(f"cannot read {label}") from error


def load_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    raw = read_bytes(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"cannot parse {label}") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return raw, value


def object_at(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise EvaluationError(f"{label}.{key} must be an object")
    return child


def list_of_objects(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise EvaluationError(f"{label} must be an array of objects")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvaluationError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError(f"{label} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{label} must include a timezone")
    return parsed


def positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EvaluationError(f"{label} must be a positive integer")
    return value


def resolve_content(registry_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise EvaluationError("source content path is missing")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise EvaluationError("source content path escapes the registry directory")
    root = registry_path.parent.resolve()
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise EvaluationError("source content path escapes the registry directory")
    return resolved


def check_sensitive_keys(value: Any, location: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_EVIDENCE_KEYS:
                raise EvaluationError(f"sensitive field {location}.{key} is prohibited")
            check_sensitive_keys(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            check_sensitive_keys(child, f"{location}[{index}]")


def check_policy(
    policy: dict[str, Any], verifier_digest: str
) -> list[tuple[str, str]]:
    if policy.get("schema") != "psb-rag-corpus-policy/v1.0":
        raise EvaluationError("unsupported RAG corpus policy schema")
    source_policy = object_at(policy, "source_registry", "policy")
    chunking = object_at(policy, "chunking", "policy")
    poisoning = object_at(policy, "poisoning", "policy")
    inspector = object_at(policy, "inspector", "policy")
    embedding = object_at(policy, "embedding_model", "policy")
    deletion = object_at(policy, "deletion", "policy")
    evidence = object_at(policy, "evidence", "policy")
    live_claims = object_at(policy, "live_claims", "policy")
    ranks = object_at(policy, "classification_ranks", "policy")
    positive_integer(source_policy.get("maximum_age_hours"), "policy source registry age")
    positive_integer(chunking.get("maximum_document_bytes"), "policy maximum document bytes")
    positive_integer(chunking.get("maximum_chunks_per_document"), "policy maximum chunks")
    positive_integer(deletion.get("maximum_propagation_seconds"), "policy deletion delay")
    if not isinstance(source_policy.get("sha256"), str) or not SHA256.fullmatch(source_policy["sha256"]):
        raise EvaluationError("policy source registry digest is invalid")
    if (
        inspector.get("id") != "psb-rag-corpus-verifier"
        or inspector.get("version") != "1.0.0"
        or inspector.get("sha256") != verifier_digest
    ):
        raise EvaluationError("policy does not bind the running RAG verifier")
    if (
        poisoning.get("upstream_control") != "PSB-AI-003"
        or poisoning.get("deny_before_embedding") is not True
        or not isinstance(poisoning.get("synthetic_marker"), str)
    ):
        raise EvaluationError("poisoning policy is incomplete")
    if (
        embedding.get("upstream_control") != "PSB-DEPS-005"
        or not isinstance(embedding.get("artifact_sha256"), str)
        or not SHA256.fullmatch(embedding["artifact_sha256"])
    ):
        raise EvaluationError("embedding model policy is incomplete")
    if ranks != {"public": 0, "internal": 1, "restricted": 2}:
        raise EvaluationError("classification ranks are unsupported")
    findings: list[tuple[str, str]] = []
    if any(
        evidence.get(key) is not False
        for key in (
            "include_document_content",
            "include_chunk_content",
            "include_query_text",
            "include_embedding_vectors",
            "include_credentials",
        )
    ):
        findings.append(("RAG-009", "evidence policy permits protected corpus or query data"))
    if set(live_claims.values()) != {"NOT_CHECKED"}:
        findings.append(("RAG-010", "fixture policy overclaims live RAG enforcement"))
    return findings


def check_registry(
    registry_path: Path,
    registry_raw: bytes,
    registry: dict[str, Any],
    policy: dict[str, Any],
    as_of: datetime,
) -> tuple[dict[str, dict[str, Any]], dict[str, bytes], list[tuple[str, str]]]:
    if registry.get("schema") != "psb-rag-source-registry/v1.0":
        raise EvaluationError("unsupported RAG source registry schema")
    if registry.get("available") is not True or registry.get("complete") is not True:
        raise EvaluationError("RAG source registry is unavailable or incomplete")
    source_policy = object_at(policy, "source_registry", "policy")
    if sha256_bytes(registry_raw) != source_policy.get("sha256"):
        raise EvaluationError("RAG source registry digest does not match policy")
    collected = parse_time(registry.get("collected_at"), "source registry collected_at")
    maximum_age = timedelta(hours=positive_integer(source_policy.get("maximum_age_hours"), "source registry age"))
    if collected > as_of or as_of - collected > maximum_age:
        raise EvaluationError("RAG source registry is stale or from the future")
    records = list_of_objects(registry.get("records"), "source registry records")
    by_source: dict[str, dict[str, Any]] = {}
    by_document: set[str] = set()
    content: dict[str, bytes] = {}
    findings: list[tuple[str, str]] = []
    maximum_bytes = positive_integer(
        object_at(policy, "chunking", "policy").get("maximum_document_bytes"),
        "maximum document bytes",
    )
    for record in records:
        source_id = record.get("source_id")
        document_id = record.get("document_id")
        if (
            not isinstance(source_id, str)
            or not source_id
            or source_id in by_source
            or not isinstance(document_id, str)
            or not document_id
            or document_id in by_document
        ):
            raise EvaluationError("source registry identities are missing or duplicated")
        if (
            not isinstance(record.get("source_url"), str)
            or not record["source_url"].startswith("https://")
            or not isinstance(record.get("source_revision"), str)
            or not FULL_SHA.fullmatch(record["source_revision"])
            or record.get("classification") not in ("public", "internal", "restricted")
            or not isinstance(record.get("owner"), str)
            or not record.get("owner")
            or not isinstance(record.get("content_sha256"), str)
            or not SHA256.fullmatch(record["content_sha256"])
        ):
            raise EvaluationError(f"source registry record {source_id} is malformed")
        status = record.get("status")
        path = resolve_content(registry_path, record.get("content_path"))
        if status in ("ACTIVE", "UNAPPROVED"):
            raw = read_bytes(path, f"source content {source_id}")
            if len(raw) > maximum_bytes or sha256_bytes(raw) != record.get("content_sha256"):
                findings.append(("RAG-002", f"{source_id} source content size or digest mismatch"))
            content[source_id] = raw
        elif status == "REVOKED":
            if path.exists():
                raise EvaluationError(f"revoked source payload {source_id} still exists")
            parse_time(record.get("revoked_at"), f"source {source_id} revoked_at")
        else:
            raise EvaluationError(f"source {source_id} has unsupported lifecycle state")
        by_source[source_id] = record
        by_document.add(document_id)
    if set(by_source) != {"SRC-001", "SRC-002", "SRC-003", "SRC-004"}:
        raise EvaluationError("source registry is not the complete expected fixture set")
    return by_source, content, findings


def expected_ingestion(
    record: dict[str, Any], content: bytes | None, policy: dict[str, Any], as_of: datetime
) -> tuple[str, list[str], list[str]]:
    status = record.get("status")
    if status == "REVOKED":
        return "DELETED", ["SOURCE_REVOKED"], []
    marker = object_at(policy, "poisoning", "policy").get("synthetic_marker")
    findings = ["RAG-POISON-001"] if content is not None and marker.encode() in content else []
    reasons: list[str] = []
    if findings:
        reasons.append("PROMPT_INJECTION")
    authorized = status == "ACTIVE"
    if authorized:
        expires = parse_time(record.get("authorization_expires_at"), "source authorization expiry")
        authorized = expires > as_of
    if (
        not authorized
        or record.get("tenant_id") not in object_at(policy, "source_registry", "policy").get("accepted_tenants", [])
        or record.get("license_expression") in (None, "UNKNOWN")
        or record.get("use_authorization") in (None, "NONE", "REVOKED")
    ):
        reasons.append("SOURCE_NOT_AUTHORIZED")
    decision = "INDEXED" if not reasons else "REJECTED"
    return decision, sorted(reasons), findings


def check_ingestion(
    ingestion: dict[str, Any],
    registry_raw: bytes,
    records: dict[str, dict[str, Any]],
    content: dict[str, bytes],
    policy: dict[str, Any],
    as_of: datetime,
    verifier_digest: str,
) -> tuple[list[tuple[str, str]], set[str]]:
    if ingestion.get("schema") != "psb-rag-ingestion-evidence/v1.0":
        raise EvaluationError("unsupported RAG ingestion evidence schema")
    if ingestion.get("available") is not True or ingestion.get("complete") is not True:
        raise EvaluationError("RAG ingestion evidence is unavailable or incomplete")
    inspector = object_at(ingestion, "inspector", "ingestion evidence")
    policy_inspector = object_at(policy, "inspector", "policy")
    if (
        ingestion.get("source_registry_sha256") != sha256_bytes(registry_raw)
        or inspector != policy_inspector
        or inspector.get("sha256") != verifier_digest
    ):
        raise EvaluationError("RAG ingestion evidence identity is not bound to policy")
    parse_time(ingestion.get("evaluated_at"), "ingestion evaluated_at")
    candidates = list_of_objects(ingestion.get("candidates"), "ingestion candidates")
    by_source = {item.get("source_id"): item for item in candidates if isinstance(item.get("source_id"), str)}
    if set(by_source) != set(records) or len(candidates) != len(records):
        raise EvaluationError("RAG ingestion evidence is incomplete or duplicated")
    findings: list[tuple[str, str]] = []
    indexed: set[str] = set()
    for source_id, record in records.items():
        candidate = by_source[source_id]
        if candidate.get("scanner_available") is not True or candidate.get("scanner_complete") is not True:
            raise EvaluationError(f"scanner evidence for {source_id} is unavailable or incomplete")
        expected_decision, expected_reasons, expected_findings = expected_ingestion(
            record, content.get(source_id), policy, as_of
        )
        if (
            candidate.get("document_id") != record.get("document_id")
            or candidate.get("content_sha256") != record.get("content_sha256")
        ):
            findings.append(("RAG-002", f"{source_id} ingestion does not bind exact source content"))
        if candidate.get("finding_ids") != expected_findings:
            findings.append(("RAG-003", f"{source_id} poisoning scan result is inconsistent"))
        if candidate.get("decision") != expected_decision or candidate.get("reasons") != expected_reasons:
            if "PROMPT_INJECTION" in expected_reasons:
                findings.append(("RAG-003", f"{source_id} poisoned content was not denied before embedding"))
            if "SOURCE_NOT_AUTHORIZED" in expected_reasons:
                findings.append(("RAG-001", f"{source_id} source authorization was not enforced"))
            if expected_decision == "DELETED":
                findings.append(("RAG-008", f"{source_id} revoked content was not removed from ingestion"))
        if candidate.get("decision") == "INDEXED":
            indexed.add(source_id)
    if ingestion.get("live_source_connectors") != "NOT_CHECKED":
        findings.append(("RAG-010", "fixture ingestion overclaims live source connector enforcement"))
    return findings, indexed


def expected_embedding_binding(model_digest: str, chunk_digest: str) -> str:
    return sha256_bytes(f"{model_digest}:{chunk_digest}".encode())


def check_snapshot(
    snapshot: dict[str, Any],
    ingestion_raw: bytes,
    registry_raw: bytes,
    records: dict[str, dict[str, Any]],
    content: dict[str, bytes],
    indexed: set[str],
    policy: dict[str, Any],
) -> tuple[list[tuple[str, str]], dict[str, dict[str, Any]]]:
    if snapshot.get("schema") != "psb-rag-corpus-snapshot/v1.0":
        raise EvaluationError("unsupported RAG corpus snapshot schema")
    embedding = object_at(snapshot, "embedding_model", "corpus snapshot")
    expected_embedding = object_at(policy, "embedding_model", "policy")
    findings: list[tuple[str, str]] = []
    if (
        snapshot.get("source_registry_sha256") != sha256_bytes(registry_raw)
        or snapshot.get("ingestion_evidence_sha256") != sha256_bytes(ingestion_raw)
    ):
        raise EvaluationError("corpus snapshot is not bound to exact ingestion evidence")
    if embedding != expected_embedding:
        findings.append(("RAG-004", "corpus uses an unapproved or unbound embedding model"))
    entries = list_of_objects(snapshot.get("entries"), "corpus snapshot entries")
    by_chunk = {item.get("chunk_id"): item for item in entries if isinstance(item.get("chunk_id"), str)}
    if len(by_chunk) != len(entries):
        raise EvaluationError("corpus snapshot chunk identities are missing or duplicated")
    expected_sources = {
        source_id for source_id in indexed if records[source_id].get("status") == "ACTIVE"
    }
    actual_sources = {item.get("source_id") for item in entries}
    if actual_sources != expected_sources or len(entries) != len(expected_sources):
        findings.append(("RAG-002", "corpus snapshot does not contain exactly the admitted active sources"))
    model_digest = expected_embedding.get("artifact_sha256")
    for entry in entries:
        source_id = entry.get("source_id")
        record = records.get(source_id)
        if record is None or source_id not in content:
            findings.append(("RAG-002", "corpus snapshot contains an unauthorized or deleted source"))
            continue
        chunk_digest = sha256_bytes(content[source_id])
        expected_chunk_id = f"CHK-{record.get('document_id')}-001"
        if (
            entry.get("chunk_id") != expected_chunk_id
            or entry.get("document_id") != record.get("document_id")
            or entry.get("source_revision") != record.get("source_revision")
            or entry.get("chunk_index") != 0
            or entry.get("chunk_sha256") != chunk_digest
            or entry.get("embedding_binding_sha256")
            != expected_embedding_binding(model_digest, chunk_digest)
        ):
            findings.append(("RAG-002", f"{source_id} chunk identity or embedding binding is invalid"))
        if (
            entry.get("tenant_id") != record.get("tenant_id")
            or entry.get("classification") != record.get("classification")
            or snapshot.get("tenant_id") != record.get("tenant_id")
        ):
            findings.append(("RAG-005", f"{source_id} tenant or classification scope changed during indexing"))
    if snapshot.get("live_vector_database") != "NOT_CHECKED":
        findings.append(("RAG-010", "fixture snapshot overclaims live vector database enforcement"))
    return findings, by_chunk


def principal_map(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    principals = list_of_objects(policy.get("principals"), "policy principals")
    result = {item.get("principal_id"): item for item in principals if isinstance(item.get("principal_id"), str)}
    if len(result) != len(principals):
        raise EvaluationError("policy principal identities are missing or duplicated")
    return result


def check_retrieval(
    retrieval: dict[str, Any],
    snapshot_raw: bytes,
    snapshot: dict[str, Any],
    chunks: dict[str, dict[str, Any]],
    policy: dict[str, Any],
) -> list[tuple[str, str]]:
    if retrieval.get("schema") != "psb-rag-retrieval-evidence/v1.0":
        raise EvaluationError("unsupported RAG retrieval evidence schema")
    if retrieval.get("available") is not True or retrieval.get("complete") is not True:
        raise EvaluationError("RAG retrieval evidence is unavailable or incomplete")
    if retrieval.get("snapshot_sha256") != sha256_bytes(snapshot_raw):
        raise EvaluationError("retrieval evidence is not bound to the exact corpus snapshot")
    scenarios = list_of_objects(policy.get("retrieval_scenarios"), "policy retrieval scenarios")
    runs = list_of_objects(retrieval.get("runs"), "retrieval runs")
    by_query = {item.get("query_id"): item for item in runs if isinstance(item.get("query_id"), str)}
    if len(by_query) != len(runs) or set(by_query) != {item.get("query_id") for item in scenarios}:
        raise EvaluationError("retrieval evidence is incomplete or duplicated")
    principals = principal_map(policy)
    ranks = object_at(policy, "classification_ranks", "policy")
    embedding = object_at(policy, "embedding_model", "policy")
    findings: list[tuple[str, str]] = []
    for scenario in scenarios:
        query_id = scenario.get("query_id")
        run = by_query[query_id]
        principal = principals.get(scenario.get("principal_id"))
        if principal is None:
            raise EvaluationError(f"retrieval scenario {query_id} references unknown principal")
        expected_ids = scenario.get("expected_chunk_ids")
        results = list_of_objects(run.get("results"), f"retrieval {query_id} results")
        actual_ids = [item.get("chunk_id") for item in results]
        expected_decision = "ALLOW" if expected_ids else "DENY"
        if (
            run.get("query_sha256") != scenario.get("query_sha256")
            or run.get("principal_id") != scenario.get("principal_id")
            or run.get("tenant_id") != principal.get("tenant_id")
            or run.get("maximum_classification") != principal.get("maximum_classification")
            or run.get("decision") != expected_decision
            or actual_ids != expected_ids
        ):
            findings.append(("RAG-006", f"{query_id} retrieval authorization or expected result set is invalid"))
        for result in results:
            chunk = chunks.get(result.get("chunk_id"))
            if chunk is None:
                findings.append(("RAG-007", f"{query_id} returned a chunk absent from the bound snapshot"))
                continue
            if (
                result.get("document_id") != chunk.get("document_id")
                or result.get("source_id") != chunk.get("source_id")
                or result.get("source_revision") != chunk.get("source_revision")
                or result.get("chunk_sha256") != chunk.get("chunk_sha256")
                or result.get("tenant_id") != chunk.get("tenant_id")
                or result.get("classification") != chunk.get("classification")
                or result.get("snapshot_sha256") != sha256_bytes(snapshot_raw)
                or result.get("embedding_model_artifact_sha256") != embedding.get("artifact_sha256")
            ):
                findings.append(("RAG-007", f"{query_id} result provenance is incomplete or substituted"))
            if (
                result.get("tenant_id") != principal.get("tenant_id")
                or ranks.get(result.get("classification"), 999)
                > ranks.get(principal.get("maximum_classification"), -1)
            ):
                findings.append(("RAG-006", f"{query_id} returned cross-tenant or over-classified content"))
    if retrieval.get("live_embedding_service") != "NOT_CHECKED":
        findings.append(("RAG-010", "fixture retrieval overclaims live embedding service enforcement"))
    return findings


def check_deletion(
    deletion: dict[str, Any],
    snapshot_raw: bytes,
    chunks: dict[str, dict[str, Any]],
    records: dict[str, dict[str, Any]],
    registry_path: Path,
    policy: dict[str, Any],
) -> list[tuple[str, str]]:
    if deletion.get("schema") != "psb-rag-deletion-evidence/v1.0":
        raise EvaluationError("unsupported RAG deletion evidence schema")
    if deletion.get("available") is not True or deletion.get("complete") is not True:
        raise EvaluationError("RAG deletion evidence is unavailable or incomplete")
    if deletion.get("snapshot_sha256") != sha256_bytes(snapshot_raw):
        raise EvaluationError("deletion evidence is not bound to the exact corpus snapshot")
    deletion_policy = object_at(policy, "deletion", "policy")
    source_id = deletion_policy.get("source_id")
    record = records.get(source_id)
    if record is None or record.get("status") != "REVOKED":
        raise EvaluationError("deletion policy does not reference one revoked source")
    tombstone = object_at(deletion, "tombstone", "deletion evidence")
    probe = object_at(deletion, "retrieval_probe", "deletion evidence")
    revoked_at = parse_time(record.get("revoked_at"), "revoked source timestamp")
    deleted_at = parse_time(deletion.get("deleted_at"), "deletion timestamp")
    maximum_delay = timedelta(
        seconds=positive_integer(
            deletion_policy.get("maximum_propagation_seconds"), "deletion propagation"
        )
    )
    retired_chunks = record.get("retired_chunk_ids")
    path = resolve_content(registry_path, record.get("content_path"))
    if (
        deletion.get("source_id") != source_id
        or deletion.get("document_id") != deletion_policy.get("document_id")
        or deleted_at < revoked_at
        or deleted_at - revoked_at > maximum_delay
        or deletion.get("removed_chunk_ids") != retired_chunks
        or any(chunk_id in chunks for chunk_id in retired_chunks)
        or path.exists()
        or deletion.get("index_lookup") != deletion_policy.get("required_index_state")
        or probe.get("decision") != deletion_policy.get("required_retrieval_decision")
        or probe.get("results") != []
        or tombstone.get("source_id") != source_id
        or tombstone.get("document_id") != record.get("document_id")
        or tombstone.get("content_sha256") != record.get("content_sha256")
        or tombstone.get("revoked_at") != record.get("revoked_at")
        or tombstone.get("deleted_at") != deletion.get("deleted_at")
        or deletion.get("live_deletion_replication") != "NOT_CHECKED"
    ):
        return [("RAG-008", "revoked source deletion index removal or retrieval denial is incomplete")]
    return []


def unique(findings: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def evaluate(args: argparse.Namespace) -> int:
    _, policy = load_json(args.policy, "RAG corpus policy")
    verifier_digest = sha256_bytes(Path(__file__).read_bytes())
    findings = check_policy(policy, verifier_digest)
    registry_raw, registry = load_json(args.source_registry, "RAG source registry")
    as_of = parse_time(args.as_of, "evaluation time")
    records, content, registry_findings = check_registry(
        args.source_registry, registry_raw, registry, policy, as_of
    )
    findings.extend(registry_findings)
    ingestion_raw, ingestion = load_json(args.ingestion, "RAG ingestion evidence")
    snapshot_raw, snapshot = load_json(args.snapshot, "RAG corpus snapshot")
    _, retrieval = load_json(args.retrieval, "RAG retrieval evidence")
    _, deletion = load_json(args.deletion, "RAG deletion evidence")
    for label, evidence in (
        ("ingestion", ingestion),
        ("snapshot", snapshot),
        ("retrieval", retrieval),
        ("deletion", deletion),
    ):
        check_sensitive_keys(evidence, label)
    ingestion_findings, indexed = check_ingestion(
        ingestion,
        registry_raw,
        records,
        content,
        policy,
        as_of,
        verifier_digest,
    )
    findings.extend(ingestion_findings)
    snapshot_findings, chunks = check_snapshot(
        snapshot,
        ingestion_raw,
        registry_raw,
        records,
        content,
        indexed,
        policy,
    )
    findings.extend(snapshot_findings)
    findings.extend(check_retrieval(retrieval, snapshot_raw, snapshot, chunks, policy))
    findings.extend(
        check_deletion(
            deletion,
            snapshot_raw,
            chunks,
            records,
            args.source_registry,
            policy,
        )
    )
    findings = unique(findings)
    if findings:
        for check_id, message in findings:
            print(f"QUARANTINE {check_id} {message}")
        print("RESULT QUARANTINE")
        return 1
    for check_id, message in (
        ("RAG-001", "source ownership authorization and lifecycle verified"),
        ("RAG-002", "exact content chunk and corpus snapshot integrity verified"),
        ("RAG-003", "poisoned source denied before embedding and indexing"),
        ("RAG-004", "PSB-DEPS-005 embedding model identity verified"),
        ("RAG-005", "tenant and classification scope preserved at ingestion"),
        ("RAG-006", "retrieval principal tenant and clearance authorization verified"),
        ("RAG-007", "retrieval results retain exact source and snapshot provenance"),
        ("RAG-008", "revoked source deletion and retrieval denial verified"),
        ("RAG-009", "complete sanitized evidence remains fail closed"),
        ("RAG-010", "live RAG services remain explicitly NOT_CHECKED"),
    ):
        print(f"PASS {check_id} {message}")
    print("RESULT ACCEPTED_FOR_RETRIEVAL")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-registry", type=Path, required=True)
    parser.add_argument("--ingestion", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--retrieval", type=Path, required=True)
    parser.add_argument("--deletion", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        return evaluate(parse_args())
    except EvaluationError as error:
        print(f"ERROR RAG-009 verification unavailable: {error}")
        print("RESULT ERROR")
        return 2
    except Exception as error:  # defensive: unknown verifier failure is never clean
        print(f"ERROR RAG-009 unexpected verifier failure: {type(error).__name__}")
        print("RESULT ERROR")
        return 2


if __name__ == "__main__":
    sys.exit(main())
