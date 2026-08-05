#!/usr/bin/env python3
"""Verify an offline AI memory and context lifecycle contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FORBIDDEN = {"raw_prompt", "raw_output", "transcript", "secret_value", "credential_value", "token", "payload_content", "tool_arguments"}


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unavailable or malformed: {exc.__class__.__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


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


def resolve(root: Path, relative: Any, label: str, require_exists: bool = True) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} path is missing")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} path escapes its trust root") from exc
    if require_exists and not path.is_file():
        raise ValueError(f"{label} is unavailable")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        if not isinstance(item, dict) or not isinstance(item.get(key), str):
            raise ValueError(f"{label} record is malformed")
        identity = item[key]
        if identity in result:
            raise ValueError(f"duplicate {label} identity {identity}")
        result[identity] = item
    return result


def expected_write(candidate: dict[str, Any], policy: dict[str, Any], payload_bytes: int, evaluation_time: datetime) -> tuple[str, str]:
    classification = candidate.get("classification")
    source = candidate.get("source", {})
    if classification in policy.get("prohibited_classifications", []) or classification not in policy.get("allowed_classifications", []):
        return "deny", "classification-prohibited"
    if source.get("trust") not in policy.get("allowed_source_trust", []):
        return "deny", "untrusted-source"
    if payload_bytes > policy.get("maximum_payload_bytes", 0):
        return "deny", "payload-too-large"
    created = parse_time(candidate.get("created_at"), f"{candidate.get('id')} created")
    expires = parse_time(candidate.get("expires_at"), f"{candidate.get('id')} expiry")
    lifetime = (expires - created).total_seconds()
    if lifetime <= 0:
        raise ValueError(f"{candidate.get('id')} retention window is invalid")
    if lifetime > policy.get("maximum_retention_seconds", 0):
        return "deny", "retention-too-long"
    if expires <= evaluation_time:
        return "deny", "already-expired"
    scope = candidate.get("scope")
    if not isinstance(scope, dict) or set(scope) != set(policy.get("scope_fields", [])) or any(not isinstance(scope.get(field), str) or not scope[field] for field in policy.get("scope_fields", [])):
        raise ValueError(f"{candidate.get('id')} scope is malformed")
    return "allow", "policy-match"


def record_matches(record: dict[str, Any], candidate: dict[str, Any]) -> bool:
    source = candidate.get("source", {})
    return (
        record.get("candidate_id") == candidate.get("id")
        and record.get("memory_id") == candidate.get("memory_id")
        and record.get("payload_sha256") == candidate.get("payload_sha256")
        and record.get("classification") == candidate.get("classification")
        and record.get("source_ref") == source.get("ref")
        and record.get("source_trust") == source.get("trust")
        and record.get("scope") == candidate.get("scope")
        and record.get("created_at") == candidate.get("created_at")
        and record.get("expires_at") == candidate.get("expires_at")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    try:
        repository_root = args.repository_root.resolve()
        control_root = args.control_root.resolve()
        policy = load_json(args.policy, "policy")
        candidates_doc = load_json(args.candidates, "candidate writes")
        evidence = load_json(args.evidence, "lifecycle evidence")
        forbidden = set(policy.get("evidence", {}).get("forbidden_fields", [])) | FORBIDDEN
        for label, document in (("candidate writes", candidates_doc), ("lifecycle evidence", evidence)):
            found = forbidden_field(document, forbidden)
            if found:
                raise ValueError(f"{label} contains forbidden evidence field {found}")
        evaluation_time = parse_time(policy.get("evaluation_time"), "policy evaluation")

        binding = policy.get("source_scenario_binding", {})
        binding_path = resolve(repository_root, binding.get("path"), "PSB-AI-003 corpus")
        if digest(binding_path) != binding.get("sha256"):
            raise ValueError("PSB-AI-003 corpus binding digest mismatch")
        bound_corpus = load_json(binding_path, "PSB-AI-003 corpus")
        if binding.get("control_id") != "PSB-AI-003" or bound_corpus.get("corpus_id") != binding.get("corpus_id"):
            raise ValueError("PSB-AI-003 corpus binding identity mismatch")
        bound_scenarios = {item.get("id") for item in bound_corpus.get("scenarios", []) if isinstance(item, dict)}

        candidates = keyed(candidates_doc.get("candidates"), "id", "candidate")
        decisions = keyed(evidence.get("write_decisions"), "candidate_id", "write decision")
        records = keyed(evidence.get("active_records"), "candidate_id", "active record")
        tombstones = keyed(evidence.get("tombstones"), "memory_id", "tombstone")
        retrievals = keyed(evidence.get("retrievals"), "id", "retrieval")

        errors: list[str] = []
        findings: list[str] = []
        expected_allowed: set[str] = set()
        candidate_by_memory: dict[str, dict[str, Any]] = {}
        for candidate_id, candidate in sorted(candidates.items()):
            memory_id = candidate.get("memory_id")
            if not isinstance(memory_id, str) or memory_id in candidate_by_memory:
                errors.append(f"{candidate_id} memory identity is missing or duplicated")
                continue
            candidate_by_memory[memory_id] = candidate
            try:
                payload_path = resolve(control_root, candidate.get("payload_path"), f"{candidate_id} payload")
                if digest(payload_path) != candidate.get("payload_sha256"):
                    errors.append(f"{candidate_id} payload digest mismatch")
                    continue
                expected_decision, expected_reason = expected_write(candidate, policy, payload_path.stat().st_size, evaluation_time)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if candidate.get("source", {}).get("ref", "").startswith("PSB-AI-003/"):
                scenario_id = candidate["source"]["ref"].split("/", 1)[1]
                if scenario_id not in bound_scenarios:
                    errors.append(f"{candidate_id} source scenario is not in the bound PSB-AI-003 corpus")
            decision = decisions.get(candidate_id)
            if not isinstance(decision, dict):
                errors.append(f"{candidate_id} write decision is unavailable")
            elif decision.get("decision") != expected_decision or decision.get("reason") != expected_reason:
                findings.append(f"{candidate_id} write decision violates memory policy")
            if expected_decision == "allow":
                expected_allowed.add(candidate_id)

        if set(decisions) != set(candidates):
            errors.append("write decision evidence is incomplete or contains unknown candidates")
        for candidate_id in sorted(set(records) - expected_allowed):
            findings.append(f"{candidate_id} denied candidate was persisted in active memory")
        for candidate_id in sorted(expected_allowed - set(records)):
            errors.append(f"{candidate_id} approved memory record is unavailable")
        for candidate_id, record in sorted(records.items()):
            candidate = candidates.get(candidate_id)
            if not isinstance(candidate, dict):
                continue
            if not record_matches(record, candidate):
                errors.append(f"{candidate_id} active record integrity or provenance mismatch")
            try:
                if parse_time(record.get("expires_at"), f"{candidate_id} active record expiry") <= evaluation_time:
                    findings.append(f"{candidate_id} expired record remains active")
            except ValueError as exc:
                errors.append(str(exc))

        for memory_id, tombstone in sorted(tombstones.items()):
            if tombstone.get("deletion_status") != "completed":
                findings.append(f"{memory_id} expired payload deletion is incomplete")
                continue
            try:
                expired_at = parse_time(tombstone.get("expired_at"), f"{memory_id} expiry")
                deleted_at = parse_time(tombstone.get("deleted_at"), f"{memory_id} deletion")
                delay = (deleted_at - expired_at).total_seconds()
                if expired_at > evaluation_time or delay < 0 or delay > policy.get("deletion_grace_seconds", 0):
                    findings.append(f"{memory_id} deletion did not meet expiry and grace policy")
                deleted_path = resolve(control_root, tombstone.get("deleted_payload_path"), f"{memory_id} deleted payload", require_exists=False)
                if deleted_path.exists():
                    findings.append(f"{memory_id} tombstoned payload still exists")
            except ValueError as exc:
                errors.append(str(exc))
            if tombstone.get("reason") != "retention-expired" or not isinstance(tombstone.get("payload_sha256"), str):
                errors.append(f"{memory_id} tombstone identity is malformed")

        required_cases = policy.get("required_retrieval_cases", {})
        if set(retrievals) != set(required_cases):
            errors.append("retrieval evidence does not exactly cover required cases")
        records_by_memory = {record.get("memory_id"): record for record in records.values()}
        for retrieval_id, retrieval in sorted(retrievals.items()):
            memory_id = retrieval.get("memory_id")
            record = records_by_memory.get(memory_id)
            tombstone = tombstones.get(memory_id)
            request_scope = retrieval.get("request_scope")
            if not isinstance(request_scope, dict) or set(request_scope) != set(policy.get("scope_fields", [])):
                errors.append(f"{retrieval_id} request scope is malformed")
                continue
            expected_case = required_cases.get(retrieval_id)
            if expected_case == "tombstoned":
                expected = ("deny", "tombstoned", None) if tombstone else ("deny", "not-found", None)
            elif record is None:
                expected = ("deny", "not-found", None)
            elif request_scope == record.get("scope"):
                expected = ("allow", "exact-scope", record.get("payload_sha256"))
            else:
                differing = [field for field in policy.get("scope_fields", []) if request_scope.get(field) != record.get("scope", {}).get(field)]
                declared_case = f"{differing[0]}-mismatch" if len(differing) == 1 else None
                if expected_case != declared_case:
                    errors.append(f"{retrieval_id} does not exercise its declared scope boundary")
                expected = ("deny", "scope-mismatch", None)
            actual = (retrieval.get("decision"), retrieval.get("reason"), retrieval.get("returned_payload_sha256"))
            if actual != expected:
                findings.append(f"{retrieval_id} retrieval decision violates exact scope or tombstone policy")

        evidence_policy = policy.get("evidence", {})
        if evidence.get("collection_status") != evidence_policy.get("required_collection_status"):
            errors.append("memory lifecycle collection is incomplete")
        if evidence.get("evaluator_status") != evidence_policy.get("required_evaluator_status"):
            errors.append("memory lifecycle evaluator is unavailable")
        if evidence.get("source_type") != "synthetic-fixture":
            errors.append("memory lifecycle evidence source is not the reviewed fixture")

        if errors:
            for message in sorted(set(errors)):
                print(f"ERROR {message}")
            print(f"ERROR memory lifecycle evidence could not be verified ({len(set(errors))} error(s))")
            return 2
        if findings:
            for message in sorted(set(findings)):
                print(f"FAIL {message}")
            print(f"FAIL memory lifecycle policy rejected the evidence ({len(set(findings))} finding(s))")
            return 1

        print(f"PASS {len(candidates)} candidate writes were derived from classification trust size scope and retention policy")
        print("PASS untrusted PSB-AI-003 content credential-class data and oversized context were denied before persistence")
        print(f"PASS {len(records)} active memory record preserves exact payload provenance user session task scope and expiry")
        print(f"PASS {len(retrievals)} retrieval cases enforce exact scope and deny tombstoned memory without returning payload data")
        print(f"PASS {len(tombstones)} expired memory tombstone proves bounded deletion and payload absence")
        print("PASS lifecycle evidence is complete sanitized and distinguishes policy findings from evaluator ERROR")
        print("PASS synthetic fixture validates the lifecycle contract; live provider memory enforcement is NOT_CHECKED")
        return 0
    except ValueError as exc:
        print(f"ERROR {exc}")
        print("ERROR memory lifecycle evidence could not be verified (1 error(s))")
        return 2


if __name__ == "__main__":
    sys.exit(main())
