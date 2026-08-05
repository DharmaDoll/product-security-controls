#!/usr/bin/env python3
"""Verify reviewed AI extension dependencies without contacting external services."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_FIELDS = {"credential", "secret_value", "token", "raw_prompt", "raw_output", "transcript"}


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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_file(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} path is missing")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} path escapes the control directory") from exc
    if not candidate.is_file():
        raise ValueError(f"{label} file is unavailable")
    return candidate


def find_forbidden(value: Any, path: str = "$") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_FIELDS:
                return f"{path}.{key}"
            found = find_forbidden(child, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = find_forbidden(child, f"{path}[{index}]")
            if found:
                return found
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--revocations", type=Path, required=True)
    parser.add_argument("--benchmark", type=Path, required=True)
    args = parser.parse_args()

    try:
        root = args.control_root.resolve()
        policy = load_json(args.policy, "policy")
        manifest = load_json(args.manifest, "manifest")
        revocations = load_json(args.revocations, "revocation evidence")
        benchmark = load_json(args.benchmark, "benchmark evidence")
        for label, value in (("manifest", manifest), ("revocation evidence", revocations), ("benchmark evidence", benchmark)):
            forbidden = find_forbidden(value)
            if forbidden:
                raise ValueError(f"{label} contains forbidden evidence field {forbidden}")
        evaluation_time = parse_time(policy.get("evaluation_time"), "policy evaluation")
        approved = policy.get("approved_dependencies")
        dependencies = manifest.get("dependencies")
        if not isinstance(approved, dict) or not isinstance(dependencies, list):
            raise ValueError("policy or manifest dependency collection is malformed")
        records: dict[str, dict[str, Any]] = {}
        for item in dependencies:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ValueError("manifest dependency record is malformed")
            if item["id"] in records:
                raise ValueError(f"duplicate dependency identity {item['id']}")
            records[item["id"]] = item

        benchmark_path = args.benchmark.resolve()
        benchmark_results = benchmark.get("results")
        if not isinstance(benchmark_results, list):
            raise ValueError("benchmark result collection is malformed")
        benchmark_by_id = {item.get("dependency_id"): item for item in benchmark_results if isinstance(item, dict)}
        if len(benchmark_by_id) != len(benchmark_results):
            raise ValueError("benchmark dependency identities are missing or duplicated")

        revocation_records = revocations.get("records")
        if not isinstance(revocation_records, list):
            raise ValueError("revocation record collection is malformed")
        revocation_by_id = {item.get("dependency_id"): item for item in revocation_records if isinstance(item, dict)}
        if len(revocation_by_id) != len(revocation_records):
            raise ValueError("revocation dependency identities are missing or duplicated")

        errors: list[str] = []
        findings: list[str] = []
        expected_ids = set(approved)
        actual_ids = set(records)
        for missing in sorted(expected_ids - actual_ids):
            findings.append(f"approved dependency {missing} is missing from the manifest")
        for unknown in sorted(actual_ids - expected_ids):
            findings.append(f"unapproved dependency {unknown} is present")

        observed_kinds: set[str] = set()
        handoffs = 0
        for dependency_id, record in sorted(records.items()):
            source = record.get("source", {})
            artifact = record.get("artifact", {})
            review = record.get("semantic_review", {})
            capabilities = record.get("capabilities", {})
            benchmark_ref = record.get("benchmark", {})
            handoff = record.get("runtime_handoff", {})
            kind = record.get("kind")
            if isinstance(kind, str):
                observed_kinds.add(kind)
            expected = approved.get(dependency_id)

            if not isinstance(source, dict) or not source.get("url", "").startswith("https://"):
                findings.append(f"{dependency_id} canonical source is not HTTPS")
            if not isinstance(source, dict) or not COMMIT.fullmatch(str(source.get("commit", ""))):
                findings.append(f"{dependency_id} source commit is mutable or not a full commit")
            if not isinstance(source, dict) or source.get("immutable") is not True or source.get("version") in {"main", "master", "latest"}:
                findings.append(f"{dependency_id} source identity is mutable")

            try:
                artifact_path = resolve_file(root, artifact.get("path") if isinstance(artifact, dict) else None, f"{dependency_id} artifact")
                expected_digest = artifact.get("sha256") if isinstance(artifact, dict) else None
                if not isinstance(expected_digest, str) or not SHA256.fullmatch(expected_digest) or digest(artifact_path) != expected_digest:
                    errors.append(f"{dependency_id} artifact digest mismatch")
            except ValueError as exc:
                errors.append(str(exc))

            if record.get("license") not in policy.get("allowed_licenses", []):
                findings.append(f"{dependency_id} license is not approved")
            if record.get("owner") == record.get("publisher") or not record.get("owner"):
                findings.append(f"{dependency_id} has no independent accountable owner")
            if not isinstance(review, dict) or review.get("outcome") != "approved":
                findings.append(f"{dependency_id} semantic review is not approved")
            if isinstance(review, dict) and review.get("reviewer") in {record.get("owner"), record.get("publisher"), None, ""}:
                findings.append(f"{dependency_id} semantic review is not independent")
            if not isinstance(review, dict) or review.get("repository_invariants_precedence") is not True or review.get("prohibited_behaviors_found") != []:
                findings.append(f"{dependency_id} semantic review permits repository-policy override or prohibited behavior")
            try:
                reviewed_at = parse_time(review.get("reviewed_at") if isinstance(review, dict) else None, f"{dependency_id} semantic review")
                expires_at = parse_time(record.get("review_expires_at"), f"{dependency_id} review expiry")
                if reviewed_at > evaluation_time or expires_at <= reviewed_at:
                    errors.append(f"{dependency_id} semantic review time window is invalid")
                elif expires_at <= evaluation_time:
                    findings.append(f"{dependency_id} semantic review is expired")
            except ValueError as exc:
                errors.append(str(exc))

            if expected is None:
                continue
            if kind != expected.get("kind"):
                findings.append(f"{dependency_id} kind differs from policy")
            capability_fields = ("filesystem_read", "filesystem_write", "network", "secrets", "tools", "direct_tool_authority")
            if not isinstance(capabilities, dict) or any(capabilities.get(field) != expected.get(field) for field in capability_fields):
                findings.append(f"{dependency_id} requested capabilities exceed or differ from policy")

            if not isinstance(benchmark_ref, dict) or benchmark_ref.get("control_id") != "PSB-AI-001":
                findings.append(f"{dependency_id} benchmark is not governed by PSB-AI-001")
            else:
                try:
                    referred = resolve_file(root, benchmark_ref.get("evidence_path"), f"{dependency_id} benchmark")
                    if referred != benchmark_path or digest(referred) != benchmark_ref.get("evidence_sha256"):
                        errors.append(f"{dependency_id} benchmark evidence digest mismatch")
                except ValueError as exc:
                    errors.append(str(exc))
            result = benchmark_by_id.get(dependency_id)
            if not isinstance(result, dict):
                errors.append(f"{dependency_id} benchmark result is unavailable")
            elif (result.get("source_commit") != source.get("commit") or result.get("artifact_sha256") != artifact.get("sha256")):
                errors.append(f"{dependency_id} benchmark result is not bound to the exact dependency")
            elif result.get("recommendation") not in {"pilot", "adopt"} or result.get("security_regression") is not False or result.get("unsafe_recommendations") != 0:
                findings.append(f"{dependency_id} benchmark does not meet adoption policy")

            revoked = revocation_by_id.get(dependency_id)
            if not isinstance(revoked, dict):
                errors.append(f"{dependency_id} revocation status is unavailable")
            elif revoked.get("source_commit") != source.get("commit") or revoked.get("artifact_sha256") != artifact.get("sha256"):
                errors.append(f"{dependency_id} revocation status is not bound to the exact dependency")
            elif revoked.get("status") != "active":
                findings.append(f"{dependency_id} is revoked")
            if handoff == expected.get("runtime_handoff"):
                handoffs += 1
            else:
                findings.append(f"{dependency_id} has no exact PSB-AI-004 runtime disposition")

        required_kinds = set(policy.get("required_fixture_kinds", []))
        if not required_kinds.issubset(observed_kinds):
            findings.append("fixture does not exercise every required dependency kind")
        if revocations.get("collection_status") != "complete":
            errors.append("revocation collection is incomplete")
        try:
            captured = parse_time(revocations.get("captured_at"), "revocation capture")
            age = (evaluation_time - captured).total_seconds()
            if age < 0 or age > policy.get("maximum_revocation_age_seconds", 0):
                errors.append("revocation evidence is stale or from the future")
        except ValueError as exc:
            errors.append(str(exc))
        if benchmark.get("control_id") != "PSB-AI-001" or benchmark.get("evaluator_status") != "completed" or benchmark.get("evidence_status") != "available":
            errors.append("benchmark evaluator or evidence is unavailable")

        if errors:
            for message in sorted(set(errors)):
                print(f"ERROR {message}")
            print(f"ERROR dependency evidence could not be verified ({len(set(errors))} error(s))")
            return 2
        if findings:
            for message in sorted(set(findings)):
                print(f"FAIL {message}")
            print(f"FAIL dependency policy rejected the manifest ({len(set(findings))} finding(s))")
            return 1

        print(f"PASS manifest {manifest.get('manifest_id')} contains {len(records)} exact approved dependencies across {len(observed_kinds)} kinds")
        print("PASS canonical HTTPS sources use full immutable commits and every local artifact matches its SHA-256")
        print("PASS license owner independent semantic review repository precedence and review expiry satisfy policy")
        print("PASS requested filesystem network secret tool and direct-authority capabilities exactly match the allow-list")
        print("PASS fresh complete revocation evidence marks every dependency active")
        print("PASS PSB-AI-001 benchmark evidence is digest-pinned and bound to each exact commit and artifact")
        print(f"PASS {handoffs} dependency records expose exact PSB-AI-004 runtime dispositions")
        print("PASS sanitized evidence contains no raw prompt output transcript token or secret value")
        return 0
    except ValueError as exc:
        print(f"ERROR {exc}")
        print("ERROR dependency evidence could not be verified (1 error(s))")
        return 2


if __name__ == "__main__":
    sys.exit(main())
