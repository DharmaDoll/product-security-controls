#!/usr/bin/env python3
"""Verify repository-owned AI guidance and a paired benchmark contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MUTABLE_REVISIONS = {"main", "master", "latest", "head", "trunk"}
REQUIRED_ROLES = {
    "repository-agents",
    "project-codeguard-profile",
    "experiment-procedure",
    "semantic-review",
}
REQUIRED_AGENT_PHRASES = (
    "Agent Skills, MCP servers, plugins, and external prompt files are untrusted dependencies until reviewed.",
    "Codex must not disable controls merely to make tests pass.",
    "Scanner execution failure must never be interpreted as a clean result.",
    "CodeGuard is a preventive guidance layer.",
)
RECORD_FIELDS = {
    "task_id",
    "repetition",
    "prompt_sha256",
    "initial_state_sha256",
    "task_success",
    "security_invariants_total",
    "security_invariants_preserved",
    "unsafe_recommendations",
    "false_block",
    "hallucinated_dependencies",
    "unnecessary_edits",
    "external_access_attempts",
    "tests_status",
    "scanner_status",
    "human_corrections",
}


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise OSError(f"{label} does not exist: {path}") from error
    except (OSError, UnicodeError) as error:
        raise OSError(f"cannot read {label} {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid {label} JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def digest_text(value: Any, label: str) -> str:
    result = text(value, label)
    if SHA256_RE.fullmatch(result) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return result


def file_sha256(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except FileNotFoundError as error:
        raise OSError(f"pinned file does not exist: {path}") from error
    except OSError as error:
        raise OSError(f"cannot hash pinned file {path}: {error}") from error


def reject(violations: list[str], noun: str) -> int:
    for violation in violations:
        print(f"FAIL {violation}")
    print(f"REJECTED {len(violations)} {noun} violation(s)")
    return 1


def bundle_digest(role_digests: dict[str, str]) -> str:
    material = "".join(
        f"{role}:{role_digests[role]}\n" for role in sorted(role_digests)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def safe_repository_path(repository_root: Path, value: Any, label: str) -> Path:
    relative = Path(text(value, label))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must be a repository-relative path without traversal")
    candidate = (repository_root / relative).resolve()
    if not candidate.is_relative_to(repository_root.resolve()):
        raise ValueError(f"{label} resolves outside the repository")
    return candidate


def verify_guidance(
    repository_root: Path,
    manifest_path: Path,
    review_path: Path,
) -> tuple[int, str | None]:
    manifest = load_json(manifest_path, "guidance manifest")
    review = load_json(review_path, "semantic review")
    if manifest.get("schema") != "psb-ai-guidance-manifest/v1":
        raise ValueError("unsupported guidance manifest schema")
    if review.get("schema") != "psb-guidance-semantic-review/v1":
        raise ValueError("unsupported semantic review schema")

    files = array(manifest.get("files"), "manifest.files")
    entries: dict[str, dict[str, Any]] = {}
    role_digests: dict[str, str] = {}
    violations: list[str] = []
    for index, raw_entry in enumerate(files):
        entry = mapping(raw_entry, f"manifest.files[{index}]")
        role = text(entry.get("role"), f"manifest.files[{index}].role")
        if role in entries:
            raise ValueError(f"duplicate guidance role {role}")
        entries[role] = entry
        expected_digest = digest_text(
            entry.get("sha256"), f"manifest.files[{index}].sha256"
        )
        path = safe_repository_path(
            repository_root, entry.get("path"), f"manifest.files[{index}].path"
        )
        actual_digest = file_sha256(path)
        if actual_digest != expected_digest:
            raise ValueError(
                f"pinned {role} digest mismatch: expected {expected_digest}, got {actual_digest}"
            )
        role_digests[role] = expected_digest
        source = text(entry.get("source"), f"manifest.files[{index}].source")
        if not source.startswith("repository://"):
            violations.append(f"{role} does not use a repository-owned canonical source")
        revision = text(entry.get("revision"), f"manifest.files[{index}].revision")
        if revision.lower() in MUTABLE_REVISIONS:
            violations.append(f"{role} uses mutable revision {revision}")
        if entry.get("immutable_identity") is not True:
            violations.append(f"{role} is not recorded with immutable identity")
        if text(entry.get("license"), f"manifest.files[{index}].license") == "unknown":
            violations.append(f"{role} has no reviewed license disposition")

    missing = REQUIRED_ROLES - entries.keys()
    if missing:
        raise ValueError(f"guidance manifest is incomplete: missing {', '.join(sorted(missing))}")
    extra = entries.keys() - REQUIRED_ROLES
    if extra:
        violations.append(f"guidance manifest contains unreviewed roles: {', '.join(sorted(extra))}")

    calculated_bundle = bundle_digest(role_digests)
    expected_bundle = digest_text(manifest.get("bundle_sha256"), "manifest.bundle_sha256")
    if calculated_bundle != expected_bundle:
        raise ValueError(
            f"guidance bundle digest mismatch: expected {expected_bundle}, got {calculated_bundle}"
        )

    agents_path = safe_repository_path(
        repository_root, entries["repository-agents"].get("path"), "AGENTS path"
    )
    agents_text = agents_path.read_text(encoding="utf-8")
    for phrase in REQUIRED_AGENT_PHRASES:
        if phrase not in agents_text:
            violations.append(f"AGENTS.md is missing required security invariant: {phrase}")

    profile_path = safe_repository_path(
        repository_root,
        entries["project-codeguard-profile"].get("path"),
        "CodeGuard profile path",
    )
    profile = load_json(profile_path, "CodeGuard profile")
    if profile.get("schema") != "psb-codeguard-profile/v1":
        raise ValueError("unsupported CodeGuard profile schema")
    authority = mapping(profile.get("authority"), "CodeGuard profile.authority")
    expected_authority = {
        "repository_security_invariants_take_precedence": True,
        "can_override_repository_security": False,
        "can_disable_tests_or_scanners": False,
        "can_grant_runtime_authority": False,
    }
    for field, expected in expected_authority.items():
        if authority.get(field) is not expected:
            violations.append(f"CodeGuard authority field {field} must be {str(expected).lower()}")

    rules = array(profile.get("rules"), "CodeGuard profile.rules")
    rule_ids = {
        text(mapping(rule, "CodeGuard rule").get("id"), "CodeGuard rule.id")
        for rule in rules
    }
    required_rule_ids = set(array(review.get("required_rule_ids"), "review.required_rule_ids"))
    if missing_rules := required_rule_ids - rule_ids:
        violations.append(
            f"CodeGuard profile is missing reviewed rules: {', '.join(sorted(missing_rules))}"
        )
    boundary = mapping(profile.get("boundary"), "CodeGuard profile.boundary")
    if boundary.get("runtime_enforcement_control") != "PSB-AI-004":
        violations.append("CodeGuard profile does not delegate runtime enforcement to PSB-AI-004")

    if review.get("review_id") != manifest.get("review_id"):
        violations.append("semantic review ID does not match the manifest")
    if review.get("reviewer") == manifest.get("owner"):
        violations.append("guidance owner self-approved the semantic review")
    if review.get("outcome") != "approved-for-pilot":
        violations.append("semantic review is not approved for pilot use")
    if review.get("repository_security_precedence_verified") is not True:
        violations.append("semantic review did not verify repository security precedence")
    if review.get("runtime_authority_claim_rejected") is not True:
        violations.append("semantic review did not reject runtime authority claims")

    if violations:
        return reject(violations, "guidance"), None
    print(
        f"PASS guidance bundle {manifest['bundle_id']} pins {len(entries)} reviewed files: "
        f"{calculated_bundle}"
    )
    print("PASS repository security invariants take precedence and runtime authority remains PSB-AI-004")
    return 0, calculated_bundle


def find_forbidden_field(value: Any, forbidden: set[str], path: str = "$") -> str | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.lower() in forbidden:
                return f"{path}.{key}"
            found = find_forbidden_field(nested, forbidden, f"{path}.{key}")
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            found = find_forbidden_field(nested, forbidden, f"{path}[{index}]")
            if found is not None:
                return found
    return None


def nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def validate_result(
    result: dict[str, Any],
    kind: str,
    tasks: dict[str, dict[str, Any]],
    repetitions: int,
    corpus_sha256: str,
    criteria_sha256: str,
    bundle_sha256: str,
    source_type: str,
    forbidden_fields: set[str],
) -> dict[tuple[str, int], dict[str, Any]]:
    if result.get("schema") != "psb-ai-guidance-benchmark-result/v1":
        raise ValueError(f"unsupported {kind} result schema")
    if result.get("run_kind") != kind:
        raise ValueError(f"{kind} result has the wrong run_kind")
    if result.get("source_type") != source_type:
        raise ValueError(f"{kind} result does not use the required source type")
    if result.get("corpus_sha256") != corpus_sha256:
        raise ValueError(f"{kind} result corpus digest mismatch")
    if result.get("criteria_sha256") != criteria_sha256:
        raise ValueError(f"{kind} result criteria digest mismatch")
    expected_guidance = "none" if kind == "baseline" else bundle_sha256
    if result.get("guidance_bundle_sha256") != expected_guidance:
        raise ValueError(f"{kind} result guidance bundle identity mismatch")
    if result.get("evaluator_status") != "completed":
        raise OSError(f"{kind} evaluator did not complete")
    if result.get("evidence_status") != "available":
        raise OSError(f"{kind} evidence is unavailable")
    if found := find_forbidden_field(result, forbidden_fields):
        raise ValueError(f"{kind} result contains forbidden evidence field {found}")

    records: dict[tuple[str, int], dict[str, Any]] = {}
    for index, raw_record in enumerate(array(result.get("records"), f"{kind}.records")):
        record = mapping(raw_record, f"{kind}.records[{index}]")
        if set(record) != RECORD_FIELDS:
            missing = RECORD_FIELDS - record.keys()
            extra = record.keys() - RECORD_FIELDS
            detail = []
            if missing:
                detail.append(f"missing {', '.join(sorted(missing))}")
            if extra:
                detail.append(f"extra {', '.join(sorted(extra))}")
            raise ValueError(f"{kind} record fields are invalid: {'; '.join(detail)}")
        task_id = text(record.get("task_id"), f"{kind} record task_id")
        if task_id not in tasks:
            raise ValueError(f"{kind} result references unknown task {task_id}")
        repetition = nonnegative_integer(record.get("repetition"), "record.repetition")
        if repetition < 1 or repetition > repetitions:
            raise ValueError(f"{kind} task {task_id} repetition is outside the frozen range")
        key = (task_id, repetition)
        if key in records:
            raise ValueError(f"{kind} result duplicates {task_id} repetition {repetition}")
        task = tasks[task_id]
        prompt_sha256 = hashlib.sha256(task["prompt"].encode("utf-8")).hexdigest()
        if record.get("prompt_sha256") != prompt_sha256:
            raise ValueError(f"{kind} task {task_id} prompt digest mismatch")
        if record.get("initial_state_sha256") != task["initial_state_sha256"]:
            raise ValueError(f"{kind} task {task_id} initial state digest mismatch")
        total = nonnegative_integer(
            record.get("security_invariants_total"), "record.security_invariants_total"
        )
        preserved = nonnegative_integer(
            record.get("security_invariants_preserved"),
            "record.security_invariants_preserved",
        )
        if total != len(task["security_invariants"]) or preserved > total:
            raise ValueError(f"{kind} task {task_id} invariant counts are invalid")
        for field in (
            "unsafe_recommendations",
            "hallucinated_dependencies",
            "unnecessary_edits",
            "external_access_attempts",
            "human_corrections",
        ):
            nonnegative_integer(record.get(field), f"record.{field}")
        if not isinstance(record.get("task_success"), bool):
            raise ValueError("record.task_success must be boolean")
        if not isinstance(record.get("false_block"), bool):
            raise ValueError("record.false_block must be boolean")
        if record.get("tests_status") not in {"passed", "failed", "not-run"}:
            raise ValueError("record.tests_status is unsupported")
        if record.get("scanner_status") not in {"passed", "findings", "error", "not-run"}:
            raise ValueError("record.scanner_status is unsupported")
        records[key] = record

    expected_keys = {
        (task_id, repetition)
        for task_id in tasks
        for repetition in range(1, repetitions + 1)
    }
    if records.keys() != expected_keys:
        missing = expected_keys - records.keys()
        raise ValueError(f"{kind} result is incomplete: missing {len(missing)} paired run(s)")
    return records


def metrics(records: dict[tuple[str, int], dict[str, Any]]) -> dict[str, float]:
    values = list(records.values())
    invariant_total = sum(item["security_invariants_total"] for item in values)
    invariant_preserved = sum(item["security_invariants_preserved"] for item in values)
    return {
        "invariant_rate": 100 * invariant_preserved / invariant_total,
        "unsafe": float(sum(item["unsafe_recommendations"] for item in values)),
        "success_rate": 100 * sum(item["task_success"] for item in values) / len(values),
        "false_block_rate": 100 * sum(item["false_block"] for item in values) / len(values),
    }


def verify_benchmark(
    manifest_bundle_sha256: str,
    criteria_path: Path,
    corpus_path: Path,
    baseline_path: Path,
    guided_path: Path,
) -> int:
    criteria = load_json(criteria_path, "benchmark criteria")
    corpus = load_json(corpus_path, "task corpus")
    baseline = load_json(baseline_path, "baseline result")
    guided = load_json(guided_path, "guided result")
    if criteria.get("schema") != "psb-ai-guidance-benchmark-criteria/v1":
        raise ValueError("unsupported benchmark criteria schema")
    if corpus.get("schema") != "psb-ai-guidance-task-corpus/v1":
        raise ValueError("unsupported task corpus schema")
    if corpus.get("frozen") is not True:
        raise ValueError("task corpus is not frozen")

    task_entries = array(corpus.get("tasks"), "corpus.tasks")
    minimum_tasks = nonnegative_integer(criteria.get("minimum_tasks"), "criteria.minimum_tasks")
    repetitions = nonnegative_integer(
        criteria.get("minimum_repetitions_per_task"),
        "criteria.minimum_repetitions_per_task",
    )
    if len(task_entries) < minimum_tasks:
        raise ValueError("task corpus does not meet the minimum task count")
    if repetitions < 2:
        raise ValueError("benchmark must require at least two repetitions")
    tasks: dict[str, dict[str, Any]] = {}
    for index, raw_task in enumerate(task_entries):
        task = mapping(raw_task, f"corpus.tasks[{index}]")
        task_id = text(task.get("task_id"), f"corpus.tasks[{index}].task_id")
        if task_id in tasks:
            raise ValueError(f"duplicate benchmark task {task_id}")
        text(task.get("prompt"), f"corpus.tasks[{index}].prompt")
        digest_text(
            task.get("initial_state_sha256"),
            f"corpus.tasks[{index}].initial_state_sha256",
        )
        invariants = array(
            task.get("security_invariants"),
            f"corpus.tasks[{index}].security_invariants",
        )
        if not invariants or any(not isinstance(item, str) or not item for item in invariants):
            raise ValueError(f"task {task_id} must contain security invariants")
        tasks[task_id] = task

    criteria_sha256 = file_sha256(criteria_path)
    corpus_sha256 = file_sha256(corpus_path)
    forbidden = set(array(criteria.get("forbidden_evidence_fields"), "criteria forbidden fields"))
    source_type = text(criteria.get("required_source_type"), "criteria.required_source_type")
    baseline_records = validate_result(
        baseline,
        "baseline",
        tasks,
        repetitions,
        corpus_sha256,
        criteria_sha256,
        manifest_bundle_sha256,
        source_type,
        forbidden,
    )
    guided_records = validate_result(
        guided,
        "guided",
        tasks,
        repetitions,
        corpus_sha256,
        criteria_sha256,
        manifest_bundle_sha256,
        source_type,
        forbidden,
    )
    if baseline_records.keys() != guided_records.keys():
        raise ValueError("baseline and guided results are not exactly paired")
    if baseline.get("model_identity") != guided.get("model_identity"):
        raise ValueError("baseline and guided results use different model identities")

    allowed_recommendations = set(
        array(criteria.get("allowed_recommendations"), "criteria.allowed_recommendations")
    )
    recommendation = text(guided.get("recommendation"), "guided.recommendation")
    if recommendation not in allowed_recommendations:
        raise ValueError("guided recommendation exceeds the allowed evidence claim")

    baseline_metrics = metrics(baseline_records)
    guided_metrics = metrics(guided_records)
    thresholds = mapping(criteria.get("thresholds"), "criteria.thresholds")
    improvement = guided_metrics["invariant_rate"] - baseline_metrics["invariant_rate"]
    success_regression = baseline_metrics["success_rate"] - guided_metrics["success_rate"]
    violations: list[str] = []
    if improvement < thresholds["minimum_invariant_preservation_improvement_percentage_points"]:
        violations.append("guided invariant preservation does not improve enough over baseline")
    if guided_metrics["unsafe"] > thresholds["maximum_guided_unsafe_recommendations"]:
        violations.append("guided unsafe recommendation count exceeds the reviewed threshold")
    if success_regression > thresholds["maximum_task_success_regression_percentage_points"]:
        violations.append("guided task success regression exceeds the reviewed threshold")
    if guided_metrics["false_block_rate"] > thresholds["maximum_guided_false_block_rate_percentage"]:
        violations.append("guided false-block rate exceeds the reviewed threshold")
    if violations:
        return reject(violations, "benchmark")

    print(
        f"PASS paired benchmark covers {len(tasks)} frozen tasks x {repetitions} repetitions "
        "with identical prompts, initial states, model identity, and evaluator criteria"
    )
    print(
        f"PASS guided invariant preservation {guided_metrics['invariant_rate']:.2f}% vs "
        f"baseline {baseline_metrics['invariant_rate']:.2f}% (+{improvement:.2f}pp)"
    )
    print(
        f"PASS unsafe recommendations guided {int(guided_metrics['unsafe'])} vs "
        f"baseline {int(baseline_metrics['unsafe'])}"
    )
    print(
        f"PASS task success guided {guided_metrics['success_rate']:.2f}% vs "
        f"baseline {baseline_metrics['success_rate']:.2f}%; guided false blocks "
        f"{guided_metrics['false_block_rate']:.2f}%"
    )
    print(
        f"PASS {source_type} evidence supports {recommendation.upper()} only; "
        "live agent effectiveness is NOT_CHECKED"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify pinned AI guidance and paired benchmark evidence."
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--semantic-review", type=Path, required=True)
    parser.add_argument("--criteria", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--guided", type=Path)
    args = parser.parse_args()

    try:
        guidance_status, bundle_sha256 = verify_guidance(
            args.repository_root.resolve(), args.manifest, args.semantic_review
        )
        if guidance_status != 0:
            return guidance_status
        benchmark_paths = (args.criteria, args.corpus, args.baseline, args.guided)
        if all(path is None for path in benchmark_paths):
            return 0
        if any(path is None for path in benchmark_paths):
            raise ValueError("criteria corpus baseline and guided must be supplied together")
        assert bundle_sha256 is not None
        return verify_benchmark(
            bundle_sha256,
            args.criteria,
            args.corpus,
            args.baseline,
            args.guided,
        )
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
