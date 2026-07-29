#!/usr/bin/env python3
"""Assess scoped SLSA Build L2 adoption from reviewed evidence metadata."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


POLICY_SCHEMA = "psb-framework-assessment-policy/v1"
INPUT_SCHEMA = "psb-slsa-build-l2-assessment-input/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CODE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
EVIDENCE_FIELDS = {
    "code",
    "type",
    "issuer_role",
    "uri",
    "sha256",
    "scope_sha256",
    "observed_at",
    "result",
    "immutable",
    "authenticated",
    "reviewed",
}
INPUT_FIELDS = {
    "schema_version",
    "source",
    "assessed_at",
    "scope",
    "evidence_catalog",
}
SCOPE_FIELDS = {
    "producer_id",
    "build_platform_id",
    "consumer_id",
    "artifact_family",
    "release_id",
    "source_revision",
}
STATUSES = ("PASS", "FAIL", "NOT_CHECKED", "ERROR")
DISCLAIMER = (
    "This scoped assessment is not certification or a general compliance claim."
)


class AssessmentError(ValueError):
    """Assessment input or profile data could not be evaluated safely."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AssessmentError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise AssessmentError(f"{label} must be an object")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise AssessmentError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AssessmentError(f"{label} must be a timestamp") from error
    if parsed.tzinfo is None:
        raise AssessmentError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def text_field(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise AssessmentError(f"{label}.{field} must be non-empty text")
    return result


def canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_https_uri(value: str) -> bool:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return all(
        (
            parsed.scheme == "https",
            bool(parsed.hostname),
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            parsed.query == "",
            parsed.fragment == "",
        )
    )


def require_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if (
        policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("profile_id") != "slsa-build-l2"
        or policy.get("framework") != "slsa"
        or policy.get("framework_version") != "1.2"
        or policy.get("track") != "build"
        or policy.get("target_level") != 2
    ):
        raise AssessmentError("SLSA Build L2 assessment policy is unsupported")
    maximum_age = policy.get("maximum_evidence_age_seconds")
    if (
        not isinstance(maximum_age, int)
        or isinstance(maximum_age, bool)
        or maximum_age < 1
    ):
        raise AssessmentError("assessment evidence age policy is malformed")
    issuers = policy.get("required_evidence_issuers")
    requirements = policy.get("requirements")
    if (
        not isinstance(issuers, dict)
        or not issuers
        or not isinstance(requirements, dict)
        or len(requirements) != 7
    ):
        raise AssessmentError("assessment requirement policy is incomplete")
    for evidence_type, role in issuers.items():
        if (
            not isinstance(evidence_type, str)
            or not CODE_RE.fullmatch(evidence_type)
            or not isinstance(role, str)
            or not role
        ):
            raise AssessmentError("assessment evidence issuer policy is malformed")
    for requirement_id, required_types in requirements.items():
        if (
            not isinstance(requirement_id, str)
            or not isinstance(required_types, list)
            or not required_types
            or len(required_types) != len(set(required_types))
            or any(value not in issuers for value in required_types)
        ):
            raise AssessmentError("assessment requirement evidence policy is malformed")
    return policy


def load_coverage(
    path: Path,
    policy: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except (OSError, UnicodeError, csv.Error) as error:
        raise AssessmentError("SLSA Build L2 coverage is unavailable") from error
    coverage: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("Profile") != policy["profile_id"]:
            continue
        requirement_id = row.get("Requirement ID", "")
        if not requirement_id or requirement_id in coverage:
            raise AssessmentError("SLSA Build L2 coverage is malformed")
        mapped_checks = [
            value.strip()
            for value in row.get("Mapped Checks", "").split(";")
            if value.strip()
        ]
        coverage[requirement_id] = {
            "title": row.get("Requirement", ""),
            "responsibility": row.get("Responsibility", ""),
            "status": row.get("Status", ""),
            "mapped_checks": mapped_checks,
            "version": row.get("Framework Version", ""),
            "track": row.get("Track", ""),
            "target_level": row.get("Target Level", ""),
        }
    if set(coverage) != set(policy["requirements"]):
        raise AssessmentError("SLSA Build L2 coverage requirement set is incomplete")
    for row in coverage.values():
        if (
            not row["title"]
            or not row["responsibility"]
            or row["version"] != policy["framework_version"]
            or row["track"] != policy["track"]
            or row["target_level"] != str(policy["target_level"])
        ):
            raise AssessmentError("SLSA Build L2 coverage metadata is malformed")
    return coverage


def require_scope(document: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scope = document.get("scope")
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise AssessmentError("assessment scope is malformed")
    for field in (
        "producer_id",
        "build_platform_id",
        "consumer_id",
        "artifact_family",
        "release_id",
        "source_revision",
    ):
        text_field(scope, field, "assessment.scope")
    for field in ("producer_id", "build_platform_id", "consumer_id"):
        if not safe_https_uri(scope[field]):
            raise AssessmentError(f"assessment.scope.{field} must be an HTTPS identity")
    if COMMIT_RE.fullmatch(scope["source_revision"]) is None:
        raise AssessmentError("assessment.scope.source_revision must be a full commit")
    return scope, canonical_digest(scope)


def index_evidence(
    document: dict[str, Any],
    policy: dict[str, Any],
    scope_digest: str,
    assessed_at: datetime,
) -> dict[str, dict[str, str]]:
    catalog = document.get("evidence_catalog")
    if not isinstance(catalog, list):
        raise AssessmentError("assessment evidence catalog must be a list")
    indexed: dict[str, dict[str, str]] = {}
    codes: set[str] = set()
    for index, raw in enumerate(catalog):
        label = f"assessment.evidence_catalog[{index}]"
        if not isinstance(raw, dict) or set(raw) != EVIDENCE_FIELDS:
            raise AssessmentError(f"{label} fields are malformed")
        code = text_field(raw, "code", label)
        evidence_type = text_field(raw, "type", label)
        if (
            CODE_RE.fullmatch(code) is None
            or evidence_type not in policy["required_evidence_issuers"]
            or code in codes
            or evidence_type in indexed
        ):
            raise AssessmentError("assessment evidence identities are malformed")
        codes.add(code)
        digest = text_field(raw, "sha256", label)
        evidence_scope = text_field(raw, "scope_sha256", label)
        if (
            SHA256_RE.fullmatch(digest) is None
            or SHA256_RE.fullmatch(evidence_scope) is None
        ):
            raise AssessmentError(f"{label} digest is malformed")
        result = text_field(raw, "result", label)
        if result not in {"pass", "finding", "error"}:
            raise AssessmentError(f"{label}.result is unsupported")
        observed_at = parse_time(raw.get("observed_at"), f"{label}.observed_at")
        age = (assessed_at - observed_at).total_seconds()
        metadata_ok = all(
            (
                raw.get("issuer_role")
                == policy["required_evidence_issuers"][evidence_type],
                safe_https_uri(text_field(raw, "uri", label)),
                evidence_scope == scope_digest,
                0 <= age <= policy["maximum_evidence_age_seconds"],
                raw.get("immutable") is True,
                raw.get("authenticated") is True,
                raw.get("reviewed") is True,
            )
        )
        # Collection/verification failures must remain ERROR even when their
        # surrounding metadata is also invalid. They must never be reported as
        # an ordinary finding, much less a clean result.
        effective_result = (
            "error" if result == "error" else result if metadata_ok else "finding"
        )
        indexed[evidence_type] = {
            "code": code,
            "result": effective_result,
        }
    return indexed


def assess(
    policy_document: dict[str, Any],
    coverage_path: Path,
    evidence_document: dict[str, Any],
    generated_at: datetime,
) -> dict[str, Any]:
    policy = require_policy(policy_document)
    if set(evidence_document) != INPUT_FIELDS:
        raise AssessmentError("assessment input fields are malformed")
    if evidence_document.get("schema_version") != INPUT_SCHEMA:
        raise AssessmentError("assessment input schema is unsupported")
    source = evidence_document.get("source")
    if source not in {"live", "test-fixture"}:
        raise AssessmentError("assessment source is unsupported")
    assessed_at = parse_time(
        evidence_document.get("assessed_at"), "assessment.assessed_at"
    )
    if assessed_at > generated_at:
        raise AssessmentError("assessment time is from the future")
    _, scope_digest = require_scope(evidence_document)
    coverage = load_coverage(coverage_path, policy)
    evidence = index_evidence(
        evidence_document,
        policy,
        scope_digest,
        assessed_at,
    )

    results: list[dict[str, Any]] = []
    for requirement_id, required_types in policy["requirements"].items():
        coverage_row = coverage[requirement_id]
        available = [
            evidence[evidence_type]
            for evidence_type in required_types
            if evidence_type in evidence
        ]
        codes = sorted(item["code"] for item in available)
        if any(item["result"] == "error" for item in available):
            status = "ERROR"
            detail = "required evidence collection or verification failed"
        elif any(item["result"] == "finding" for item in available):
            status = "FAIL"
            detail = "required evidence contains a security finding"
        elif (
            coverage_row["status"] != "mapped-evidence"
            or not coverage_row["mapped_checks"]
            or len(available) != len(required_types)
        ):
            status = "NOT_CHECKED"
            detail = "required reviewed mapping or scoped evidence is missing"
        else:
            status = "PASS"
            detail = "all required scoped evidence passed"
        results.append(
            {
                "requirement_id": requirement_id,
                "title": coverage_row["title"],
                "responsibility": coverage_row["responsibility"],
                "status": status,
                "mapped_checks": sorted(coverage_row["mapped_checks"]),
                "evidence_codes": codes,
                "detail": detail,
            }
        )

    counts = Counter(result["status"] for result in results)
    summary = {status: counts.get(status, 0) for status in STATUSES}
    if summary["ERROR"]:
        conclusion = "ERROR"
    elif summary["FAIL"]:
        conclusion = "FAIL"
    elif summary["NOT_CHECKED"]:
        conclusion = "INCOMPLETE"
    else:
        conclusion = "PASS"
    return {
        "schema_version": "1.0",
        "assessment_kind": "framework-adoption",
        "source": source,
        "generated_at": generated_at.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "profile": {
            "id": policy["profile_id"],
            "framework": policy["framework"],
            "version": policy["framework_version"],
            "track": policy["track"],
            "target_level": policy["target_level"],
        },
        "scope_sha256": scope_digest,
        "conclusion": conclusion,
        "summary": summary,
        "results": results,
        "disclaimer": DISCLAIMER,
    }


def write_outputs(
    result: dict[str, Any],
    json_output: Path,
    csv_output: Path,
) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    csv_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with csv_output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "Profile",
                "Framework Version",
                "Target Level",
                "Scope SHA-256",
                "Requirement ID",
                "Responsibility",
                "Status",
                "Mapped Checks",
                "Evidence Codes",
                "Detail",
                "Disclaimer",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        for item in result["results"]:
            writer.writerow(
                {
                    "Profile": result["profile"]["id"],
                    "Framework Version": result["profile"]["version"],
                    "Target Level": result["profile"]["target_level"],
                    "Scope SHA-256": result["scope_sha256"],
                    "Requirement ID": item["requirement_id"],
                    "Responsibility": item["responsibility"],
                    "Status": item["status"],
                    "Mapped Checks": "; ".join(item["mapped_checks"]),
                    "Evidence Codes": "; ".join(item["evidence_codes"]),
                    "Detail": item["detail"],
                    "Disclaimer": result["disclaimer"],
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--now")
    args = parser.parse_args()
    try:
        generated_at = (
            parse_time(args.now, "assessment generation time")
            if args.now
            else datetime.now(timezone.utc)
        )
        result = assess(
            load_json(args.policy, "assessment policy"),
            args.coverage,
            load_json(args.evidence, "assessment evidence"),
            generated_at,
        )
        write_outputs(result, args.json_output, args.csv_output)
    except AssessmentError as error:
        print(f"ERROR slsa-build-l2 assessment unavailable: {error}")
        return 2

    for item in result["results"]:
        print(
            f"{item['status']} slsa-build-l2 "
            f"requirement={item['requirement_id']} "
            f"responsibility={item['responsibility']} "
            f"evidence={len(item['evidence_codes'])}"
        )
    summary = result["summary"]
    print(
        f"RESULT {result['conclusion']} profile=slsa-build-l2 "
        f"requirements={len(result['results'])} "
        f"pass={summary['PASS']} fail={summary['FAIL']} "
        f"not_checked={summary['NOT_CHECKED']} error={summary['ERROR']}"
    )
    if result["conclusion"] == "PASS":
        return 0
    if result["conclusion"] == "ERROR":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
