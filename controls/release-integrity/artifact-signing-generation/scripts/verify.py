#!/usr/bin/env python3
"""Verify provider-neutral release artifact signing-generation evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


CONTROL = "PSB-REL-005"
CHECKS = {
    "ASG-001": "exact immutable artifact and release request",
    "ASG-002": "short-lived exact workload signing authorization",
    "ASG-003": "active non-exportable sign-only signer",
    "ASG-004": "signed statement binds request artifact release source and signer",
    "ASG-005": "signature verifies with the policy-pinned public key",
    "ASG-006": "immutable signature publication and transparency receipt",
    "ASG-007": "signing failure blocks release completion",
    "ASG-008": "metadata-only evidence and fail-closed evaluation",
}
FULL_SHA256 = re.compile(r"^[0-9a-f]{64}$")
FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


class EvaluationError(RuntimeError):
    """Trusted input or verification infrastructure cannot be evaluated."""


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvaluationError(f"cannot read {label}") from error


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path, label))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"cannot parse {label}") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return value


def object_at(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    result = value.get(key)
    if not isinstance(result, dict):
        raise EvaluationError(f"{label}.{key} must be an object")
    return result


def text_at(value: dict[str, Any], key: str, label: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise EvaluationError(f"{label}.{key} must be non-empty text")
    return result


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


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def add(findings: dict[str, list[str]], check: str, message: str) -> None:
    if message not in findings[check]:
        findings[check].append(message)


def resolve_public_key(policy_path: Path, policy: dict[str, Any]) -> Path:
    relative = Path(text_at(policy, "trusted_public_key", "policy"))
    if relative.is_absolute() or ".." in relative.parts:
        raise EvaluationError("trusted public key must remain inside policy directory")
    path = (policy_path.parent / relative).resolve()
    if not path.is_file():
        raise EvaluationError("trusted public key is unavailable")
    expected = text_at(policy, "trusted_public_key_sha256", "policy")
    if not FULL_SHA256.fullmatch(expected) or sha256(read_bytes(path, "public key")) != expected:
        raise EvaluationError("trusted public key digest does not match policy")
    return path


def verify_signature(
    statement_path: Path, signature_path: Path, public_key: Path, openssl: str
) -> tuple[bool, bytes]:
    encoded = read_bytes(signature_path, "signature").strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EvaluationError("signature is not valid base64") from error
    try:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(signature)
            handle.flush()
            result = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(statement_path),
                    "-sigfile",
                    handle.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    except OSError as error:
        raise EvaluationError("cannot execute OpenSSL") from error
    return result.returncode == 0, signature


def evaluate_preflight(
    policy: dict[str, Any],
    artifact: bytes,
    request: dict[str, Any],
    authorization: dict[str, Any],
    signer: dict[str, Any],
    as_of: datetime,
) -> dict[str, list[str]]:
    findings = {check: [] for check in CHECKS}
    if policy.get("schema") != "psb-artifact-signing-policy/1.0":
        raise EvaluationError("unsupported signing policy schema")
    expected = object_at(policy, "expected", "policy")
    for field in (
        "artifact_family",
        "artifact_name",
        "release_id",
        "release_ref",
        "source_repository",
        "source_revision",
        "workload_identity",
        "audience",
        "scope",
        "signer_id",
        "key_version",
    ):
        text_at(expected, field, "policy.expected")
    if policy.get("signature_algorithm") != "ed25519" or policy.get("digest_algorithm") != "sha256":
        add(findings, "ASG-005", "signing policy allows unsupported algorithms")
    maximum_auth = policy.get("maximum_authorization_seconds")
    maximum_status = policy.get("maximum_signer_status_age_hours")
    if not isinstance(maximum_auth, int) or isinstance(maximum_auth, bool) or maximum_auth <= 0:
        raise EvaluationError("policy.maximum_authorization_seconds must be positive")
    if not isinstance(maximum_status, int) or isinstance(maximum_status, bool) or maximum_status <= 0:
        raise EvaluationError("policy.maximum_signer_status_age_hours must be positive")

    if request.get("schema") != "psb-artifact-signing-request/1.0":
        raise EvaluationError("unsupported signing request schema")
    artifact_claim = object_at(request, "artifact", "request")
    release = object_at(request, "release", "request")
    source = object_at(request, "source", "request")
    artifact_digest = sha256(artifact)
    request_ok = (
        artifact_claim.get("family") == expected.get("artifact_family")
        and artifact_claim.get("name") == expected.get("artifact_name")
        and artifact_claim.get("sha256") == artifact_digest
        and release.get("id") == expected.get("release_id")
        and release.get("ref") == expected.get("release_ref")
        and isinstance(release.get("ref"), str)
        and release["ref"].startswith("refs/tags/")
        and "latest" not in release["id"].lower()
        and source.get("repository") == expected.get("source_repository")
        and source.get("revision") == expected.get("source_revision")
        and isinstance(source.get("revision"), str)
        and bool(FULL_GIT_SHA.fullmatch(source["revision"]))
    )
    if not request_ok:
        add(findings, "ASG-001", "signing request does not bind the exact immutable release artifact")

    if authorization.get("schema") != "psb-artifact-signing-authorization/1.0":
        raise EvaluationError("unsupported authorization schema")
    issued = parse_time(authorization.get("issued_at"), "authorization.issued_at")
    expires = parse_time(authorization.get("expires_at"), "authorization.expires_at")
    scopes = authorization.get("scopes")
    auth_ok = (
        authorization.get("status") == "ACTIVE"
        and authorization.get("workload_identity") == expected.get("workload_identity")
        and authorization.get("audience") == expected.get("audience")
        and scopes == [expected.get("scope")]
        and authorization.get("artifact_family") == expected.get("artifact_family")
        and authorization.get("artifact_sha256") == artifact_digest
        and authorization.get("release_id") == expected.get("release_id")
        and authorization.get("signer_id") == expected.get("signer_id")
        and expires > issued
        and expires - issued <= timedelta(seconds=maximum_auth)
        and issued <= as_of <= expires
        and isinstance(authorization.get("nonce"), str)
        and len(authorization["nonce"]) >= 24
        and authorization.get("token_retained") is False
        and policy.get("require_token_non_retention") is True
        and maximum_auth <= 300
    )
    if not auth_ok:
        add(findings, "ASG-002", "signing authorization is broad stale retained or not request-bound")

    if signer.get("schema") != "psb-artifact-signer-evidence/1.0":
        raise EvaluationError("unsupported signer evidence schema")
    observed = parse_time(signer.get("observed_at"), "signer.observed_at")
    allowed_types = policy.get("allowed_signer_provider_types")
    required_ops = policy.get("required_signer_operations")
    forbidden_ops = policy.get("forbidden_signer_operations")
    operations = signer.get("allowed_operations")
    lists = (allowed_types, required_ops, forbidden_ops, operations)
    if not all(
        isinstance(items, list)
        and all(isinstance(item, str) and item for item in items)
        for items in lists
    ):
        raise EvaluationError("signer operation and provider policy must use arrays")
    signer_ok = (
        signer.get("available") is True
        and signer.get("provider_type") in allowed_types
        and signer.get("provider_type") in {"kms", "hsm", "keyless"}
        and signer.get("signer_id") == expected.get("signer_id")
        and signer.get("key_version") == expected.get("key_version")
        and signer.get("key_status") == "ACTIVE"
        and signer.get("key_exportable") is False
        and policy.get("require_non_exportable_key") is True
        and set(required_ops).issubset(set(operations))
        and not set(forbidden_ops).intersection(operations)
        and set(operations) == {"sign"}
        and as_of >= observed
        and as_of - observed <= timedelta(hours=maximum_status)
        and signer.get("public_key_sha256") == policy.get("trusted_public_key_sha256")
        and signer.get("private_key_material_in_evidence") is False
    )
    if not signer_ok:
        add(findings, "ASG-003", "signer is unavailable stale exportable overprivileged or outside policy")

    evidence = object_at(policy, "evidence", "policy")
    safe_evidence = (
        evidence.get("include_identity_token") is False
        and evidence.get("include_private_key_material") is False
        and evidence.get("include_signature_body") is False
        and isinstance(evidence.get("allowed_fields"), list)
        and "identity_token" not in evidence.get("allowed_fields", [])
        and "private_key" not in evidence.get("allowed_fields", [])
        and "signature" not in evidence.get("allowed_fields", [])
    )
    if not safe_evidence:
        add(findings, "ASG-008", "evidence policy retains signing credentials or signature body")
    return findings


def evaluate(
    policy_path: Path,
    artifact_path: Path,
    request_path: Path,
    authorization_path: Path,
    signer_path: Path,
    statement_path: Path,
    signature_path: Path,
    receipt_path: Path,
    as_of: datetime,
    openssl: str,
) -> tuple[dict[str, list[str]], str]:
    policy = load_json(policy_path, "signing policy")
    request_bytes = read_bytes(request_path, "signing request")
    authorization_bytes = read_bytes(authorization_path, "authorization")
    statement_bytes = read_bytes(statement_path, "signed statement")
    artifact = read_bytes(artifact_path, "artifact")
    request = load_json(request_path, "signing request")
    authorization = load_json(authorization_path, "authorization")
    signer = load_json(signer_path, "signer evidence")
    statement = load_json(statement_path, "signed statement")
    receipt = load_json(receipt_path, "signing receipt")
    findings = evaluate_preflight(policy, artifact, request, authorization, signer, as_of)
    expected = object_at(policy, "expected", "policy")
    artifact_digest = sha256(artifact)

    statement_artifact = object_at(statement, "artifact", "statement")
    statement_release = object_at(statement, "release", "statement")
    statement_source = object_at(statement, "source", "statement")
    statement_signer = object_at(statement, "signer", "statement")
    signed_at = parse_time(statement.get("signed_at"), "statement.signed_at")
    issued = parse_time(authorization.get("issued_at"), "authorization.issued_at")
    expires = parse_time(authorization.get("expires_at"), "authorization.expires_at")
    statement_ok = (
        statement.get("schema") == "psb-artifact-signature-statement/1.0"
        and statement.get("request_sha256") == sha256(request_bytes)
        and statement.get("authorization_sha256") == sha256(authorization_bytes)
        and statement_artifact.get("family") == expected.get("artifact_family")
        and statement_artifact.get("name") == expected.get("artifact_name")
        and statement_artifact.get("sha256") == artifact_digest
        and statement_release.get("id") == expected.get("release_id")
        and statement_release.get("ref") == expected.get("release_ref")
        and statement_source.get("repository") == expected.get("source_repository")
        and statement_source.get("revision") == expected.get("source_revision")
        and statement_signer.get("id") == expected.get("signer_id")
        and statement_signer.get("key_version") == expected.get("key_version")
        and statement_signer.get("algorithm") == "ed25519"
        and issued <= signed_at <= expires
    )
    if not statement_ok:
        add(findings, "ASG-004", "signed statement is detached from request artifact release source or signer")

    public_key = resolve_public_key(policy_path, policy)
    signature_valid, signature = verify_signature(statement_path, signature_path, public_key, openssl)
    if not signature_valid:
        add(findings, "ASG-005", "artifact signature verification failed")

    if receipt.get("schema") != "psb-artifact-signing-receipt/1.0":
        raise EvaluationError("unsupported signing receipt schema")
    publication = object_at(receipt, "publication", "receipt")
    expected_publication = object_at(policy, "publication", "policy")
    transparency = object_at(receipt, "transparency", "receipt")
    receipt_signed_at = parse_time(receipt.get("signed_at"), "receipt.signed_at")
    integrated_at = parse_time(transparency.get("integrated_at"), "receipt.transparency.integrated_at")
    receipt_ok = (
        receipt.get("status") == "SIGNED"
        and receipt.get("request_sha256") == sha256(request_bytes)
        and receipt.get("statement_sha256") == sha256(statement_bytes)
        and receipt.get("signature_sha256") == sha256(signature)
        and receipt.get("artifact_sha256") == artifact_digest
        and receipt.get("signer_id") == expected.get("signer_id")
        and receipt.get("key_version") == expected.get("key_version")
        and receipt_signed_at == signed_at
        and publication.get("location") == expected_publication.get("location")
        and isinstance(publication.get("location"), str)
        and publication["location"].startswith("https://")
        and "latest" not in publication["location"].lower()
        and publication.get("immutable") is True
        and expected_publication.get("immutable") is True
        and transparency.get("included") is True
        and policy.get("require_transparency_receipt") is True
        and isinstance(transparency.get("log_id"), str)
        and bool(transparency["log_id"])
        and integrated_at >= signed_at
    )
    if not receipt_ok:
        add(findings, "ASG-006", "signature publication or transparency receipt is missing mutable or mismatched")

    gate = object_at(receipt, "release_gate", "receipt")
    gate_ok = (
        policy.get("release_gate_failure_policy") == "BLOCK"
        and gate.get("failure_policy") == "BLOCK"
        and gate.get("status") == "ALLOW"
        and receipt.get("status") == "SIGNED"
    )
    if not gate_ok:
        add(findings, "ASG-007", "release gate can complete without successful signing")

    receipt_evidence = object_at(receipt, "evidence", "receipt")
    if (
        receipt_evidence.get("contains_identity_token") is not False
        or receipt_evidence.get("contains_private_key_material") is not False
        or receipt_evidence.get("contains_signature_body") is not False
    ):
        add(findings, "ASG-008", "signing receipt contains sensitive or unnecessary evidence")
    profile = policy.get("profile")
    if not isinstance(profile, str) or not profile:
        raise EvaluationError("policy.profile must be non-empty text")
    return findings, profile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--signer-evidence", type=Path, required=True)
    parser.add_argument("--statement", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        as_of = parse_time(args.as_of, "as-of")
        findings, profile = evaluate(
            args.policy,
            args.artifact,
            args.request,
            args.authorization,
            args.signer_evidence,
            args.statement,
            args.signature,
            args.receipt,
            as_of,
            args.openssl,
        )
    except EvaluationError as error:
        print(f"ERROR {CONTROL}/ASG-008 verification unavailable: {error}")
        print("RESULT ERROR profile=unknown checks=0 failures=0")
        return 2
    failures = sum(bool(messages) for messages in findings.values())
    for check, title in CHECKS.items():
        if findings[check]:
            print(f"FAIL {CONTROL}/{check} {findings[check][0]}")
        else:
            print(f"PASS {CONTROL}/{check} {title}")
    status = "PASS" if failures == 0 else "FAIL"
    print(f"RESULT {status} profile={profile} checks={len(CHECKS)} failures={failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
