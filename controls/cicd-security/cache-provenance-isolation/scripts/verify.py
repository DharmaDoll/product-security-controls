#!/usr/bin/env python3
"""Verify authenticated exact-scope CI cache production and restore evidence."""

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ci-cache-policy/v1"
RECORD_SCHEMA = "psb-ci-cache-record/v1"
REQUEST_SCHEMA = "psb-ci-cache-restore-request/v1"
KEY_VERSION = "psb-ci-cache-key/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_ID_RE = re.compile(r"^[1-9][0-9]*$")
PLATFORM_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")
WORKFLOW_REF_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}$"
)
TRUST_CLASSES = {"trusted", "untrusted"}
POLICY_FIELDS = {
    "schema",
    "key_derivation_version",
    "trusted_signer",
    "allowed_trust_transitions",
    "allowed_cache_paths",
    "max_ttl_seconds",
    "require_exact_revision",
    "allow_restore_prefixes",
    "evidence_mode",
    "max_document_bytes",
}
SIGNER_FIELDS = {"key_id", "algorithm", "public_key_path", "public_key_sha256"}
RECORD_FIELDS = {
    "schema",
    "cache_id",
    "cache_key",
    "repository_id",
    "workflow_ref",
    "producer_revision",
    "producer_run_id",
    "producer_attempt",
    "trust_class",
    "platform",
    "dependency_lock_sha256",
    "paths",
    "content_sha256",
    "created_at",
    "expires_at",
    "policy_sha256",
    "signer_key_id",
}
REQUEST_FIELDS = {
    "schema",
    "repository_id",
    "workflow_ref",
    "consumer_revision",
    "trust_class",
    "platform",
    "dependency_lock_sha256",
    "paths",
    "restore_prefixes",
    "expected_cache_key",
    "expected_content_sha256",
    "expected_record_sha256",
    "expected_policy_sha256",
}
CHECK_MESSAGES = {
    "CAC-001": "producer record signature signer and policy binding are authentic",
    "CAC-002": "cache key binds exact repository workflow trust platform and dependency identity",
    "CAC-003": "producer to consumer trust transition is explicitly allowed",
    "CAC-004": "cache content digest and restored paths match the reviewed request",
    "CAC-005": "cache record is current and bound to the exact source revision",
    "CAC-006": "restore uses exact record content and key identities without prefix fallback",
    "CAC-007": "policy is complete and evidence output is metadata only",
}


class EvaluationError(ValueError):
    """Evidence could not be evaluated safely."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_bytes(path: Path, label: str, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvaluationError(f"{label} is unavailable or symbolic")
    try:
        value = path.read_bytes()
    except OSError as error:
        raise EvaluationError(f"cannot read {label}") from error
    if not value or len(value) > maximum:
        raise EvaluationError(f"{label} size is empty or exceeds policy")
    return value


def load_json(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = read_bytes(path, label, maximum)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(data, dict):
        raise EvaluationError(f"{label} root must be an object")
    return data, raw


def require_fields(data: dict[str, Any], fields: set[str], label: str) -> None:
    if set(data) != fields:
        raise EvaluationError(f"{label} fields are incomplete or unknown")


def require_text(data: dict[str, Any], field: str, label: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise EvaluationError(f"{label}.{field} must be non-empty text")
    return value


def require_sha256(data: dict[str, Any], field: str, label: str) -> str:
    value = require_text(data, field, label)
    if not SHA256_RE.fullmatch(value):
        raise EvaluationError(f"{label}.{field} must be a lowercase SHA-256")
    return value


def require_string_list(data: dict[str, Any], field: str, label: str) -> list[str]:
    value = data.get(field)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise EvaluationError(f"{label}.{field} must be a unique non-empty string list")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvaluationError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvaluationError(f"{label} must be an RFC 3339 UTC timestamp") from error
    if result.tzinfo != timezone.utc:
        raise EvaluationError(f"{label} must use UTC")
    return result


def validate_policy(data: dict[str, Any]) -> None:
    require_fields(data, POLICY_FIELDS, "policy")
    if data.get("schema") != POLICY_SCHEMA or data.get("key_derivation_version") != KEY_VERSION:
        raise EvaluationError("unsupported cache policy schema or key derivation")
    signer = data.get("trusted_signer")
    if not isinstance(signer, dict):
        raise EvaluationError("policy.trusted_signer must be an object")
    require_fields(signer, SIGNER_FIELDS, "policy.trusted_signer")
    if signer.get("algorithm") != "Ed25519":
        raise EvaluationError("policy signer algorithm must be Ed25519")
    require_text(signer, "key_id", "policy.trusted_signer")
    require_sha256(signer, "public_key_sha256", "policy.trusted_signer")

    transitions = data.get("allowed_trust_transitions")
    expected = {
        ("trusted", "trusted"),
        ("untrusted", "untrusted"),
    }
    if not isinstance(transitions, list):
        raise EvaluationError("policy trust transitions must be a list")
    observed: set[tuple[str, str]] = set()
    for transition in transitions:
        if not isinstance(transition, dict) or set(transition) != {"producer", "consumer"}:
            raise EvaluationError("policy trust transition is malformed")
        pair = (transition.get("producer"), transition.get("consumer"))
        if pair[0] not in TRUST_CLASSES or pair[1] not in TRUST_CLASSES:
            raise EvaluationError("policy trust transition has an unknown class")
        observed.add((str(pair[0]), str(pair[1])))
    if observed != expected or len(transitions) != len(expected):
        raise EvaluationError("policy must allow only same-class cache transitions")
    paths = require_string_list(data, "allowed_cache_paths", "policy")
    if any(path.startswith(("/", "../")) or "/../" in path for path in paths):
        raise EvaluationError("policy cache paths must be repository-relative")
    if data.get("max_ttl_seconds") != 86400:
        raise EvaluationError("policy max_ttl_seconds must be 86400")
    if data.get("require_exact_revision") is not True:
        raise EvaluationError("policy must require exact revision")
    if data.get("allow_restore_prefixes") is not False:
        raise EvaluationError("policy must prohibit restore prefixes")
    if data.get("evidence_mode") != "metadata-only":
        raise EvaluationError("policy evidence must remain metadata-only")
    maximum = data.get("max_document_bytes")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum != 1048576:
        raise EvaluationError("policy max_document_bytes must be 1048576")


def validate_record(data: dict[str, Any], raw: bytes) -> None:
    require_fields(data, RECORD_FIELDS, "cache record")
    if data.get("schema") != RECORD_SCHEMA:
        raise EvaluationError("unsupported cache record schema")
    canonical = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"
    if raw != canonical:
        raise EvaluationError("cache record is not canonical JSON")
    if not REPOSITORY_ID_RE.fullmatch(require_text(data, "repository_id", "cache record")):
        raise EvaluationError("cache record repository_id is invalid")
    if not WORKFLOW_REF_RE.fullmatch(require_text(data, "workflow_ref", "cache record")):
        raise EvaluationError("cache record workflow_ref is invalid")
    if not REVISION_RE.fullmatch(require_text(data, "producer_revision", "cache record")):
        raise EvaluationError("cache record producer_revision is invalid")
    require_sha256(data, "dependency_lock_sha256", "cache record")
    require_sha256(data, "content_sha256", "cache record")
    require_sha256(data, "policy_sha256", "cache record")
    require_string_list(data, "paths", "cache record")
    if data.get("trust_class") not in TRUST_CLASSES:
        raise EvaluationError("cache record trust_class is invalid")
    if not PLATFORM_RE.fullmatch(require_text(data, "platform", "cache record")):
        raise EvaluationError("cache record platform is invalid")
    if not isinstance(data.get("producer_attempt"), int) or isinstance(data.get("producer_attempt"), bool) or data["producer_attempt"] < 1:
        raise EvaluationError("cache record producer_attempt is invalid")
    if not require_text(data, "producer_run_id", "cache record").isdigit():
        raise EvaluationError("cache record producer_run_id is invalid")
    require_text(data, "cache_id", "cache record")
    require_text(data, "cache_key", "cache record")
    require_text(data, "signer_key_id", "cache record")
    parse_time(data.get("created_at"), "cache record.created_at")
    parse_time(data.get("expires_at"), "cache record.expires_at")


def validate_request(data: dict[str, Any]) -> None:
    require_fields(data, REQUEST_FIELDS, "restore request")
    if data.get("schema") != REQUEST_SCHEMA:
        raise EvaluationError("unsupported restore request schema")
    if not REPOSITORY_ID_RE.fullmatch(require_text(data, "repository_id", "restore request")):
        raise EvaluationError("restore request repository_id is invalid")
    if not WORKFLOW_REF_RE.fullmatch(require_text(data, "workflow_ref", "restore request")):
        raise EvaluationError("restore request workflow_ref is invalid")
    if not REVISION_RE.fullmatch(require_text(data, "consumer_revision", "restore request")):
        raise EvaluationError("restore request consumer_revision is invalid")
    if data.get("trust_class") not in TRUST_CLASSES:
        raise EvaluationError("restore request trust_class is invalid")
    if not PLATFORM_RE.fullmatch(require_text(data, "platform", "restore request")):
        raise EvaluationError("restore request platform is invalid")
    require_sha256(data, "dependency_lock_sha256", "restore request")
    require_sha256(data, "expected_content_sha256", "restore request")
    require_sha256(data, "expected_record_sha256", "restore request")
    require_sha256(data, "expected_policy_sha256", "restore request")
    require_text(data, "expected_cache_key", "restore request")
    require_string_list(data, "paths", "restore request")
    prefixes = data.get("restore_prefixes")
    if not isinstance(prefixes, list) or any(not isinstance(item, str) for item in prefixes):
        raise EvaluationError("restore request restore_prefixes must be a string list")


def resolve_public_key(policy_path: Path, policy: dict[str, Any], maximum: int) -> Path:
    signer = policy["trusted_signer"]
    relative = Path(require_text(signer, "public_key_path", "policy.trusted_signer"))
    if relative.is_absolute() or ".." in relative.parts:
        raise EvaluationError("trusted public key must remain inside policy directory")
    key = (policy_path.parent / relative).resolve()
    expected_parent = policy_path.parent.resolve()
    if key.is_symlink() or not key.is_file() or not key.is_relative_to(expected_parent):
        raise EvaluationError("trusted public key is unavailable or outside policy directory")
    raw = read_bytes(key, "trusted public key", maximum)
    if sha256_bytes(raw) != signer["public_key_sha256"]:
        raise EvaluationError("trusted public key digest does not match policy")
    return key


def verify_signature(
    record_path: Path, signature_path: Path, public_key: Path, openssl: str, maximum: int
) -> bool:
    encoded = read_bytes(signature_path, "cache record signature", maximum).strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EvaluationError("cache record signature is not valid base64") from error
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
                    str(record_path),
                    "-sigfile",
                    handle.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
    except subprocess.TimeoutExpired as error:
        raise EvaluationError("OpenSSL verification timed out") from error
    except OSError as error:
        raise EvaluationError("cannot execute OpenSSL") from error
    return result.returncode == 0


def derive_cache_key(record: dict[str, Any]) -> str:
    workflow_digest = sha256_bytes(record["workflow_ref"].encode("utf-8"))
    return "/".join(
        [
            KEY_VERSION,
            f"repo-{record['repository_id']}",
            f"workflow-{workflow_digest}",
            f"trust-{record['trust_class']}",
            f"platform-{record['platform']}",
            f"revision-{record['producer_revision']}",
            f"lock-{record['dependency_lock_sha256']}",
        ]
    )


def add(findings: dict[str, list[str]], check: str, message: str) -> None:
    if message not in findings[check]:
        findings[check].append(message)


def evaluate(
    policy: dict[str, Any],
    policy_digest: str,
    record: dict[str, Any],
    record_digest: str,
    request: dict[str, Any],
    content_digest: str,
    as_of: datetime,
) -> dict[str, list[str]]:
    findings = {check: [] for check in CHECK_MESSAGES}
    signer = policy["trusted_signer"]
    if record["signer_key_id"] != signer["key_id"]:
        add(findings, "CAC-001", "record signer does not match the trusted signer")
    if record["policy_sha256"] != policy_digest:
        add(findings, "CAC-001", "record policy digest does not match the reviewed policy")

    derived_key = derive_cache_key(record)
    if record["cache_key"] != derived_key:
        add(findings, "CAC-002", "record cache key does not match independently derived identity")
    for field in ("repository_id", "workflow_ref", "platform", "dependency_lock_sha256"):
        if request[field] != record[field]:
            add(findings, "CAC-002", f"consumer {field} does not match producer record")

    transitions = {
        (item["producer"], item["consumer"])
        for item in policy["allowed_trust_transitions"]
    }
    if (record["trust_class"], request["trust_class"]) not in transitions:
        add(findings, "CAC-003", "producer to consumer trust transition is denied")

    if content_digest != record["content_sha256"]:
        add(findings, "CAC-004", "cache content digest does not match producer record")
    if request["expected_content_sha256"] != record["content_sha256"]:
        add(findings, "CAC-004", "consumer content digest does not match producer record")
    if request["paths"] != record["paths"]:
        add(findings, "CAC-004", "consumer cache paths do not match producer record")
    if record["paths"] != policy["allowed_cache_paths"]:
        add(findings, "CAC-004", "producer cache paths are outside the reviewed allowlist")

    created = parse_time(record["created_at"], "cache record.created_at")
    expires = parse_time(record["expires_at"], "cache record.expires_at")
    ttl = int((expires - created).total_seconds())
    if ttl <= 0 or ttl > policy["max_ttl_seconds"]:
        add(findings, "CAC-005", "cache lifetime exceeds the reviewed policy")
    if as_of < created or as_of >= expires:
        add(findings, "CAC-005", "cache record is not current at evaluation time")
    if request["consumer_revision"] != record["producer_revision"]:
        add(findings, "CAC-005", "consumer revision does not match producer revision")

    if request["restore_prefixes"]:
        add(findings, "CAC-006", "restore prefix fallback is prohibited")
    if request["expected_cache_key"] != record["cache_key"]:
        add(findings, "CAC-006", "consumer cache key does not match producer record")
    if request["expected_record_sha256"] != record_digest:
        add(findings, "CAC-006", "consumer record digest does not match signed record")
    if request["expected_policy_sha256"] != policy_digest:
        add(findings, "CAC-006", "consumer policy digest does not match reviewed policy")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--content", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        policy, policy_raw = load_json(args.policy, "cache policy", 1048576)
        validate_policy(policy)
        maximum = policy["max_document_bytes"]
        record, record_raw = load_json(args.record, "cache record", maximum)
        request, _ = load_json(args.request, "restore request", maximum)
        content_raw = read_bytes(args.content, "cache content", maximum)
        validate_record(record, record_raw)
        validate_request(request)
        as_of = parse_time(args.as_of, "evaluation time")
        policy_digest = sha256_bytes(policy_raw)
        record_digest = sha256_bytes(record_raw)
        public_key = resolve_public_key(args.policy, policy, maximum)
        signature_valid = verify_signature(
            args.record, args.signature, public_key, args.openssl, maximum
        )
        if not signature_valid:
            print(f"POLICY sha256={policy_digest}")
            print("FAIL CAC-001 cache record signature is invalid")
            print("REJECTED 1 finding(s); cache restore denied")
            return 1
        findings = evaluate(
            policy,
            policy_digest,
            record,
            record_digest,
            request,
            sha256_bytes(content_raw),
            as_of,
        )
    except EvaluationError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    print(f"POLICY sha256={policy_digest}")
    finding_count = 0
    for check, message in CHECK_MESSAGES.items():
        if findings[check]:
            for finding in findings[check]:
                print(f"FAIL {check} {finding}")
                finding_count += 1
        else:
            print(f"PASS {check} {message}")
    if finding_count:
        print(f"REJECTED {finding_count} finding(s); cache restore denied")
        return 1
    print(f"ACCEPTED cache_id={record['cache_id']} exact trusted restore")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
