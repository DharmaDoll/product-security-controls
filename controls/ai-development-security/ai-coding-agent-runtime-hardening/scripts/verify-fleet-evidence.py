#!/usr/bin/env python3
"""Authenticate one fleet snapshot and reject tampering or replay offline."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-fleet-evidence-trust-policy/v1"
TRUST_SCHEMA = "psb-ai-fleet-collector-trust/v1"
ENVELOPE_SCHEMA = "psb-ai-signed-fleet-snapshot/v1"
STATEMENT_SCHEMA = "psb-ai-fleet-snapshot-statement/v1"
CHECKPOINT_SCHEMA = "psb-ai-fleet-checkpoint/v1"
ALGORITHM = "rsa-pkcs1v15-sha256"
POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "policy_revision",
    "expected_fleet_policy_id",
    "expected_fleet_policy_revision",
    "expected_snapshot_schema",
    "expected_statement_schema",
    "signature_algorithm",
    "maximum_statement_age_seconds",
    "require_exact_next_sequence",
    "require_previous_snapshot_digest",
}
ENVELOPE_FIELDS = {
    "schema_version",
    "key_id",
    "algorithm",
    "statement",
    "signature_base64",
}
STATEMENT_FIELDS = {
    "schema_version",
    "statement_id",
    "issuer",
    "subject_schema",
    "subject_sha256",
    "sequence",
    "previous_snapshot_sha256",
    "collected_at",
    "policy_id",
    "policy_revision",
}
CHECKPOINT_FIELDS = {
    "schema_version",
    "collector_issuer",
    "last_sequence",
    "last_snapshot_sha256",
    "updated_at",
}
TRUST_KEY_FIELDS = {
    "issuer",
    "algorithm",
    "status",
    "public_key",
    "public_key_sha256",
    "not_before",
    "not_after",
}


class EvaluationError(Exception):
    """Evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Result:
    surface: str
    passed: bool
    pass_reason: str
    fail_reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        reason = self.pass_reason if self.passed else self.fail_reason
        return (
            f"{status} PSB-AI-004/AAR-026 "
            f"surface={self.surface} {reason}"
        )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is unavailable") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be an object")
    return value


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvaluationError(f"{label} is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{label} has no timezone")
    return parsed.astimezone(timezone.utc)


def require_string(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise EvaluationError(f"{label} {field} is malformed")
    return result


def require_sha256(value: dict[str, Any], field: str, label: str) -> str:
    result = require_string(value, field, label)
    if len(result) != 64:
        raise EvaluationError(f"{label} {field} is malformed")
    try:
        bytes.fromhex(result)
    except ValueError as error:
        raise EvaluationError(f"{label} {field} is malformed") from error
    return result


def require_policy(policy: dict[str, Any]) -> dict[str, Any]:
    maximum_age = policy.get("maximum_statement_age_seconds")
    if (
        set(policy) != POLICY_FIELDS
        or policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("expected_statement_schema") != STATEMENT_SCHEMA
        or policy.get("signature_algorithm") != ALGORITHM
        or policy.get("require_exact_next_sequence") is not True
        or policy.get("require_previous_snapshot_digest") is not True
        or not isinstance(maximum_age, int)
        or isinstance(maximum_age, bool)
        or maximum_age < 1
    ):
        raise EvaluationError("fleet evidence trust policy is malformed or unsafe")
    for field in (
        "policy_id",
        "policy_revision",
        "expected_fleet_policy_id",
        "expected_fleet_policy_revision",
        "expected_snapshot_schema",
    ):
        require_string(policy, field, "fleet evidence trust policy")
    return policy


def require_managed_file(path: Path, label: str) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise EvaluationError(f"{label} is unavailable")


def resolve_key(
    trust_path: Path,
    trust: dict[str, Any],
    key_id: str,
    issuer: str,
    now: datetime,
) -> Path:
    require_managed_file(trust_path, "fleet collector trust manifest")
    if set(trust) != {"schema_version", "keys"} or (
        trust.get("schema_version") != TRUST_SCHEMA
    ):
        raise EvaluationError("fleet collector trust manifest is malformed")
    keys = trust.get("keys")
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, dict):
        raise EvaluationError("fleet collector signing key is not trusted")
    if set(key) != TRUST_KEY_FIELDS:
        raise EvaluationError("fleet collector signing key record is malformed")
    if (
        key.get("issuer") != issuer
        or key.get("algorithm") != ALGORITHM
        or key.get("status") != "active"
    ):
        raise EvaluationError("fleet collector signing key trust binding is invalid")
    not_before = parse_time(key.get("not_before"), "collector key not_before")
    not_after = parse_time(key.get("not_after"), "collector key not_after")
    if not not_before <= now < not_after:
        raise EvaluationError("fleet collector signing key is not active")
    relative = require_string(key, "public_key", "collector key")
    trust_root = trust_path.parent.resolve()
    candidate = trust_root / relative
    if candidate.is_symlink():
        raise EvaluationError("fleet collector public key must not be a symbolic link")
    public_key = candidate.resolve()
    try:
        public_key.relative_to(trust_root)
    except ValueError as error:
        raise EvaluationError(
            "fleet collector public key leaves the trust directory"
        ) from error
    if not public_key.is_file():
        raise EvaluationError("fleet collector public key is unavailable")
    expected_digest = require_sha256(
        key, "public_key_sha256", "collector key"
    )
    try:
        actual_digest = hashlib.sha256(public_key.read_bytes()).hexdigest()
    except OSError as error:
        raise EvaluationError("fleet collector public key is unavailable") from error
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise EvaluationError("fleet collector public key integrity check failed")
    return public_key


def verify_openssl(openssl_path: Path) -> None:
    if (
        not openssl_path.is_absolute()
        or openssl_path.is_symlink()
        or not openssl_path.is_file()
    ):
        raise EvaluationError("managed crypto verifier is unavailable")
    try:
        result = subprocess.run(
            [str(openssl_path), "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvaluationError("managed crypto verifier is unavailable") from error
    if result.returncode != 0 or not result.stdout.startswith("OpenSSL 3."):
        raise EvaluationError("managed crypto verifier version is unsupported")


def verify_signature(
    statement: dict[str, Any],
    signature_text: Any,
    public_key: Path,
    openssl_path: Path,
) -> bool:
    if not isinstance(signature_text, str) or not signature_text:
        raise EvaluationError("fleet collector signature is missing")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise EvaluationError("fleet collector signature encoding is invalid") from error
    if not signature:
        raise EvaluationError("fleet collector signature is empty")
    verify_openssl(openssl_path)
    try:
        with tempfile.NamedTemporaryFile(mode="wb") as handle:
            handle.write(signature)
            handle.flush()
            result = subprocess.run(
                [
                    str(openssl_path),
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key),
                    "-signature",
                    handle.name,
                ],
                input=canonical_json(statement),
                check=False,
                capture_output=True,
                timeout=3,
            )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvaluationError(
            "fleet collector signature verification failed"
        ) from error
    combined = result.stdout + result.stderr
    if result.returncode == 0 and result.stdout.strip() == b"Verified OK":
        return True
    if result.returncode == 1 and b"Verification failure" in combined:
        return False
    raise EvaluationError("fleet collector signature verifier returned an error")


def require_statement(envelope: dict[str, Any]) -> dict[str, Any]:
    if (
        set(envelope) != ENVELOPE_FIELDS
        or envelope.get("schema_version") != ENVELOPE_SCHEMA
        or envelope.get("algorithm") != ALGORITHM
    ):
        raise EvaluationError("signed fleet snapshot envelope is malformed")
    statement = envelope.get("statement")
    if (
        not isinstance(statement, dict)
        or set(statement) != STATEMENT_FIELDS
        or statement.get("schema_version") != STATEMENT_SCHEMA
    ):
        raise EvaluationError("fleet snapshot statement is malformed")
    for field in (
        "statement_id",
        "issuer",
        "subject_schema",
        "collected_at",
        "policy_id",
        "policy_revision",
    ):
        require_string(statement, field, "fleet snapshot statement")
    require_sha256(statement, "subject_sha256", "fleet snapshot statement")
    require_sha256(
        statement, "previous_snapshot_sha256", "fleet snapshot statement"
    )
    sequence = statement.get("sequence")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
    ):
        raise EvaluationError("fleet snapshot statement sequence is malformed")
    return statement


def require_checkpoint(checkpoint_path: Path, checkpoint: dict[str, Any]) -> None:
    require_managed_file(checkpoint_path, "fleet checkpoint")
    sequence = checkpoint.get("last_sequence")
    if (
        set(checkpoint) != CHECKPOINT_FIELDS
        or checkpoint.get("schema_version") != CHECKPOINT_SCHEMA
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
    ):
        raise EvaluationError("fleet checkpoint is malformed")
    require_string(checkpoint, "collector_issuer", "fleet checkpoint")
    require_sha256(checkpoint, "last_snapshot_sha256", "fleet checkpoint")
    parse_time(checkpoint.get("updated_at"), "fleet checkpoint update time")


def evaluate(
    policy_document: dict[str, Any],
    trust_path: Path,
    trust: dict[str, Any],
    envelope: dict[str, Any],
    evidence: dict[str, Any],
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    openssl_path: Path,
    now: datetime,
) -> list[Result]:
    policy = require_policy(policy_document)
    statement = require_statement(envelope)
    require_checkpoint(checkpoint_path, checkpoint)
    if evidence.get("schema_version") != policy["expected_snapshot_schema"]:
        raise EvaluationError("fleet snapshot schema is unsupported")
    captured_at = parse_time(evidence.get("captured_at"), "fleet snapshot time")
    collected_at = parse_time(
        statement.get("collected_at"), "fleet statement collection time"
    )
    key_id = require_string(envelope, "key_id", "signed fleet snapshot")
    public_key = resolve_key(
        trust_path,
        trust,
        key_id,
        statement["issuer"],
        now,
    )
    signature_ok = verify_signature(
        statement,
        envelope.get("signature_base64"),
        public_key,
        openssl_path,
    )
    actual_snapshot_digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
    age = (now - collected_at).total_seconds()
    payload_ok = all(
        (
            statement["subject_schema"] == policy["expected_snapshot_schema"],
            hmac.compare_digest(
                statement["subject_sha256"], actual_snapshot_digest
            ),
            statement["policy_id"] == policy["expected_fleet_policy_id"],
            statement["policy_revision"]
            == policy["expected_fleet_policy_revision"],
            collected_at == captured_at,
            0 <= age <= policy["maximum_statement_age_seconds"],
        )
    )
    chain_ok = all(
        (
            statement["issuer"] == checkpoint["collector_issuer"],
            statement["sequence"] == checkpoint["last_sequence"] + 1,
            hmac.compare_digest(
                statement["previous_snapshot_sha256"],
                checkpoint["last_snapshot_sha256"],
            ),
        )
    )
    return [
        Result(
            "issuer-auth",
            signature_ok,
            "collector statement is authenticated by the active pinned key",
            "collector statement signature is invalid",
        ),
        Result(
            "payload-binding",
            payload_ok,
            "statement binds the exact recent fleet snapshot and policy",
            "snapshot digest policy or collection-time binding is invalid",
        ),
        Result(
            "sequence-chain",
            chain_ok,
            "snapshot sequence advances the managed checkpoint exactly once",
            "snapshot sequence or previous digest is replayed or discontinuous",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("trust", type=Path)
    parser.add_argument("envelope", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    parser.add_argument("--now", default="2026-07-29T12:02:00Z")
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "fleet evidence trust policy")
        trust = load_json(args.trust, "fleet collector trust manifest")
        envelope = load_json(args.envelope, "signed fleet snapshot")
        evidence = load_json(args.evidence, "fleet snapshot")
        checkpoint = load_json(args.checkpoint, "fleet checkpoint")
        if isinstance(evidence.get("profile"), str):
            profile = evidence["profile"]
        results = evaluate(
            policy,
            args.trust,
            trust,
            envelope,
            evidence,
            args.checkpoint,
            checkpoint,
            args.openssl,
            parse_time(args.now, "fleet evidence assessment time"),
        )
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004/AAR-026 "
            f"profile={profile} fleet evidence authentication failed: {error}"
        )
        print(f"RESULT ERROR profile={profile} checks=0 failures=1")
        return 2
    for result in results:
        print(result.render())
    failures = sum(not result.passed for result in results)
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} profile={profile} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
