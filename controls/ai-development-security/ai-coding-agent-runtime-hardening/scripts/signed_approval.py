"""Authenticate and atomically consume PSB-AI-004 approval evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from approval_core import (
    APPROVAL_SCHEMA,
    EvaluationError,
    canonical_json,
    canonical_request_digest,
    evaluate_approval,
    load_json,
    parse_timestamp,
    require_schema,
    require_string,
)


ENVELOPE_SCHEMA = "psb-ai-signed-action-approval/v1"
TRUST_SCHEMA = "psb-ai-approval-trust/v1"
ACTOR_SCHEMA = "psb-ai-managed-actor-state/v1"
ALGORITHM = "rsa-pkcs1v15-sha256"


@dataclass(frozen=True)
class AuthorizationResult:
    status: str
    request_id: str
    approval_id: str
    request_digest: str
    key_id: str
    signature_ok: bool
    approval_ok: bool
    consumed: bool

    @property
    def allowed(self) -> bool:
        return (
            self.status == "allowed"
            and self.signature_ok
            and self.approval_ok
            and self.consumed
        )


def utc_now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def resolve_trust_key(
    trust_path: Path,
    trust: dict[str, Any],
    key_id: str,
    issuer: str,
    now_text: str,
) -> tuple[Path, dict[str, Any]]:
    if (
        not trust_path.is_absolute()
        or trust_path.is_symlink()
        or not trust_path.is_file()
    ):
        raise EvaluationError("approval trust manifest is unavailable")
    require_schema(trust, TRUST_SCHEMA, "approval trust manifest")
    keys = trust.get("keys")
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, dict):
        raise EvaluationError("approval signing key is not trusted")
    if (
        key.get("status") != "active"
        or key.get("algorithm") != ALGORITHM
        or key.get("issuer") != issuer
    ):
        raise EvaluationError("approval signing key trust binding is invalid")
    now = parse_timestamp(now_text, "evaluation now")
    not_before = parse_timestamp(key.get("not_before"), "key not_before")
    not_after = parse_timestamp(key.get("not_after"), "key not_after")
    if not not_before <= now < not_after:
        raise EvaluationError("approval signing key is not active")
    relative = key.get("public_key")
    if not isinstance(relative, str) or not relative:
        raise EvaluationError("approval public key path is missing")
    trust_root = trust_path.parent
    public_key_candidate = trust_root / relative
    if public_key_candidate.is_symlink():
        raise EvaluationError("approval public key must not be a symbolic link")
    public_key = public_key_candidate.resolve()
    try:
        public_key.relative_to(trust_root)
    except ValueError as error:
        raise EvaluationError("approval public key leaves the trust directory") from error
    if not public_key.is_file():
        raise EvaluationError("approval public key is unavailable")
    expected_digest = key.get("public_key_sha256")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise EvaluationError("approval public key digest is missing")
    try:
        actual_digest = hashlib.sha256(public_key.read_bytes()).hexdigest()
    except OSError as error:
        raise EvaluationError("approval public key is unavailable") from error
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise EvaluationError("approval public key integrity check failed")
    return public_key, key


def verify_openssl_version(openssl_path: Path) -> None:
    if not openssl_path.is_absolute() or not openssl_path.is_file():
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
    envelope: dict[str, Any],
    trust_path: Path,
    openssl_path: Path,
    now_text: str,
) -> tuple[dict[str, Any], str, bool]:
    require_schema(envelope, ENVELOPE_SCHEMA, "signed approval envelope")
    key_id = require_string(envelope, "key_id", "signed approval envelope")
    if envelope.get("algorithm") != ALGORITHM:
        raise EvaluationError("signed approval algorithm is unsupported")
    approval = envelope.get("approval")
    if not isinstance(approval, dict):
        raise EvaluationError("signed approval payload is missing")
    require_schema(approval, APPROVAL_SCHEMA, "action approval")
    issuer = require_string(approval, "issuer", "action approval")
    trust = load_json(trust_path, "approval trust manifest")
    public_key, _ = resolve_trust_key(
        trust_path, trust, key_id, issuer, now_text
    )
    signature_text = envelope.get("signature_base64")
    if not isinstance(signature_text, str) or not signature_text:
        raise EvaluationError("approval signature is missing")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise EvaluationError("approval signature encoding is invalid") from error
    if not signature:
        raise EvaluationError("approval signature is empty")

    verify_openssl_version(openssl_path)
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
                input=canonical_json(approval),
                check=False,
                capture_output=True,
                timeout=3,
            )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvaluationError("approval signature verification failed") from error
    if result.returncode == 0 and result.stdout.strip() == b"Verified OK":
        return approval, key_id, True
    if result.returncode == 1 and b"Verification failure" in (
        result.stdout + result.stderr
    ):
        return approval, key_id, False
    raise EvaluationError("approval signature verifier returned an error")


def ensure_ledger_file(ledger_path: Path) -> None:
    if not ledger_path.is_absolute():
        raise EvaluationError("approval ledger path must be absolute")
    parent = ledger_path.parent
    if not parent.is_dir():
        raise EvaluationError("approval ledger directory is unavailable")
    if ledger_path.is_symlink():
        raise EvaluationError("approval ledger must not be a symbolic link")
    try:
        descriptor = os.open(
            ledger_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError:
        pass
    except OSError as error:
        raise EvaluationError("approval ledger is unavailable") from error
    else:
        os.close(descriptor)
    try:
        mode = stat.S_IMODE(ledger_path.stat().st_mode)
    except OSError as error:
        raise EvaluationError("approval ledger is unavailable") from error
    if mode & 0o077:
        raise EvaluationError("approval ledger permissions are too broad")


def consume_once(
    ledger_path: Path,
    approval_id: str,
    request_digest: str,
    actor_id: str,
    agent_id: str,
    action_class: str,
    consumed_at: str,
) -> bool:
    ensure_ledger_file(ledger_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            ledger_path,
            timeout=2,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 2000")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_consumption (
                approval_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL UNIQUE,
                actor_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action_class TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )
        try:
            connection.execute(
                """
                INSERT INTO approval_consumption (
                    approval_id,
                    request_digest,
                    actor_id,
                    agent_id,
                    action_class,
                    consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    request_digest,
                    actor_id,
                    agent_id,
                    action_class,
                    consumed_at,
                ),
            )
        except sqlite3.IntegrityError:
            connection.execute("ROLLBACK")
            return False
        connection.execute("COMMIT")
        return True
    except sqlite3.Error as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise EvaluationError("approval ledger transaction failed") from error
    finally:
        if connection is not None:
            connection.close()


def authorize_and_consume(
    runtime_policy: dict[str, Any],
    request: dict[str, Any],
    envelope: dict[str, Any],
    trust_path: Path,
    ledger_path: Path,
    openssl_path: Path,
    now_text: str,
) -> AuthorizationResult:
    approval, key_id, signature_ok = verify_signature(
        envelope,
        trust_path,
        openssl_path,
        now_text,
    )
    trusted_issuer = require_string(approval, "issuer", "action approval")
    evaluation = evaluate_approval(
        runtime_policy,
        request,
        approval,
        {
            "schema_version": "psb-ai-approval-replay-state/v1",
            "used_approval_ids": [],
            "used_request_digests": [],
        },
        {
            "schema_version": "psb-ai-approval-validation-state/v1",
            "available": True,
            "trusted_issuers": [trusted_issuer],
        },
        now_text,
    )
    approval_ok = evaluation.passed
    consumed = False
    status = "denied"
    if signature_ok and approval_ok:
        consumed = consume_once(
            ledger_path,
            evaluation.approval_id,
            evaluation.request_digest,
            require_string(request, "actor_id", "action request"),
            require_string(request, "agent_id", "action request"),
            evaluation.action_class,
            now_text,
        )
        status = "allowed" if consumed else "replayed"
    return AuthorizationResult(
        status=status,
        request_id=evaluation.request_id,
        approval_id=evaluation.approval_id,
        request_digest=evaluation.request_digest,
        key_id=key_id,
        signature_ok=signature_ok,
        approval_ok=approval_ok,
        consumed=consumed,
    )


def load_managed_actor(actor_path: Path) -> str:
    if (
        not actor_path.is_absolute()
        or actor_path.is_symlink()
        or not actor_path.is_file()
    ):
        raise EvaluationError("managed actor state is unavailable")
    state = load_json(actor_path, "managed actor state")
    require_schema(state, ACTOR_SCHEMA, "managed actor state")
    if state.get("available") is not True:
        raise EvaluationError("managed actor identity is unavailable")
    return require_string(state, "actor_id", "managed actor state")


def normalized_high_impact_request(
    runtime_policy: dict[str, Any],
    provider: str,
    event: dict[str, Any],
    actor_id: str,
) -> dict[str, Any]:
    if event.get("tool_name") != "mcp__source_manager__create_pull_request":
        raise EvaluationError("high-impact hook tool is unsupported")
    session_id = require_string(event, "session_id", "hook input")
    arguments = event.get("tool_input")
    if not isinstance(arguments, dict):
        raise EvaluationError("hook tool input is malformed")
    required_arguments = ("resource", "base", "head", "title", "idempotency_key")
    allowed_arguments = {*required_arguments, "body"}
    if set(arguments) - allowed_arguments:
        raise EvaluationError("high-impact tool arguments contain unknown fields")
    normalized: dict[str, str] = {}
    for name in required_arguments:
        value = arguments.get(name)
        if not isinstance(value, str) or not value:
            raise EvaluationError("high-impact tool arguments are malformed")
        normalized[name] = value
    body = arguments.get("body", "")
    if not isinstance(body, str):
        raise EvaluationError("high-impact tool body is malformed")

    capability_policy = runtime_policy.get("extension_capabilities")
    extensions = (
        capability_policy.get("extensions")
        if isinstance(capability_policy, dict)
        else None
    )
    source_manager = (
        extensions.get("source_manager") if isinstance(extensions, dict) else None
    )
    tools = (
        source_manager.get("tools") if isinstance(source_manager, dict) else None
    )
    tool_policy = (
        tools.get("create_pull_request") if isinstance(tools, dict) else None
    )
    constraints = (
        tool_policy.get("constraints") if isinstance(tool_policy, dict) else None
    )
    if (
        not isinstance(tool_policy, dict)
        or tool_policy.get("effect") != "high-impact"
        or tool_policy.get("decision") != "require-bound-approval"
        or tool_policy.get("action_class") != "source-publication"
        or not isinstance(constraints, dict)
        or constraints.get("require_idempotency_key") is not True
    ):
        raise EvaluationError("high-impact tool policy is unavailable")
    maximum_title_bytes = constraints.get("maximum_title_bytes")
    maximum_body_bytes = constraints.get("maximum_body_bytes")
    maximum_idempotency_characters = constraints.get(
        "maximum_idempotency_key_characters"
    )
    if (
        not isinstance(maximum_title_bytes, int)
        or maximum_title_bytes < 0
        or not isinstance(maximum_body_bytes, int)
        or maximum_body_bytes < 0
        or not isinstance(maximum_idempotency_characters, int)
        or maximum_idempotency_characters < 1
    ):
        raise EvaluationError("high-impact tool constraints are malformed")
    if (
        len(normalized["title"].encode("utf-8")) > maximum_title_bytes
        or len(body.encode("utf-8")) > maximum_body_bytes
        or len(normalized["idempotency_key"]) > maximum_idempotency_characters
    ):
        raise EvaluationError("high-impact tool arguments exceed policy limits")
    approval_policy = runtime_policy.get("high_impact_approval")
    if not isinstance(approval_policy, dict):
        raise EvaluationError("high-impact approval policy is unavailable")
    request: dict[str, Any] = {
        "schema_version": "psb-ai-action-request/v1",
        "request_id": "pending",
        "actor_id": actor_id,
        "agent_id": f"managed-{provider}:{session_id}",
        "action_class": "source-publication",
        "tool": "mcp:source_manager",
        "operation": "create-pull-request",
        "target": {
            "repository": normalized["resource"],
            "base": normalized["base"],
            "head": normalized["head"],
        },
        "parameters": {
            "title": normalized["title"],
            "body": body,
            "idempotency_key": normalized["idempotency_key"],
        },
        "policy_id": approval_policy.get("policy_id"),
        "policy_revision": approval_policy.get("policy_revision"),
    }
    digest = canonical_request_digest(request)
    request["request_id"] = f"REQ-{digest[:20].upper()}"
    return request


def approval_envelope_path(approval_dir: Path, request: dict[str, Any]) -> Path | None:
    if (
        not approval_dir.is_absolute()
        or not approval_dir.is_dir()
        or approval_dir.is_symlink()
    ):
        raise EvaluationError("approval inbox is unavailable")
    digest = canonical_request_digest(request)
    candidate = approval_dir / f"{digest}.json"
    if candidate.is_symlink():
        raise EvaluationError("approval evidence must not be a symbolic link")
    if not candidate.exists():
        return None
    if not candidate.is_file():
        raise EvaluationError("approval evidence is not a regular file")
    return candidate
