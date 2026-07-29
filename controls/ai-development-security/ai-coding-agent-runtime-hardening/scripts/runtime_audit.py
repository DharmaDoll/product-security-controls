"""Write fixed-schema sanitized PSB-AI-004 runtime audit events."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from approval_core import EvaluationError, load_json, parse_timestamp


ASSESSMENT_POLICY_SCHEMA = "psb-ai-runtime-assessment-policy/v1"
AUDIT_POLICY_SCHEMA = "psb-ai-runtime-audit-policy/v1"
TOOL_REFERENCE = re.compile(
    r"^[A-Za-z0-9_-]{1,128}(?:__[A-Za-z0-9_-]{1,128})*$"
)


class AuditError(EvaluationError):
    """The managed audit event could not be written safely."""


def hash_reference(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_audit_policy(policy_path: Path) -> dict[str, Any]:
    if (
        not policy_path.is_absolute()
        or path_has_symlink(policy_path)
        or not policy_path.is_file()
    ):
        raise AuditError("runtime audit policy is unavailable")
    try:
        policy = load_json(policy_path, "runtime assessment policy")
    except EvaluationError as error:
        raise AuditError("runtime audit policy is unavailable") from error
    if policy.get("schema_version") != ASSESSMENT_POLICY_SCHEMA:
        raise AuditError("runtime assessment policy schema is unsupported")
    audit = policy.get("audit")
    if (
        not isinstance(audit, dict)
        or audit.get("schema_version") != AUDIT_POLICY_SCHEMA
    ):
        raise AuditError("runtime audit policy is unavailable")
    required_fields = audit.get("allowed_event_fields")
    allowed_reasons = audit.get("allowed_reason_codes")
    if (
        not isinstance(required_fields, list)
        or not all(isinstance(value, str) for value in required_fields)
        or len(required_fields) != len(set(required_fields))
        or not isinstance(allowed_reasons, list)
        or not all(isinstance(value, str) for value in allowed_reasons)
    ):
        raise AuditError("runtime audit policy is malformed")
    return policy


def parse_mode(value: Any, label: str) -> int:
    if not isinstance(value, str) or len(value) != 4:
        raise AuditError(f"{label} is malformed")
    try:
        mode = int(value, 8)
    except ValueError as error:
        raise AuditError(f"{label} is malformed") from error
    if mode < 0 or mode > 0o777:
        raise AuditError(f"{label} is malformed")
    return mode


def build_event(
    policy: dict[str, Any],
    provider: str,
    hook_input: dict[str, Any],
    decision: str,
    reason_code: str,
    now_text: str,
    request_ref: str | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    audit = policy["audit"]
    parse_timestamp(now_text, "runtime audit timestamp")
    allowed_reasons = audit["allowed_reason_codes"]
    if decision not in audit.get("required_decisions", []) or reason_code not in (
        allowed_reasons
    ):
        raise AuditError("runtime audit decision is unsupported")
    session_id = hook_input.get("session_id")
    session_ref = (
        hash_reference(session_id)
        if isinstance(session_id, str) and session_id
        else "unavailable"
    )
    tool_use_id = hook_input.get("tool_use_id")
    event_ref = (
        hash_reference(tool_use_id)
        if isinstance(tool_use_id, str) and tool_use_id
        else "unavailable"
    )
    tool_name = hook_input.get("tool_name")
    tool_ref = (
        tool_name
        if isinstance(tool_name, str)
        and TOOL_REFERENCE.fullmatch(tool_name)
        else "unavailable"
    )
    if request_ref is not None and (
        len(request_ref) != 64
        or any(character not in "0123456789abcdef" for character in request_ref)
    ):
        raise AuditError("runtime audit request reference is malformed")
    event: dict[str, Any] = {
        "schema_version": audit.get("event_schema_version"),
        "timestamp": now_text,
        "control_id": "PSB-AI-004",
        "policy_revision": audit.get("policy_revision"),
        "provider": provider,
        "session_ref": session_ref,
        "event_ref": event_ref,
        "tool_ref": tool_ref,
        "decision": decision,
        "reason_code": reason_code,
        "request_ref": request_ref,
        "approval_ref": (
            hash_reference(approval_id)
            if isinstance(approval_id, str) and approval_id
            else None
        ),
    }
    if set(event) != set(audit["allowed_event_fields"]):
        raise AuditError("runtime audit event schema is inconsistent")
    return event


def append_event(
    policy: dict[str, Any],
    audit_path: Path,
    event: dict[str, Any],
) -> None:
    audit = policy["audit"]
    if not audit_path.is_absolute():
        raise AuditError("runtime audit path must be absolute")
    parent = audit_path.parent
    if not parent.is_dir() or path_has_symlink(parent):
        raise AuditError("runtime audit directory is unavailable")
    directory_mode = parse_mode(audit.get("directory_mode"), "audit directory mode")
    file_mode = parse_mode(audit.get("file_mode"), "audit file mode")
    maximum_bytes = audit.get("maximum_file_bytes")
    if not isinstance(maximum_bytes, int) or maximum_bytes < 1024:
        raise AuditError("runtime audit size policy is malformed")
    try:
        actual_directory_mode = stat.S_IMODE(parent.stat().st_mode)
    except OSError as error:
        raise AuditError("runtime audit directory is unavailable") from error
    if actual_directory_mode != directory_mode:
        raise AuditError("runtime audit directory permissions are invalid")
    if not hasattr(os, "O_NOFOLLOW"):
        raise AuditError("runtime audit no-follow protection is unavailable")
    flags = (
        os.O_APPEND
        | os.O_CREAT
        | os.O_WRONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    try:
        descriptor = os.open(audit_path, flags, file_mode)
    except OSError as error:
        raise AuditError("runtime audit file is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != file_mode
            or metadata.st_nlink != 1
        ):
            raise AuditError("runtime audit file permissions are invalid")
        line = (
            json.dumps(
                event,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current_size = os.lseek(descriptor, 0, os.SEEK_END)
        if current_size + len(line) > maximum_bytes:
            raise AuditError("runtime audit file size limit is reached")
        remaining = memoryview(line)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise AuditError("runtime audit write failed")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except OSError as error:
        raise AuditError("runtime audit write failed") from error
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def path_has_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def record_event(
    policy: dict[str, Any],
    audit_path: Path,
    provider: str,
    hook_input: dict[str, Any],
    decision: str,
    reason_code: str,
    now_text: str,
    request_ref: str | None = None,
    approval_id: str | None = None,
) -> None:
    append_event(
        policy,
        audit_path,
        build_event(
            policy,
            provider,
            hook_input,
            decision,
            reason_code,
            now_text,
            request_ref,
            approval_id,
        ),
    )
