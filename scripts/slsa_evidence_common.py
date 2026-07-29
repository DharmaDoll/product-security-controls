"""Shared fail-closed helpers for SLSA evidence collectors."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SCOPE_FIELDS = {
    "producer_id",
    "build_platform_id",
    "consumer_id",
    "artifact_family",
    "release_id",
    "source_revision",
}


class CollectorError(ValueError):
    """Evidence could not be collected safely."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise CollectorError(f"{label} must be an object")
    return value


def text_field(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise CollectorError(f"{label}.{field} must be non-empty text")
    return result


def object_field(
    value: dict[str, Any],
    field: str,
    label: str,
) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise CollectorError(f"{label}.{field} must be an object")
    return result


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


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


def require_https_uri(value: Any, label: str) -> str:
    if not isinstance(value, str) or not safe_https_uri(value):
        raise CollectorError(f"{label} must be a safe HTTPS URI")
    return value


def require_scope(document: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scope = document.get("scope")
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise CollectorError("collector scope is malformed")
    for field in SCOPE_FIELDS:
        text_field(scope, field, "collector.scope")
    for field in ("producer_id", "build_platform_id", "consumer_id"):
        require_https_uri(scope[field], f"collector.scope.{field}")
    if COMMIT_RE.fullmatch(scope["source_revision"]) is None:
        raise CollectorError("collector source revision must be a full commit")
    return scope, canonical_digest(scope)


def safe_relative_path(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise CollectorError(f"{label} must be a safe relative path")
    return path


def resolve_local_file(policy_path: Path, value: str, label: str) -> Path:
    relative = safe_relative_path(value, label)
    current = policy_path.parent
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CollectorError(f"{label} must not use symlinks")
    try:
        base = policy_path.parent.resolve(strict=True)
        resolved = (policy_path.parent / relative).resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError) as error:
        raise CollectorError(f"{label} is unavailable") from error
    if not resolved.is_file():
        raise CollectorError(f"{label} must be a file")
    return resolved


def sha256_file(path: Path, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CollectorError(f"{label} is unavailable") from error


def require_digest(path: Path, expected: str, label: str) -> str:
    if SHA256_RE.fullmatch(expected) is None:
        raise CollectorError(f"{label} pin must be a lowercase SHA-256")
    actual = sha256_file(path, label)
    if actual != expected:
        raise CollectorError(f"{label} digest mismatch")
    return actual


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise CollectorError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CollectorError(f"{label} must be a timestamp") from error
    if parsed.tzinfo is None:
        raise CollectorError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def require_output_path(path: Path, label: str) -> None:
    if path.exists() and path.is_symlink():
        raise CollectorError(f"{label} must not be a symlink")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise CollectorError(f"{label} parent is unavailable") from error
    if not parent.is_dir():
        raise CollectorError(f"{label} parent must be a directory")


def atomic_write_json(path: Path, value: Any, label: str) -> bytes:
    require_output_path(path, label)
    content = (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            os.chmod(handle.name, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise CollectorError(f"cannot write {label}") from error
    return content
