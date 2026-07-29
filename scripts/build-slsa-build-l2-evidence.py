#!/usr/bin/env python3
"""Build a scoped SLSA Build L2 catalog from digest-pinned issuer bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ASSESSMENT_POLICY_SCHEMA = "psb-framework-assessment-policy/v1"
ADAPTER_POLICY_SCHEMA = "psb-slsa-build-l2-evidence-adapter-policy/v1"
BUNDLE_SCHEMA = "psb-slsa-build-l2-issuer-bundle/v1"
OUTPUT_SCHEMA = "psb-slsa-build-l2-assessment-input/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CODE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SCOPE_FIELDS = {
    "producer_id",
    "build_platform_id",
    "consumer_id",
    "artifact_family",
    "release_id",
    "source_revision",
}
ADAPTER_POLICY_FIELDS = {
    "schema_version",
    "source",
    "profile_id",
    "bundle_root",
    "scope",
    "trusted_bundles",
}
TRUSTED_BUNDLE_FIELDS = {
    "issuer_role",
    "path",
    "sha256",
    "reviewed_by",
    "reviewed_at",
}
BUNDLE_FIELDS = {
    "schema_version",
    "profile_id",
    "issuer_role",
    "scope_sha256",
    "observed_at",
    "evidence",
}
EVIDENCE_FIELDS = {
    "code",
    "type",
    "uri",
    "sha256",
    "result",
    "immutable",
}


class AdapterError(ValueError):
    """Issuer evidence could not be converted safely."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must be an object")
    return value


def text_field(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise AdapterError(f"{label}.{field} must be non-empty text")
    return result


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise AdapterError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AdapterError(f"{label} must be a timestamp") from error
    if parsed.tzinfo is None:
        raise AdapterError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


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


def require_scope(document: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scope = document.get("scope")
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise AdapterError("adapter scope is malformed")
    for field in SCOPE_FIELDS:
        text_field(scope, field, "adapter.scope")
    for field in ("producer_id", "build_platform_id", "consumer_id"):
        if not safe_https_uri(scope[field]):
            raise AdapterError(f"adapter.scope.{field} must be an HTTPS identity")
    if COMMIT_RE.fullmatch(scope["source_revision"]) is None:
        raise AdapterError("adapter.scope.source_revision must be a full commit")
    return scope, canonical_digest(scope)


def require_assessment_policy(
    policy: dict[str, Any],
) -> tuple[dict[str, str], set[str]]:
    if (
        policy.get("schema_version") != ASSESSMENT_POLICY_SCHEMA
        or policy.get("profile_id") != "slsa-build-l2"
        or policy.get("framework") != "slsa"
        or policy.get("framework_version") != "1.2"
        or policy.get("track") != "build"
        or policy.get("target_level") != 2
    ):
        raise AdapterError("SLSA Build L2 assessment policy is unsupported")
    issuers = policy.get("required_evidence_issuers")
    requirements = policy.get("requirements")
    if (
        not isinstance(issuers, dict)
        or not isinstance(requirements, dict)
        or len(requirements) != 7
        or any(
            not isinstance(required_types, list) or not required_types
            for required_types in requirements.values()
        )
    ):
        raise AdapterError("SLSA Build L2 assessment policy is incomplete")
    normalized: dict[str, str] = {}
    for evidence_type, issuer_role in issuers.items():
        if (
            not isinstance(evidence_type, str)
            or CODE_RE.fullmatch(evidence_type) is None
            or not isinstance(issuer_role, str)
            or not issuer_role
        ):
            raise AdapterError("assessment evidence issuer policy is malformed")
        normalized[evidence_type] = issuer_role
    referenced = {
        evidence_type
        for required_types in requirements.values()
        if isinstance(required_types, list)
        for evidence_type in required_types
    }
    if referenced != set(normalized):
        raise AdapterError("assessment evidence issuer policy has unused types")
    return normalized, set(normalized.values())


def relative_path(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise AdapterError(f"{label} must be a safe relative path")
    return path


def resolve_bundle_root(policy_path: Path, value: str) -> Path:
    relative = relative_path(value, "adapter.bundle_root")
    candidate = policy_path.parent / relative
    if candidate.is_symlink():
        raise AdapterError("adapter bundle root must not be a symlink")
    try:
        root = candidate.resolve(strict=True)
    except OSError as error:
        raise AdapterError("adapter bundle root is unavailable") from error
    if not root.is_dir():
        raise AdapterError("adapter bundle root must be a directory")
    return root


def resolve_bundle(root: Path, value: str, issuer_role: str) -> Path:
    relative = relative_path(value, f"trusted bundle {issuer_role}.path")
    candidate = root / relative
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise AdapterError(f"trusted bundle {issuer_role} uses a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise AdapterError(f"trusted bundle {issuer_role} is unavailable") from error
    if not resolved.is_file():
        raise AdapterError(f"trusted bundle {issuer_role} must be a file")
    return resolved


def load_pinned_bundle(
    path: Path,
    expected_digest: str,
    issuer_role: str,
) -> dict[str, Any]:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise AdapterError(f"trusted bundle {issuer_role} is unavailable") from error
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise AdapterError(f"trusted bundle {issuer_role} digest mismatch")
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"trusted bundle {issuer_role} is malformed") from error
    if not isinstance(value, dict):
        raise AdapterError(f"trusted bundle {issuer_role} must be an object")
    return value


def build_catalog(
    assessment_policy: dict[str, Any],
    adapter_policy: dict[str, Any],
    adapter_policy_path: Path,
    assessed_at: datetime,
) -> dict[str, Any]:
    evidence_issuers, required_roles = require_assessment_policy(
        assessment_policy
    )
    if set(adapter_policy) != ADAPTER_POLICY_FIELDS:
        raise AdapterError("adapter policy fields are malformed")
    if (
        adapter_policy.get("schema_version") != ADAPTER_POLICY_SCHEMA
        or adapter_policy.get("profile_id") != "slsa-build-l2"
    ):
        raise AdapterError("adapter policy is unsupported")
    source = adapter_policy.get("source")
    if source not in {"live", "test-fixture"}:
        raise AdapterError("adapter source is unsupported")
    scope, scope_digest = require_scope(adapter_policy)
    root = resolve_bundle_root(
        adapter_policy_path,
        text_field(adapter_policy, "bundle_root", "adapter"),
    )
    trusted_bundles = adapter_policy.get("trusted_bundles")
    if not isinstance(trusted_bundles, list):
        raise AdapterError("adapter.trusted_bundles must be a list")

    trusted_by_role: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(trusted_bundles):
        label = f"adapter.trusted_bundles[{index}]"
        if not isinstance(raw, dict) or set(raw) != TRUSTED_BUNDLE_FIELDS:
            raise AdapterError(f"{label} fields are malformed")
        issuer_role = text_field(raw, "issuer_role", label)
        reviewed_by = text_field(raw, "reviewed_by", label)
        if (
            issuer_role not in required_roles
            or issuer_role in trusted_by_role
            or reviewed_by == issuer_role
        ):
            raise AdapterError("adapter trusted bundle roles are malformed")
        digest = text_field(raw, "sha256", label)
        if SHA256_RE.fullmatch(digest) is None:
            raise AdapterError(f"{label}.sha256 must be a lowercase SHA-256")
        reviewed_at = parse_time(raw.get("reviewed_at"), f"{label}.reviewed_at")
        if reviewed_at > assessed_at:
            raise AdapterError(f"{label}.reviewed_at is from the future")
        trusted_by_role[issuer_role] = raw
    if set(trusted_by_role) != required_roles:
        raise AdapterError("adapter trusted bundle role set is incomplete")

    catalog_by_type: dict[str, dict[str, Any]] = {}
    codes: set[str] = set()
    for issuer_role in sorted(required_roles):
        trust = trusted_by_role[issuer_role]
        bundle_path = resolve_bundle(
            root,
            text_field(trust, "path", f"trusted bundle {issuer_role}"),
            issuer_role,
        )
        bundle = load_pinned_bundle(
            bundle_path,
            text_field(trust, "sha256", f"trusted bundle {issuer_role}"),
            issuer_role,
        )
        if set(bundle) != BUNDLE_FIELDS:
            raise AdapterError(f"trusted bundle {issuer_role} fields are malformed")
        if (
            bundle.get("schema_version") != BUNDLE_SCHEMA
            or bundle.get("profile_id") != "slsa-build-l2"
            or bundle.get("issuer_role") != issuer_role
            or bundle.get("scope_sha256") != scope_digest
        ):
            raise AdapterError(f"trusted bundle {issuer_role} identity is invalid")
        observed_at = parse_time(
            bundle.get("observed_at"),
            f"trusted bundle {issuer_role}.observed_at",
        )
        evidence = bundle.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise AdapterError(f"trusted bundle {issuer_role} evidence is empty")
        expected_types = {
            evidence_type
            for evidence_type, expected_role in evidence_issuers.items()
            if expected_role == issuer_role
        }
        actual_types: set[str] = set()
        for index, raw in enumerate(evidence):
            label = f"trusted bundle {issuer_role}.evidence[{index}]"
            if not isinstance(raw, dict) or set(raw) != EVIDENCE_FIELDS:
                raise AdapterError(f"{label} fields are malformed")
            evidence_type = text_field(raw, "type", label)
            code = text_field(raw, "code", label)
            if (
                evidence_type not in expected_types
                or evidence_type in actual_types
                or evidence_type in catalog_by_type
                or code != evidence_type
                or CODE_RE.fullmatch(code) is None
                or code in codes
            ):
                raise AdapterError(f"{label} identity is invalid")
            actual_types.add(evidence_type)
            codes.add(code)
            uri = text_field(raw, "uri", label)
            digest = text_field(raw, "sha256", label)
            result = text_field(raw, "result", label)
            immutable = raw.get("immutable")
            if (
                not safe_https_uri(uri)
                or SHA256_RE.fullmatch(digest) is None
                or result not in {"pass", "finding", "error"}
                or not isinstance(immutable, bool)
            ):
                raise AdapterError(f"{label} metadata is invalid")
            catalog_by_type[evidence_type] = {
                "code": code,
                "type": evidence_type,
                "issuer_role": issuer_role,
                "uri": uri,
                "sha256": digest,
                "scope_sha256": scope_digest,
                "observed_at": observed_at.isoformat(timespec="seconds").replace(
                    "+00:00", "Z"
                ),
                "result": result,
                "immutable": immutable,
                "authenticated": True,
                "reviewed": True,
            }
        if actual_types != expected_types:
            raise AdapterError(
                f"trusted bundle {issuer_role} evidence set is incomplete"
            )
    if set(catalog_by_type) != set(evidence_issuers):
        raise AdapterError("assembled evidence catalog is incomplete")

    return {
        "schema_version": OUTPUT_SCHEMA,
        "source": source,
        "assessed_at": assessed_at.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "scope": scope,
        "evidence_catalog": [
            catalog_by_type[evidence_type]
            for evidence_type in sorted(catalog_by_type)
        ],
    }


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass
        raise AdapterError("evidence catalog output is unavailable") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assessment-policy", type=Path, required=True)
    parser.add_argument("--adapter-policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--now")
    args = parser.parse_args()
    try:
        assessed_at = (
            parse_time(args.now, "adapter assessment time")
            if args.now
            else datetime.now(timezone.utc)
        )
        catalog = build_catalog(
            load_json(args.assessment_policy, "assessment policy"),
            load_json(args.adapter_policy, "adapter policy"),
            args.adapter_policy,
            assessed_at,
        )
        write_json_atomic(args.output, catalog)
    except AdapterError as error:
        print(f"ERROR slsa-build-l2 evidence adapter unavailable: {error}")
        return 2
    print(
        "PASS slsa-build-l2 evidence catalog assembled "
        f"roles={len({item['issuer_role'] for item in catalog['evidence_catalog']})} "
        f"evidence={len(catalog['evidence_catalog'])} "
        f"scope_sha256={canonical_digest(catalog['scope'])}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
