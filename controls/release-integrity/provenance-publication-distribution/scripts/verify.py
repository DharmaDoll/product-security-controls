#!/usr/bin/env python3
"""Verify provenance publication, discoverability, retention, and no-downgrade."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class InputError(ValueError):
    """Publication evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Result:
    check_id: str
    passed: bool
    pass_reason: str
    fail_reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        reason = self.pass_reason if self.passed else self.fail_reason
        return f"{status} PSB-REL-002/{self.check_id} {reason}"


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    if value.get("schema_version") != 1:
        raise InputError(f"{label} schema is unsupported")
    return value


def object_field(value: dict[str, Any], field: str, label: str) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise InputError(f"{label}.{field} must be an object")
    return result


def list_field(value: dict[str, Any], field: str, label: str) -> list[Any]:
    result = value.get(field)
    if not isinstance(result, list):
        raise InputError(f"{label}.{field} must be a list")
    return result


def text_field(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise InputError(f"{label}.{field} must be non-empty text")
    return result


def bool_field(value: dict[str, Any], field: str, label: str) -> bool:
    result = value.get(field)
    if not isinstance(result, bool):
        raise InputError(f"{label}.{field} must be a boolean")
    return result


def int_field(value: dict[str, Any], field: str, label: str) -> int:
    result = value.get(field)
    if not isinstance(result, int) or isinstance(result, bool):
        raise InputError(f"{label}.{field} must be an integer")
    return result


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise InputError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InputError(f"{label} must be a timestamp") from error
    if parsed.tzinfo is None:
        raise InputError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def digest_field(value: dict[str, Any], field: str, label: str) -> str:
    digest = text_field(value, field, label)
    if SHA256_RE.fullmatch(digest) is None:
        raise InputError(f"{label}.{field} must be a lowercase SHA-256")
    return digest


def compile_release_pattern(value: str) -> re.Pattern[str]:
    try:
        return re.compile(value)
    except re.error as error:
        raise InputError("policy.release_id_pattern is invalid") from error


def location_ok(
    location: dict[str, Any],
    *,
    label: str,
    allowed_host: str,
    required_prefix: str,
    release_id: str,
    required_authentication: str,
    required_access: str,
) -> bool:
    uri = text_field(location, "uri", label)
    try:
        parsed = urlparse(uri)
        port = parsed.port
    except ValueError as error:
        raise InputError(f"{label}.uri is malformed") from error
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    return all(
        (
            parsed.scheme == "https",
            parsed.hostname == allowed_host,
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            parsed.query == "",
            parsed.fragment == "",
            parsed.path.startswith(required_prefix),
            release_id in path_segments,
            bool_field(location, "immutable", label) is True,
            text_field(location, "authentication", label)
            == required_authentication,
            text_field(location, "access", label) == required_access,
            bool_field(location, "available", label) is True,
        )
    )


def evaluate(
    policy: dict[str, Any],
    manifest: dict[str, Any],
) -> list[Result]:
    policy_id = text_field(policy, "policy_id", "policy")
    text_field(policy, "policy_revision", "policy")
    if policy_id != "PSB-REL-002-PUBLICATION":
        raise InputError("policy identity is unsupported")

    release_pattern_text = text_field(policy, "release_id_pattern", "policy")
    release_pattern = compile_release_pattern(release_pattern_text)
    release_pattern_safe = all(
        (
            release_pattern_text.startswith("^"),
            release_pattern_text.endswith("$"),
            ".*" not in release_pattern_text,
        )
    )
    allowed_host = text_field(policy, "allowed_host", "policy")
    required_prefix = text_field(policy, "required_path_prefix", "policy")
    required_access = text_field(policy, "required_access", "policy")
    required_authentication = text_field(
        policy, "required_authentication", "policy"
    )
    required_media_type = text_field(
        policy, "required_provenance_media_type", "policy"
    )
    maximum_delay = int_field(
        policy, "maximum_publication_delay_seconds", "policy"
    )
    minimum_retention_days = int_field(
        policy, "minimum_retention_days", "policy"
    )
    if maximum_delay < 0 or minimum_retention_days < 0:
        raise InputError("publication timing policy cannot be negative")
    if minimum_retention_days > 36500:
        raise InputError("publication retention policy is unreasonably large")
    protected_families_raw = list_field(
        policy, "protected_artifact_families", "policy"
    )
    if not all(
        isinstance(value, str) and value for value in protected_families_raw
    ):
        raise InputError("policy.protected_artifact_families is malformed")
    protected_families = set(protected_families_raw)

    binding_ok = required_media_type == "application/vnd.in-toto+json"
    distribution_ok = all(
        (
            release_pattern_safe,
            allowed_host == "releases.example.invalid",
            required_prefix.startswith("/"),
            required_prefix.endswith("/"),
            required_access == "public",
            required_authentication == "tls-server-authenticated",
        )
    )
    lifecycle_ok = 1 <= maximum_delay <= 300 and minimum_retention_days >= 365
    downgrade_ok = release_pattern_safe and bool(protected_families)

    parse_time(
        manifest.get("evidence_collected_at"), "manifest.evidence_collected_at"
    )
    probe = object_field(manifest, "publication_probe", "manifest")
    if text_field(probe, "status", "manifest.publication_probe") != "complete":
        raise InputError("publication or storage probe is unavailable")
    if text_field(probe, "source", "manifest.publication_probe") != "release-api":
        raise InputError("publication probe source is unsupported")

    release = object_field(manifest, "release", "manifest")
    release_id = text_field(release, "id", "manifest.release")
    artifact_family = text_field(
        release, "artifact_family", "manifest.release"
    )
    published_at = parse_time(
        release.get("published_at"), "manifest.release.published_at"
    )
    provenance_required = bool_field(
        release, "provenance_required", "manifest.release"
    )
    if release_pattern.fullmatch(release_id) is None:
        distribution_ok = False
    manifest_location = object_field(
        release, "manifest_location", "manifest.release"
    )
    if not location_ok(
        manifest_location,
        label="manifest.release.manifest_location",
        allowed_host=allowed_host,
        required_prefix=required_prefix,
        release_id=release_id,
        required_authentication=required_authentication,
        required_access=required_access,
    ):
        distribution_ok = False

    artifacts = list_field(manifest, "artifacts", "manifest")
    if not artifacts:
        raise InputError("manifest.artifacts must not be empty")
    artifact_names: set[str] = set()
    artifact_digests: set[str] = set()
    provenance_digests: set[str] = set()
    publication_uris: set[str] = {
        text_field(manifest_location, "uri", "manifest.release.manifest_location")
    }

    for index, artifact_value in enumerate(artifacts):
        if not isinstance(artifact_value, dict):
            raise InputError(f"manifest.artifacts[{index}] must be an object")
        label = f"manifest.artifacts[{index}]"
        name = text_field(artifact_value, "name", label)
        artifact_digest = digest_field(artifact_value, "sha256", label)
        text_field(artifact_value, "media_type", label)
        artifact_published_at = parse_time(
            artifact_value.get("published_at"), f"{label}.published_at"
        )
        if name in artifact_names or artifact_digest in artifact_digests:
            binding_ok = False
        artifact_names.add(name)
        artifact_digests.add(artifact_digest)

        artifact_location = object_field(artifact_value, "location", label)
        artifact_uri = text_field(
            artifact_location, "uri", f"{label}.location"
        )
        if artifact_uri in publication_uris:
            distribution_ok = False
        publication_uris.add(artifact_uri)
        if not location_ok(
            artifact_location,
            label=f"{label}.location",
            allowed_host=allowed_host,
            required_prefix=required_prefix,
            release_id=release_id,
            required_authentication=required_authentication,
            required_access=required_access,
        ):
            distribution_ok = False
        if artifact_published_at != published_at:
            lifecycle_ok = False

        provenance_value = artifact_value.get("provenance")
        if not isinstance(provenance_value, dict):
            binding_ok = False
            distribution_ok = False
            lifecycle_ok = False
            if artifact_family in protected_families:
                downgrade_ok = False
            continue
        provenance_label = f"{label}.provenance"
        provenance_digest = digest_field(
            provenance_value, "sha256", provenance_label
        )
        subject_digest = digest_field(
            provenance_value, "subject_sha256", provenance_label
        )
        if provenance_digest in provenance_digests:
            binding_ok = False
        provenance_digests.add(provenance_digest)
        if (
            subject_digest != artifact_digest
            or text_field(provenance_value, "media_type", provenance_label)
            != required_media_type
        ):
            binding_ok = False
        discovery = object_field(
            provenance_value, "discovery", provenance_label
        )
        if (
            text_field(discovery, "method", f"{provenance_label}.discovery")
            != "release-manifest"
            or digest_field(
                discovery,
                "artifact_sha256",
                f"{provenance_label}.discovery",
            )
            != artifact_digest
        ):
            binding_ok = False
            distribution_ok = False

        provenance_location = object_field(
            provenance_value, "location", provenance_label
        )
        provenance_uri = text_field(
            provenance_location, "uri", f"{provenance_label}.location"
        )
        if provenance_uri in publication_uris:
            distribution_ok = False
        publication_uris.add(provenance_uri)
        provenance_location_ok = location_ok(
            provenance_location,
            label=f"{provenance_label}.location",
            allowed_host=allowed_host,
            required_prefix=required_prefix,
            release_id=release_id,
            required_authentication=required_authentication,
            required_access=required_access,
        )
        if not provenance_location_ok:
            distribution_ok = False

        provenance_published_at = parse_time(
            provenance_value.get("published_at"),
            f"{provenance_label}.published_at",
        )
        delay = (provenance_published_at - artifact_published_at).total_seconds()
        retention_until = parse_time(
            provenance_value.get("retention_until"),
            f"{provenance_label}.retention_until",
        )
        minimum_retention = published_at + timedelta(
            days=minimum_retention_days
        )
        if (
            not 0 <= delay <= maximum_delay
            or retention_until < minimum_retention
        ):
            lifecycle_ok = False
        if artifact_family in protected_families and not provenance_location_ok:
            downgrade_ok = False

    if artifact_family in protected_families and not provenance_required:
        downgrade_ok = False

    return [
        Result(
            "RPD-001",
            binding_ok,
            "every artifact has one digest-bound discoverable provenance object",
            "artifact and provenance one-to-one digest binding is incomplete",
        ),
        Result(
            "RPD-002",
            distribution_ok,
            "release evidence is immutable authenticated and consumer-accessible",
            "publication location discoverability or consumer access is unsafe",
        ),
        Result(
            "RPD-003",
            lifecycle_ok,
            "provenance publication delay and retention meet policy",
            "provenance publication is late or retention is insufficient",
        ),
        Result(
            "RPD-004",
            downgrade_ok,
            "protected artifact family retains required provenance",
            "protected artifact family silently downgraded provenance",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "publication policy")
        manifest = load_json(args.manifest, "release manifest")
        if isinstance(manifest.get("profile"), str):
            profile = manifest["profile"]
        results = evaluate(policy, manifest)
    except InputError as error:
        print(
            "ERROR PSB-REL-002/RPD-005 "
            f"profile={profile} publication verification unavailable: {error}"
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
