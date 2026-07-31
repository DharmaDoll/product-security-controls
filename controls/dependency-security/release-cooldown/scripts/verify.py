#!/usr/bin/env python3
"""Verify dependency release age, registry, integrity, and exceptions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REFERENCE_MINIMUM_HOURS = 168
REFERENCE_MAX_EXCEPTION_HOURS = 72
INTEGRITY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._/-]*$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")


class InputError(ValueError):
    """Raised when verification inputs cannot establish a reliable result."""


@dataclass(frozen=True)
class ExceptionRecord:
    package: str
    version: str
    owner: str
    justification: str
    approved_by: str
    created_at: datetime
    expires_at: datetime


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InputError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} is not a valid timestamp: {value!r}") from error
    if parsed.tzinfo != timezone.utc:
        raise InputError(f"{label} must use UTC")
    return parsed


def require_nonempty_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label} must be non-empty text")
    return value.strip()


def validate_registry_url(value: Any, label: str) -> str:
    url = require_nonempty_text(value, label)
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise InputError(
            f"{label} must be an HTTPS registry origin without credentials, "
            "query, fragment, or path"
        )
    return url.rstrip("/")


def validate_proxy_endpoint(value: Any, label: str) -> str:
    url = require_nonempty_text(value, label)
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise InputError(
            f"{label} must be an HTTPS endpoint without credentials, query, or fragment"
        )
    return url.rstrip("/")


def validate_exact_identifier(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    text = require_nonempty_text(value, label)
    if "*" in text or not pattern.fullmatch(text):
        raise InputError(f"{label} must be an exact identifier: {text!r}")
    return text


def load_policy(
    value: dict[str, Any], as_of: datetime
) -> tuple[int, set[str], bool, list[ExceptionRecord], list[str]]:
    findings: list[str] = []
    minimum_hours = value.get("minimum_release_age_hours")
    max_exception_hours = value.get("max_exception_hours")
    require_integrity = value.get("require_integrity")
    if not isinstance(minimum_hours, int) or minimum_hours < 0:
        raise InputError("policy.minimum_release_age_hours must be a non-negative integer")
    if minimum_hours < REFERENCE_MINIMUM_HOURS:
        findings.append(
            "policy.minimum_release_age_hours is "
            f"{minimum_hours}; reference minimum is {REFERENCE_MINIMUM_HOURS}"
        )
    if not isinstance(max_exception_hours, int) or max_exception_hours <= 0:
        raise InputError("policy.max_exception_hours must be a positive integer")
    if max_exception_hours > REFERENCE_MAX_EXCEPTION_HOURS:
        findings.append(
            "policy.max_exception_hours is "
            f"{max_exception_hours}; reference maximum is "
            f"{REFERENCE_MAX_EXCEPTION_HOURS}"
        )
    effective_max_exception_hours = min(
        max_exception_hours, REFERENCE_MAX_EXCEPTION_HOURS
    )
    if require_integrity is not True:
        findings.append("policy.require_integrity must be true")

    raw_registries = value.get("allowed_registries")
    if not isinstance(raw_registries, list) or not raw_registries:
        raise InputError("policy.allowed_registries must be a non-empty list")
    registries = {
        validate_registry_url(registry, "policy.allowed_registries[]")
        for registry in raw_registries
    }
    if len(registries) != len(raw_registries):
        raise InputError("policy.allowed_registries contains duplicates")

    raw_exceptions = value.get("exceptions")
    if not isinstance(raw_exceptions, list):
        raise InputError("policy.exceptions must be a list")
    exceptions: list[ExceptionRecord] = []
    exception_keys: set[tuple[str, str]] = set()
    for index, raw_exception in enumerate(raw_exceptions):
        label = f"policy.exceptions[{index}]"
        if not isinstance(raw_exception, dict):
            raise InputError(f"{label} must be an object")
        package = validate_exact_identifier(
            raw_exception.get("package"), f"{label}.package", PACKAGE_RE
        )
        version = validate_exact_identifier(
            raw_exception.get("version"), f"{label}.version", VERSION_RE
        )
        key = (package, version)
        if key in exception_keys:
            raise InputError(f"{label} duplicates exception for {package}@{version}")
        exception_keys.add(key)
        created_at = parse_timestamp(raw_exception.get("created_at"), f"{label}.created_at")
        expires_at = parse_timestamp(raw_exception.get("expires_at"), f"{label}.expires_at")
        if expires_at <= created_at:
            raise InputError(f"{label}.expires_at must be after created_at")
        if expires_at - created_at > timedelta(hours=effective_max_exception_hours):
            findings.append(
                f"exception {package}@{version} exceeds "
                f"{effective_max_exception_hours} hour maximum"
            )
        owner = require_nonempty_text(raw_exception.get("owner"), f"{label}.owner")
        justification = require_nonempty_text(
            raw_exception.get("justification"), f"{label}.justification"
        )
        approved_by = require_nonempty_text(
            raw_exception.get("approved_by"), f"{label}.approved_by"
        )
        if len(justification) < 20:
            findings.append(
                f"exception {package}@{version} justification is too short"
            )
        if owner == approved_by:
            findings.append(
                f"exception {package}@{version} owner and approver must differ"
            )
        exception = ExceptionRecord(
            package=package,
            version=version,
            owner=owner,
            justification=justification,
            approved_by=approved_by,
            created_at=created_at,
            expires_at=expires_at,
        )
        exceptions.append(exception)
        if as_of < created_at:
            findings.append(f"exception {package}@{version} is not active yet")
    return minimum_hours, registries, require_integrity is True, exceptions, findings


def resolve_artifact(lockfile_path: Path, raw_path: Any, label: str) -> Path:
    relative = Path(require_nonempty_text(raw_path, label))
    if relative.is_absolute():
        raise InputError(f"{label} must be relative to the lockfile")
    root = lockfile_path.parent.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise InputError(f"{label} escapes the lockfile directory") from error
    if not resolved.is_file():
        raise InputError(f"{label} does not exist: {relative}")
    return resolved


def artifact_integrity(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise InputError(f"cannot read artifact {path}: {error}") from error
    return f"sha256:{digest.hexdigest()}"


def resolve_client_config(policy_path: Path, raw_path: Any, label: str) -> Path:
    relative = Path(require_nonempty_text(raw_path, label))
    if relative.is_absolute():
        raise InputError(f"{label} must be relative to the proxy policy")
    root = policy_path.parent.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise InputError(f"{label} escapes the proxy policy directory") from error
    if not resolved.is_file():
        raise InputError(f"{label} does not exist: {relative}")
    return resolved


def read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InputError(f"cannot read {label} {path}: {error}") from error


def validate_client_config(
    ecosystem: str, path: Path, endpoint: str
) -> list[str]:
    findings: list[str] = []
    text = read_text(path, f"{ecosystem} client config")
    if ecosystem == "npm":
        values = [
            line.split("=", 1)[1].strip().rstrip("/")
            for line in text.splitlines()
            if line.strip().startswith("registry=")
        ]
        if values != [endpoint]:
            findings.append("npm registry does not use the exact managed proxy")
    elif ecosystem == "pip":
        index_values = []
        extra_values = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("index-url") and "=" in line:
                index_values.append(line.split("=", 1)[1].strip().rstrip("/"))
            if line.startswith("extra-index-url") and "=" in line:
                extra_values.append(line.split("=", 1)[1].strip())
        if index_values != [endpoint]:
            findings.append("pip index-url does not use the exact managed proxy")
        if extra_values:
            findings.append("pip extra-index-url creates a dependency-confusion fallback")
    elif ecosystem == "go":
        values = [
            line.split("=", 1)[1].strip().rstrip("/")
            for line in text.splitlines()
            if line.strip().startswith("GOPROXY=")
        ]
        if values != [endpoint]:
            findings.append("GOPROXY does not use only the exact managed proxy")
        if any(
            "direct" in value.split(",") or "direct" in value.split("|")
            for value in values
        ):
            findings.append("GOPROXY permits a direct fallback")
    elif ecosystem == "composer":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise InputError(f"cannot parse composer client config {path}: {error}") from error
        if not isinstance(value, dict):
            raise InputError("composer client config must be a JSON object")
        repositories = value.get("repositories")
        if not isinstance(repositories, list):
            raise InputError("composer repositories must be a list")
        proxy_rows = [
            item
            for item in repositories
            if isinstance(item, dict) and item.get("url") == endpoint
        ]
        if len(proxy_rows) != 1 or proxy_rows[0].get("canonical") is not True:
            findings.append("Composer proxy is missing or is not canonical")
        packagist_disabled = any(
            isinstance(item, dict) and item.get("packagist.org") is False
            for item in repositories
        )
        if not packagist_disabled:
            findings.append("Composer permits direct Packagist fallback")
    else:
        raise InputError(f"unsupported proxy client ecosystem: {ecosystem}")
    return findings


def validate_proxy_policy(
    policy_path: Path,
    value: dict[str, Any],
    minimum_release_age_hours: int,
    allowed_registries: set[str],
) -> list[str]:
    findings: list[str] = []
    if value.get("schema") != "psb-registry-proxy-policy/1.0":
        findings.append("proxy policy schema is unsupported")
    if value.get("mode") != "managed-security-registry-proxy":
        findings.append("dependency proxy is optional or unmanaged")
    if value.get("managed_distribution") != "mdm-and-ci-template":
        findings.append("dependency proxy configuration is not centrally distributed")
    if value.get("direct_registry_egress") != "denied":
        findings.append("public registry egress can bypass the proxy")
    if value.get("fallback") != "denied":
        findings.append("package manager can fall back around the proxy")
    if value.get("outage_state") != "ERROR":
        findings.append("proxy outage can appear clean or use a fallback")
    if value.get("credential_handling") != "keychain-or-runtime-injection":
        findings.append("proxy credential handling can persist plaintext credentials")
    if value.get("publish_path") != "separate-explicit-upstream":
        findings.append("read-only install proxy and package publication are not separated")

    cooldown = value.get("cooldown")
    if not isinstance(cooldown, dict):
        raise InputError("proxy policy.cooldown must be an object")
    if cooldown.get("enforcement") != "repository-owned-pre-resolution-verifier":
        findings.append("proxy blocklist is incorrectly treated as release cooldown")
    if cooldown.get("minimum_release_age_hours") != minimum_release_age_hours:
        findings.append("proxy profile cooldown does not match repository policy")
    if cooldown.get("proxy_minimum_age_claim") != "not-relied-upon":
        findings.append("undocumented proxy minimum-age behavior is relied upon")

    expected_capabilities = {
        "malicious-package-blocking",
        "download-tracking",
        "breach-notification",
    }
    raw_capabilities = value.get("proxy_capabilities")
    if not isinstance(raw_capabilities, list):
        raise InputError("proxy policy.proxy_capabilities must be a list")
    if set(raw_capabilities) != expected_capabilities:
        findings.append("proxy blocking tracking and notification capabilities are incomplete")

    clients = value.get("client_configs")
    if not isinstance(clients, list):
        raise InputError("proxy policy.client_configs must be a list")
    expected_ecosystems = {"npm", "pip", "go", "composer"}
    seen: set[str] = set()
    endpoints: set[str] = set()
    for index, client in enumerate(clients):
        label = f"proxy policy.client_configs[{index}]"
        if not isinstance(client, dict):
            raise InputError(f"{label} must be an object")
        ecosystem = require_nonempty_text(client.get("ecosystem"), f"{label}.ecosystem")
        if ecosystem in seen:
            raise InputError(f"{label} duplicates ecosystem {ecosystem}")
        seen.add(ecosystem)
        endpoint = validate_proxy_endpoint(client.get("endpoint"), f"{label}.endpoint")
        endpoints.add(endpoint)
        config_path = resolve_client_config(
            policy_path, client.get("path"), f"{label}.path"
        )
        findings.extend(validate_client_config(ecosystem, config_path, endpoint))
    if seen != expected_ecosystems:
        findings.append("npm pip Go and Composer proxy profiles are all required")
    if not allowed_registries <= endpoints:
        findings.append("cooldown registry allowlist is not routed through a client proxy")

    canary = value.get("canary")
    if not isinstance(canary, dict):
        raise InputError("proxy policy.canary must be an object")
    if (
        canary.get("kind") != "synthetic-provider-test-package"
        or canary.get("expected") != "blocked-before-artifact-download"
        or canary.get("real_malware") is not False
    ):
        findings.append("proxy path is not verified with a harmless blocking canary")
    return findings


def verify(
    policy_path: Path,
    proxy_policy_path: Path,
    lockfile_path: Path,
    metadata_path: Path,
    as_of: datetime,
) -> tuple[int, int, list[str]]:
    policy = load_json(policy_path, "policy")
    lockfile = load_json(lockfile_path, "lockfile")
    metadata = load_json(metadata_path, "metadata")
    (
        minimum_hours,
        allowed_registries,
        require_integrity,
        exceptions,
        findings,
    ) = load_policy(policy, as_of)
    findings.extend(
        validate_proxy_policy(
            proxy_policy_path,
            load_json(proxy_policy_path, "proxy policy"),
            minimum_hours,
            allowed_registries,
        )
    )
    effective_minimum = max(minimum_hours, REFERENCE_MINIMUM_HOURS)

    dependencies = lockfile.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise InputError("lockfile.dependencies must be a non-empty list")
    packages = metadata.get("packages")
    if not isinstance(packages, dict):
        raise InputError("metadata.packages must be an object")

    seen_dependencies: set[tuple[str, str]] = set()
    used_exceptions: set[tuple[str, str]] = set()
    for index, dependency in enumerate(dependencies):
        label = f"lockfile.dependencies[{index}]"
        if not isinstance(dependency, dict):
            raise InputError(f"{label} must be an object")
        package = validate_exact_identifier(
            dependency.get("package"), f"{label}.package", PACKAGE_RE
        )
        version = validate_exact_identifier(
            dependency.get("version"), f"{label}.version", VERSION_RE
        )
        key = (package, version)
        if key in seen_dependencies:
            raise InputError(f"duplicate dependency {package}@{version}")
        seen_dependencies.add(key)

        registry = validate_registry_url(dependency.get("registry"), f"{label}.registry")
        if registry not in allowed_registries:
            findings.append(f"{package}@{version} uses unapproved registry {registry}")

        package_metadata = packages.get(package)
        if not isinstance(package_metadata, dict):
            raise InputError(f"metadata missing package {package}")
        versions = package_metadata.get("versions")
        if not isinstance(versions, dict) or not isinstance(versions.get(version), dict):
            raise InputError(f"metadata missing version {package}@{version}")
        version_metadata = versions[version]
        metadata_registry = validate_registry_url(
            version_metadata.get("registry"),
            f"metadata {package}@{version}.registry",
        )
        if metadata_registry != registry:
            findings.append(
                f"{package}@{version} registry differs between lockfile and metadata"
            )

        released_at = parse_timestamp(
            version_metadata.get("released_at"),
            f"metadata {package}@{version}.released_at",
        )
        if released_at > as_of:
            raise InputError(f"metadata release time is in the future for {package}@{version}")
        age_hours = int((as_of - released_at).total_seconds() // 3600)

        lock_integrity = dependency.get("integrity")
        metadata_integrity = version_metadata.get("integrity")
        integrity_valid = (
            isinstance(lock_integrity, str)
            and INTEGRITY_RE.fullmatch(lock_integrity) is not None
        )
        if require_integrity and not integrity_valid:
            findings.append(f"{package}@{version} has missing or invalid sha256 integrity")
        if integrity_valid:
            if metadata_integrity != lock_integrity:
                findings.append(
                    f"{package}@{version} integrity differs between lockfile and metadata"
                )
            artifact = resolve_artifact(lockfile_path, dependency.get("artifact"), f"{label}.artifact")
            if artifact_integrity(artifact) != lock_integrity:
                findings.append(f"{package}@{version} artifact sha256 does not match lockfile")

        if age_hours < effective_minimum:
            active_exception = next(
                (
                    exception
                    for exception in exceptions
                    if (exception.package, exception.version) == key
                    and exception.created_at <= as_of < exception.expires_at
                ),
                None,
            )
            if active_exception is None:
                findings.append(
                    f"{package}@{version} age is {age_hours} hours; "
                    f"minimum is {effective_minimum}"
                )
            else:
                used_exceptions.add(key)

    for exception in exceptions:
        key = (exception.package, exception.version)
        if key not in used_exceptions:
            findings.append(f"exception {exception.package}@{exception.version} is unused")

    return len(dependencies), len(used_exceptions), findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--proxy-policy", required=True, type=Path)
    parser.add_argument("--lockfile", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()

    try:
        as_of = parse_timestamp(args.as_of, "--as-of")
        dependencies, used_exceptions, findings = verify(
            args.policy,
            args.proxy_policy,
            args.lockfile,
            args.metadata,
            as_of,
        )
    except InputError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    for finding in findings:
        print(f"FAIL {finding}")
    if findings:
        print(f"REJECTED {len(findings)} cooldown finding(s)")
        return 1
    print(
        f"ACCEPTED {dependencies} dependencies; "
        f"{used_exceptions} cooldown exception(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
