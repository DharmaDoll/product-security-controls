#!/usr/bin/env python3
"""Verify normalized manifest, lockfile, registry, and artifact integrity."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z-]+)+(?:\+[0-9A-Za-z.-]+)?$")


class InputError(ValueError):
    pass


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise InputError(f"cannot read {label} {path}: {error}") from error


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path, label))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot parse {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def digest(path: Path, label: str) -> str:
    return hashlib.sha256(read_bytes(path, label)).hexdigest()


def registry_origin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise InputError(f"{label} must be text")
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise InputError(f"{label} must be a credential-free HTTPS origin")
    return value.rstrip("/")


def resolve_artifact(lockfile_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise InputError("lockfile artifact path must be non-empty text")
    relative = Path(value)
    if relative.is_absolute():
        raise InputError("lockfile artifact path must be relative")
    root = lockfile_path.parent.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise InputError("lockfile artifact path escapes fixture root") from error
    if not resolved.is_file():
        raise InputError(f"artifact does not exist: {value}")
    return resolved


def verify(policy_path: Path, manifest_path: Path, lockfile_path: Path) -> list[str]:
    policy = load_json(policy_path, "policy")
    manifest = load_json(manifest_path, "manifest")
    lockfile = load_json(lockfile_path, "lockfile")
    findings: list[str] = []

    if policy.get("require_frozen") is not True:
        findings.append("policy.require_frozen must be true")
    if policy.get("require_manifest_digest") is not True:
        findings.append("policy.require_manifest_digest must be true")
    if policy.get("allowed_integrity_algorithms") != ["sha256"]:
        findings.append("policy.allowed_integrity_algorithms must be exactly [sha256]")

    registry_route = policy.get("registry_route")
    if not isinstance(registry_route, dict):
        raise InputError("policy.registry_route must be an object")
    if registry_route.get("mode") != "managed-security-proxy":
        findings.append("dependency registry route must use a managed security proxy")
    if registry_route.get("direct_fallback") is not False:
        findings.append("dependency registry route permits direct fallback")
    if registry_route.get("outage_state") != "ERROR":
        findings.append("dependency registry proxy outage is not an ERROR")
    if registry_route.get("credentials") != "external-runtime-injection":
        findings.append("dependency registry credentials are not externally injected")

    raw_registries = policy.get("allowed_registries")
    if not isinstance(raw_registries, list) or not raw_registries:
        raise InputError("policy.allowed_registries must be a non-empty list")
    try:
        registries = {registry_origin(item, "allowed registry") for item in raw_registries}
    except InputError as error:
        findings.append(str(error))
        registries = set()

    if lockfile.get("frozen") is not True:
        findings.append("lockfile.frozen must be true")
    expected_manifest_digest = digest(manifest_path, "manifest")
    if lockfile.get("manifest_sha256") != expected_manifest_digest:
        findings.append("lockfile manifest SHA-256 does not match manifest")

    manifest_dependencies = manifest.get("dependencies")
    locked_dependencies = lockfile.get("dependencies")
    if not isinstance(manifest_dependencies, dict) or not manifest_dependencies:
        raise InputError("manifest.dependencies must be a non-empty object")
    if not isinstance(locked_dependencies, dict) or not locked_dependencies:
        raise InputError("lockfile.dependencies must be a non-empty object")
    if set(manifest_dependencies) != set(locked_dependencies):
        findings.append("manifest and lockfile dependency sets differ")

    for package in sorted(set(manifest_dependencies) & set(locked_dependencies)):
        wanted = manifest_dependencies[package]
        locked = locked_dependencies[package]
        if not isinstance(wanted, str) or not EXACT_VERSION_RE.fullmatch(wanted):
            findings.append(f"{package} manifest version must be exact: {wanted}")
        if not isinstance(locked, dict):
            raise InputError(f"lockfile dependency {package} must be an object")
        version = locked.get("version")
        if version != wanted:
            findings.append(f"{package} manifest and lockfile versions differ")
        if not isinstance(version, str) or not EXACT_VERSION_RE.fullmatch(version):
            findings.append(f"{package} lockfile version must be exact")

        try:
            registry = registry_origin(locked.get("registry"), f"{package} registry")
        except InputError as error:
            findings.append(str(error))
        else:
            if registry not in registries:
                findings.append(f"{package} registry is not allowed: {registry}")

        integrity = locked.get("integrity")
        if not isinstance(integrity, str) or not SHA256_RE.fullmatch(integrity):
            findings.append(f"{package} integrity must be SHA-256")
            continue
        artifact = resolve_artifact(lockfile_path, locked.get("artifact"))
        actual = f"sha256:{digest(artifact, f'{package} artifact')}"
        if actual != integrity:
            findings.append(f"{package} artifact SHA-256 does not match lockfile")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lockfile", type=Path, required=True)
    args = parser.parse_args()
    try:
        findings = verify(args.policy, args.manifest, args.lockfile)
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print("PASS frozen lockfile manifest registry and artifact integrity verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
