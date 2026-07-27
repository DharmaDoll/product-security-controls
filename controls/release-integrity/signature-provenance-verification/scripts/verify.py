#!/usr/bin/env python3
"""Verify an artifact, signed SLSA provenance, and consumer expectations."""

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
from pathlib import Path
from typing import Any


FULL_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
TRUST_LEVELS = {"unsigned": 0, "signed": 1, "signed-provenance": 2}


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


def policy_text(policy: dict[str, Any], field: str) -> str:
    value = policy.get(field)
    if not isinstance(value, str) or not value:
        raise InputError(f"policy.{field} must be non-empty text")
    return value


def resolve_key(policy_path: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute():
        raise InputError("trusted_public_key must be relative to policy")
    resolved = (policy_path.parent / relative).resolve()
    if not resolved.is_file():
        raise InputError(f"trusted public key does not exist: {value}")
    return resolved


def verify_signature(
    provenance_path: Path, signature_path: Path, public_key: Path
) -> bool:
    encoded = read_bytes(signature_path, "signature").strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InputError(f"signature is not valid base64: {error}") from error
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(signature)
        handle.flush()
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(provenance_path),
                    "-sigfile",
                    handle.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as error:
            raise InputError(f"cannot execute OpenSSL: {error}") from error
    return result.returncode == 0


def nested(value: Any, path: list[str], label: str) -> Any:
    current = value
    for part in path:
        if not isinstance(current, dict) or part not in current:
            raise InputError(f"{label} missing {'.'.join(path)}")
        current = current[part]
    return current


def verify(
    policy_path: Path,
    artifact_path: Path,
    provenance_path: Path,
    signature_path: Path,
) -> list[str]:
    policy = load_json(policy_path, "policy")
    provenance = load_json(provenance_path, "provenance")
    findings: list[str] = []

    minimum = policy_text(policy, "minimum_trust_level")
    previous = policy_text(policy, "previous_trust_level")
    if minimum not in TRUST_LEVELS or previous not in TRUST_LEVELS:
        raise InputError("policy trust levels are unsupported")
    if TRUST_LEVELS[minimum] < TRUST_LEVELS[previous]:
        findings.append(f"trust level downgrade: {previous} to {minimum}")
    if minimum != "signed-provenance":
        findings.append("minimum_trust_level must be signed-provenance")
    if policy_text(policy, "signature_algorithm") != "ed25519":
        findings.append("signature_algorithm must be ed25519")

    artifact_digest = hashlib.sha256(read_bytes(artifact_path, "artifact")).hexdigest()
    subjects = provenance.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise InputError("provenance.subject must contain exactly one subject")
    subject = subjects[0]
    if not isinstance(subject, dict):
        raise InputError("provenance subject must be an object")
    if subject.get("name") != policy_text(policy, "expected_subject_name"):
        findings.append("provenance subject name does not match expectation")
    digest_value = nested(subject, ["digest", "sha256"], "provenance subject")
    if digest_value != artifact_digest:
        findings.append("artifact SHA-256 does not match provenance subject")

    public_key = resolve_key(policy_path, policy_text(policy, "trusted_public_key"))
    if not verify_signature(provenance_path, signature_path, public_key):
        findings.append("provenance signature verification failed")

    if provenance.get("_type") != "https://in-toto.io/Statement/v1":
        findings.append("provenance _type must be in-toto Statement v1")
    if provenance.get("predicateType") != policy_text(
        policy, "expected_predicate_type"
    ):
        findings.append("provenance predicateType does not match expectation")

    build_definition = nested(
        provenance, ["predicate", "buildDefinition"], "provenance"
    )
    run_details = nested(provenance, ["predicate", "runDetails"], "provenance")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        raise InputError("provenance buildDefinition and runDetails must be objects")
    if build_definition.get("buildType") != policy_text(policy, "expected_build_type"):
        findings.append("provenance buildType does not match expectation")
    builder = nested(run_details, ["builder", "id"], "provenance runDetails")
    if builder != policy_text(policy, "expected_builder_id"):
        findings.append("provenance builder.id does not match trusted signer-builder pair")

    external = build_definition.get("externalParameters")
    if not isinstance(external, dict):
        raise InputError("provenance externalParameters must be an object")
    allowed = policy.get("allowed_external_parameters")
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        raise InputError("policy.allowed_external_parameters must be a string list")
    unknown = sorted(set(external) - set(allowed))
    if unknown:
        findings.append(f"provenance has unknown external parameters: {', '.join(unknown)}")
    if external.get("repository") != policy_text(policy, "expected_repository"):
        findings.append("provenance source repository does not match expectation")
    if external.get("ref") != policy_text(policy, "expected_ref"):
        findings.append("provenance source ref does not match expectation")

    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or len(dependencies) != 1:
        raise InputError("provenance must contain one resolved source dependency")
    source_commit = nested(
        dependencies[0], ["digest", "gitCommit"], "resolved source dependency"
    )
    expected_commit = policy_text(policy, "expected_source_commit")
    if not isinstance(source_commit, str) or not FULL_SHA_RE.fullmatch(source_commit):
        findings.append("provenance source commit must be a full immutable SHA")
    if source_commit != expected_commit:
        findings.append("provenance source commit does not match expectation")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    try:
        findings = verify(
            args.policy, args.artifact, args.provenance, args.signature
        )
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print("PASS artifact signature and SLSA provenance expectations verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
