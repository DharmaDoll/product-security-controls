#!/usr/bin/env python3
"""Verify automatic, control-plane-generated, authentic build provenance."""

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


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_CONTROL_PLANE_FIELDS = (
    "predicate.buildDefinition.buildType",
    "predicate.buildDefinition.externalParameters",
    "predicate.runDetails.builder.id",
    "predicate.runDetails.metadata.invocationId",
)


class InputError(ValueError):
    """The verifier could not evaluate the supplied evidence."""


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


def object_field(value: dict[str, Any], field: str, label: str) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise InputError(f"{label}.{field} must be an object")
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


def nested(value: Any, path: list[str], label: str) -> Any:
    current = value
    for part in path:
        if not isinstance(current, dict) or part not in current:
            raise InputError(f"{label} missing {'.'.join(path)}")
        current = current[part]
    return current


def resolve_key(policy_path: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute():
        raise InputError("trusted_public_key must be relative to platform policy")
    policy_directory = policy_path.parent.resolve()
    resolved = (policy_directory / relative).resolve()
    try:
        resolved.relative_to(policy_directory)
    except ValueError as error:
        raise InputError("trusted_public_key must remain within policy directory") from error
    if not resolved.is_file():
        raise InputError(f"trusted public key does not exist: {value}")
    return resolved


def verify_signature(
    provenance_path: Path,
    signature_path: Path,
    public_key: Path,
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


def verify(
    policy_path: Path,
    artifact_path: Path,
    provenance_path: Path,
    signature_path: Path,
) -> list[str]:
    policy = load_json(policy_path, "platform policy")
    provenance = load_json(provenance_path, "provenance")
    findings: list[str] = []

    if policy.get("schema_version") != 1:
        raise InputError("platform policy.schema_version must be 1")
    target_level = policy.get("target_slsa_build_level")
    if not isinstance(target_level, int) or isinstance(target_level, bool):
        raise InputError("platform policy.target_slsa_build_level must be an integer")
    if target_level != 2:
        findings.append("platform policy target SLSA Build level must be exactly 2")

    generation = object_field(policy, "generation", "platform policy")
    if (
        bool_field(
            generation,
            "automatic_on_build_success",
            "platform policy.generation",
        )
        is not True
    ):
        findings.append("provenance generation must be automatic on build success")
    if (
        text_field(
            generation,
            "generator_trust_boundary",
            "platform policy.generation",
        )
        != "control-plane"
    ):
        findings.append("provenance generator must run in the control plane")
    if (
        bool_field(
            generation,
            "build_steps_can_disable",
            "platform policy.generation",
        )
        is not False
    ):
        findings.append("tenant build steps must not disable provenance generation")
    if (
        bool_field(
            generation,
            "build_steps_can_modify",
            "platform policy.generation",
        )
        is not False
    ):
        findings.append("tenant build steps must not modify generated provenance")

    authenticity = object_field(policy, "authenticity", "platform policy")
    if (
        text_field(authenticity, "algorithm", "platform policy.authenticity")
        != "ed25519"
    ):
        findings.append("provenance signature algorithm must be ed25519")
    if (
        text_field(
            authenticity,
            "signer_trust_boundary",
            "platform policy.authenticity",
        )
        != "control-plane"
    ):
        findings.append("provenance signer must run in the control plane")
    if (
        text_field(authenticity, "key_owner", "platform policy.authenticity")
        != "build-platform"
    ):
        findings.append("provenance signing identity must be owned by the build platform")
    if (
        bool_field(
            authenticity,
            "tenant_signing_capability",
            "platform policy.authenticity",
        )
        is not False
    ):
        findings.append("tenant must not have platform provenance signing capability")
    public_key = resolve_key(
        policy_path,
        text_field(
            authenticity,
            "trusted_public_key",
            "platform policy.authenticity",
        ),
    )

    field_sources = object_field(policy, "field_sources", "platform policy")
    for field in REQUIRED_CONTROL_PLANE_FIELDS:
        if field_sources.get(field) != "control-plane":
            findings.append(f"required provenance field must come from control plane: {field}")

    expected = object_field(policy, "expected", "platform policy")
    expected_subject = text_field(expected, "subject_name", "platform policy.expected")
    expected_builder = text_field(expected, "builder_id", "platform policy.expected")
    expected_build_type = text_field(
        expected, "build_type", "platform policy.expected"
    )
    expected_repository = text_field(
        expected, "repository", "platform policy.expected"
    )
    expected_ref = text_field(expected, "ref", "platform policy.expected")
    expected_commit = text_field(
        expected, "source_commit", "platform policy.expected"
    )
    if COMMIT_RE.fullmatch(expected_commit) is None:
        raise InputError("platform policy.expected.source_commit must be a full SHA")

    artifact_digest = hashlib.sha256(read_bytes(artifact_path, "artifact")).hexdigest()
    subjects = provenance.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise InputError("provenance.subject must contain exactly one subject")
    subject = subjects[0]
    if not isinstance(subject, dict):
        raise InputError("provenance subject must be an object")
    if subject.get("name") != expected_subject:
        findings.append("provenance subject name does not match platform policy")
    if nested(subject, ["digest", "sha256"], "provenance subject") != artifact_digest:
        findings.append("artifact SHA-256 does not match provenance subject")

    if provenance.get("_type") != "https://in-toto.io/Statement/v1":
        findings.append("provenance _type must be in-toto Statement v1")
    if provenance.get("predicateType") != "https://slsa.dev/provenance/v1":
        findings.append("provenance predicateType must be SLSA provenance v1")

    build_definition = nested(
        provenance, ["predicate", "buildDefinition"], "provenance"
    )
    run_details = nested(provenance, ["predicate", "runDetails"], "provenance")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        raise InputError("provenance buildDefinition and runDetails must be objects")
    if build_definition.get("buildType") != expected_build_type:
        findings.append("provenance buildType does not match platform policy")
    external_parameters = object_field(
        build_definition,
        "externalParameters",
        "provenance.predicate.buildDefinition",
    )
    if external_parameters.get("repository") != expected_repository:
        findings.append("provenance repository does not match platform policy")
    if external_parameters.get("ref") != expected_ref:
        findings.append("provenance ref does not match platform policy")

    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or len(dependencies) != 1:
        raise InputError("provenance must contain one resolved source dependency")
    dependency = dependencies[0]
    if not isinstance(dependency, dict):
        raise InputError("resolved source dependency must be an object")
    if dependency.get("uri") != f"git+{expected_repository}":
        findings.append("resolved source URI does not match platform policy")
    source_commit = nested(
        dependency,
        ["digest", "gitCommit"],
        "resolved source dependency",
    )
    if not isinstance(source_commit, str) or COMMIT_RE.fullmatch(source_commit) is None:
        findings.append("provenance source commit must be a full SHA")
    if source_commit != expected_commit:
        findings.append("provenance source commit does not match platform policy")

    builder = nested(run_details, ["builder", "id"], "provenance runDetails")
    if builder != expected_builder:
        findings.append("provenance builder identity does not match platform policy")
    invocation_id = nested(
        run_details,
        ["metadata", "invocationId"],
        "provenance runDetails",
    )
    if not isinstance(invocation_id, str) or not invocation_id:
        findings.append("provenance invocationId must be non-empty")

    if not verify_signature(provenance_path, signature_path, public_key):
        findings.append("platform provenance signature verification failed")
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
            args.policy,
            args.artifact,
            args.provenance,
            args.signature,
        )
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print("PASS automatic control-plane-generated authentic provenance verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
