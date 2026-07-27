#!/usr/bin/env python3
"""Verify producer selection and use of a consistent hosted build process."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class InputError(ValueError):
    """The verifier could not evaluate the supplied evidence."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    if value.get("schema_version") != 1:
        raise InputError(f"{label}.schema_version must be 1")
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


def is_https_url(value: str) -> bool:
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.fragment == ""
    )


def verify(policy_path: Path, record_path: Path) -> list[str]:
    policy = load_json(policy_path, "build policy")
    record = load_json(record_path, "build record")
    findings: list[str] = []

    target_level = int_field(policy, "target_slsa_build_level", "policy")
    if target_level != 2:
        findings.append("policy target SLSA Build level must be exactly 2")
    source_repository = text_field(policy, "source_repository", "policy")
    if not is_https_url(source_repository):
        findings.append("policy source repository must be an exact HTTPS URL")

    approved_builders = list_field(policy, "approved_builders", "policy")
    if not approved_builders:
        raise InputError("policy.approved_builders must not be empty")
    indexed_builders: dict[str, dict[str, Any]] = {}
    for index, raw_builder in enumerate(approved_builders):
        if not isinstance(raw_builder, dict):
            raise InputError(f"policy.approved_builders[{index}] must be an object")
        label = f"policy.approved_builders[{index}]"
        identity = text_field(raw_builder, "identity", label)
        if identity in indexed_builders:
            raise InputError(f"duplicate approved builder identity: {identity}")
        indexed_builders[identity] = raw_builder
        if not is_https_url(identity):
            findings.append(f"approved builder {identity} must use an HTTPS identity")
        if bool_field(raw_builder, "hosted", label) is not True:
            findings.append(f"approved builder {identity} must be hosted")
        assessed_level = int_field(raw_builder, "assessed_slsa_build_level", label)
        if assessed_level < target_level:
            findings.append(
                f"approved builder {identity} assessed level must be at least "
                f"{target_level}"
            )
        evidence = object_field(raw_builder, "capability_evidence", label)
        evidence_uri = text_field(evidence, "uri", f"{label}.capability_evidence")
        if not is_https_url(evidence_uri):
            findings.append(
                f"approved builder {identity} capability evidence must use HTTPS"
            )
        evidence_digest = text_field(
            evidence, "sha256", f"{label}.capability_evidence"
        )
        if SHA256_RE.fullmatch(evidence_digest) is None:
            findings.append(
                f"approved builder {identity} capability evidence must be SHA-256 pinned"
            )

    expected_process = object_field(policy, "process", "policy")
    definition_repository = text_field(
        expected_process, "definition_repository", "policy.process"
    )
    definition_path = text_field(
        expected_process, "definition_path", "policy.process"
    )
    revision_binding = text_field(
        expected_process, "revision_binding", "policy.process"
    )
    if revision_binding != "source-revision":
        findings.append("build definition must be bound to the source revision")
    entry_point = text_field(expected_process, "entry_point", "policy.process")
    expected_parameters = object_field(expected_process, "parameters", "policy.process")
    allowed_triggers = list_field(
        expected_process, "allowed_triggers", "policy.process"
    )
    if not allowed_triggers or any(
        not isinstance(trigger, str) or not trigger for trigger in allowed_triggers
    ):
        raise InputError("policy.process.allowed_triggers must contain text values")

    release_policy = object_field(policy, "release_policy", "policy")
    if bool_field(release_policy, "require_hosted", "policy.release_policy") is not True:
        findings.append("release policy must require hosted builds")
    if (
        bool_field(
            release_policy,
            "allow_developer_workstation",
            "policy.release_policy",
        )
        is not False
    ):
        findings.append("release policy must reject developer workstation builds")

    artifact = object_field(record, "artifact", "record")
    text_field(artifact, "name", "record.artifact")
    artifact_digest = text_field(artifact, "sha256", "record.artifact")
    if SHA256_RE.fullmatch(artifact_digest) is None:
        findings.append("artifact digest must be a lowercase SHA-256")

    actual_builder = object_field(record, "builder", "record")
    builder_identity = text_field(actual_builder, "identity", "record.builder")
    selected_builder = indexed_builders.get(builder_identity)
    if selected_builder is None:
        findings.append(f"builder {builder_identity} is not approved by the producer")
    execution_environment = text_field(
        actual_builder, "execution_environment", "record.builder"
    )
    if execution_environment != "hosted":
        findings.append("release build must run in a hosted execution environment")
    executor_control = text_field(
        actual_builder, "executor_control", "record.builder"
    )
    if executor_control != "build-platform":
        findings.append("release build execution must be controlled by the build platform")

    source = object_field(record, "source", "record")
    actual_source_repository = text_field(source, "repository", "record.source")
    if actual_source_repository != source_repository:
        findings.append("recorded source repository does not match producer policy")
    source_revision = text_field(source, "revision", "record.source")
    if COMMIT_RE.fullmatch(source_revision) is None:
        findings.append("source revision must be a full lowercase commit SHA")

    actual_process = object_field(record, "process", "record")
    if (
        text_field(
            actual_process, "definition_repository", "record.process"
        )
        != definition_repository
    ):
        findings.append("build definition repository does not match producer policy")
    definition_revision = text_field(
        actual_process, "definition_revision", "record.process"
    )
    if COMMIT_RE.fullmatch(definition_revision) is None:
        findings.append("build definition revision must be a full lowercase commit SHA")
    if revision_binding == "source-revision" and definition_revision != source_revision:
        findings.append("build definition revision must equal the source revision")
    if (
        text_field(actual_process, "definition_path", "record.process")
        != definition_path
    ):
        findings.append("build definition path does not match producer policy")
    if text_field(actual_process, "entry_point", "record.process") != entry_point:
        findings.append("build entry point does not match producer policy")
    actual_parameters = object_field(actual_process, "parameters", "record.process")
    if actual_parameters != expected_parameters:
        findings.append("build parameters do not exactly match producer policy")
    trigger = text_field(record, "trigger", "record")
    if trigger not in allowed_triggers:
        findings.append(f"release trigger {trigger} is not allowed by producer policy")

    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    args = parser.parse_args()
    try:
        findings = verify(args.policy, args.record)
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print(
        "PASS consistent hosted build process verified for "
        "SLSA Build L2 producer requirements"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
