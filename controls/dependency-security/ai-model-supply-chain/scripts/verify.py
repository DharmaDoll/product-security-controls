#!/usr/bin/env python3
"""Verify an AI model bundle without executing the model or its loader."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DTYPE_BYTES = {"F32": 4}


class EvaluationError(RuntimeError):
    """Trusted policy or verification infrastructure is unavailable."""


class BundleError(ValueError):
    """Untrusted model-bundle input is absent, malformed, or unsupported."""

    def __init__(self, message: str, check_id: str) -> None:
        super().__init__(message)
        self.check_id = check_id


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_trusted(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvaluationError(f"cannot read {label}") from error


def read_bundle(path: Path, label: str, check_id: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise BundleError(f"{label} is missing or unreadable", check_id) from error


def load_json_bytes(raw: bytes, label: str, *, trusted: bool, check_id: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        if trusted:
            raise EvaluationError(f"cannot parse {label}") from error
        raise BundleError(f"{label} is malformed", check_id) from error
    if not isinstance(value, dict):
        if trusted:
            raise EvaluationError(f"{label} must be a JSON object")
        raise BundleError(f"{label} must be a JSON object", check_id)
    return value


def load_trusted_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    raw = read_trusted(path, label)
    return raw, load_json_bytes(raw, label, trusted=True, check_id="AMS-008")


def load_bundle_json(
    path: Path, label: str, check_id: str
) -> tuple[bytes, dict[str, Any]]:
    raw = read_bundle(path, label, check_id)
    return raw, load_json_bytes(raw, label, trusted=False, check_id=check_id)


def trusted_object(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise EvaluationError(f"{label}.{key} must be an object")
    return child


def bundle_object(
    value: dict[str, Any], key: str, label: str, check_id: str
) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise BundleError(f"{label}.{key} must be an object", check_id)
    return child


def parse_time(value: Any, label: str, *, trusted: bool, check_id: str) -> datetime:
    if not isinstance(value, str):
        if trusted:
            raise EvaluationError(f"{label} must be an RFC3339 timestamp")
        raise BundleError(f"{label} must be an RFC3339 timestamp", check_id)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        if trusted:
            raise EvaluationError(f"{label} must be an RFC3339 timestamp") from error
        raise BundleError(f"{label} must be an RFC3339 timestamp", check_id) from error
    if parsed.tzinfo is None:
        if trusted:
            raise EvaluationError(f"{label} must include a timezone")
        raise BundleError(f"{label} must include a timezone", check_id)
    return parsed


def positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EvaluationError(f"{label} must be a positive integer")
    return value


def decode_artifact(path: Path) -> bytes:
    encoded = read_bundle(path, "model artifact fixture", "AMS-001").strip()
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise BundleError(
            "model artifact fixture is not valid base64", "AMS-001"
        ) from error


def resolve_public_key(policy_path: Path, signer: dict[str, Any]) -> Path:
    relative_value = signer.get("public_key")
    if not isinstance(relative_value, str) or not relative_value:
        raise EvaluationError("policy trusted signer public key is missing")
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise EvaluationError("trusted public key must remain inside the policy directory")
    key = (policy_path.parent / relative).resolve()
    if not key.is_file():
        raise EvaluationError("trusted public key is unavailable")
    expected = signer.get("public_key_sha256")
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise EvaluationError("trusted public key digest is invalid")
    if sha256_bytes(read_trusted(key, "trusted public key")) != expected:
        raise EvaluationError("trusted public key digest does not match policy")
    return key


def verify_signature(
    attestation_path: Path,
    signature_path: Path,
    public_key: Path,
    openssl: str,
) -> bool:
    encoded = read_bundle(signature_path, "attestation signature", "AMS-005").strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise BundleError("attestation signature is not valid base64", "AMS-005") from error
    with tempfile.NamedTemporaryFile() as signature_file:
        signature_file.write(signature)
        signature_file.flush()
        try:
            result = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(attestation_path),
                    "-sigfile",
                    signature_file.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as error:
            raise EvaluationError("cannot execute OpenSSL") from error
    return result.returncode == 0


def check_policy(policy: dict[str, Any]) -> list[tuple[str, str]]:
    if policy.get("schema") != "psb-ai-model-intake-policy/v1.0":
        raise EvaluationError("unsupported model intake policy schema")
    artifact = trusted_object(policy, "artifact", "policy")
    mlbom = trusted_object(policy, "mlbom", "policy")
    inspector = trusted_object(policy, "inspector", "policy")
    signer = trusted_object(policy, "trusted_signer", "policy")
    handoff = trusted_object(policy, "handoff", "policy")
    evidence = trusted_object(policy, "evidence", "policy")
    trusted_object(policy, "expected", "policy")
    for key in (
        "maximum_artifact_bytes",
        "maximum_header_bytes",
        "maximum_tensors",
        "maximum_dimensions",
    ):
        positive_integer(artifact.get(key), f"policy.artifact.{key}")
    positive_integer(
        inspector.get("maximum_receipt_age_hours"),
        "policy.inspector.maximum_receipt_age_hours",
    )
    positive_integer(
        signer.get("maximum_status_age_hours"),
        "policy.trusted_signer.maximum_status_age_hours",
    )
    positive_integer(
        signer.get("maximum_attestation_age_hours"),
        "policy.trusted_signer.maximum_attestation_age_hours",
    )
    if mlbom.get("format") != "CycloneDX" or mlbom.get("spec_version") != "1.7":
        raise EvaluationError("only the reviewed CycloneDX 1.7 ML-BOM profile is supported")
    findings: list[tuple[str, str]] = []
    if (
        artifact.get("accepted_serializations") != ["safetensors"]
        or artifact.get("allow_remote_code") is not False
        or artifact.get("require_complete_tensor_buffer") is not True
    ):
        findings.append(("AMS-003", "artifact policy permits executable or ambiguous loading"))
    if (
        handoff.get("required_decision") != "ACCEPTED"
        or handoff.get("require_remote_code") is not False
        or handoff.get("dependency_control") != "PSB-DEPS-003"
    ):
        findings.append(("AMS-007", "deployment handoff policy can bypass accepted immutable dependencies"))
    if any(
        evidence.get(key) is not False
        for key in (
            "include_model_bytes",
            "include_dataset_rows",
            "include_signature",
            "include_key_material",
            "include_source_credentials",
        )
    ):
        findings.append(("AMS-009", "evidence policy permits sensitive model data or trust material"))
    return findings


def check_signer_status(
    snapshot: dict[str, Any],
    policy: dict[str, Any],
    as_of: datetime,
) -> list[tuple[str, str]]:
    if snapshot.get("schema") != "psb-ai-model-signer-status/v1.0":
        raise EvaluationError("unsupported signer status schema")
    if snapshot.get("available") is not True or snapshot.get("complete") is not True:
        raise EvaluationError("signer status evidence is unavailable or incomplete")
    signer_policy = trusted_object(policy, "trusted_signer", "policy")
    collected = parse_time(
        snapshot.get("collected_at"),
        "signer status collected_at",
        trusted=True,
        check_id="AMS-008",
    )
    maximum_age = timedelta(
        hours=positive_integer(
            signer_policy.get("maximum_status_age_hours"),
            "policy.trusted_signer.maximum_status_age_hours",
        )
    )
    if collected > as_of or as_of - collected > maximum_age:
        raise EvaluationError("signer status evidence is stale or from the future")
    records = snapshot.get("signers")
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise EvaluationError("signer status records are malformed")
    signer_id = signer_policy.get("id")
    matching = [item for item in records if item.get("id") == signer_id]
    if len(matching) != 1:
        return [("AMS-005", "attestation signer is absent or ambiguous in the complete status snapshot")]
    record = matching[0]
    findings: list[tuple[str, str]] = []
    if (
        record.get("algorithm") != signer_policy.get("algorithm")
        or record.get("public_key_sha256") != signer_policy.get("public_key_sha256")
        or record.get("status") != "ACTIVE"
    ):
        findings.append(("AMS-005", "attestation signer algorithm key or lifecycle state is not trusted"))
    valid_from = parse_time(
        record.get("valid_from"), "signer valid_from", trusted=True, check_id="AMS-008"
    )
    valid_until = parse_time(
        record.get("valid_until"), "signer valid_until", trusted=True, check_id="AMS-008"
    )
    if not valid_from <= as_of < valid_until:
        findings.append(("AMS-005", "attestation signer is outside its validity window"))
    allowed = record.get("allowed_model_ids")
    expected = trusted_object(policy, "expected", "policy")
    if allowed != [expected.get("model_id")]:
        findings.append(("AMS-005", "attestation signer scope is not bound to the expected model"))
    return findings


def check_acquisition(
    acquisition: dict[str, Any],
    artifact: bytes,
    dataset: bytes,
    policy: dict[str, Any],
) -> list[tuple[str, str]]:
    if acquisition.get("schema") != "psb-ai-model-acquisition/v1.0":
        raise BundleError("unsupported acquisition schema", "AMS-001")
    model = bundle_object(acquisition, "model", "acquisition", "AMS-001")
    dataset_claim = bundle_object(acquisition, "dataset", "acquisition", "AMS-006")
    loader = bundle_object(acquisition, "loader", "acquisition", "AMS-003")
    expected = trusted_object(policy, "expected", "policy")
    artifact_policy = trusted_object(policy, "artifact", "policy")
    findings: list[tuple[str, str]] = []
    if (
        model.get("id") != expected.get("model_id")
        or model.get("version") != expected.get("model_version")
        or model.get("source_url") != expected.get("model_source_url")
        or model.get("source_revision") != expected.get("model_source_revision")
        or not isinstance(model.get("source_url"), str)
        or not model["source_url"].startswith("https://")
        or not isinstance(model.get("source_revision"), str)
        or not FULL_SHA.fullmatch(model["source_revision"])
        or model.get("immutable") is not True
        or model.get("sha256") != sha256_bytes(artifact)
        or model.get("size_bytes") != len(artifact)
    ):
        findings.append(("AMS-001", "model source revision or exact artifact identity is mutable or mismatched"))
    filename = model.get("artifact_filename")
    serialization = model.get("serialization")
    denied_extensions = artifact_policy.get("denied_extensions")
    unsafe_extension = not isinstance(filename, str) or any(
        filename.endswith(extension)
        for extension in denied_extensions
        if isinstance(extension, str)
    )
    if (
        serialization not in artifact_policy.get("accepted_serializations", [])
        or filename is None
        or not filename.endswith(".safetensors")
        or unsafe_extension
        or model.get("trust_remote_code") is not False
        or loader.get("name") != expected.get("loader_name")
        or loader.get("version") != expected.get("loader_version")
        or loader.get("source_commit") != expected.get("loader_source_commit")
        or loader.get("dependency_control") != "PSB-DEPS-003"
        or loader.get("inspection_mode") != "non-executing-static-header"
    ):
        findings.append(("AMS-003", "unsafe serialization remote code or unapproved loader is requested"))
    if (
        dataset_claim.get("id") != expected.get("dataset_id")
        or dataset_claim.get("version") != expected.get("dataset_version")
        or dataset_claim.get("source_url") != expected.get("dataset_source_url")
        or dataset_claim.get("source_revision") != expected.get("dataset_source_revision")
        or not isinstance(dataset_claim.get("source_url"), str)
        or not dataset_claim["source_url"].startswith("https://")
        or not isinstance(dataset_claim.get("source_revision"), str)
        or not FULL_SHA.fullmatch(dataset_claim["source_revision"])
        or dataset_claim.get("immutable") is not True
        or dataset_claim.get("sha256") != sha256_bytes(dataset)
        or dataset_claim.get("license_expression") != expected.get("dataset_license_expression")
        or dataset_claim.get("use_authorization") != expected.get("dataset_use_authorization")
        or dataset_claim.get("contains_personal_data") is not False
    ):
        findings.append(("AMS-006", "dataset provenance license use authorization or exact bytes are not approved"))
    return findings


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def check_safetensors(artifact: bytes, policy: dict[str, Any]) -> list[tuple[str, str]]:
    artifact_policy = trusted_object(policy, "artifact", "policy")
    findings: list[tuple[str, str]] = []
    maximum_artifact = positive_integer(
        artifact_policy.get("maximum_artifact_bytes"),
        "policy.artifact.maximum_artifact_bytes",
    )
    if len(artifact) > maximum_artifact or len(artifact) < 9:
        return [("AMS-004", "safetensors artifact size is outside the inspection boundary")]
    header_size = struct.unpack("<Q", artifact[:8])[0]
    maximum_header = positive_integer(
        artifact_policy.get("maximum_header_bytes"),
        "policy.artifact.maximum_header_bytes",
    )
    if header_size == 0 or header_size > maximum_header or 8 + header_size > len(artifact):
        return [("AMS-004", "safetensors header length is invalid or unbounded")]
    header_bytes = artifact[8 : 8 + header_size]
    if not header_bytes.startswith(b"{"):
        return [("AMS-004", "safetensors header does not begin with a JSON object")]
    try:
        header = json.loads(
            header_bytes,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid numeric constant: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        return [("AMS-004", "safetensors header is malformed or contains duplicate keys")]
    if not isinstance(header, dict):
        return [("AMS-004", "safetensors header must be an object")]
    metadata = header.get("__metadata__", {})
    if not isinstance(metadata, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in metadata.items()
    ):
        findings.append(("AMS-004", "safetensors metadata is not a string map"))
    tensors = [(key, value) for key, value in header.items() if key != "__metadata__"]
    maximum_tensors = positive_integer(
        artifact_policy.get("maximum_tensors"), "policy.artifact.maximum_tensors"
    )
    if not tensors or len(tensors) > maximum_tensors:
        findings.append(("AMS-004", "safetensors tensor count is empty or unbounded"))
        return findings
    intervals: list[tuple[int, int]] = []
    allowed_dtypes = artifact_policy.get("allowed_dtypes")
    maximum_dimensions = positive_integer(
        artifact_policy.get("maximum_dimensions"),
        "policy.artifact.maximum_dimensions",
    )
    for name, tensor in tensors:
        if not isinstance(name, str) or not name or not isinstance(tensor, dict):
            findings.append(("AMS-004", "safetensors tensor entry is invalid"))
            continue
        dtype = tensor.get("dtype")
        shape = tensor.get("shape")
        offsets = tensor.get("data_offsets")
        if (
            dtype not in allowed_dtypes
            or dtype not in DTYPE_BYTES
            or not isinstance(shape, list)
            or len(shape) > maximum_dimensions
            or not all(
                isinstance(size, int) and not isinstance(size, bool) and size >= 0
                for size in shape
            )
            or not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(
                isinstance(offset, int) and not isinstance(offset, bool) and offset >= 0
                for offset in offsets
            )
        ):
            findings.append(("AMS-004", "safetensors tensor dtype shape or offsets are invalid"))
            continue
        start, end = offsets
        count = 1
        for size in shape:
            count *= size
        if end < start or end - start != count * DTYPE_BYTES[dtype]:
            findings.append(("AMS-004", "safetensors tensor byte range does not match its shape"))
            continue
        intervals.append((start, end))
    data_size = len(artifact) - 8 - header_size
    intervals.sort()
    if intervals:
        cursor = 0
        for start, end in intervals:
            if start != cursor or end > data_size:
                findings.append(("AMS-004", "safetensors tensor ranges overlap contain holes or exceed the buffer"))
                break
            cursor = end
        if cursor != data_size and not any(item[0] == "AMS-004" for item in findings):
            findings.append(("AMS-004", "safetensors data buffer is not completely indexed"))
    return findings


def component_hash(component: dict[str, Any]) -> str | None:
    hashes = component.get("hashes")
    if not isinstance(hashes, list):
        return None
    values = [
        item.get("content")
        for item in hashes
        if isinstance(item, dict) and item.get("alg") == "SHA-256"
    ]
    return values[0] if len(values) == 1 and isinstance(values[0], str) else None


def property_map(component: dict[str, Any]) -> dict[str, str]:
    properties = component.get("properties")
    if not isinstance(properties, list):
        return {}
    result: dict[str, str] = {}
    for item in properties:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str):
            result[item["name"]] = item["value"]
    return result


def check_mlbom(
    mlbom: dict[str, Any],
    mlbom_raw: bytes,
    acquisition: dict[str, Any],
    artifact: bytes,
    dataset: bytes,
    policy: dict[str, Any],
) -> list[tuple[str, str]]:
    expected = trusted_object(policy, "expected", "policy")
    mlbom_policy = trusted_object(policy, "mlbom", "policy")
    if (
        mlbom.get("bomFormat") != mlbom_policy.get("format")
        or mlbom.get("specVersion") != mlbom_policy.get("spec_version")
        or mlbom.get("serialNumber") != expected.get("mlbom_serial_number")
        or mlbom.get("version") != 1
    ):
        return [("AMS-002", "ML-BOM format version or identity does not match policy")]
    components = mlbom.get("components")
    dependencies = mlbom.get("dependencies")
    if not isinstance(components, list) or not all(isinstance(item, dict) for item in components):
        return [("AMS-002", "ML-BOM components are malformed")]
    if not isinstance(dependencies, list) or not all(isinstance(item, dict) for item in dependencies):
        return [("AMS-002", "ML-BOM dependency graph is malformed")]
    model_ref = f"model:{expected.get('model_id')}@{expected.get('model_version')}"
    dataset_ref = f"dataset:{expected.get('dataset_id')}@{expected.get('dataset_version')}"
    loader_ref = f"loader:{expected.get('loader_name')}@{expected.get('loader_version')}"
    by_ref = {item.get("bom-ref"): item for item in components if isinstance(item.get("bom-ref"), str)}
    model = by_ref.get(model_ref)
    dataset_component = by_ref.get(dataset_ref)
    loader = by_ref.get(loader_ref)
    if not all(isinstance(item, dict) for item in (model, dataset_component, loader)):
        return [("AMS-002", "ML-BOM omits the exact model dataset or loader component")]
    assert isinstance(model, dict)
    assert isinstance(dataset_component, dict)
    assert isinstance(loader, dict)
    model_properties = property_map(model)
    dataset_properties = property_map(dataset_component)
    loader_properties = property_map(loader)
    model_card = model.get("modelCard")
    model_parameters = model_card.get("modelParameters") if isinstance(model_card, dict) else None
    datasets = model_parameters.get("datasets") if isinstance(model_parameters, dict) else None
    dataset_refs = [item.get("ref") for item in datasets if isinstance(item, dict)] if isinstance(datasets, list) else []
    license_values = dataset_component.get("licenses")
    dataset_licenses = [item.get("expression") for item in license_values if isinstance(item, dict)] if isinstance(license_values, list) else []
    graph = {
        item.get("ref"): item.get("dependsOn")
        for item in dependencies
        if isinstance(item.get("ref"), str) and isinstance(item.get("dependsOn"), list)
    }
    root = trusted_object(mlbom, "metadata", "ML-BOM").get("component")
    root_ref = root.get("bom-ref") if isinstance(root, dict) else None
    if (
        model.get("type") != "machine-learning-model"
        or model.get("name") != expected.get("model_id")
        or model.get("version") != expected.get("model_version")
        or component_hash(model) != sha256_bytes(artifact)
        or model_properties.get("psb:serialization") != acquisition["model"].get("serialization")
        or model_properties.get("psb:source-revision") != expected.get("model_source_revision")
        or dataset_ref not in dataset_refs
        or dataset_component.get("type") != "data"
        or component_hash(dataset_component) != sha256_bytes(dataset)
        or expected.get("dataset_license_expression") not in dataset_licenses
        or dataset_properties.get("psb:source-revision") != expected.get("dataset_source_revision")
        or dataset_properties.get("psb:use-authorization") != expected.get("dataset_use_authorization")
        or loader.get("type") != "library"
        or loader_properties.get("psb:source-commit") != expected.get("loader_source_commit")
        or graph.get(model_ref) != [dataset_ref, loader_ref]
        or not isinstance(root_ref, str)
        or graph.get(root_ref) != [model_ref]
    ):
        return [("AMS-002", "ML-BOM model dataset loader identity or relationship is incomplete or mismatched")]
    if not SHA256.fullmatch(sha256_bytes(mlbom_raw)):
        return [("AMS-002", "ML-BOM digest could not be derived")]
    return []


def check_attestation(
    attestation: dict[str, Any],
    acquisition_raw: bytes,
    mlbom_raw: bytes,
    dataset: bytes,
    artifact: bytes,
    policy: dict[str, Any],
    as_of: datetime,
    verifier_digest: str,
) -> list[tuple[str, str]]:
    if attestation.get("schema") != "psb-ai-model-intake-attestation/v1.0":
        raise BundleError("unsupported intake attestation schema", "AMS-005")
    expected = trusted_object(policy, "expected", "policy")
    signer = trusted_object(policy, "trusted_signer", "policy")
    inspector = trusted_object(policy, "inspector", "policy")
    subject = bundle_object(attestation, "subject", "attestation", "AMS-005")
    materials = bundle_object(attestation, "materials", "attestation", "AMS-005")
    inspection = bundle_object(attestation, "inspection", "attestation", "AMS-005")
    issued = parse_time(
        attestation.get("issued_at"), "attestation issued_at", trusted=False, check_id="AMS-005"
    )
    maximum_age = timedelta(
        hours=positive_integer(
            signer.get("maximum_attestation_age_hours"),
            "policy.trusted_signer.maximum_attestation_age_hours",
        )
    )
    findings: list[tuple[str, str]] = []
    if issued > as_of or as_of - issued > maximum_age:
        findings.append(("AMS-005", "signed intake attestation is stale or from the future"))
    if (
        attestation.get("signer_id") != signer.get("id")
        or subject.get("model_id") != expected.get("model_id")
        or subject.get("model_version") != expected.get("model_version")
        or subject.get("artifact_sha256") != sha256_bytes(artifact)
        or materials.get("acquisition_sha256") != sha256_bytes(acquisition_raw)
        or materials.get("mlbom_sha256") != sha256_bytes(mlbom_raw)
        or materials.get("dataset_sha256") != sha256_bytes(dataset)
    ):
        findings.append(("AMS-005", "signed attestation does not bind the exact model acquisition ML-BOM and dataset"))
    if (
        inspector.get("sha256") != verifier_digest
        or inspection.get("inspector_id") != inspector.get("id")
        or inspection.get("inspector_version") != inspector.get("version")
        or inspection.get("inspector_sha256") != verifier_digest
        or inspection.get("available") is not True
        or inspection.get("complete") is not True
        or inspection.get("result") != "CLEAN"
        or inspection.get("remote_code_requested") is not False
        or inspection.get("unsafe_serialization_findings") != []
        or inspection.get("malware_findings") != []
    ):
        findings.append(("AMS-005", "signed inspection is unbound incomplete unavailable or contains findings"))
    return findings


def check_handoff(
    handoff: dict[str, Any],
    acquisition: dict[str, Any],
    mlbom: dict[str, Any],
    mlbom_raw: bytes,
    artifact: bytes,
    dataset: bytes,
    policy: dict[str, Any],
) -> list[tuple[str, str]]:
    if handoff.get("schema") != "psb-ai-model-deployment-handoff/v1.0":
        raise BundleError("unsupported deployment handoff schema", "AMS-007")
    expected = trusted_object(policy, "expected", "policy")
    handoff_policy = trusted_object(policy, "handoff", "policy")
    loader = bundle_object(handoff, "loader", "deployment handoff", "AMS-007")
    if (
        handoff.get("decision") != handoff_policy.get("required_decision")
        or handoff.get("target_environment") not in handoff_policy.get("allowed_target_environments", [])
        or handoff.get("model_id") != expected.get("model_id")
        or handoff.get("model_version") != expected.get("model_version")
        or handoff.get("artifact_sha256") != sha256_bytes(artifact)
        or handoff.get("mlbom_serial_number") != mlbom.get("serialNumber")
        or handoff.get("mlbom_sha256") != sha256_bytes(mlbom_raw)
        or handoff.get("dataset_sha256") != sha256_bytes(dataset)
        or loader.get("name") != expected.get("loader_name")
        or loader.get("version") != expected.get("loader_version")
        or loader.get("source_commit") != expected.get("loader_source_commit")
        or loader.get("dependency_control") != handoff_policy.get("dependency_control")
        or handoff.get("trust_remote_code") is not handoff_policy.get("require_remote_code")
        or acquisition.get("model", {}).get("sha256") != handoff.get("artifact_sha256")
    ):
        return [("AMS-007", "deployment handoff is not bound to the accepted model ML-BOM dataset and loader")]
    return []


def unique_findings(findings: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    return [item for item in findings if not (item in seen or seen.add(item))]


def evaluate(args: argparse.Namespace) -> int:
    _, policy = load_trusted_json(args.policy, "model intake policy")
    policy_findings = check_policy(policy)
    _, signer_status = load_trusted_json(args.signer_status, "signer status evidence")
    as_of = parse_time(args.as_of, "evaluation time", trusted=True, check_id="AMS-008")
    signer_findings = check_signer_status(signer_status, policy, as_of)
    signer_policy = trusted_object(policy, "trusted_signer", "policy")
    public_key = resolve_public_key(args.policy, signer_policy)

    acquisition_raw, acquisition = load_bundle_json(
        args.acquisition, "acquisition manifest", "AMS-001"
    )
    mlbom_raw, mlbom = load_bundle_json(args.mlbom, "ML-BOM", "AMS-002")
    _, attestation = load_bundle_json(
        args.attestation, "intake attestation", "AMS-005"
    )
    _, handoff = load_bundle_json(args.handoff, "deployment handoff", "AMS-007")
    artifact = decode_artifact(args.artifact)
    dataset = read_bundle(args.dataset, "dataset fixture", "AMS-006")
    verifier_digest = sha256_bytes(Path(__file__).read_bytes())

    findings = list(policy_findings)
    findings.extend(signer_findings)
    if not verify_signature(args.attestation, args.signature, public_key, args.openssl):
        findings.append(("AMS-005", "intake attestation signature verification failed"))
    findings.extend(check_acquisition(acquisition, artifact, dataset, policy))
    if acquisition.get("model", {}).get("serialization") == "safetensors":
        findings.extend(check_safetensors(artifact, policy))
    else:
        findings.append(("AMS-004", "model artifact is not eligible for non-executing safetensors inspection"))
    findings.extend(check_mlbom(mlbom, mlbom_raw, acquisition, artifact, dataset, policy))
    findings.extend(
        check_attestation(
            attestation,
            acquisition_raw,
            mlbom_raw,
            dataset,
            artifact,
            policy,
            as_of,
            verifier_digest,
        )
    )
    findings.extend(check_handoff(handoff, acquisition, mlbom, mlbom_raw, artifact, dataset, policy))
    findings = unique_findings(findings)
    if findings:
        for check_id, message in findings:
            print(f"QUARANTINE {check_id} {message}")
        print("RESULT QUARANTINE")
        return 1
    for check_id, message in (
        ("AMS-001", "immutable source and exact model artifact identity verified"),
        ("AMS-002", "CycloneDX 1.7 ML-BOM relationships verified"),
        ("AMS-003", "non-executable serialization and pinned loader verified"),
        ("AMS-004", "bounded safetensors structure verified without model execution"),
        ("AMS-005", "signed inspection and current signer lifecycle verified"),
        ("AMS-006", "dataset provenance license and use authorization verified"),
        ("AMS-007", "accepted deployment handoff identity verified"),
        ("AMS-008", "verification dependencies available and current"),
        ("AMS-009", "evidence policy remains metadata-only"),
    ):
        print(f"PASS {check_id} {message}")
    print("RESULT ACCEPTED_FOR_STAGING")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--acquisition", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--mlbom", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--signer-status", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--openssl", default="openssl")
    return parser.parse_args()


def main() -> int:
    try:
        return evaluate(parse_args())
    except BundleError as error:
        print(f"QUARANTINE {error.check_id} {error}")
        print("RESULT QUARANTINE")
        return 1
    except EvaluationError as error:
        print(f"ERROR AMS-008 verification unavailable: {error}")
        print("RESULT ERROR")
        return 2
    except Exception as error:  # defensive: unknown verifier failure is never clean
        print(f"ERROR AMS-008 unexpected verifier failure: {type(error).__name__}")
        print("RESULT ERROR")
        return 2


if __name__ == "__main__":
    sys.exit(main())
