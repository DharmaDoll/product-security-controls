#!/usr/bin/env python3
"""Run one central model-intake request without loading model or dataset code."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID = re.compile(r"^intake-[a-z0-9][a-z0-9-]{2,78}$")


class TrustedError(RuntimeError):
    """Trusted service policy, state, or verification infrastructure failed."""


class IntakeFinding(ValueError):
    """An untrusted request or bundle must remain quarantined."""

    def __init__(self, check_id: str, message: str) -> None:
        super().__init__(message)
        self.check_id = check_id


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_bytes(path: Path, *, trusted: bool, label: str, check_id: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        if trusted:
            raise TrustedError(f"cannot read {label}") from error
        raise IntakeFinding(check_id, f"{label} is missing or unreadable") from error


def load_json(path: Path, *, trusted: bool, label: str, check_id: str) -> tuple[bytes, dict[str, Any]]:
    raw = read_bytes(path, trusted=trusted, label=label, check_id=check_id)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        if trusted:
            raise TrustedError(f"cannot parse {label}") from error
        raise IntakeFinding(check_id, f"{label} is malformed") from error
    if not isinstance(value, dict):
        if trusted:
            raise TrustedError(f"{label} must be an object")
        raise IntakeFinding(check_id, f"{label} must be an object")
    return raw, value


def object_field(value: dict[str, Any], key: str, *, trusted: bool, check_id: str) -> dict[str, Any]:
    child = value.get(key)
    if isinstance(child, dict):
        return child
    if trusted:
        raise TrustedError(f"trusted policy {key} must be an object")
    raise IntakeFinding(check_id, f"intake request {key} must be an object")


def positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise TrustedError(f"{label} must be a positive integer")
    return value


def trusted_path(policy_path: Path, relative_value: Any, label: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        raise TrustedError(f"trusted {label} path is missing")
    relative = Path(relative_value)
    if relative.is_absolute():
        raise TrustedError(f"trusted {label} path must be relative")
    return (policy_path.parent / relative).resolve()


def bundle_path(bundle_dir: Path, relative_value: Any, label: str, check_id: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        raise IntakeFinding(check_id, f"{label} path is missing")
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise IntakeFinding(check_id, f"{label} path escapes the intake bundle")
    base = bundle_dir.resolve()
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as error:
        raise IntakeFinding(check_id, f"{label} path escapes the intake bundle") from error
    return candidate


def relative_bundle_path(relative_value: Any, label: str, check_id: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        raise IntakeFinding(check_id, f"{label} path is missing")
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise IntakeFinding(check_id, f"{label} path escapes the intake bundle")
    return relative


def verify_pinned_file(path: Path, expected: Any, label: str) -> None:
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise TrustedError(f"trusted {label} digest is invalid")
    if sha256_bytes(read_bytes(path, trusted=True, label=label, check_id="AMS-008")) != expected:
        raise TrustedError(f"trusted {label} digest does not match service policy")


def source_origin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise IntakeFinding("AMS-001", f"{label} source URL is invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise IntakeFinding("AMS-001", f"{label} source is not approved immutable HTTPS")
    try:
        port_value = parsed.port
    except ValueError as error:
        raise IntakeFinding("AMS-001", f"{label} source URL has an invalid port") from error
    port = f":{port_value}" if port_value is not None else ""
    return f"https://{parsed.hostname}{port}"


def validate_policy(policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if policy.get("schema") != "psb-ai-model-intake-service-policy/v1.0":
        raise TrustedError("unsupported service policy schema")
    trusted = object_field(policy, "trusted_inputs", trusted=True, check_id="AMS-008")
    acquisition = object_field(policy, "acquisition", trusted=True, check_id="AMS-008")
    storage = object_field(policy, "storage", trusted=True, check_id="AMS-008")
    promotion = object_field(policy, "promotion", trusted=True, check_id="AMS-008")
    evidence = object_field(policy, "evidence", trusted=True, check_id="AMS-008")
    origins = acquisition.get("allowed_source_origins")
    if not isinstance(origins, list) or not origins or not all(
        isinstance(item, str) and item.startswith("https://") for item in origins
    ):
        raise TrustedError("allowed source origins are invalid")
    positive_integer(acquisition.get("maximum_artifact_bytes"), "maximum artifact bytes")
    if acquisition.get("require_full_revision") is not True:
        raise TrustedError("service policy must require full source revisions")
    if (
        storage.get("digest_algorithm") != "sha256"
        or storage.get("quarantine_namespace") == storage.get("trusted_namespace")
        or storage.get("immutable_promotion") is not True
    ):
        raise TrustedError("storage namespaces or immutable promotion policy are invalid")
    if (
        promotion.get("required_verifier_result") != "ACCEPTED_FOR_STAGING"
        or promotion.get("require_digest_readback") is not True
        or promotion.get("allowed_target_environments") != ["staging"]
    ):
        raise TrustedError("promotion policy can bypass staging verification")
    if any(value is not False for value in evidence.values()) or set(evidence) != {
        "include_model_bytes",
        "include_dataset_rows",
        "include_signature",
        "include_key_material",
        "include_source_credentials",
    }:
        raise TrustedError("service evidence policy permits protected content")
    return trusted, acquisition, storage, promotion


def validate_storage_roots(args: argparse.Namespace, storage: dict[str, Any]) -> None:
    quarantine = args.quarantine_dir.resolve()
    trusted = args.trusted_dir.resolve()
    state = args.state_dir.resolve()
    if quarantine == trusted or quarantine == state or trusted == state:
        raise TrustedError("state quarantine and trusted storage roots must be distinct")
    if (
        quarantine.name != storage.get("quarantine_namespace")
        or trusted.name != storage.get("trusted_namespace")
    ):
        raise TrustedError("storage roots do not match the trusted namespace policy")


def validate_request(
    request: dict[str, Any],
    acquisition_manifest: dict[str, Any],
    service_acquisition: dict[str, Any],
    promotion: dict[str, Any],
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if request.get("schema") != "psb-ai-model-intake-request/v1.0":
        raise IntakeFinding("AMS-001", "unsupported intake request schema")
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise IntakeFinding("AMS-001", "intake request ID is invalid")
    if request.get("requested_by_role") not in {"model-owner", "data-owner", "platform"}:
        raise IntakeFinding("AMS-001", "intake requester role is not approved")
    if not isinstance(request.get("purpose"), str) or not request["purpose"].strip():
        raise IntakeFinding("AMS-006", "intake purpose is missing")
    model = object_field(request, "model", trusted=False, check_id="AMS-001")
    dataset = object_field(request, "dataset", trusted=False, check_id="AMS-006")
    manifest_model = acquisition_manifest.get("model")
    manifest_dataset = acquisition_manifest.get("dataset")
    if not isinstance(manifest_model, dict) or not isinstance(manifest_dataset, dict):
        raise IntakeFinding("AMS-001", "acquisition manifest identities are malformed")
    for label, requested, claimed, check_id in (
        ("model", model, manifest_model, "AMS-001"),
        ("dataset", dataset, manifest_dataset, "AMS-006"),
    ):
        if any(requested.get(key) != claimed.get(key) for key in ("id", "version", "source_url", "source_revision")):
            raise IntakeFinding(check_id, f"{label} request does not match acquired identity")
        revision = requested.get("source_revision")
        if not isinstance(revision, str) or not FULL_SHA.fullmatch(revision):
            raise IntakeFinding(check_id, f"{label} source revision is mutable")
        if source_origin(requested.get("source_url"), label) not in service_acquisition["allowed_source_origins"]:
            raise IntakeFinding(check_id, f"{label} source origin is not approved")
    if request.get("target_environment") not in promotion.get("allowed_target_environments", []):
        raise IntakeFinding("AMS-007", "intake target environment is not approved")
    return request_id, model, dataset


def artifact_from_bundle(bundle_dir: Path, acquisition: dict[str, Any], maximum_bytes: int) -> tuple[bytes, str]:
    model = acquisition.get("model")
    if not isinstance(model, dict):
        raise IntakeFinding("AMS-001", "acquisition model identity is malformed")
    encoded = read_bytes(
        bundle_path(bundle_dir, model.get("fixture_path"), "model artifact", "AMS-001"),
        trusted=False,
        label="model artifact",
        check_id="AMS-001",
    ).strip()
    try:
        artifact = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise IntakeFinding("AMS-001", "model artifact is not valid base64") from error
    if not artifact or len(artifact) > maximum_bytes:
        raise IntakeFinding("AMS-004", "model artifact size is outside the service boundary")
    return artifact, sha256_bytes(artifact)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except OSError as error:
        raise TrustedError("cannot persist intake state") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def store_immutable(path: Path, value: bytes, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if sha256_bytes(read_bytes(path, trusted=True, label=label, check_id="AMS-008")) != sha256_bytes(value):
            raise TrustedError(f"existing {label} does not match its digest path")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if sha256_bytes(read_bytes(path, trusted=True, label=label, check_id="AMS-008")) != sha256_bytes(value):
                raise TrustedError(f"concurrent {label} does not match its digest path")
    except OSError as error:
        raise TrustedError(f"cannot store {label}") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def snapshot_bundle(
    bundle_dir: Path,
    quarantine_dir: Path,
    request_id: str,
    request_digest: str,
    request_raw: bytes,
    acquisition_raw: bytes,
    acquisition: dict[str, Any],
) -> Path:
    model = acquisition.get("model")
    dataset = acquisition.get("dataset")
    if not isinstance(model, dict) or not isinstance(dataset, dict):
        raise IntakeFinding("AMS-001", "acquisition identities are malformed")
    specifications = (
        ("acquisition.json", "acquisition manifest", "AMS-001", acquisition_raw),
        (model.get("fixture_path"), "model artifact", "AMS-001", None),
        (dataset.get("fixture_path"), "dataset artifact", "AMS-006", None),
        ("model.mlbom.cdx.json", "ML-BOM", "AMS-002", None),
        ("intake-attestation.json", "intake attestation", "AMS-005", None),
        ("intake-attestation.sig.b64", "intake signature", "AMS-005", None),
        ("deployment-handoff.json", "deployment handoff", "AMS-007", None),
    )
    snapshot_root = (
        quarantine_dir
        / "requests"
        / request_id
        / "sha256"
        / request_digest
    )
    snapshot = snapshot_root / "bundle"
    store_immutable(snapshot_root / "request.json", request_raw, "quarantine request")
    seen: dict[Path, bytes] = {}
    for relative_value, label, check_id, provided_raw in specifications:
        relative = relative_bundle_path(relative_value, label, check_id)
        raw = provided_raw
        if raw is None:
            raw = read_bytes(
                bundle_path(bundle_dir, relative_value, label, check_id),
                trusted=False,
                label=label,
                check_id=check_id,
            )
        previous = seen.get(relative)
        if previous is not None and previous != raw:
            raise IntakeFinding(check_id, f"{label} path conflicts with another bundle material")
        seen[relative] = raw
    for relative, raw in seen.items():
        store_immutable(snapshot / relative, raw, "quarantine bundle material")
    return snapshot


def state_record(
    request_id: str,
    request_sha256: str,
    state: str,
    as_of: str,
    *,
    artifact_sha256: str | None = None,
    model_id: str | None = None,
    model_version: str | None = None,
    target_environment: str | None = None,
    material_digests: dict[str, str] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "psb-ai-model-intake-state/v1.0",
        "request_id": request_id,
        "request_sha256": request_sha256,
        "state": state,
        "updated_at": as_of,
    }
    if artifact_sha256 is not None:
        value["artifact_sha256"] = artifact_sha256
    if model_id is not None:
        value["model_id"] = model_id
    if model_version is not None:
        value["model_version"] = model_version
    if target_environment is not None:
        value["target_environment"] = target_environment
    if material_digests is not None:
        value["material_digests"] = material_digests
    return value


def run_verifier(
    verifier: Path,
    model_policy: Path,
    signer_status: Path,
    bundle_dir: Path,
    acquisition: dict[str, Any],
    as_of: str,
    openssl: str,
) -> subprocess.CompletedProcess[str]:
    model = acquisition["model"]
    dataset = acquisition["dataset"]
    command = [
        sys.executable,
        str(verifier),
        "--policy",
        str(model_policy),
        "--acquisition",
        str(bundle_path(bundle_dir, "acquisition.json", "acquisition manifest", "AMS-001")),
        "--artifact",
        str(bundle_path(bundle_dir, model.get("fixture_path"), "model artifact", "AMS-001")),
        "--dataset",
        str(bundle_path(bundle_dir, dataset.get("fixture_path"), "dataset artifact", "AMS-006")),
        "--mlbom",
        str(bundle_path(bundle_dir, "model.mlbom.cdx.json", "ML-BOM", "AMS-002")),
        "--attestation",
        str(bundle_path(bundle_dir, "intake-attestation.json", "intake attestation", "AMS-005")),
        "--signature",
        str(bundle_path(bundle_dir, "intake-attestation.sig.b64", "intake signature", "AMS-005")),
        "--signer-status",
        str(signer_status),
        "--handoff",
        str(bundle_path(bundle_dir, "deployment-handoff.json", "deployment handoff", "AMS-007")),
        "--as-of",
        as_of,
        "--openssl",
        openssl,
    ]
    try:
        return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except OSError as error:
        raise TrustedError("cannot execute the model-intake verifier") from error


def evaluate(args: argparse.Namespace) -> int:
    policy_raw, service_policy = load_json(
        args.service_policy,
        trusted=True,
        label="service policy",
        check_id="AMS-008",
    )
    trusted, service_acquisition, storage, promotion = validate_policy(service_policy)
    validate_storage_roots(args, storage)
    model_policy = trusted_path(args.service_policy, trusted.get("model_intake_policy"), "model intake policy")
    signer_status = trusted_path(args.service_policy, trusted.get("signer_status"), "signer status")
    verifier = trusted_path(args.service_policy, trusted.get("verifier"), "verifier")
    verify_pinned_file(model_policy, trusted.get("model_intake_policy_sha256"), "model intake policy")
    verify_pinned_file(verifier, trusted.get("verifier_sha256"), "verifier")
    read_bytes(signer_status, trusted=True, label="signer status", check_id="AMS-008")

    request_raw, request = load_json(
        args.request,
        trusted=False,
        label="intake request",
        check_id="AMS-001",
    )
    request_id_value = request.get("request_id")
    request_id = request_id_value if isinstance(request_id_value, str) and REQUEST_ID.fullmatch(request_id_value) else "intake-invalid-request"
    request_digest = sha256_bytes(request_raw)
    state_path = args.state_dir / f"{request_id}.json"
    if state_path.exists():
        _, previous = load_json(state_path, trusted=True, label="existing intake state", check_id="AMS-008")
        if previous.get("request_sha256") != request_digest:
            raise TrustedError("request ID was reused with different bytes")
        if previous.get("state") == "PROMOTED":
            artifact_digest = previous.get("artifact_sha256")
            if not isinstance(artifact_digest, str) or not SHA256.fullmatch(artifact_digest):
                raise TrustedError("promoted state has an invalid artifact digest")
            trusted_artifact = args.trusted_dir / "sha256" / artifact_digest / "model.safetensors"
            if sha256_bytes(read_bytes(trusted_artifact, trusted=True, label="trusted artifact", check_id="AMS-008")) != artifact_digest:
                raise TrustedError("trusted artifact readback failed")
            print("STATE PROMOTED idempotent readback verified")
            print(f"RESULT PROMOTED sha256:{artifact_digest}")
            return 0

    acquisition_raw, acquisition = load_json(
        bundle_path(args.bundle_dir, "acquisition.json", "acquisition manifest", "AMS-001"),
        trusted=False,
        label="acquisition manifest",
        check_id="AMS-001",
    )
    request_id, request_model, _ = validate_request(request, acquisition, service_acquisition, promotion)
    snapshot = snapshot_bundle(
        args.bundle_dir,
        args.quarantine_dir,
        request_id,
        request_digest,
        request_raw,
        acquisition_raw,
        acquisition,
    )
    artifact, artifact_digest = artifact_from_bundle(
        snapshot,
        acquisition,
        positive_integer(service_acquisition.get("maximum_artifact_bytes"), "maximum artifact bytes"),
    )
    if acquisition.get("model", {}).get("sha256") != artifact_digest:
        raise IntakeFinding("AMS-001", "acquired model digest does not match its manifest")

    common = {
        "artifact_sha256": artifact_digest,
        "model_id": request_model.get("id"),
        "model_version": request_model.get("version"),
        "target_environment": request.get("target_environment"),
    }
    atomic_json(state_path, state_record(request_id, request_digest, "RECEIVED", args.as_of, **common))
    print("STATE RECEIVED request identity accepted")
    quarantine_artifact = args.quarantine_dir / "sha256" / artifact_digest / "model.bin"
    store_immutable(quarantine_artifact, artifact, "quarantine artifact")
    atomic_json(state_path, state_record(request_id, request_digest, "QUARANTINED", args.as_of, **common))
    print("STATE QUARANTINED exact bundle stored before verification")

    atomic_json(state_path, state_record(request_id, request_digest, "VERIFYING", args.as_of, **common))
    print("STATE VERIFYING model and loader code remain unexecuted")
    result = run_verifier(verifier, model_policy, signer_status, snapshot, acquisition, args.as_of, args.openssl)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.returncode == 1:
        atomic_json(state_path, state_record(request_id, request_digest, "QUARANTINE", args.as_of, **common))
        print("STATE QUARANTINE trusted namespace unchanged")
        return 1
    if result.returncode == 2:
        atomic_json(state_path, state_record(request_id, request_digest, "ERROR", args.as_of, **common))
        print("STATE ERROR trusted namespace unchanged")
        return 2
    if result.returncode != 0 or "RESULT ACCEPTED_FOR_STAGING" not in result.stdout.splitlines():
        raise TrustedError("verifier returned an unsupported result")

    mlbom_raw = read_bytes(
        bundle_path(snapshot, "model.mlbom.cdx.json", "ML-BOM", "AMS-002"),
        trusted=False,
        label="ML-BOM",
        check_id="AMS-002",
    )
    handoff_raw = read_bytes(
        bundle_path(snapshot, "deployment-handoff.json", "deployment handoff", "AMS-007"),
        trusted=False,
        label="deployment handoff",
        check_id="AMS-007",
    )
    material_digests = {
        "service_policy_sha256": sha256_bytes(policy_raw),
        "model_intake_policy_sha256": sha256_bytes(read_bytes(model_policy, trusted=True, label="model intake policy", check_id="AMS-008")),
        "mlbom_sha256": sha256_bytes(mlbom_raw),
        "handoff_sha256": sha256_bytes(handoff_raw),
        "verifier_sha256": sha256_bytes(read_bytes(verifier, trusted=True, label="verifier", check_id="AMS-008")),
    }
    accepted = state_record(
        request_id,
        request_digest,
        "ACCEPTED_FOR_STAGING",
        args.as_of,
        material_digests=material_digests,
        **common,
    )
    atomic_json(state_path, accepted)
    print("STATE ACCEPTED_FOR_STAGING exact signed bundle accepted")

    trusted_artifact = args.trusted_dir / "sha256" / artifact_digest / "model.safetensors"
    store_immutable(trusted_artifact, artifact, "trusted artifact")
    if sha256_bytes(read_bytes(trusted_artifact, trusted=True, label="trusted artifact", check_id="AMS-008")) != artifact_digest:
        raise TrustedError("trusted artifact readback failed")
    promotion_receipt = dict(accepted)
    promotion_receipt["schema"] = "psb-ai-model-promotion-receipt/v1.0"
    promotion_receipt["state"] = "PROMOTED"
    atomic_json(trusted_artifact.parent / "promotions" / f"{request_id}.json", promotion_receipt)
    atomic_json(
        state_path,
        state_record(
            request_id,
            request_digest,
            "PROMOTED",
            args.as_of,
            material_digests=material_digests,
            **common,
        ),
    )
    print("STATE PROMOTED immutable digest readback verified")
    print(f"RESULT PROMOTED sha256:{artifact_digest}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-policy", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--quarantine-dir", type=Path, required=True)
    parser.add_argument("--trusted-dir", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--openssl", default="openssl")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return evaluate(args)
    except IntakeFinding as error:
        print(f"QUARANTINE {error.check_id} {error}")
        print("STATE QUARANTINE trusted namespace unchanged")
        print("RESULT QUARANTINE")
        return 1
    except TrustedError as error:
        print(f"ERROR AMS-008 central intake unavailable: {error}")
        print("STATE ERROR trusted namespace unchanged")
        print("RESULT ERROR")
        return 2
    except Exception as error:  # defensive: unknown service failure is never clean
        print(f"ERROR AMS-008 unexpected central intake failure: {type(error).__name__}")
        print("STATE ERROR trusted namespace unchanged")
        print("RESULT ERROR")
        return 2


if __name__ == "__main__":
    sys.exit(main())
