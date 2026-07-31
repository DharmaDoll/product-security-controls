#!/usr/bin/env python3
"""Verify a signed supplier SBOM before it crosses the portfolio trust boundary."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID


class EvaluationError(RuntimeError):
    """Trusted policy or verification infrastructure cannot be evaluated."""


class SupplierContentError(ValueError):
    """Untrusted supplier input is absent, malformed, or unsupported."""

    def __init__(self, message: str, check_id: str = "SUP-005") -> None:
        super().__init__(message)
        self.check_id = check_id


def read_trusted(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvaluationError(f"cannot read {label}") from error


def read_supplier(path: Path, label: str, check_id: str = "SUP-005") -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise SupplierContentError(
            f"{label} is missing or unreadable", check_id
        ) from error


def load_trusted_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_trusted(path, label))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"cannot parse {label}") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return value


def load_supplier_json(
    path: Path, label: str, check_id: str
) -> dict[str, Any]:
    try:
        value = json.loads(read_supplier(path, label, check_id))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SupplierContentError(f"{label} is malformed", check_id) from error
    if not isinstance(value, dict):
        raise SupplierContentError(f"{label} must be a JSON object", check_id)
    return value


def object_at(
    value: dict[str, Any],
    key: str,
    label: str,
    check_id: str = "SUP-003",
) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise SupplierContentError(
            f"{label}.{key} must be an object", check_id
        )
    return child


def trusted_object_at(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise EvaluationError(f"{label}.{key} must be an object")
    return child


def parse_time(value: Any, label: str, *, trusted: bool) -> datetime:
    error_type = EvaluationError if trusted else SupplierContentError
    if not isinstance(value, str):
        if trusted:
            raise error_type(f"{label} must be an RFC3339 timestamp")
        raise error_type(f"{label} must be an RFC3339 timestamp", "SUP-004")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        if trusted:
            raise error_type(f"{label} must be an RFC3339 timestamp") from error
        raise error_type(
            f"{label} must be an RFC3339 timestamp", "SUP-004"
        ) from error
    if parsed.tzinfo is None:
        if trusted:
            raise error_type(f"{label} must include a timezone")
        raise error_type(f"{label} must include a timezone", "SUP-004")
    return parsed


def text(value: dict[str, Any], key: str, label: str, *, trusted: bool) -> str:
    error_type = EvaluationError if trusted else SupplierContentError
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise error_type(f"{label}.{key} must be non-empty text")
    return result


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def resolve_public_key(policy_path: Path, signer: dict[str, Any]) -> Path:
    value = text(signer, "public_key", "policy.trusted_signer", trusted=True)
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise EvaluationError("trusted public key must remain inside the policy directory")
    key = (policy_path.parent / relative).resolve()
    if not key.is_file():
        raise EvaluationError("trusted public key is unavailable")
    return key


def verify_signature(
    envelope_path: Path,
    signature_path: Path,
    public_key: Path,
    openssl: str,
) -> bool:
    encoded = read_supplier(
        signature_path, "detached signature", "SUP-001"
    ).strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SupplierContentError(
            "detached signature is not valid base64", "SUP-001"
        ) from error
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(signature)
        handle.flush()
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
                    str(envelope_path),
                    "-sigfile",
                    handle.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as error:
            raise EvaluationError("cannot execute OpenSSL") from error
    return result.returncode == 0


def check_policy(policy: dict[str, Any]) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if policy.get("schema") != "psb-supplier-sbom-intake-policy/1.0":
        raise EvaluationError("unsupported intake policy schema")
    signer = trusted_object_at(policy, "trusted_signer", "policy")
    if signer.get("algorithm") != "ed25519":
        raise EvaluationError("policy requires unsupported signature algorithm")
    for field in ("maximum_signature_age_hours", "maximum_revocation_age_hours"):
        value = policy.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise EvaluationError(f"policy.{field} must be a positive integer")

    import_policy = trusted_object_at(policy, "import", "policy")
    project = import_policy.get("portfolio_project_id")
    try:
        project_is_uuid = isinstance(project, str) and str(UUID(project)) == project
    except ValueError:
        project_is_uuid = False
    if (
        not project_is_uuid
        or import_policy.get("auto_import") is not False
        or import_policy.get("allowed_permissions") != ["BOM_UPLOAD"]
        or import_policy.get("may_create_project") is not False
        or import_policy.get("may_modify_policy") is not False
    ):
        findings.append(
            ("SUP-006", "supplier intake identity is not project-bound and least privileged")
        )

    evidence = trusted_object_at(policy, "evidence", "policy")
    if (
        evidence.get("include_component_inventory") is not False
        or evidence.get("include_key_material") is not False
    ):
        findings.append(
            ("SUP-007", "evidence policy permits supplier content or key material")
        )
    return findings


def check_sbom_schema(
    sbom: dict[str, Any], policy: dict[str, Any]
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    accepted = trusted_object_at(policy, "accepted_sbom", "policy")
    if (
        sbom.get("bomFormat") != accepted.get("format")
        or sbom.get("specVersion") != accepted.get("spec_version")
        or sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.7"
    ):
        findings.append(("SUP-003", "supplier SBOM format or version is unsupported"))
        return findings
    if not isinstance(sbom.get("serialNumber"), str) or not isinstance(
        sbom.get("version"), int
    ):
        findings.append(("SUP-003", "supplier SBOM identity fields are invalid"))
    try:
        root = object_at(
            object_at(sbom, "metadata", "SBOM"),
            "component",
            "SBOM.metadata",
        )
    except SupplierContentError:
        findings.append(("SUP-003", "supplier SBOM root component is missing"))
        return findings
    for field in ("type", "bom-ref", "name", "version", "purl"):
        if not isinstance(root.get(field), str) or not root[field]:
            findings.append(("SUP-003", "supplier SBOM root component is incomplete"))
            break
    components = sbom.get("components")
    dependencies = sbom.get("dependencies")
    if not isinstance(components, list) or not all(
        isinstance(item, dict) for item in components
    ):
        findings.append(("SUP-003", "supplier SBOM components are invalid"))
    if not isinstance(dependencies, list) or not all(
        isinstance(item, dict) for item in dependencies
    ):
        findings.append(("SUP-003", "supplier SBOM dependency graph is invalid"))
    return findings


def check_identity(
    artifact: bytes,
    sbom_bytes: bytes,
    sbom: dict[str, Any],
    envelope: dict[str, Any],
    policy: dict[str, Any],
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if envelope.get("schema") != "psb-supplier-sbom-envelope/1.0":
        findings.append(("SUP-002", "signed supplier envelope schema is unsupported"))
        return findings
    expected = trusted_object_at(policy, "expected_product", "policy")
    product = object_at(envelope, "product", "supplier envelope", "SUP-002")
    artifact_claim = object_at(
        envelope, "artifact", "supplier envelope", "SUP-002"
    )
    sbom_claim = object_at(envelope, "sbom", "supplier envelope", "SUP-002")
    if (
        envelope.get("supplier_id") != policy.get("expected_supplier_id")
        or product.get("name") != expected.get("name")
        or product.get("version") != expected.get("version")
    ):
        findings.append(
            ("SUP-002", "signed supplier and product identity does not match intake policy")
        )
    artifact_digest = sha256_bytes(artifact)
    sbom_digest = sha256_bytes(sbom_bytes)
    if (
        artifact_claim.get("sha256") != artifact_digest
        or artifact_claim.get("sha256") != expected.get("artifact_sha256")
        or sbom_claim.get("sha256") != sbom_digest
    ):
        findings.append(
            ("SUP-002", "signed envelope does not bind the exact artifact and SBOM bytes")
        )
    if (
        sbom_claim.get("format") != sbom.get("bomFormat")
        or sbom_claim.get("spec_version") != sbom.get("specVersion")
        or sbom_claim.get("serial_number") != sbom.get("serialNumber")
    ):
        findings.append(
            ("SUP-002", "signed envelope SBOM identity does not match supplied SBOM")
        )
    try:
        root = object_at(
            object_at(sbom, "metadata", "SBOM"),
            "component",
            "SBOM.metadata",
        )
    except SupplierContentError:
        return findings
    hashes = root.get("hashes")
    root_has_artifact = (
        isinstance(hashes, list)
        and any(
            isinstance(item, dict)
            and item.get("alg") == "SHA-256"
            and item.get("content") == artifact_digest
            for item in hashes
        )
    )
    if (
        root.get("name") != product.get("name")
        or root.get("version") != product.get("version")
        or not root_has_artifact
    ):
        findings.append(
            ("SUP-002", "supplier SBOM root does not identify the signed product artifact")
        )
    return findings


def check_signer_status(
    envelope: dict[str, Any],
    policy: dict[str, Any],
    snapshot: dict[str, Any],
    public_key_digest: str,
    as_of: datetime,
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if snapshot.get("schema") != "psb-signer-status-snapshot/1.0":
        raise EvaluationError("unsupported signer status snapshot schema")
    if snapshot.get("status") != "AVAILABLE":
        raise EvaluationError("signer status source is unavailable")
    observed = parse_time(snapshot.get("observed_at"), "snapshot.observed_at", trusted=True)
    expires = parse_time(snapshot.get("expires_at"), "snapshot.expires_at", trusted=True)
    maximum_age = timedelta(hours=policy["maximum_revocation_age_hours"])
    if as_of < observed or as_of > expires or as_of - observed > maximum_age:
        raise EvaluationError("signer status snapshot is stale")

    signer_policy = trusted_object_at(policy, "trusted_signer", "policy")
    signer_id = envelope.get("signer_id")
    if signer_id != signer_policy.get("id"):
        findings.append(("SUP-001", "signed envelope uses an untrusted signer identity"))
    configured_key_digest = signer_policy.get("public_key_sha256")
    if configured_key_digest != public_key_digest:
        findings.append(("SUP-001", "trusted public key does not match its pinned digest"))

    signers = snapshot.get("signers")
    if not isinstance(signers, list) or not all(
        isinstance(item, dict) for item in signers
    ):
        raise EvaluationError("snapshot.signers must be an object list")
    matching = [
        item
        for item in signers
        if item.get("id") == signer_id
        and item.get("public_key_sha256") == public_key_digest
    ]
    if len(matching) != 1:
        findings.append(("SUP-004", "signer is unknown in the current status snapshot"))
        return findings
    signer = matching[0]
    signed_at = parse_time(envelope.get("signed_at"), "envelope.signed_at", trusted=False)
    not_before = parse_time(signer.get("not_before"), "signer.not_before", trusted=True)
    not_after = parse_time(signer.get("not_after"), "signer.not_after", trusted=True)
    if signer.get("status") != "ACTIVE":
        findings.append(("SUP-004", "signer is not active in the current status snapshot"))
    if signed_at < not_before or signed_at > not_after:
        findings.append(("SUP-004", "signature timestamp is outside signer validity"))
    maximum_signature_age = timedelta(hours=policy["maximum_signature_age_hours"])
    if signed_at > as_of or as_of - signed_at > maximum_signature_age:
        findings.append(("SUP-004", "signature timestamp is outside the accepted window"))
    return findings


def verify(args: argparse.Namespace) -> list[tuple[str, str]]:
    policy = load_trusted_json(args.policy, "intake policy")
    snapshot = load_trusted_json(args.revocation_snapshot, "signer status snapshot")
    findings = check_policy(policy)

    artifact = read_supplier(args.artifact, "supplier artifact", "SUP-002")
    sbom_bytes = read_supplier(args.sbom, "supplier SBOM", "SUP-003")
    sbom = load_supplier_json(args.sbom, "supplier SBOM", "SUP-003")
    envelope = load_supplier_json(
        args.envelope, "supplier envelope", "SUP-002"
    )
    public_key = resolve_public_key(
        args.policy, trusted_object_at(policy, "trusted_signer", "policy")
    )
    public_key_digest = sha256_bytes(read_trusted(public_key, "trusted public key"))

    if not verify_signature(args.envelope, args.signature, public_key, args.openssl):
        findings.append(("SUP-001", "supplier envelope signature verification failed"))
    findings.extend(check_sbom_schema(sbom, policy))
    findings.extend(check_identity(artifact, sbom_bytes, sbom, envelope, policy))
    findings.extend(
        check_signer_status(
            envelope,
            policy,
            snapshot,
            public_key_digest,
            args.as_of,
        )
    )
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--revocation-snapshot", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    args.as_of = parse_time(args.as_of, "--as-of", trusted=True)
    return args


def main() -> int:
    try:
        args = parse_args()
        findings = verify(args)
    except SupplierContentError as error:
        print(f"QUARANTINE {error.check_id} supplier input rejected: {error}")
        print("RESULT QUARANTINE 1 finding(s); portfolio import blocked")
        return 1
    except EvaluationError as error:
        print(f"ERROR SUP-008 verification unavailable: {error}")
        print("RESULT ERROR; portfolio import blocked")
        return 2
    if findings:
        for check_id, finding in findings:
            print(f"QUARANTINE {check_id} {finding}")
        print(f"RESULT QUARANTINE {len(findings)} finding(s); portfolio import blocked")
        return 1
    print("PASS supplier signature identity schema and signer status verified")
    print("RESULT ACCEPTED_FOR_PORTFOLIO_IMPORT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
