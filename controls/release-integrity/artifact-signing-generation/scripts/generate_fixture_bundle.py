#!/usr/bin/env python3
"""Create a synthetic signing bundle with an ephemeral test key.

This harness demonstrates the request-to-signature contract. Production must
replace the private-key file with a reviewed KMS, HSM, or keyless adapter and
must use authentic provider and transparency-log receipts.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
import verify


def canonical(value: dict[str, object]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write_new(path: Path, value: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def run_openssl(command: list[str], label: str) -> None:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise verify.EvaluationError(f"cannot execute OpenSSL for {label}") from error
    if result.returncode != 0:
        raise verify.EvaluationError(f"OpenSSL {label} failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--signer-evidence", type=Path, required=True)
    parser.add_argument("--fixture-private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signed-at", required=True)
    parser.add_argument("--fixture-transparency-log-id", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        signed_at = verify.parse_time(args.signed_at, "signed-at")
        policy = verify.load_json(args.policy, "signing policy")
        artifact = verify.read_bytes(args.artifact, "artifact")
        request_bytes = verify.read_bytes(args.request, "signing request")
        authorization_bytes = verify.read_bytes(args.authorization, "authorization")
        request = verify.load_json(args.request, "signing request")
        authorization = verify.load_json(args.authorization, "authorization")
        signer = verify.load_json(args.signer_evidence, "signer evidence")
        findings = verify.evaluate_preflight(
            policy, artifact, request, authorization, signer, signed_at
        )
        if any(findings.values()):
            raise verify.EvaluationError("signing preflight rejected the request")
        if not args.fixture_private_key.is_file():
            raise verify.EvaluationError("fixture private key is unavailable")
        if args.fixture_private_key.stat().st_mode & 0o077:
            raise verify.EvaluationError("fixture private key permissions must be 0600")
        public_key = verify.resolve_public_key(args.policy, policy)
        with tempfile.NamedTemporaryFile() as derived:
            run_openssl(
                [
                    args.openssl,
                    "pkey",
                    "-in",
                    str(args.fixture_private_key),
                    "-pubout",
                    "-out",
                    derived.name,
                ],
                "public-key derivation",
            )
            if Path(derived.name).read_bytes() != public_key.read_bytes():
                raise verify.EvaluationError("fixture private key does not match trusted public key")
        expected = verify.object_at(policy, "expected", "policy")
        artifact_claim = verify.object_at(request, "artifact", "request")
        release = verify.object_at(request, "release", "request")
        source = verify.object_at(request, "source", "request")
        statement: dict[str, object] = {
            "schema": "psb-artifact-signature-statement/1.0",
            "artifact": {
                "family": artifact_claim["family"],
                "name": artifact_claim["name"],
                "sha256": hashlib.sha256(artifact).hexdigest(),
            },
            "release": {"id": release["id"], "ref": release["ref"]},
            "source": {
                "repository": source["repository"],
                "revision": source["revision"],
            },
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "authorization_sha256": hashlib.sha256(authorization_bytes).hexdigest(),
            "signer": {
                "id": expected["signer_id"],
                "key_version": expected["key_version"],
                "algorithm": "ed25519",
            },
            "signed_at": args.signed_at,
        }
        if args.output.exists():
            raise verify.EvaluationError("output directory already exists")
        args.output.mkdir(mode=0o700, parents=True)
        statement_path = args.output / "signature-statement.json"
        signature_path = args.output / "signature.bin"
        signature_b64_path = args.output / "signature.b64"
        receipt_path = args.output / "signing-receipt.json"
        write_new(statement_path, canonical(statement))
        run_openssl(
            [
                args.openssl,
                "pkeyutl",
                "-sign",
                "-inkey",
                str(args.fixture_private_key),
                "-rawin",
                "-in",
                str(statement_path),
                "-out",
                str(signature_path),
            ],
            "signing",
        )
        signature = signature_path.read_bytes()
        write_new(signature_b64_path, base64.b64encode(signature) + b"\n")
        signature_path.unlink()
        publication = verify.object_at(policy, "publication", "policy")
        receipt: dict[str, object] = {
            "schema": "psb-artifact-signing-receipt/1.0",
            "status": "SIGNED",
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "statement_sha256": hashlib.sha256(statement_path.read_bytes()).hexdigest(),
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
            "signer_id": expected["signer_id"],
            "key_version": expected["key_version"],
            "signed_at": args.signed_at,
            "publication": {
                "location": publication["location"],
                "immutable": publication["immutable"],
            },
            "transparency": {
                "included": True,
                "log_id": args.fixture_transparency_log_id,
                "integrated_at": args.signed_at,
            },
            "release_gate": {
                "status": "ALLOW",
                "failure_policy": policy["release_gate_failure_policy"],
            },
            "evidence": {
                "contains_identity_token": False,
                "contains_private_key_material": False,
                "contains_signature_body": False,
            },
        }
        write_new(receipt_path, canonical(receipt))
    except (KeyError, OSError, verify.EvaluationError) as error:
        print(f"ERROR PSB-REL-005/ASG-008 fixture signing unavailable: {error}")
        return 2
    print("PASS PSB-REL-005 fixture bundle generated without retaining private key material")
    return 0


if __name__ == "__main__":
    sys.exit(main())
