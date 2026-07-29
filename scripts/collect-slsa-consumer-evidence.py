#!/usr/bin/env python3
"""Collect a consumer issuer bundle from PSB-REL-001 verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from slsa_evidence_common import (
    CollectorError,
    SHA256_RE,
    atomic_write_json,
    format_time,
    load_json,
    object_field,
    require_digest,
    require_https_uri,
    require_scope,
    resolve_local_file,
    text_field,
)


POLICY_SCHEMA = "psb-slsa-consumer-collector-policy/v1"
FIXTURE_SCHEMA = "psb-slsa-consumer-verification-fixture/v1"
RECEIPT_SCHEMA = "psb-slsa-consumer-receipt/v1"
BUNDLE_SCHEMA = "psb-slsa-build-l2-issuer-bundle/v1"
PROFILE_ID = "slsa-build-l2"
OPENSSL_FIELDS = {"version", "sha256", "timeout_seconds"}
COMMON_FIELDS = {
    "schema_version",
    "source",
    "profile_id",
    "scope",
    "artifact_file",
    "artifact_sha256",
    "provenance_file",
    "provenance_sha256",
    "signature_file",
    "signature_sha256",
    "trust_policy_file",
    "trust_policy_sha256",
    "trusted_public_key_sha256",
    "verifier_sha256",
    "trust_policy_uri",
    "verification_receipt_uri",
}
TRUST_POLICY_FIELDS = {
    "minimum_trust_level",
    "previous_trust_level",
    "signature_algorithm",
    "trusted_public_key",
    "expected_subject_name",
    "expected_predicate_type",
    "expected_builder_id",
    "expected_build_type",
    "expected_repository",
    "expected_source_commit",
    "expected_ref",
    "allowed_external_parameters",
}
REASON_RE = re.compile(r"^[a-z]+(?:-[a-z]+)*$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}[a-z]?$")
VERIFIER = (
    Path(__file__).resolve().parent.parent
    / "controls"
    / "release-integrity"
    / "signature-provenance-verification"
    / "scripts"
    / "verify.py"
)


def require_tool(path: Path, policy: dict[str, Any]) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise CollectorError("OpenSSL path must be absolute and not a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CollectorError("OpenSSL is unavailable") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise CollectorError("OpenSSL must be an executable file")
    if resolved.name != "openssl":
        raise CollectorError("OpenSSL executable must be named openssl")
    require_digest(resolved, policy["sha256"], "OpenSSL")
    try:
        completed = subprocess.run(
            [str(resolved), "version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={"LC_ALL": "C", "PATH": str(resolved.parent)},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError("OpenSSL version check failed") from error
    expected = f"OpenSSL {policy['version']}"
    if (
        completed.returncode != 0
        or not completed.stdout.startswith(expected)
    ):
        raise CollectorError("OpenSSL version does not match policy")
    return resolved


def require_policy(
    raw: dict[str, Any],
    policy_path: Path,
) -> dict[str, Any]:
    source = raw.get("source")
    expected = set(COMMON_FIELDS)
    if source == "live":
        expected.add("openssl")
    elif source == "test-fixture":
        expected.add("verification_fixture")
    else:
        raise CollectorError("consumer collector source is unsupported")
    if set(raw) != expected:
        raise CollectorError("consumer collector policy fields are malformed")
    if (
        raw.get("schema_version") != POLICY_SCHEMA
        or raw.get("profile_id") != PROFILE_ID
    ):
        raise CollectorError("consumer collector policy is unsupported")

    scope, scope_digest = require_scope(raw)
    files: dict[str, Path] = {}
    digests: dict[str, str] = {}
    for name in ("artifact", "provenance", "signature", "trust_policy"):
        path = resolve_local_file(
            policy_path,
            text_field(raw, f"{name}_file", "collector"),
            f"collector.{name}_file",
        )
        digest = require_digest(
            path,
            text_field(raw, f"{name}_sha256", "collector"),
            f"collector {name}",
        )
        files[name] = path
        digests[name] = digest

    verifier_digest = require_digest(
        VERIFIER,
        text_field(raw, "verifier_sha256", "collector"),
        "PSB-REL-001 verifier",
    )
    trust_policy = load_json(files["trust_policy"], "consumer trust policy")
    if set(trust_policy) != TRUST_POLICY_FIELDS:
        raise CollectorError("consumer trust policy fields are malformed")
    if trust_policy.get("expected_source_commit") != scope["source_revision"]:
        raise CollectorError(
            "consumer trust policy source revision does not match scope"
        )
    if trust_policy.get("expected_subject_name") != files["artifact"].name:
        raise CollectorError(
            "consumer trust policy subject does not match artifact"
        )
    key_name = trust_policy.get("trusted_public_key")
    if not isinstance(key_name, str) or not key_name:
        raise CollectorError(
            "consumer trust policy trusted key is malformed"
        )
    trusted_key = resolve_local_file(
        files["trust_policy"],
        key_name,
        "consumer trusted public key",
    )
    trusted_key_digest = require_digest(
        trusted_key,
        text_field(raw, "trusted_public_key_sha256", "collector"),
        "consumer trusted public key",
    )
    trust_policy_uri = require_https_uri(
        raw.get("trust_policy_uri"),
        "collector.trust_policy_uri",
    )
    receipt_uri = require_https_uri(
        raw.get("verification_receipt_uri"),
        "collector.verification_receipt_uri",
    )

    result: dict[str, Any] = {
        "source": source,
        "scope": scope,
        "scope_digest": scope_digest,
        "files": files,
        "digests": digests,
        "trusted_key_digest": trusted_key_digest,
        "verifier_digest": verifier_digest,
        "trust_policy_uri": trust_policy_uri,
        "receipt_uri": receipt_uri,
    }
    if source == "test-fixture":
        result["fixture"] = resolve_local_file(
            policy_path,
            text_field(raw, "verification_fixture", "collector"),
            "collector.verification_fixture",
        )
    else:
        openssl = object_field(raw, "openssl", "collector")
        if set(openssl) != OPENSSL_FIELDS:
            raise CollectorError("collector.openssl fields are malformed")
        version = text_field(openssl, "version", "collector.openssl")
        if VERSION_RE.fullmatch(version) is None:
            raise CollectorError("collector.openssl.version is malformed")
        digest = text_field(openssl, "sha256", "collector.openssl")
        timeout = openssl.get("timeout_seconds")
        if (
            SHA256_RE.fullmatch(digest) is None
            or not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= 120
        ):
            raise CollectorError("collector.openssl policy is malformed")
        result["openssl"] = {
            "version": version,
            "sha256": digest,
            "timeout_seconds": timeout,
        }
    return result


def fixture_result(path: Path) -> tuple[int, list[str], str]:
    value = load_json(path, "consumer verification fixture")
    if set(value) != {"schema_version", "verifier_exit_code", "reason_codes"}:
        raise CollectorError("consumer verification fixture fields are malformed")
    if value.get("schema_version") != FIXTURE_SCHEMA:
        raise CollectorError("consumer verification fixture is unsupported")
    exit_code = value.get("verifier_exit_code")
    reasons = value.get("reason_codes")
    if (
        exit_code not in {0, 1, 2}
        or not isinstance(reasons, list)
        or not all(
            isinstance(item, str) and REASON_RE.fullmatch(item)
            for item in reasons
        )
        or len(reasons) != len(set(reasons))
        or (exit_code == 0 and reasons)
        or (exit_code == 1 and not reasons)
    ):
        raise CollectorError("consumer verification fixture result is malformed")
    return exit_code, reasons, hashlib.sha256(
        json.dumps(value, sort_keys=True).encode("utf-8")
    ).hexdigest()


def live_result(
    policy: dict[str, Any],
    openssl_path: Path,
) -> tuple[int, list[str], str]:
    verified_openssl = require_tool(openssl_path, policy["openssl"])
    files = policy["files"]
    command = [
        sys.executable,
        str(VERIFIER),
        "--policy",
        str(files["trust_policy"]),
        "--artifact",
        str(files["artifact"]),
        "--provenance",
        str(files["provenance"]),
        "--signature",
        str(files["signature"]),
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=policy["openssl"]["timeout_seconds"],
            check=False,
            env={
                "LC_ALL": "C",
                "PATH": str(verified_openssl.parent),
                "PYTHONIOENCODING": "utf-8",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError("consumer verification execution failed") from error
    output_digest = hashlib.sha256(
        completed.stdout.encode("utf-8")
    ).hexdigest()
    if completed.returncode == 0:
        return 0, [], output_digest
    if completed.returncode == 1:
        return 1, ["consumer-verification-rejected"], output_digest
    raise CollectorError("consumer verification was unavailable")


def collect(
    raw: dict[str, Any],
    policy_path: Path,
    openssl_path: Path,
    now: datetime,
) -> dict[str, Any]:
    policy = require_policy(raw, policy_path)
    if policy["source"] == "test-fixture":
        exit_code, reasons, output_digest = fixture_result(policy["fixture"])
    else:
        exit_code, reasons, output_digest = live_result(policy, openssl_path)
    if exit_code == 2:
        raise CollectorError("consumer verification was unavailable")
    result = "pass" if exit_code == 0 else "finding"
    observed_at = format_time(now)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "profile_id": PROFILE_ID,
        "issuer_role": "consumer",
        "observed_at": observed_at,
        "scope_sha256": policy["scope_digest"],
        "input_digests": {
            **policy["digests"],
            "trusted_public_key": policy["trusted_key_digest"],
            "verifier": policy["verifier_digest"],
        },
        "verifier_exit_code": exit_code,
        "verifier_output_sha256": output_digest,
        "result": result,
        "reason_codes": sorted(reasons),
        "disclaimer": (
            "This consumer receipt is evidence input, not a SLSA level claim."
        ),
    }
    return {
        "policy": policy,
        "receipt": receipt,
        "result": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    parser.add_argument("--now")
    args = parser.parse_args()
    try:
        now = (
            datetime.now(timezone.utc)
            if args.now is None
            else datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        )
        if now.tzinfo is None:
            raise CollectorError("--now must include a timezone")
        collected = collect(
            load_json(args.policy, "consumer collector policy"),
            args.policy,
            args.openssl,
            now.astimezone(timezone.utc),
        )
        receipt_bytes = atomic_write_json(
            args.receipt_output,
            collected["receipt"],
            "consumer receipt output",
        )
        receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
        policy = collected["policy"]
        result = collected["result"]
        bundle = {
            "schema_version": BUNDLE_SCHEMA,
            "profile_id": PROFILE_ID,
            "issuer_role": "consumer",
            "scope_sha256": policy["scope_digest"],
            "observed_at": collected["receipt"]["observed_at"],
            "evidence": [
                {
                    "code": "consumer-verification-result",
                    "type": "consumer-verification-result",
                    "uri": policy["receipt_uri"],
                    "sha256": receipt_digest,
                    "result": result,
                    "immutable": True,
                },
                {
                    "code": "consumer-trust-policy",
                    "type": "consumer-trust-policy",
                    "uri": policy["trust_policy_uri"],
                    "sha256": policy["digests"]["trust_policy"],
                    "result": result,
                    "immutable": True,
                },
                {
                    "code": "provenance-signature-verification",
                    "type": "provenance-signature-verification",
                    "uri": policy["receipt_uri"],
                    "sha256": receipt_digest,
                    "result": result,
                    "immutable": True,
                },
            ],
        }
        atomic_write_json(args.output, bundle, "consumer bundle output")
    except (CollectorError, OSError, ValueError) as error:
        print(f"ERROR consumer evidence unavailable: {error}")
        return 2
    status = "PASS" if collected["result"] == "pass" else "FINDING"
    reasons = ",".join(collected["receipt"]["reason_codes"]) or "none"
    print(
        f"COLLECTED {status} issuer=consumer evidence=3 "
        f"reason_codes={reasons}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
