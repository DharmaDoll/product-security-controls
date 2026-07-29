#!/usr/bin/env python3
"""Collect independently signed build-platform review evidence."""

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
import tempfile
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
    parse_time,
    require_digest,
    require_https_uri,
    require_scope,
    resolve_local_file,
    text_field,
)


POLICY_SCHEMA = "psb-slsa-security-review-collector-policy/v1"
REVIEW_SCHEMA = "psb-slsa-build-platform-security-review/v1"
FIXTURE_SCHEMA = "psb-slsa-security-review-verification-fixture/v1"
RECEIPT_SCHEMA = "psb-slsa-security-review-receipt/v1"
BUNDLE_SCHEMA = "psb-slsa-build-l2-issuer-bundle/v1"
PROFILE_ID = "slsa-build-l2"
OPENSSL_FIELDS = {"version", "sha256", "timeout_seconds"}
COMMON_FIELDS = {
    "schema_version",
    "source",
    "profile_id",
    "scope",
    "review_file",
    "review_sha256",
    "signature_file",
    "signature_sha256",
    "trusted_public_key_file",
    "trusted_public_key_sha256",
    "expected_reviewer_id",
    "expected_signer_id",
    "maximum_review_age_seconds",
    "receipt_uri",
}
REVIEW_FIELDS = {
    "schema_version",
    "profile_id",
    "scope_sha256",
    "reviewer",
    "reviewed_at",
    "expires_at",
    "platform_capability_assessment",
    "signer_ownership_assessment",
    "limitations",
}
REVIEWER_FIELDS = {"id", "role"}
CAPABILITY_FIELDS = {
    "result",
    "build_platform_id",
    "target_level",
    "hosted_execution",
    "consistent_build_process",
    "control_plane_provenance_generation",
    "evidence_uri",
    "evidence_sha256",
}
SIGNER_FIELDS = {
    "result",
    "signer_id",
    "platform_owned_identity",
    "tenant_signing_capability",
    "rotation_and_revocation_reviewed",
    "evidence_uri",
    "evidence_sha256",
}
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}[a-z]?$")


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
    if (
        completed.returncode != 0
        or not completed.stdout.startswith(f"OpenSSL {policy['version']}")
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
        raise CollectorError("security review collector source is unsupported")
    if set(raw) != expected:
        raise CollectorError(
            "security review collector policy fields are malformed"
        )
    if (
        raw.get("schema_version") != POLICY_SCHEMA
        or raw.get("profile_id") != PROFILE_ID
    ):
        raise CollectorError("security review collector policy is unsupported")

    scope, scope_digest = require_scope(raw)
    files: dict[str, Path] = {}
    digests: dict[str, str] = {}
    for name in ("review", "signature", "trusted_public_key"):
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

    reviewer_id = require_https_uri(
        raw.get("expected_reviewer_id"),
        "collector.expected_reviewer_id",
    )
    signer_id = require_https_uri(
        raw.get("expected_signer_id"),
        "collector.expected_signer_id",
    )
    maximum_age = raw.get("maximum_review_age_seconds")
    if (
        not isinstance(maximum_age, int)
        or isinstance(maximum_age, bool)
        or not 1 <= maximum_age <= 31_536_000
    ):
        raise CollectorError(
            "collector.maximum_review_age_seconds is malformed"
        )
    receipt_uri = require_https_uri(
        raw.get("receipt_uri"),
        "collector.receipt_uri",
    )

    result: dict[str, Any] = {
        "source": source,
        "scope": scope,
        "scope_digest": scope_digest,
        "files": files,
        "digests": digests,
        "reviewer_id": reviewer_id,
        "signer_id": signer_id,
        "maximum_age": maximum_age,
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
        digest = text_field(openssl, "sha256", "collector.openssl")
        timeout = openssl.get("timeout_seconds")
        if (
            VERSION_RE.fullmatch(version) is None
            or SHA256_RE.fullmatch(digest) is None
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


def verify_signature_fixture(path: Path) -> bool:
    value = load_json(path, "security review verification fixture")
    if set(value) != {"schema_version", "verifier_exit_code"}:
        raise CollectorError(
            "security review verification fixture fields are malformed"
        )
    if value.get("schema_version") != FIXTURE_SCHEMA:
        raise CollectorError(
            "security review verification fixture is unsupported"
        )
    exit_code = value.get("verifier_exit_code")
    if exit_code == 0:
        return True
    if exit_code == 1:
        return False
    if exit_code == 2:
        raise CollectorError("security review signature verification unavailable")
    raise CollectorError(
        "security review verification fixture result is malformed"
    )


def verify_signature_live(
    policy: dict[str, Any],
    openssl_path: Path,
) -> bool:
    openssl = require_tool(openssl_path, policy["openssl"])
    try:
        encoded = policy["files"]["signature"].read_bytes().strip()
        signature = base64.b64decode(encoded, validate=True)
    except (OSError, binascii.Error, ValueError) as error:
        raise CollectorError("security review signature is malformed") from error
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".psb-review-signature.",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            os.chmod(handle.name, 0o600)
            handle.write(signature)
        completed = subprocess.run(
            [
                str(openssl),
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(policy["files"]["trusted_public_key"]),
                "-rawin",
                "-in",
                str(policy["files"]["review"]),
                "-sigfile",
                temporary_name,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=policy["openssl"]["timeout_seconds"],
            check=False,
            env={"LC_ALL": "C", "PATH": str(openssl.parent)},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError(
            "security review signature verification failed"
        ) from error
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise CollectorError("security review signature verification unavailable")


def require_assessment(
    value: Any,
    fields: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CollectorError(f"{label} fields are malformed")
    if value.get("result") not in {"pass", "finding"}:
        raise CollectorError(f"{label}.result is malformed")
    require_https_uri(value.get("evidence_uri"), f"{label}.evidence_uri")
    digest = value.get("evidence_sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise CollectorError(f"{label}.evidence_sha256 is malformed")
    return value


def inspect_review(
    review: dict[str, Any],
    policy: dict[str, Any],
    now: datetime,
    signature_verified: bool,
) -> tuple[list[str], list[str], datetime, datetime]:
    if set(review) != REVIEW_FIELDS:
        raise CollectorError("security review record fields are malformed")
    if (
        review.get("schema_version") != REVIEW_SCHEMA
        or review.get("profile_id") != PROFILE_ID
        or review.get("scope_sha256") != policy["scope_digest"]
    ):
        raise CollectorError("security review record identity is invalid")
    reviewer = review.get("reviewer")
    if not isinstance(reviewer, dict) or set(reviewer) != REVIEWER_FIELDS:
        raise CollectorError("security review reviewer fields are malformed")
    if (
        reviewer.get("id") != policy["reviewer_id"]
        or reviewer.get("role") != "security-review"
    ):
        raise CollectorError("security review reviewer identity is invalid")
    reviewed_at = parse_time(review.get("reviewed_at"), "review.reviewed_at")
    expires_at = parse_time(review.get("expires_at"), "review.expires_at")
    if expires_at <= reviewed_at:
        raise CollectorError("security review validity interval is invalid")
    limitations = review.get("limitations")
    if (
        not isinstance(limitations, list)
        or not limitations
        or not all(isinstance(item, str) and item for item in limitations)
    ):
        raise CollectorError("security review limitations are malformed")

    capability = require_assessment(
        review.get("platform_capability_assessment"),
        CAPABILITY_FIELDS,
        "platform capability assessment",
    )
    signer = require_assessment(
        review.get("signer_ownership_assessment"),
        SIGNER_FIELDS,
        "signer ownership assessment",
    )
    capability_findings: list[str] = []
    signer_findings: list[str] = []
    if not signature_verified:
        capability_findings.append("review-signature-invalid")
        signer_findings.append("review-signature-invalid")
    if reviewer["id"] in {
        policy["scope"]["producer_id"],
        policy["scope"]["build_platform_id"],
        policy["scope"]["consumer_id"],
    }:
        capability_findings.append("reviewer-not-independent")
        signer_findings.append("reviewer-not-independent")
    if reviewed_at > now:
        capability_findings.append("review-time-future")
        signer_findings.append("review-time-future")
    if expires_at <= now:
        capability_findings.append("review-expired")
        signer_findings.append("review-expired")
    if (now - reviewed_at).total_seconds() > policy["maximum_age"]:
        capability_findings.append("review-stale")
        signer_findings.append("review-stale")

    if capability["result"] == "finding":
        capability_findings.append("platform-capability-rejected")
    if capability.get("build_platform_id") != policy["scope"]["build_platform_id"]:
        capability_findings.append("build-platform-identity")
    if capability.get("target_level") != 2:
        capability_findings.append("target-level")
    for field, code in (
        ("hosted_execution", "hosted-execution"),
        ("consistent_build_process", "consistent-build-process"),
        (
            "control_plane_provenance_generation",
            "control-plane-provenance",
        ),
    ):
        if capability.get(field) is not True:
            capability_findings.append(code)

    if signer["result"] == "finding":
        signer_findings.append("signer-ownership-rejected")
    if signer.get("signer_id") != policy["signer_id"]:
        signer_findings.append("signer-identity")
    if signer.get("platform_owned_identity") is not True:
        signer_findings.append("platform-ownership")
    if signer.get("tenant_signing_capability") is not False:
        signer_findings.append("tenant-signing-capability")
    if signer.get("rotation_and_revocation_reviewed") is not True:
        signer_findings.append("signer-lifecycle")
    return (
        sorted(set(capability_findings)),
        sorted(set(signer_findings)),
        reviewed_at,
        expires_at,
    )


def collect(
    raw: dict[str, Any],
    policy_path: Path,
    openssl_path: Path,
    now: datetime,
) -> dict[str, Any]:
    policy = require_policy(raw, policy_path)
    review = load_json(policy["files"]["review"], "security review record")
    signature_verified = (
        verify_signature_fixture(policy["fixture"])
        if policy["source"] == "test-fixture"
        else verify_signature_live(policy, openssl_path)
    )
    (
        capability_findings,
        signer_findings,
        reviewed_at,
        expires_at,
    ) = inspect_review(review, policy, now, signature_verified)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "profile_id": PROFILE_ID,
        "issuer_role": "security-review",
        "collected_at": format_time(now),
        "observed_at": format_time(reviewed_at),
        "expires_at": format_time(expires_at),
        "scope_sha256": policy["scope_digest"],
        "input_digests": policy["digests"],
        "signature_verified": signature_verified,
        "signed_review_record": review,
        "findings": {
            "platform_capability_assessment": capability_findings,
            "signer_ownership_assessment": signer_findings,
        },
        "disclaimer": (
            "This review receipt is evidence input, not a SLSA level claim."
        ),
    }
    return {
        "policy": policy,
        "receipt": receipt,
        "capability_result": (
            "finding" if capability_findings else "pass"
        ),
        "signer_result": "finding" if signer_findings else "pass",
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
            load_json(args.policy, "security review collector policy"),
            args.policy,
            args.openssl,
            now.astimezone(timezone.utc),
        )
        receipt_bytes = atomic_write_json(
            args.receipt_output,
            collected["receipt"],
            "security review receipt output",
        )
        receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
        policy = collected["policy"]
        bundle = {
            "schema_version": BUNDLE_SCHEMA,
            "profile_id": PROFILE_ID,
            "issuer_role": "security-review",
            "scope_sha256": policy["scope_digest"],
            "observed_at": collected["receipt"]["observed_at"],
            "evidence": [
                {
                    "code": "platform-capability-assessment",
                    "type": "platform-capability-assessment",
                    "uri": policy["receipt_uri"],
                    "sha256": receipt_digest,
                    "result": collected["capability_result"],
                    "immutable": True,
                },
                {
                    "code": "signer-ownership-assessment",
                    "type": "signer-ownership-assessment",
                    "uri": policy["receipt_uri"],
                    "sha256": receipt_digest,
                    "result": collected["signer_result"],
                    "immutable": True,
                },
            ],
        }
        atomic_write_json(args.output, bundle, "security review bundle output")
    except (CollectorError, OSError, ValueError) as error:
        print(f"ERROR security review evidence unavailable: {error}")
        return 2
    results = {
        collected["capability_result"],
        collected["signer_result"],
    }
    status = "PASS" if results == {"pass"} else "FINDING"
    reasons = sorted(
        {
            reason
            for values in collected["receipt"]["findings"].values()
            for reason in values
        }
    )
    print(
        f"COLLECTED {status} issuer=security-review evidence=2 "
        f"reason_codes={','.join(reasons) or 'none'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
