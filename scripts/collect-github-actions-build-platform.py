#!/usr/bin/env python3
"""Collect a GitHub Actions build-platform issuer bundle."""

from __future__ import annotations

import argparse
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
from urllib.parse import urlparse


POLICY_SCHEMA = "psb-github-actions-build-platform-collector-policy/v1"
BUNDLE_SCHEMA = "psb-slsa-build-l2-issuer-bundle/v1"
PROFILE_ID = "slsa-build-l2"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REPOSITORY_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
SCOPE_FIELDS = {
    "producer_id",
    "build_platform_id",
    "consumer_id",
    "artifact_family",
    "release_id",
    "source_revision",
}
COMMON_POLICY_FIELDS = {
    "schema_version",
    "source",
    "profile_id",
    "scope",
    "repository",
    "source_ref",
    "artifact_file",
    "artifact_sha256",
    "platform_policy_file",
    "platform_policy_repository_path",
    "platform_policy_sha256",
    "signer_workflow",
    "signer_digest",
    "expected_invocation_id",
    "build_record_uri",
    "expected_builder_id",
    "expected_build_type",
}
GH_FIELDS = {
    "version",
    "sha256",
    "timeout_seconds",
    "allow_public_good",
}


class CollectorError(ValueError):
    """GitHub build evidence could not be collected safely."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise CollectorError(f"{label} must be an object")
    return value


def text_field(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise CollectorError(f"{label}.{field} must be non-empty text")
    return result


def object_field(value: dict[str, Any], field: str, label: str) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise CollectorError(f"{label}.{field} must be an object")
    return result


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise CollectorError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CollectorError(f"{label} must be a timestamp") from error
    if parsed.tzinfo is None:
        raise CollectorError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def safe_https_uri(value: str) -> bool:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return all(
        (
            parsed.scheme == "https",
            bool(parsed.hostname),
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            parsed.query == "",
            parsed.fragment == "",
        )
    )


def require_scope(document: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scope = document.get("scope")
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise CollectorError("collector scope is malformed")
    for field in SCOPE_FIELDS:
        text_field(scope, field, "collector.scope")
    for field in ("producer_id", "build_platform_id", "consumer_id"):
        if not safe_https_uri(scope[field]):
            raise CollectorError(
                f"collector.scope.{field} must be an HTTPS identity"
            )
    if COMMIT_RE.fullmatch(scope["source_revision"]) is None:
        raise CollectorError("collector source revision must be a full commit")
    return scope, canonical_digest(scope)


def safe_relative_path(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise CollectorError(f"{label} must be a safe relative path")
    return path


def resolve_local_file(policy_path: Path, value: str, label: str) -> Path:
    relative = safe_relative_path(value, label)
    current = policy_path.parent
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CollectorError(f"{label} must not use symlinks")
    try:
        resolved = (policy_path.parent / relative).resolve(strict=True)
        resolved.relative_to(policy_path.parent.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise CollectorError(f"{label} is unavailable") from error
    if not resolved.is_file():
        raise CollectorError(f"{label} must be a file")
    return resolved


def require_digest(path: Path, expected: str, label: str) -> str:
    if SHA256_RE.fullmatch(expected) is None:
        raise CollectorError(f"{label} pin must be a lowercase SHA-256")
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CollectorError(f"{label} is unavailable") from error
    if actual != expected:
        raise CollectorError(f"{label} digest mismatch")
    return actual


def require_policy(
    policy: dict[str, Any],
    policy_path: Path,
) -> dict[str, Any]:
    source = policy.get("source")
    expected_fields = set(COMMON_POLICY_FIELDS)
    if source == "live":
        expected_fields.add("github_cli")
    elif source == "test-fixture":
        expected_fields.add("verification_fixture")
    else:
        raise CollectorError("collector source is unsupported")
    if set(policy) != expected_fields:
        raise CollectorError("collector policy fields are malformed")
    if (
        policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("profile_id") != PROFILE_ID
    ):
        raise CollectorError("collector policy is unsupported")

    scope, scope_digest = require_scope(policy)
    repository = text_field(policy, "repository", "collector")
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise CollectorError("collector.repository must be owner/name")
    source_ref = text_field(policy, "source_ref", "collector")
    if not source_ref.startswith("refs/") or any(
        character.isspace() for character in source_ref
    ):
        raise CollectorError("collector.source_ref must be an exact Git ref")

    artifact = resolve_local_file(
        policy_path,
        text_field(policy, "artifact_file", "collector"),
        "collector.artifact_file",
    )
    artifact_digest = require_digest(
        artifact,
        text_field(policy, "artifact_sha256", "collector"),
        "collector artifact",
    )
    platform_policy = resolve_local_file(
        policy_path,
        text_field(policy, "platform_policy_file", "collector"),
        "collector.platform_policy_file",
    )
    platform_policy_digest = require_digest(
        platform_policy,
        text_field(policy, "platform_policy_sha256", "collector"),
        "collector platform policy",
    )
    repository_path = text_field(
        policy,
        "platform_policy_repository_path",
        "collector",
    )
    repository_path_value = Path(repository_path)
    if (
        REPOSITORY_PATH_RE.fullmatch(repository_path) is None
        or repository_path_value.is_absolute()
        or ".." in repository_path_value.parts
        or not repository_path.startswith(".github/workflows/")
        or not repository_path.endswith((".yml", ".yaml"))
    ):
        raise CollectorError("collector platform policy path is unsafe")
    expected_policy_uri = (
        f"https://github.com/{repository}/blob/{scope['source_revision']}/"
        f"{repository_path}"
    )
    if not safe_https_uri(expected_policy_uri):
        raise CollectorError("collector platform policy URI is unsafe")

    signer_workflow = text_field(policy, "signer_workflow", "collector")
    signer_parts = signer_workflow.split("/", 2)
    if (
        len(signer_parts) != 3
        or REPOSITORY_RE.fullmatch("/".join(signer_parts[:2])) is None
        or not signer_parts[2].startswith(".github/workflows/")
        or not signer_parts[2].endswith((".yml", ".yaml"))
    ):
        raise CollectorError("collector.signer_workflow is malformed")
    signer_digest = text_field(policy, "signer_digest", "collector")
    if COMMIT_RE.fullmatch(signer_digest) is None:
        raise CollectorError("collector.signer_digest must be a full commit")
    expected_invocation_id = text_field(
        policy,
        "expected_invocation_id",
        "collector",
    )
    invocation_prefix = f"https://github.com/{repository}/actions/runs/"
    if not safe_https_uri(expected_invocation_id) or re.fullmatch(
        re.escape(invocation_prefix) + r"[1-9][0-9]*/attempts/[1-9][0-9]*",
        expected_invocation_id,
    ) is None:
        raise CollectorError("collector.expected_invocation_id is malformed")
    build_record_uri = text_field(policy, "build_record_uri", "collector")
    if not safe_https_uri(build_record_uri):
        raise CollectorError("collector.build_record_uri must be an HTTPS URI")
    expected_builder_id = text_field(policy, "expected_builder_id", "collector")
    expected_build_type = text_field(policy, "expected_build_type", "collector")
    if not safe_https_uri(expected_builder_id) or not safe_https_uri(
        expected_build_type
    ):
        raise CollectorError("collector expected provenance identities are unsafe")

    result: dict[str, Any] = {
        "source": source,
        "scope": scope,
        "scope_digest": scope_digest,
        "repository": repository,
        "source_ref": source_ref,
        "artifact": artifact,
        "artifact_digest": artifact_digest,
        "platform_policy_digest": platform_policy_digest,
        "platform_policy_uri": expected_policy_uri,
        "signer_workflow": signer_workflow,
        "signer_digest": signer_digest,
        "expected_invocation_id": expected_invocation_id,
        "build_record_uri": build_record_uri,
        "expected_builder_id": expected_builder_id,
        "expected_build_type": expected_build_type,
    }
    if source == "test-fixture":
        result["verification_fixture"] = resolve_local_file(
            policy_path,
            text_field(policy, "verification_fixture", "collector"),
            "collector.verification_fixture",
        )
    else:
        github_cli = object_field(policy, "github_cli", "collector")
        if set(github_cli) != GH_FIELDS:
            raise CollectorError("collector.github_cli fields are malformed")
        version = text_field(github_cli, "version", "collector.github_cli")
        digest = text_field(github_cli, "sha256", "collector.github_cli")
        timeout = github_cli.get("timeout_seconds")
        allow_public_good = github_cli.get("allow_public_good")
        if (
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= 120
            or not isinstance(allow_public_good, bool)
        ):
            raise CollectorError("collector.github_cli metadata is malformed")
        result["github_cli"] = {
            "version": version,
            "sha256": digest,
            "timeout_seconds": timeout,
            "allow_public_good": allow_public_good,
        }
    return result


def require_gh_binary(path: Path, policy: dict[str, Any]) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise CollectorError("GitHub CLI must be an absolute non-symlink file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CollectorError("GitHub CLI is unavailable") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise CollectorError("GitHub CLI is unavailable")
    require_digest(resolved, policy["sha256"], "GitHub CLI")
    try:
        completed = subprocess.run(
            [str(resolved), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={
                **os.environ,
                "GH_PROMPT_DISABLED": "1",
                "GH_PAGER": "cat",
                "NO_COLOR": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError("GitHub CLI version check failed") from error
    expected = re.compile(
        rf"^gh version {re.escape(policy['version'])}(?: \(|$)"
    )
    first_line = completed.stdout.splitlines()[0] if completed.stdout else ""
    if completed.returncode != 0 or expected.match(first_line) is None:
        raise CollectorError("GitHub CLI version does not match policy")
    return resolved


def run_live_verification(
    gh_path: Path,
    policy: dict[str, Any],
) -> Any:
    github_cli = policy["github_cli"]
    verified_gh = require_gh_binary(gh_path, github_cli)
    command = [
        str(verified_gh),
        "attestation",
        "verify",
        str(policy["artifact"]),
        "--repo",
        policy["repository"],
        "--signer-workflow",
        policy["signer_workflow"],
        "--signer-digest",
        policy["signer_digest"],
        "--source-digest",
        policy["scope"]["source_revision"],
        "--source-ref",
        policy["source_ref"],
        "--deny-self-hosted-runners",
        "--predicate-type",
        PREDICATE_TYPE,
        "--cert-oidc-issuer",
        OIDC_ISSUER,
        "--hostname",
        "github.com",
        "--limit",
        "30",
        "--format",
        "json",
    ]
    if not github_cli["allow_public_good"]:
        command.append("--no-public-good")
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=github_cli["timeout_seconds"],
            check=False,
            env={
                **os.environ,
                "GH_PROMPT_DISABLED": "1",
                "GH_PAGER": "cat",
                "NO_COLOR": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError("GitHub attestation verification failed") from error
    if completed.returncode != 0:
        raise CollectorError("GitHub attestation verification failed")
    if len(completed.stdout.encode("utf-8")) > 4 * 1024 * 1024:
        raise CollectorError("GitHub attestation verification output is too large")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise CollectorError(
            "GitHub attestation verification output is malformed"
        ) from error


def list_field(value: dict[str, Any], field: str, label: str) -> list[Any]:
    result = value.get(field)
    if not isinstance(result, list):
        raise CollectorError(f"{label}.{field} must be a list")
    return result


def inspect_verification(
    verification: Any,
    policy: dict[str, Any],
) -> tuple[list[str], str, dict[str, Any]]:
    if not isinstance(verification, list) or not verification:
        raise CollectorError("verified attestation set must not be empty")
    matching_items: list[dict[str, Any]] = []
    for candidate in verification:
        if not isinstance(candidate, dict):
            raise CollectorError("verified attestation item must be an object")
        candidate_result = object_field(
            candidate,
            "verificationResult",
            "verified attestation",
        )
        candidate_statement = object_field(
            candidate_result,
            "statement",
            "verification result",
        )
        candidate_predicate = object_field(
            candidate_statement,
            "predicate",
            "statement",
        )
        candidate_run = object_field(
            candidate_predicate,
            "runDetails",
            "predicate",
        )
        candidate_metadata = object_field(
            candidate_run,
            "metadata",
            "predicate.runDetails",
        )
        if (
            candidate_metadata.get("invocationId")
            == policy["expected_invocation_id"]
        ):
            matching_items.append(candidate)
    if len(matching_items) != 1:
        raise CollectorError(
            "expected workflow run has no unique verified attestation"
        )
    item = matching_items[0]
    result = object_field(item, "verificationResult", "verified attestation")
    statement = object_field(result, "statement", "verification result")
    findings: list[str] = []
    if statement.get("_type") != STATEMENT_TYPE:
        findings.append("statement-type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        findings.append("predicate-type")

    subjects = list_field(statement, "subject", "statement")
    if len(subjects) != 1 or not isinstance(subjects[0], dict):
        findings.append("subject-cardinality")
    else:
        subject = subjects[0]
        digest = subject.get("digest")
        if (
            subject.get("name") != policy["artifact"].name
            or not isinstance(digest, dict)
            or digest.get("sha256") != policy["artifact_digest"]
        ):
            findings.append("subject-binding")

    predicate = object_field(statement, "predicate", "statement")
    definition = object_field(predicate, "buildDefinition", "predicate")
    if definition.get("buildType") != policy["expected_build_type"]:
        findings.append("build-type")
    external = object_field(
        definition,
        "externalParameters",
        "predicate.buildDefinition",
    )
    workflow = object_field(external, "workflow", "external parameters")
    expected_repository = f"https://github.com/{policy['repository']}"
    expected_path = "/" + policy["signer_workflow"].split("/", 2)[2]
    if (
        workflow.get("repository") != expected_repository
        or workflow.get("path") != expected_path
        or workflow.get("ref") != policy["source_ref"]
    ):
        findings.append("workflow-binding")

    dependencies = list_field(
        definition,
        "resolvedDependencies",
        "predicate.buildDefinition",
    )
    expected_dependency_uri = f"git+https://github.com/{policy['repository']}"
    source_matches = [
        dependency
        for dependency in dependencies
        if isinstance(dependency, dict)
        and dependency.get("uri") == expected_dependency_uri
        and isinstance(dependency.get("digest"), dict)
        and dependency["digest"].get("gitCommit")
        == policy["scope"]["source_revision"]
    ]
    if len(source_matches) != 1:
        findings.append("source-binding")

    run_details = object_field(predicate, "runDetails", "predicate")
    builder = object_field(run_details, "builder", "predicate.runDetails")
    if builder.get("id") != policy["expected_builder_id"]:
        findings.append("builder-identity")
    metadata = object_field(run_details, "metadata", "predicate.runDetails")
    invocation_id = text_field(metadata, "invocationId", "run metadata")
    if invocation_id != policy["expected_invocation_id"]:
        findings.append("invocation-binding")

    return sorted(set(findings)), invocation_id, item


def collect(
    raw_policy: dict[str, Any],
    policy_path: Path,
    gh_path: Path,
    observed_at: datetime,
) -> dict[str, Any]:
    policy = require_policy(raw_policy, policy_path)
    if policy["source"] == "test-fixture":
        verification = load_json(
            policy["verification_fixture"],
            "verification fixture",
        ).get("results")
    else:
        verification = run_live_verification(gh_path, policy)
    findings, invocation_id, verified_item = inspect_verification(
        verification,
        policy,
    )
    build_result = "finding" if findings else "pass"
    return {
        "receipt": {
            "schema_version": "psb-github-actions-build-platform-receipt/v1",
            "provider": "github-actions",
            "profile_id": PROFILE_ID,
            "observed_at": observed_at.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            "scope_sha256": policy["scope_digest"],
            "artifact": {
                "name": policy["artifact"].name,
                "sha256": policy["artifact_digest"],
            },
            "invocation_id": invocation_id,
            "verified_attestation": verified_item,
            "findings": findings,
            "disclaimer": (
                "This provider receipt is evidence input, not a SLSA level claim."
            ),
        },
        "bundle": {
            "schema_version": BUNDLE_SCHEMA,
            "profile_id": PROFILE_ID,
            "issuer_role": "build-platform",
            "scope_sha256": policy["scope_digest"],
            "observed_at": observed_at.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            "evidence": [
                {
                    "code": "platform-policy",
                    "type": "platform-policy",
                    "uri": policy["platform_policy_uri"],
                    "sha256": policy["platform_policy_digest"],
                    "result": "pass",
                    "immutable": True,
                },
                {
                    "code": "build-record",
                    "type": "build-record",
                    "uri": policy["build_record_uri"],
                    "sha256": "",
                    "result": build_result,
                    "immutable": True,
                },
            ],
        },
        "findings": findings,
    }


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass
        raise CollectorError("collector output is unavailable") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--gh", type=Path, default=Path("/usr/bin/gh"))
    parser.add_argument("--now")
    args = parser.parse_args()
    try:
        if args.output.absolute() == args.receipt_output.absolute():
            raise CollectorError("bundle and receipt outputs must be different")
        observed_at = (
            parse_time(args.now, "collector observation time")
            if args.now
            else datetime.now(timezone.utc)
        )
        result = collect(
            load_json(args.policy, "collector policy"),
            args.policy,
            args.gh,
            observed_at,
        )
        write_json_atomic(args.receipt_output, result["receipt"])
        try:
            receipt_digest = hashlib.sha256(
                args.receipt_output.read_bytes()
            ).hexdigest()
        except OSError as error:
            raise CollectorError("collector receipt is unavailable") from error
        result["bundle"]["evidence"][1]["sha256"] = receipt_digest
        write_json_atomic(args.output, result["bundle"])
    except CollectorError as error:
        print(f"ERROR github-actions build-platform collector: {error}")
        return 2
    status = "FINDING" if result["findings"] else "PASS"
    reason_codes = ",".join(result["findings"]) or "none"
    print(
        f"COLLECTED {status} issuer=build-platform evidence=2 "
        f"reason_codes={reason_codes}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
