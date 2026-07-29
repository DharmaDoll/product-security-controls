#!/usr/bin/env python3
"""Collect software-producer or security-monitor evidence from GitHub Releases."""

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
from urllib.parse import quote, urlparse


POLICY_SCHEMA = "psb-github-releases-collector-policy/v1"
BUNDLE_SCHEMA = "psb-slsa-build-l2-issuer-bundle/v1"
RECEIPT_SCHEMA = "psb-github-releases-receipt/v1"
PROFILE_ID = "slsa-build-l2"
API_VERSION = "2026-03-10"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SCOPE_FIELDS = {
    "producer_id",
    "build_platform_id",
    "consumer_id",
    "artifact_family",
    "release_id",
    "source_revision",
}
COMMON_FIELDS = {
    "schema_version",
    "source",
    "profile_id",
    "issuer_role",
    "scope",
    "repository",
    "release_tag",
    "artifact",
    "provenance",
    "maximum_publication_delay_seconds",
    "receipt_uri",
}
ASSET_FIELDS = {"name", "sha256", "content_type"}
UPSTREAM_FIELDS = {"uri", "sha256", "result", "immutable"}
GH_FIELDS = {"version", "sha256", "timeout_seconds"}


class CollectorError(ValueError):
    """GitHub Releases evidence could not be collected safely."""


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


def require_scope(policy: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scope = policy.get("scope")
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise CollectorError("collector scope is malformed")
    for field in SCOPE_FIELDS:
        text_field(scope, field, "collector.scope")
    for field in ("producer_id", "build_platform_id", "consumer_id"):
        if not safe_https_uri(scope[field]):
            raise CollectorError(f"collector.scope.{field} is unsafe")
    if COMMIT_RE.fullmatch(scope["source_revision"]) is None:
        raise CollectorError("collector source revision must be a full commit")
    return scope, canonical_digest(scope)


def require_asset(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != ASSET_FIELDS:
        raise CollectorError(f"{label} fields are malformed")
    name = text_field(value, "name", label)
    digest = text_field(value, "sha256", label)
    content_type = text_field(value, "content_type", label)
    if (
        SAFE_NAME_RE.fullmatch(name) is None
        or SHA256_RE.fullmatch(digest) is None
        or "/" not in content_type
        or any(character.isspace() for character in content_type)
    ):
        raise CollectorError(f"{label} metadata is malformed")
    return {"name": name, "sha256": digest, "content_type": content_type}


def require_upstream(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != UPSTREAM_FIELDS:
        raise CollectorError(f"{label} fields are malformed")
    uri = text_field(value, "uri", label)
    digest = text_field(value, "sha256", label)
    result = text_field(value, "result", label)
    immutable = value.get("immutable")
    if (
        not safe_https_uri(uri)
        or SHA256_RE.fullmatch(digest) is None
        or result not in {"pass", "finding", "error"}
        or not isinstance(immutable, bool)
    ):
        raise CollectorError(f"{label} metadata is malformed")
    return {
        "uri": uri,
        "sha256": digest,
        "result": result,
        "immutable": immutable,
    }


def safe_relative_file(policy_path: Path, value: str, label: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise CollectorError(f"{label} must be a safe relative path")
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


def require_policy(
    raw: dict[str, Any],
    policy_path: Path,
) -> dict[str, Any]:
    source = raw.get("source")
    role = raw.get("issuer_role")
    fields = set(COMMON_FIELDS)
    if source == "live":
        fields.add("github_cli")
    elif source == "test-fixture":
        fields.add("release_fixture")
    else:
        raise CollectorError("collector source is unsupported")
    if role == "software-producer":
        fields.update({"producer_policy_evidence", "build_policy_evidence"})
    elif role != "security-monitor":
        raise CollectorError("collector issuer role is unsupported")
    if set(raw) != fields:
        raise CollectorError("collector policy fields are malformed")
    if (
        raw.get("schema_version") != POLICY_SCHEMA
        or raw.get("profile_id") != PROFILE_ID
    ):
        raise CollectorError("collector policy is unsupported")
    scope, scope_digest = require_scope(raw)
    repository = text_field(raw, "repository", "collector")
    release_tag = text_field(raw, "release_tag", "collector")
    if (
        REPOSITORY_RE.fullmatch(repository) is None
        or SAFE_NAME_RE.fullmatch(release_tag) is None
        or release_tag != scope["release_id"]
    ):
        raise CollectorError("collector release identity is malformed")
    artifact = require_asset(raw.get("artifact"), "collector.artifact")
    provenance = require_asset(raw.get("provenance"), "collector.provenance")
    if artifact["name"] == provenance["name"]:
        raise CollectorError("collector assets must have distinct names")
    maximum_delay = raw.get("maximum_publication_delay_seconds")
    if (
        not isinstance(maximum_delay, int)
        or isinstance(maximum_delay, bool)
        or not 0 <= maximum_delay <= 300
    ):
        raise CollectorError("collector publication delay is malformed")
    receipt_uri = text_field(raw, "receipt_uri", "collector")
    if not safe_https_uri(receipt_uri):
        raise CollectorError("collector receipt URI is unsafe")

    policy: dict[str, Any] = {
        "source": source,
        "role": role,
        "scope": scope,
        "scope_digest": scope_digest,
        "repository": repository,
        "release_tag": release_tag,
        "artifact": artifact,
        "provenance": provenance,
        "maximum_delay": maximum_delay,
        "receipt_uri": receipt_uri,
    }
    if role == "software-producer":
        policy["producer_policy_evidence"] = require_upstream(
            raw.get("producer_policy_evidence"),
            "collector.producer_policy_evidence",
        )
        policy["build_policy_evidence"] = require_upstream(
            raw.get("build_policy_evidence"),
            "collector.build_policy_evidence",
        )
    if source == "test-fixture":
        policy["release_fixture"] = safe_relative_file(
            policy_path,
            text_field(raw, "release_fixture", "collector"),
            "collector.release_fixture",
        )
    else:
        gh = raw.get("github_cli")
        if not isinstance(gh, dict) or set(gh) != GH_FIELDS:
            raise CollectorError("collector.github_cli fields are malformed")
        version = text_field(gh, "version", "collector.github_cli")
        digest = text_field(gh, "sha256", "collector.github_cli")
        timeout = gh.get("timeout_seconds")
        if (
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= 120
        ):
            raise CollectorError("collector.github_cli metadata is malformed")
        policy["github_cli"] = {
            "version": version,
            "sha256": digest,
            "timeout_seconds": timeout,
        }
    return policy


def require_gh(path: Path, policy: dict[str, Any]) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise CollectorError("GitHub CLI must be an absolute non-symlink file")
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
    except OSError as error:
        raise CollectorError("GitHub CLI is unavailable") from error
    if (
        not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or hashlib.sha256(content).hexdigest() != policy["sha256"]
    ):
        raise CollectorError("GitHub CLI does not match the pinned binary")
    environment = {
        **os.environ,
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
    }
    try:
        completed = subprocess.run(
            [str(resolved), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError("GitHub CLI version check failed") from error
    line = completed.stdout.splitlines()[0] if completed.stdout else ""
    expected = re.compile(
        rf"^gh version {re.escape(policy['version'])}(?: \(|$)"
    )
    if completed.returncode != 0 or expected.match(line) is None:
        raise CollectorError("GitHub CLI version does not match policy")
    return resolved


def fetch_release(gh_path: Path, policy: dict[str, Any]) -> dict[str, Any]:
    verified_gh = require_gh(gh_path, policy["github_cli"])
    endpoint = (
        f"repos/{policy['repository']}/releases/tags/"
        f"{quote(policy['release_tag'], safe='')}"
    )
    command = [
        str(verified_gh),
        "api",
        endpoint,
        "--method",
        "GET",
        "--hostname",
        "github.com",
        "--header",
        "Accept: application/vnd.github+json",
        "--header",
        f"X-GitHub-Api-Version: {API_VERSION}",
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=policy["github_cli"]["timeout_seconds"],
            check=False,
            env={
                **os.environ,
                "GH_PROMPT_DISABLED": "1",
                "GH_PAGER": "cat",
                "NO_COLOR": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CollectorError("GitHub release API collection failed") from error
    if completed.returncode != 0:
        raise CollectorError("GitHub release API collection failed")
    if len(completed.stdout.encode("utf-8")) > 4 * 1024 * 1024:
        raise CollectorError("GitHub release API output is too large")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise CollectorError("GitHub release API output is malformed") from error
    if not isinstance(value, dict):
        raise CollectorError("GitHub release API output must be an object")
    return value


def asset_findings(
    raw: Any,
    expected: dict[str, str],
    expected_url: str,
    label: str,
) -> tuple[list[str], datetime]:
    if not isinstance(raw, dict):
        raise CollectorError(f"{label} asset is malformed")
    findings: list[str] = []
    if raw.get("name") != expected["name"]:
        findings.append(f"{label}-name")
    if raw.get("digest") != f"sha256:{expected['sha256']}":
        findings.append(f"{label}-digest")
    if raw.get("content_type") != expected["content_type"]:
        findings.append(f"{label}-content-type")
    if raw.get("state") != "uploaded":
        findings.append(f"{label}-state")
    if raw.get("browser_download_url") != expected_url:
        findings.append(f"{label}-location")
    created = parse_time(raw.get("created_at"), f"{label}.created_at")
    updated = parse_time(raw.get("updated_at"), f"{label}.updated_at")
    if updated != created:
        findings.append(f"{label}-mutation")
    return findings, created


def inspect_release(
    release: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    findings: list[str] = []
    expected_release_url = (
        f"https://github.com/{policy['repository']}/releases/tag/"
        f"{policy['release_tag']}"
    )
    if release.get("tag_name") != policy["release_tag"]:
        findings.append("release-tag")
    if release.get("html_url") != expected_release_url:
        findings.append("release-location")
    if release.get("draft") is not False:
        findings.append("release-draft")
    if release.get("prerelease") is not False:
        findings.append("release-prerelease")
    if release.get("immutable") is not True:
        findings.append("release-mutable")
    published_at = parse_time(release.get("published_at"), "release.published_at")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise CollectorError("release.assets must be a list")
    by_name: dict[str, list[dict[str, Any]]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise CollectorError("release asset is malformed")
        by_name.setdefault(asset["name"], []).append(asset)
    expected_names = {
        policy["artifact"]["name"],
        policy["provenance"]["name"],
    }
    if any(len(by_name.get(name, [])) != 1 for name in expected_names):
        findings.append("required-assets")
        return sorted(set(findings)), {
            "published_at": published_at.isoformat(),
            "assets_seen": sorted(by_name),
        }
    base = (
        f"https://github.com/{policy['repository']}/releases/download/"
        f"{policy['release_tag']}/"
    )
    artifact_findings, artifact_created = asset_findings(
        by_name[policy["artifact"]["name"]][0],
        policy["artifact"],
        base + policy["artifact"]["name"],
        "artifact",
    )
    provenance_findings, provenance_created = asset_findings(
        by_name[policy["provenance"]["name"]][0],
        policy["provenance"],
        base + policy["provenance"]["name"],
        "provenance",
    )
    findings.extend(artifact_findings)
    findings.extend(provenance_findings)
    delay = (provenance_created - artifact_created).total_seconds()
    if not 0 <= delay <= policy["maximum_delay"]:
        findings.append("publication-delay")
    if published_at < artifact_created or published_at < provenance_created:
        findings.append("release-publication-order")
    return sorted(set(findings)), {
        "published_at": published_at.isoformat(),
        "artifact_created_at": artifact_created.isoformat(),
        "provenance_created_at": provenance_created.isoformat(),
        "publication_delay_seconds": delay,
        "assets_seen": sorted(by_name),
    }


def collect(
    raw_policy: dict[str, Any],
    policy_path: Path,
    gh_path: Path,
    observed_at: datetime,
) -> dict[str, Any]:
    policy = require_policy(raw_policy, policy_path)
    release = (
        load_json(policy["release_fixture"], "release fixture")
        if policy["source"] == "test-fixture"
        else fetch_release(gh_path, policy)
    )
    findings, observations = inspect_release(release, policy)
    result = "finding" if findings else "pass"
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "provider": "github-releases",
        "profile_id": PROFILE_ID,
        "issuer_role": policy["role"],
        "observed_at": observed_at.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "scope_sha256": policy["scope_digest"],
        "release_snapshot": release,
        "observations": observations,
        "findings": findings,
        "disclaimer": (
            "This provider receipt is evidence input, not a SLSA level claim."
        ),
    }
    evidence: list[dict[str, Any]] = []
    if policy["role"] == "software-producer":
        for evidence_type in ("producer-policy", "build-policy"):
            upstream = policy[
                evidence_type.replace("-", "_") + "_evidence"
            ]
            evidence.append(
                {
                    "code": evidence_type,
                    "type": evidence_type,
                    **upstream,
                }
            )
        evidence.append(
            {
                "code": "publication-manifest",
                "type": "publication-manifest",
                "uri": policy["receipt_uri"],
                "sha256": "",
                "result": result,
                "immutable": True,
            }
        )
    else:
        evidence.append(
            {
                "code": "storage-probe",
                "type": "storage-probe",
                "uri": policy["receipt_uri"],
                "sha256": "",
                "result": result,
                "immutable": True,
            }
        )
    return {
        "receipt": receipt,
        "bundle": {
            "schema_version": BUNDLE_SCHEMA,
            "profile_id": PROFILE_ID,
            "issuer_role": policy["role"],
            "scope_sha256": policy["scope_digest"],
            "observed_at": receipt["observed_at"],
            "evidence": evidence,
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
        generated_type = (
            "publication-manifest"
            if result["bundle"]["issuer_role"] == "software-producer"
            else "storage-probe"
        )
        generated = next(
            item
            for item in result["bundle"]["evidence"]
            if item["type"] == generated_type
        )
        generated["sha256"] = receipt_digest
        write_json_atomic(args.output, result["bundle"])
    except CollectorError as error:
        print(f"ERROR github-releases evidence collector: {error}")
        return 2
    status = "FINDING" if result["findings"] else "PASS"
    reasons = ",".join(result["findings"]) or "none"
    print(
        f"COLLECTED {status} issuer={result['bundle']['issuer_role']} "
        f"evidence={len(result['bundle']['evidence'])} reason_codes={reasons}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
