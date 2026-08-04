#!/usr/bin/env python3
"""Verify a provider-neutral GitHub Actions OIDC federation contract."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-oidc-federation-policy/v1"
INVENTORY_SCHEMA = "psb-repository-secret-inventory/v1"
REPLAY_SCHEMA = "psb-oidc-replay-state/v1"
RECEIPT_SCHEMA = "psb-cloud-credential-receipt/v1"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_SUB_RE = re.compile(
    r"^repo:[^/@:]+@[0-9]+/[^/@:]+@[0-9]+:environment:[^:]+$"
)
KEY_VALUE_RE = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*):"
    r"(?: *(?P<value>.*?))? *$"
)
SECRET_REFERENCE_RE = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
STATIC_CLOUD_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|"
    r"AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|"
    r"GCP_SERVICE_ACCOUNT_KEY|CLOUD_ACCESS_KEY|CLOUD_SECRET_KEY)(?![A-Za-z0-9])",
    re.IGNORECASE,
)


class InputError(ValueError):
    """The verifier cannot safely evaluate an input."""


@dataclass(frozen=True)
class Job:
    job_id: str
    condition: str | None
    environment: str | None
    permissions: dict[str, str] | None
    raw_text: str


def read_text(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise InputError(f"{label} is unavailable: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InputError(f"cannot read {label}: {error}") from error


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path, label))
    except json.JSONDecodeError as error:
        raise InputError(f"cannot parse {label}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def require_schema(value: dict[str, Any], schema: str, label: str) -> None:
    if value.get("schema_version") != schema:
        raise InputError(f"{label} schema_version must be {schema}")


def text_field(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise InputError(f"{label}.{field} must be non-empty text")
    return result


def int_field(value: dict[str, Any], field: str, label: str) -> int:
    result = value.get(field)
    if isinstance(result, bool) or not isinstance(result, int):
        raise InputError(f"{label}.{field} must be an integer")
    return result


def string_list(value: dict[str, Any], field: str, label: str) -> list[str]:
    result = value.get(field)
    if not isinstance(result, list) or not all(
        isinstance(item, str) and item for item in result
    ):
        raise InputError(f"{label}.{field} must be a non-empty string list")
    return result


def decode_segment(segment: str, label: str) -> bytes:
    if not segment or "=" in segment or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise InputError(f"JWT {label} is not canonical base64url")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as error:
        raise InputError(f"cannot decode JWT {label}: {error}") from error


def decode_object(segment: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(decode_segment(segment, label))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot parse JWT {label}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"JWT {label} must be a JSON object")
    return value


def resolve_public_key(policy_path: Path, relative_text: str) -> Path:
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise InputError("policy trusted_public_key must remain policy-relative")
    path = (policy_path.parent / relative).resolve()
    if path.is_symlink() or not path.is_file():
        raise InputError(f"trusted public key is unavailable: {relative_text}")
    return path


def verify_signature(
    signing_input: bytes,
    signature: bytes,
    public_key: Path,
    openssl_path: Path,
) -> bool:
    if (
        not openssl_path.is_absolute()
        or openssl_path.is_symlink()
        or not openssl_path.is_file()
    ):
        raise InputError("OpenSSL verifier is unavailable or not a regular absolute path")
    with tempfile.NamedTemporaryFile() as message, tempfile.NamedTemporaryFile() as sig:
        message.write(signing_input)
        message.flush()
        sig.write(signature)
        sig.flush()
        try:
            result = subprocess.run(
                [
                    str(openssl_path),
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key),
                    "-signature",
                    sig.name,
                    message.name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                env={"LC_ALL": "C", "PATH": str(openssl_path.parent)},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InputError(f"OpenSSL verification failed to execute: {error}") from error
    if result.returncode not in {0, 1}:
        raise InputError(f"OpenSSL verification returned error status {result.returncode}")
    return result.returncode == 0


def strip_yaml_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if character == "#" and quote is None:
            return line[:index]
    if quote is not None:
        raise InputError("unterminated quoted YAML scalar")
    return line


def scalar(value: str) -> str:
    result = value.strip()
    if len(result) >= 2 and result[0] == result[-1] and result[0] in {"'", '"'}:
        return result[1:-1]
    return result


def key_value(line: str) -> tuple[int, str, str] | None:
    match = KEY_VALUE_RE.fullmatch(line)
    if match is None:
        return None
    return (
        len(match.group("indent")),
        match.group("key"),
        scalar(match.group("value") or ""),
    )


def parse_workflow(path: Path) -> tuple[str | None, dict[str, Job], str]:
    raw = read_text(path, "workflow")
    if "\t" in raw:
        raise InputError("tabs are unsupported in workflow YAML")
    lines: list[str] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        try:
            lines.append(strip_yaml_comment(raw_line).rstrip())
        except InputError as error:
            raise InputError(f"workflow:{line_number}: {error}") from error

    top_permissions: str | None = None
    for line in lines:
        parsed = key_value(line)
        if parsed is not None and parsed[0] == 0 and parsed[1] == "permissions":
            if top_permissions is not None:
                raise InputError("workflow has duplicate top-level permissions")
            top_permissions = parsed[2]

    jobs_starts = [
        index for index, line in enumerate(lines) if key_value(line) == (0, "jobs", "")
    ]
    if len(jobs_starts) != 1:
        raise InputError("workflow must contain one jobs mapping")
    jobs_start = jobs_starts[0]
    jobs: dict[str, Job] = {}
    starts: list[tuple[int, str]] = []
    for index in range(jobs_start + 1, len(lines)):
        parsed = key_value(lines[index])
        if parsed is not None and parsed[0] == 2 and parsed[2] == "":
            starts.append((index, parsed[1]))
    if not starts:
        raise InputError("workflow jobs mapping is empty or unsupported")
    for position, (start, job_id) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        if job_id in jobs:
            raise InputError(f"workflow has duplicate job {job_id}")
        condition: str | None = None
        environment: str | None = None
        permissions: dict[str, str] | None = None
        for index in range(start + 1, end):
            parsed = key_value(lines[index])
            if parsed is None or parsed[0] != 4:
                continue
            _, key, value = parsed
            if key == "if":
                if condition is not None or not value:
                    raise InputError(f"job {job_id} has malformed if")
                condition = value
            elif key == "environment":
                if environment is not None or not value:
                    raise InputError(f"job {job_id} has unsupported environment syntax")
                environment = value
            elif key == "permissions":
                if permissions is not None or value:
                    raise InputError(f"job {job_id} has unsupported permissions syntax")
                permissions = {}
                for child_index in range(index + 1, end):
                    child = key_value(lines[child_index])
                    indent = len(lines[child_index]) - len(lines[child_index].lstrip(" "))
                    if lines[child_index].strip() and indent <= 4:
                        break
                    if child is not None and child[0] == 6:
                        if child[1] in permissions or child[2] not in {"none", "read", "write"}:
                            raise InputError(f"job {job_id} has invalid permission mapping")
                        permissions[child[1]] = child[2]
        jobs[job_id] = Job(
            job_id=job_id,
            condition=condition,
            environment=environment,
            permissions=permissions,
            raw_text="\n".join(lines[start:end]),
        )
    return top_permissions, jobs, "\n".join(lines)


def claim_findings(policy: dict[str, Any], claims: dict[str, Any]) -> tuple[list[str], list[str]]:
    identity: list[str] = []
    context: list[str] = []
    expected = policy.get("expected_claims")
    if not isinstance(expected, dict) or not expected:
        raise InputError("policy.expected_claims must be a non-empty mapping")
    required_identity = {
        "iss", "aud", "sub", "repository", "repository_id",
        "repository_owner_id", "environment",
    }
    required_context = {
        "ref", "ref_type", "event_name", "workflow_ref", "job_workflow_ref",
        "job_workflow_sha", "runner_environment",
    }
    if not required_identity | required_context <= set(expected):
        raise InputError("policy.expected_claims omits a required trust claim")
    for key, wanted in expected.items():
        if not isinstance(wanted, str) or not wanted:
            raise InputError(f"policy.expected_claims.{key} must be non-empty text")
        target = identity if key in required_identity else context
        if "*" in wanted or "?" in wanted:
            target.append(f"trust policy {key} contains a wildcard")
        if claims.get(key) != wanted:
            target.append(f"{key} claim does not match exact trust policy")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not IMMUTABLE_SUB_RE.fullmatch(subject):
        identity.append("sub claim does not contain immutable owner and repository IDs")
    sha = claims.get("sha")
    workflow_sha = claims.get("workflow_sha")
    job_workflow_sha = claims.get("job_workflow_sha")
    job_workflow_ref = claims.get("job_workflow_ref")
    if not isinstance(sha, str) or not FULL_SHA_RE.fullmatch(sha):
        context.append("sha claim is not an immutable full commit SHA")
    if workflow_sha != sha:
        context.append("workflow_sha is not bound to the source commit SHA")
    if not isinstance(job_workflow_sha, str) or not FULL_SHA_RE.fullmatch(job_workflow_sha):
        context.append("job_workflow_sha is not an immutable full commit SHA")
    if (
        not isinstance(job_workflow_ref, str)
        or not re.search(r"@[0-9a-f]{40}$", job_workflow_ref)
    ):
        context.append("job_workflow_ref uses a mutable or unsupported ref")
    elif job_workflow_ref.rsplit("@", 1)[1] != job_workflow_sha:
        context.append("job_workflow_ref does not match job_workflow_sha")
    if claims.get("head_ref") not in {None, ""} or claims.get("base_ref") not in {None, ""}:
        context.append("pull-request head/base claims are present in deploy token")
    return identity, context


def temporal_findings(
    policy: dict[str, Any], claims: dict[str, Any], replay: dict[str, Any], now: int
) -> list[str]:
    token_policy = policy.get("token")
    if not isinstance(token_policy, dict):
        raise InputError("policy.token must be a mapping")
    iat = int_field(claims, "iat", "claims")
    nbf = int_field(claims, "nbf", "claims")
    exp = int_field(claims, "exp", "claims")
    maximum_lifetime = int_field(token_policy, "max_lifetime_seconds", "policy.token")
    maximum_age = int_field(token_policy, "max_age_seconds", "policy.token")
    skew = int_field(token_policy, "clock_skew_seconds", "policy.token")
    if min(maximum_lifetime, maximum_age) <= 0 or skew < 0:
        raise InputError("policy token time bounds are invalid")
    findings: list[str] = []
    if exp <= iat or exp - iat > maximum_lifetime:
        findings.append("token lifetime exceeds policy")
    if nbf > now + skew:
        findings.append("token is not yet valid")
    if exp < now - skew:
        findings.append("token is expired")
    if iat > now + skew or now - iat > maximum_age:
        findings.append("token issue time is outside the freshness window")
    require_schema(replay, REPLAY_SCHEMA, "replay state")
    if replay.get("status") != "complete":
        raise InputError("replay state collection is not complete")
    used = replay.get("used_jtis")
    if not isinstance(used, list) or not all(isinstance(item, str) for item in used):
        raise InputError("replay state used_jtis must be a string list")
    jti = text_field(claims, "jti", "claims")
    if jti in used:
        findings.append("token jti was already consumed")
    return findings


def workflow_findings(policy: dict[str, Any], workflow_path: Path) -> list[str]:
    contract = policy.get("workflow_contract")
    if not isinstance(contract, dict):
        raise InputError("policy.workflow_contract must be a mapping")
    exchange_job = text_field(contract, "exchange_job", "policy.workflow_contract")
    required_if = text_field(contract, "required_if", "policy.workflow_contract")
    environment = text_field(contract, "environment", "policy.workflow_contract")
    audience = text_field(policy["expected_claims"], "aud", "policy.expected_claims")
    required_permissions = contract.get("permissions")
    if not isinstance(required_permissions, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in required_permissions.items()
    ):
        raise InputError("policy workflow permissions must be a mapping")
    top_permissions, jobs, workflow_text = parse_workflow(workflow_path)
    findings: list[str] = []
    if top_permissions != "{}":
        findings.append("workflow does not deny permissions by default")
    if exchange_job not in jobs:
        raise InputError(f"exchange job is missing: {exchange_job}")
    for job_id, job in jobs.items():
        if job.permissions is None:
            findings.append(f"job {job_id} has implicit permissions")
        if job_id == exchange_job:
            if job.permissions != required_permissions:
                findings.append("exchange job permissions do not exactly match policy")
            if job.condition != required_if:
                findings.append("exchange job trusted-ref condition does not match policy")
            if job.environment != environment:
                findings.append("exchange job is not bound to the protected environment")
            if f'OIDC_AUDIENCE: "{audience}"' not in job.raw_text:
                findings.append("exchange job does not request the exact OIDC audience")
        elif job.permissions and job.permissions.get("id-token") == "write":
            findings.append(f"non-exchange job {job_id} can request an OIDC token")
    if SECRET_REFERENCE_RE.search(workflow_text):
        findings.append("workflow references a repository or environment secret")
    if STATIC_CLOUD_SECRET_RE.search(workflow_text):
        findings.append("workflow contains a static cloud credential name")
    return findings


def secret_findings(inventory: dict[str, Any], now: int) -> list[str]:
    require_schema(inventory, INVENTORY_SCHEMA, "secret inventory")
    if inventory.get("status") != "complete":
        raise InputError("repository secret inventory is not complete")
    collected_at = int_field(inventory, "collected_at", "secret inventory")
    if collected_at > now or now - collected_at > 86400:
        raise InputError("repository secret inventory is stale or future-dated")
    names = inventory.get("secret_names")
    if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
        raise InputError("secret inventory secret_names must be a string list")
    return [
        f"static cloud credential remains in repository secrets: {name}"
        for name in names
        if STATIC_CLOUD_SECRET_RE.search(name)
    ]


def receipt_findings(
    policy: dict[str, Any], claims: dict[str, Any], receipt: dict[str, Any], now: int
) -> list[str]:
    require_schema(receipt, RECEIPT_SCHEMA, "credential receipt")
    exchange = policy.get("credential_contract")
    if not isinstance(exchange, dict):
        raise InputError("policy.credential_contract must be a mapping")
    findings: list[str] = []
    if receipt.get("status") != "issued":
        findings.append("cloud credential exchange did not issue a credential")
    exact_fields = {
        "policy_revision": text_field(policy, "policy_revision", "policy"),
        "source_jti": text_field(claims, "jti", "claims"),
        "audience": text_field(claims, "aud", "claims"),
        "subject": text_field(claims, "sub", "claims"),
        "role": text_field(exchange, "role", "policy.credential_contract"),
        "credential_type": "temporary",
    }
    for field, wanted in exact_fields.items():
        if receipt.get(field) != wanted:
            findings.append(f"credential receipt {field} does not match policy or token")
    expected_actions = string_list(exchange, "allowed_actions", "policy.credential_contract")
    expected_resources = string_list(exchange, "allowed_resources", "policy.credential_contract")
    if any("*" in value or "?" in value for value in expected_actions):
        findings.append("credential action policy contains a wildcard")
    if any("*" in value or "?" in value for value in expected_resources):
        findings.append("credential resource policy contains a wildcard")
    if receipt.get("actions") != expected_actions:
        findings.append("issued credential actions exceed or differ from policy")
    if receipt.get("resources") != expected_resources:
        findings.append("issued credential resources exceed or differ from policy")
    issued_at = int_field(receipt, "issued_at", "credential receipt")
    expires_at = int_field(receipt, "expires_at", "credential receipt")
    max_ttl = int_field(exchange, "max_ttl_seconds", "policy.credential_contract")
    if max_ttl <= 0 or max_ttl > 900:
        findings.append("credential policy lifetime exceeds 15 minutes")
    if issued_at > now or expires_at <= now or expires_at - issued_at > max_ttl:
        findings.append("issued credential is not current and short lived")
    prohibited_material = {
        "access_key", "secret_key", "session_token", "token", "private_key", "password"
    }
    if prohibited_material & set(receipt):
        findings.append("credential receipt exposes credential material")
    return findings


def line(check_id: str, summary: str, findings: list[str]) -> str:
    if findings:
        return f"FAIL PSB-CICD-006/{check_id} {summary}: {'; '.join(findings)}"
    return f"PASS PSB-CICD-006/{check_id} {summary}"


def verify(args: argparse.Namespace) -> list[str]:
    policy = load_json(args.policy, "policy")
    require_schema(policy, POLICY_SCHEMA, "policy")
    token_policy = policy.get("token")
    if not isinstance(token_policy, dict):
        raise InputError("policy.token must be a mapping")
    token = read_text(args.token, "OIDC token").strip()
    segments = token.split(".")
    if len(segments) != 3:
        raise InputError("OIDC token must be a compact three-segment JWT")
    header = decode_object(segments[0], "header")
    claims = decode_object(segments[1], "claims")
    signature = decode_segment(segments[2], "signature")
    envelope: list[str] = []
    if header.get("typ") != "JWT":
        envelope.append("JWT typ is not JWT")
    if header.get("alg") != "RS256" or token_policy.get("algorithm") != "RS256":
        envelope.append("JWT algorithm is not policy-approved RS256")
    if header.get("kid") != token_policy.get("key_id"):
        envelope.append("JWT key ID does not match policy")
    public_key = resolve_public_key(
        args.policy, text_field(token_policy, "trusted_public_key", "policy.token")
    )
    if not verify_signature(
        f"{segments[0]}.{segments[1]}".encode("ascii"),
        signature,
        public_key,
        args.openssl,
    ):
        envelope.append("JWT signature verification failed")
    identity, context = claim_findings(policy, claims)
    replay = load_json(args.replay_state, "replay state")
    temporal = temporal_findings(policy, claims, replay, args.now)
    workflow = workflow_findings(policy, args.workflow)
    inventory = load_json(args.secret_inventory, "secret inventory")
    secrets = secret_findings(inventory, args.now)
    receipt = load_json(args.receipt, "credential receipt")
    credential = receipt_findings(policy, claims, receipt, args.now)
    return [
        line("OIDC-001", "signed JWT envelope is authentic", envelope),
        line("OIDC-002", "issuer audience subject and immutable repository identity are exact", identity),
        line("OIDC-003", "trusted deploy context and reusable workflow identity are exact", context),
        line("OIDC-004", "token is current short lived and unused", temporal),
        line("OIDC-005", "OIDC issuance is isolated to the protected exchange job", workflow),
        line("OIDC-006", "stored cloud credentials are absent", secrets),
        line("OIDC-007", "downstream credential is bounded and exchange succeeded", credential),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--token", type=Path, required=True)
    parser.add_argument("--secret-inventory", type=Path, required=True)
    parser.add_argument("--replay-state", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--now", type=int, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    args = parser.parse_args()
    try:
        results = verify(args)
    except InputError as error:
        print(f"ERROR PSB-CICD-006 OIDC federation could not be evaluated: {error}")
        return 2
    for result in results:
        print(result)
    return 1 if any(result.startswith("FAIL ") for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
