#!/usr/bin/env python3
"""Verify normalized CI runner fleet evidence without contacting a provider."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


CHECKS = {
    "RNR-001": "trust-class routing and exact runner scope",
    "RNR-002": "self-hosted JIT one-job lifecycle",
    "RNR-003": "immutable verified runner image",
    "RNR-004": "clean runner startup without prior or host state",
    "RNR-005": "metadata host-socket and management-network isolation",
    "RNR-006": "bounded registration and management authority",
    "RNR-007": "self-hosted deregistration and destruction",
    "RNR-008": "external logs correlated before teardown",
    "RNR-009": "complete fresh fail-closed evidence",
}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
POLICY_RE = re.compile(r"^[a-z0-9-]+@sha256:[0-9a-f]{64}$")
REQUIRED_SOURCES = {
    "dispatch-audit",
    "image-pipeline",
    "network-probe",
    "runner-provisioner",
    "runner-teardown",
    "security-log-export",
}
FORBIDDEN_KEYS = {
    "access_key",
    "access_token",
    "client_secret",
    "credential",
    "credential_value",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}


class InputError(ValueError):
    """Evidence is unavailable or unsafe to evaluate."""


def reject_secret_fields(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise InputError(f"{label} contains a non-text key")
            if key.lower() in FORBIDDEN_KEYS:
                raise InputError(f"{label} contains forbidden credential field {key}")
            reject_secret_fields(child, label)
    elif isinstance(value, list):
        for child in value:
            reject_secret_fields(child, label)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise InputError(f"cannot read {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise InputError(f"invalid {label} JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    reject_secret_fields(value, label)
    return value


def expect_schema(value: dict[str, Any], expected: str, label: str) -> None:
    if value.get("schema") != expected:
        raise InputError(f"unsupported {label} schema")


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{label} must be non-empty text")
    return value


def boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise InputError(f"{label} must be boolean")
    return value


def integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InputError(f"{label} must be an integer")
    return value


def objects(value: Any, label: str, *, non_empty: bool = True) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (non_empty and not value):
        raise InputError(f"{label} must be a non-empty array")
    if not all(isinstance(item, dict) for item in value):
        raise InputError(f"{label} must contain objects")
    return value


def strings(value: Any, label: str, *, non_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        raise InputError(f"{label} must be a non-empty string array")
    if not all(isinstance(item, str) and item for item in value):
        raise InputError(f"{label} must contain non-empty strings")
    if len(value) != len(set(value)):
        raise InputError(f"{label} must not contain duplicates")
    return value


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def instant(value: Any, label: str) -> datetime:
    raw = text(value, label)
    if not raw.endswith("Z"):
        raise InputError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        return datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} must be an RFC3339 UTC timestamp") from error


def require_fresh(value: dict[str, Any], label: str, now: datetime, maximum: int) -> None:
    collected = instant(value.get("collected_at"), f"{label}.collected_at")
    if collected > now:
        raise InputError(f"{label} is from the future")
    if now - collected > timedelta(seconds=maximum):
        raise InputError(f"{label} is stale")


def add(issues: list[tuple[str, str]], check: str, message: str) -> None:
    issues.append((check, message))


def validate(
    policy: dict[str, Any],
    fleet: dict[str, Any],
    images: dict[str, Any],
    teardown: dict[str, Any],
    health: dict[str, Any],
    now: datetime,
) -> list[tuple[str, str]]:
    expect_schema(policy, "psb-ci-runner-policy/v1", "policy")
    expect_schema(fleet, "psb-ci-runner-fleet/v1", "fleet snapshot")
    expect_schema(images, "psb-ci-runner-images/v1", "image evidence")
    expect_schema(teardown, "psb-ci-runner-teardown/v1", "teardown receipts")
    expect_schema(health, "psb-ci-runner-evidence-health/v1", "evidence health")

    maximum_age = integer(policy.get("maximum_evidence_age_seconds"), "maximum evidence age")
    if maximum_age <= 0:
        raise InputError("maximum evidence age must be positive")
    for value, label in (
        (fleet, "fleet snapshot"),
        (images, "image evidence"),
        (teardown, "teardown receipts"),
        (health, "evidence health"),
    ):
        require_fresh(value, label, now, maximum_age)

    if not boolean(health.get("collector_available"), "collector_available"):
        raise InputError("runner evidence collector is unavailable")
    if not boolean(health.get("collection_complete"), "collection_complete"):
        raise InputError("runner evidence collection is incomplete")
    sources = set(strings(health.get("sources"), "evidence sources"))
    if not REQUIRED_SOURCES <= sources:
        raise InputError("runner evidence sources are incomplete")

    issues: list[tuple[str, str]] = []
    if POLICY_RE.fullmatch(str(policy.get("policy_version", ""))) is None:
        add(issues, "RNR-009", "policy version is not digest-pinned")
    if maximum_age > 900:
        add(issues, "RNR-009", "maximum evidence age exceeds 900 seconds")

    registration_max = integer(
        policy.get("maximum_registration_token_seconds"),
        "maximum registration token seconds",
    )
    teardown_max = integer(policy.get("maximum_teardown_seconds"), "maximum teardown seconds")
    if not 1 <= registration_max <= 300:
        add(issues, "RNR-006", "registration authority is not bounded to 300 seconds")
    if not 1 <= teardown_max <= 600:
        add(issues, "RNR-007", "teardown deadline exceeds 600 seconds")

    profiles: dict[str, dict[str, Any]] = {}
    for profile in objects(policy.get("profiles"), "profiles"):
        profile_id = text(profile.get("id"), "profile id")
        if profile_id in profiles:
            raise InputError("profile ids must be unique")
        profiles[profile_id] = profile
        provider_type = text(profile.get("provider_type"), f"profile {profile_id} provider type")
        trust_classes = strings(
            profile.get("accepted_trust_classes"), f"profile {profile_id} trust classes"
        )
        labels = strings(profile.get("runner_labels"), f"profile {profile_id} labels")
        if "*" in trust_classes or "*" in labels:
            add(issues, "RNR-001", f"profile {profile_id} uses wildcard routing")
        self_hosted = boolean(profile.get("self_hosted"), f"profile {profile_id} self_hosted")
        assurance = text(
            profile.get("lifecycle_assurance_source"),
            f"profile {profile_id} lifecycle assurance",
        )
        if self_hosted:
            if "untrusted" in trust_classes:
                add(issues, "RNR-001", f"self-hosted profile {profile_id} accepts untrusted jobs")
            for field in ("runner_group",):
                if profile.get(field) in (None, "", "*"):
                    add(issues, "RNR-001", f"profile {profile_id} lacks an exact {field}")
            for field in ("allowed_repositories", "allowed_workflows", "allowed_events"):
                values = strings(profile.get(field), f"profile {profile_id} {field}")
                if "*" in values:
                    add(issues, "RNR-001", f"profile {profile_id} has wildcard {field}")
            if provider_type != "self-hosted-jit" or assurance != "organization-provisioner":
                add(issues, "RNR-002", f"profile {profile_id} is not provisioner-attested JIT")
            if not boolean(profile.get("ephemeral"), f"profile {profile_id} ephemeral"):
                add(issues, "RNR-002", f"profile {profile_id} is persistent")
            if not boolean(profile.get("jit"), f"profile {profile_id} jit"):
                add(issues, "RNR-002", f"profile {profile_id} is not just-in-time")
            if integer(profile.get("maximum_jobs"), f"profile {profile_id} maximum_jobs") != 1:
                add(issues, "RNR-002", f"profile {profile_id} can process more than one job")
            if boolean(profile.get("reuse_underlying_host"), f"profile {profile_id} reuse host"):
                add(issues, "RNR-002", f"profile {profile_id} reuses its underlying host")
            if profile.get("image_update_mode") != "replace-image":
                add(issues, "RNR-003", f"profile {profile_id} mutates images in place")
        else:
            if provider_type != "managed-hosted" or assurance != "provider-contract":
                add(issues, "RNR-002", f"hosted profile {profile_id} lacks provider lifecycle evidence")
        if boolean(profile.get("internal_network_access"), f"profile {profile_id} internal access"):
            add(issues, "RNR-005", f"profile {profile_id} can reach an internal network")

    network = mapping(policy.get("network_boundary"), "network boundary")
    origins = strings(network.get("allowed_control_plane_origins"), "control plane origins")
    if network.get("default_egress") != "deny" or "*" in origins:
        add(issues, "RNR-005", "runner network is not exact default-deny")
    for field, message in (
        ("cloud_metadata_ipv4_blocked", "IPv4 cloud metadata is not blocked"),
        ("cloud_metadata_ipv6_blocked", "IPv6 cloud metadata is not blocked"),
        ("management_network_blocked", "management network is not blocked"),
        ("host_runtime_sockets_absent", "host runtime socket is exposed"),
    ):
        if not boolean(network.get(field), field):
            add(issues, "RNR-005", message)

    management = mapping(policy.get("management"), "management policy")
    if management.get("interactive_ingress") != "deny":
        add(issues, "RNR-006", "ordinary interactive management ingress is allowed")
    if not boolean(management.get("break_glass_separate"), "break_glass_separate"):
        add(issues, "RNR-006", "break-glass authority is not separate")
    if not boolean(management.get("registration_token_one_use"), "registration_token_one_use"):
        add(issues, "RNR-006", "runner registration authority is reusable")
    if boolean(management.get("registration_token_retained"), "registration_token_retained"):
        add(issues, "RNR-006", "runner registration authority is retained")

    teardown_policy = mapping(policy.get("teardown"), "teardown policy")
    for field in (
        "deregister",
        "destroy_compute",
        "discard_workspace",
        "destroy_ephemeral_storage_key",
        "terminate_job_processes",
    ):
        if not boolean(teardown_policy.get(field), field):
            add(issues, "RNR-007", f"teardown does not require {field}")
    if not boolean(teardown_policy.get("export_logs_before_destroy"), "export logs"):
        add(issues, "RNR-008", "logs are not exported before runner destruction")

    image_by_profile: dict[str, dict[str, Any]] = {}
    for image in objects(images.get("images"), "images"):
        profile_id = text(image.get("profile_id"), "image profile id")
        if profile_id in image_by_profile:
            raise InputError("image profile ids must be unique")
        image_by_profile[profile_id] = image
    for profile_id, profile in profiles.items():
        image = image_by_profile.get(profile_id)
        if image is None:
            raise InputError(f"image evidence is missing for profile {profile_id}")
        text(image.get("image_reference"), f"profile {profile_id} image reference")
        digest = image.get("image_digest")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            add(issues, "RNR-003", f"profile {profile_id} image lacks an exact digest")
        if not boolean(image.get("provenance_verified"), f"profile {profile_id} provenance"):
            add(issues, "RNR-003", f"profile {profile_id} image provenance is unverified")
        if not boolean(image.get("runner_version_supported"), f"profile {profile_id} version support"):
            add(issues, "RNR-003", f"profile {profile_id} runner version is unsupported")
        if boolean(image.get("mutable_tag_only"), f"profile {profile_id} mutable tag"):
            add(issues, "RNR-003", f"profile {profile_id} relies on a mutable image tag")
        if profile.get("self_hosted") and boolean(
            image.get("in_place_auto_update"), f"profile {profile_id} in-place update"
        ):
            add(issues, "RNR-003", f"profile {profile_id} updates the runner in place")

    dispatches = objects(fleet.get("dispatches"), "dispatches")
    dispatch_by_job: dict[str, dict[str, Any]] = {}
    for dispatch in dispatches:
        job_id = text(dispatch.get("job_id"), "job id")
        if job_id in dispatch_by_job:
            raise InputError("job ids must be unique")
        dispatch_by_job[job_id] = dispatch
        profile_id = text(dispatch.get("profile_id"), f"job {job_id} profile id")
        if profile_id not in profiles:
            raise InputError(f"job {job_id} references unknown profile {profile_id}")
        profile = profiles[profile_id]
        trust = text(dispatch.get("trust_class"), f"job {job_id} trust class")
        accepted = strings(profile.get("accepted_trust_classes"), f"profile {profile_id} trust")
        if trust not in accepted:
            add(issues, "RNR-001", f"job {job_id} trust class is not accepted by its profile")
        if trust == "untrusted" and profile.get("self_hosted"):
            add(issues, "RNR-001", f"untrusted job {job_id} ran on self-hosted infrastructure")
        if sorted(strings(dispatch.get("runner_labels"), f"job {job_id} labels")) != sorted(
            strings(profile.get("runner_labels"), f"profile {profile_id} labels")
        ):
            add(issues, "RNR-001", f"job {job_id} runner labels differ from policy")
        if profile.get("self_hosted"):
            if dispatch.get("runner_group") != profile.get("runner_group"):
                add(issues, "RNR-001", f"job {job_id} runner group differs from policy")
            for observed, policy_field in (
                (text(dispatch.get("repository"), f"job {job_id} repository"), "allowed_repositories"),
                (text(dispatch.get("workflow"), f"job {job_id} workflow"), "allowed_workflows"),
                (text(dispatch.get("event"), f"job {job_id} event"), "allowed_events"),
            ):
                if observed not in strings(profile.get(policy_field), f"profile {profile_id} {policy_field}"):
                    add(issues, "RNR-001", f"job {job_id} is outside exact {policy_field}")
        if dispatch.get("previous_job_id") is not None:
            add(issues, "RNR-004", f"job {job_id} runner contains a previous job identity")
        if not boolean(dispatch.get("clean_workspace"), f"job {job_id} clean workspace"):
            add(issues, "RNR-004", f"job {job_id} started with a non-clean workspace")
        for field, message in (
            ("foreign_processes", "foreign processes"),
            ("host_credentials_present", "host credentials"),
            ("cloud_credentials_present", "cloud credentials"),
            ("ssh_keys_present", "SSH keys"),
        ):
            if boolean(dispatch.get(field), f"job {job_id} {field}"):
                add(issues, "RNR-004", f"job {job_id} can observe {message}")
        for field, message in (
            ("metadata_ipv4_reachable", "IPv4 metadata"),
            ("metadata_ipv6_reachable", "IPv6 metadata"),
            ("management_network_reachable", "management network"),
            ("host_runtime_socket_present", "host runtime socket"),
        ):
            if boolean(dispatch.get(field), f"job {job_id} {field}"):
                add(issues, "RNR-005", f"job {job_id} can reach {message}")
        if profile.get("self_hosted"):
            ttl = integer(dispatch.get("registration_token_ttl_seconds"), f"job {job_id} registration TTL")
            if ttl > registration_max or ttl <= 0:
                add(issues, "RNR-006", f"job {job_id} registration authority exceeds policy")
            if boolean(dispatch.get("registration_token_retained"), f"job {job_id} retained registration"):
                add(issues, "RNR-006", f"job {job_id} retained runner registration authority")

    receipts: dict[str, dict[str, Any]] = {}
    for receipt in objects(teardown.get("receipts"), "receipts", non_empty=False):
        job_id = text(receipt.get("job_id"), "receipt job id")
        if job_id in receipts:
            raise InputError("teardown receipt job ids must be unique")
        receipts[job_id] = receipt
    for job_id, dispatch in dispatch_by_job.items():
        profile = profiles[dispatch["profile_id"]]
        if not profile.get("self_hosted"):
            continue
        receipt = receipts.get(job_id)
        if receipt is None:
            add(issues, "RNR-007", f"self-hosted job {job_id} lacks a teardown receipt")
            continue
        if receipt.get("runner_generation") != dispatch.get("runner_generation"):
            add(issues, "RNR-007", f"job {job_id} teardown generation does not match dispatch")
        if integer(receipt.get("jobs_processed"), f"job {job_id} jobs processed") != 1:
            add(issues, "RNR-002", f"runner for {job_id} processed more than one job")
        if boolean(receipt.get("second_job_observed"), f"job {job_id} second job"):
            add(issues, "RNR-002", f"runner for {job_id} accepted a second job")
        finished = instant(receipt.get("job_finished_at"), f"job {job_id} finished")
        destroyed = instant(receipt.get("destroyed_at"), f"job {job_id} destroyed")
        if destroyed < finished or destroyed - finished > timedelta(seconds=teardown_max):
            add(issues, "RNR-007", f"job {job_id} runner was not destroyed within policy")
        for field, message in (
            ("deregistered", "deregistered"),
            ("compute_destroyed", "compute destroyed"),
            ("workspace_discarded", "workspace discarded"),
            ("ephemeral_storage_key_destroyed", "ephemeral storage key destroyed"),
        ):
            if not boolean(receipt.get(field), f"job {job_id} {field}"):
                add(issues, "RNR-007", f"job {job_id} was not {message}")
        if boolean(receipt.get("job_processes_remaining"), f"job {job_id} remaining processes"):
            add(issues, "RNR-007", f"job {job_id} left processes after teardown")
        if not boolean(receipt.get("logs_exported"), f"job {job_id} logs exported"):
            add(issues, "RNR-008", f"job {job_id} logs were not exported")
        expected_correlation = f"{job_id}/{dispatch.get('runner_generation')}"
        if receipt.get("log_correlation") != expected_correlation:
            add(issues, "RNR-008", f"job {job_id} log correlation is incomplete")

    return sorted(set(issues), key=lambda item: (item[0], item[1]))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--fleet-snapshot", type=Path, required=True)
    parser.add_argument("--image-evidence", type=Path, required=True)
    parser.add_argument("--teardown-receipts", type=Path, required=True)
    parser.add_argument("--evidence-health", type=Path, required=True)
    parser.add_argument("--evaluation-time", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        now = instant(args.evaluation_time, "evaluation time")
        issues = validate(
            load_json(args.policy, "policy"),
            load_json(args.fleet_snapshot, "fleet snapshot"),
            load_json(args.image_evidence, "image evidence"),
            load_json(args.teardown_receipts, "teardown receipts"),
            load_json(args.evidence_health, "evidence health"),
            now,
        )
    except InputError as error:
        print(f"ERROR PSB-CICD-007 runner evaluation unavailable: {error}")
        return 2

    if issues:
        for check, message in issues:
            print(f"FAIL {check} {message}")
        print(f"REJECT PSB-CICD-007 {len(issues)} runner hardening finding(s)")
        return 1

    for check, title in CHECKS.items():
        print(f"PASS {check} {title}")
    print("ACCEPT PSB-CICD-007 runner fleet evidence satisfies the reference policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
