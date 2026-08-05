#!/usr/bin/env python3
"""Verify normalized Linux container host and daemon evidence offline."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


CHECK_ORDER = {f"HST-{number:03d}": number for number in range(1, 10)}
POLICY_VERSION_RE = re.compile(r"^[a-z0-9-]+@sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MODE_RE = re.compile(r"^0[0-7]{3}$")
COMPONENT_TYPES = {"host-os", "kernel", "runtime", "daemon"}
PATH_TYPES = {"file", "directory", "socket"}
REQUIRED_PROHIBITED_WORKLOADS = {
    "database",
    "developer-tools",
    "general-purpose",
    "office",
    "web-browsing",
}
REQUIRED_AUDIT_EVENTS = {
    "daemon-config-write",
    "operator-session",
    "runtime-binary-write",
    "runtime-socket-access",
    "service-unit-write",
}
REQUIRED_COMPENSATING_CONTROLS = {
    "dedicated-host",
    "enforcing-lsm",
    "management-network-restricted",
    "seccomp-default",
}
REQUIRED_SOURCES = {
    "access-audit",
    "daemon-config",
    "file-integrity",
    "hardware-attestation",
    "host-inventory",
    "patch-service",
    "platform-inventory",
}
ALLOWED_ROLE_ACTIONS = {"configure", "read", "read-audit", "restart"}
FORBIDDEN_KEYS = {
    "access_key",
    "access_token",
    "client_secret",
    "credential_value",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}


class InputError(ValueError):
    """Evidence cannot be evaluated safely."""


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


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def objects(value: Any, label: str, *, non_empty: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise InputError(f"{label} must be a {qualifier}array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise InputError(f"{label}[{index}] must be an object")
        result.append(item)
    return result


def strings(value: Any, label: str, *, non_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise InputError(f"{label} must be a {qualifier}array")
    if not all(isinstance(item, str) and item for item in value):
        raise InputError(f"{label} must contain non-empty strings")
    if len(set(value)) != len(value):
        raise InputError(f"{label} must not contain duplicates")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{label} must be non-empty text")
    return value


def integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InputError(f"{label} must be an integer")
    return value


def instant(value: Any, label: str) -> datetime:
    raw = text(value, label)
    if not raw.endswith("Z"):
        raise InputError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} must be an RFC3339 UTC timestamp") from error
    return parsed


def schema(value: dict[str, Any], expected: str, label: str) -> None:
    if value.get("schema") != expected:
        raise InputError(f"unsupported {label} schema")


def add(issues: list[tuple[str, str]], check_id: str, message: str) -> None:
    issues.append((check_id, message))


def fresh(
    value: datetime,
    evaluation_time: datetime,
    maximum_age_seconds: int,
    label: str,
) -> None:
    if value > evaluation_time:
        raise InputError(f"{label} is in the future")
    if evaluation_time - value > timedelta(seconds=maximum_age_seconds):
        raise InputError(f"{label} is stale")


def network(value: str, label: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise InputError(f"{label} must be an exact CIDR") from error


def address(value: str, label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError as error:
        raise InputError(f"{label} must be an IP address") from error


def mode(value: Any, label: str) -> int:
    raw = text(value, label)
    if MODE_RE.fullmatch(raw) is None:
        raise InputError(f"{label} must be a four-digit octal mode")
    return int(raw, 8)


def validate_roles(value: Any, label: str) -> list[dict[str, Any]]:
    roles = objects(value, label, non_empty=True)
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for role in roles:
        role_id = text(role.get("id"), f"{label} role id")
        if role_id in seen:
            raise InputError(f"{label} role ids must be unique")
        seen.add(role_id)
        subjects = strings(role.get("subjects"), f"role {role_id} subjects", non_empty=True)
        node_pools = strings(
            role.get("node_pools"), f"role {role_id} node pools", non_empty=True
        )
        actions = strings(role.get("actions"), f"role {role_id} actions", non_empty=True)
        normalized.append(
            {
                "id": role_id,
                "subjects": sorted(subjects),
                "node_pools": sorted(node_pools),
                "actions": sorted(actions),
            }
        )
    return sorted(normalized, key=lambda item: item["id"])


def validate_policy(policy: dict[str, Any]) -> list[tuple[str, str]]:
    schema(policy, "psb-container-host-policy/v1", "policy")
    issues: list[tuple[str, str]] = []
    version = policy.get("policy_version")
    if not isinstance(version, str) or POLICY_VERSION_RE.fullmatch(version) is None:
        add(issues, "HST-009", "policy version is not immutable and digest-pinned")

    scope = mapping(policy.get("scope"), "policy.scope")
    if scope.get("required_purpose") != "production-container-host":
        add(issues, "HST-001", "policy does not require a dedicated production host")
    allowed_workloads = set(
        strings(scope.get("allowed_workload_classes"), "allowed workload classes")
    )
    prohibited = set(
        strings(scope.get("prohibited_workload_classes"), "prohibited workload classes")
    )
    allowed_services = set(
        strings(scope.get("allowed_enabled_services"), "allowed enabled services")
    )
    if not allowed_workloads or "*" in allowed_workloads:
        add(issues, "HST-001", "allowed workload classes must be exact and non-empty")
    if not REQUIRED_PROHIBITED_WORKLOADS <= prohibited:
        add(issues, "HST-001", "prohibited mixed workload classes are incomplete")
    if not allowed_services or "*" in allowed_services:
        add(issues, "HST-001", "enabled service allowlist must be exact and non-empty")

    components = mapping(policy.get("components"), "policy.components")
    patch_days = integer(components.get("maximum_patch_age_days"), "maximum patch age")
    if not 1 <= patch_days <= 30:
        add(issues, "HST-002", "maximum patch age must be between 1 and 30 days")
    required_components = objects(
        components.get("required"), "required components", non_empty=True
    )
    component_types: set[str] = set()
    for component in required_components:
        component_type = text(component.get("type"), "component type")
        if component_type in component_types:
            raise InputError("required component types must be unique")
        component_types.add(component_type)
        text(component.get("name"), f"{component_type} component name")
        text(component.get("version"), f"{component_type} component version")
    if component_types != COMPONENT_TYPES:
        add(issues, "HST-002", "required host component baseline is incomplete")

    management = mapping(policy.get("management"), "policy.management")
    schemes = set(
        strings(management.get("allowed_endpoint_schemes"), "allowed endpoint schemes")
    )
    if schemes != {"unix"}:
        add(issues, "HST-003", "daemon management must use reviewed local Unix sockets")
    socket_paths = strings(
        management.get("allowed_socket_paths"), "allowed socket paths", non_empty=True
    )
    if "*" in socket_paths or any(not item.startswith("/") for item in socket_paths):
        add(issues, "HST-003", "daemon socket paths must be exact absolute paths")
    if management.get("required_authentication") != "peer-credentials":
        add(issues, "HST-003", "daemon management authentication is not peer credentials")
    if management.get("public_endpoints_allowed") is not False:
        add(issues, "HST-003", "public daemon management endpoints are allowed")
    if management.get("workload_runtime_socket_mounts_allowed") is not False:
        add(issues, "HST-003", "workload runtime socket mounts are allowed")
    cidrs = strings(
        management.get("allowed_management_cidrs"), "allowed management CIDRs", non_empty=True
    )
    for index, item in enumerate(cidrs):
        parsed = network(item, f"management CIDR {index}")
        if not parsed.is_private or parsed.prefixlen == 0:
            add(issues, "HST-007", "management network must be private and bounded")

    isolation = mapping(policy.get("isolation"), "policy.isolation")
    if isolation.get("require_rootless_or_user_namespace") is not True:
        add(issues, "HST-004", "rootless or user namespace isolation is not required")
    lockdown = set(
        strings(isolation.get("allowed_kernel_lockdown"), "allowed kernel lockdown")
    )
    if not lockdown or not lockdown <= {"integrity", "confidentiality"}:
        add(issues, "HST-004", "kernel lockdown policy permits a disabled state")
    if isolation.get("required_seccomp_profile") != "default":
        add(issues, "HST-006", "default seccomp is not required")
    lsms = set(strings(isolation.get("allowed_enforcing_lsm"), "allowed enforcing LSM"))
    if not lsms or not lsms <= {"apparmor", "selinux"}:
        add(issues, "HST-006", "enforcing LSM policy is missing or unsupported")
    if isolation.get("require_restricted_kernel_modules") is not True:
        add(issues, "HST-006", "restricted kernel module loading is not required")

    protected_paths = objects(
        policy.get("protected_paths"), "policy protected paths", non_empty=True
    )
    seen_paths: set[str] = set()
    path_types: set[str] = set()
    for item in protected_paths:
        path = text(item.get("path"), "protected path")
        if not path.startswith("/") or path in seen_paths:
            raise InputError("protected paths must be unique absolute paths")
        seen_paths.add(path)
        path_type = text(item.get("type"), f"protected path {path} type")
        if path_type not in PATH_TYPES:
            raise InputError(f"protected path {path} type is unsupported")
        path_types.add(path_type)
        text(item.get("owner"), f"protected path {path} owner")
        text(item.get("group"), f"protected path {path} group")
        maximum_mode = mode(item.get("maximum_mode"), f"protected path {path} mode")
        if maximum_mode & 0o002:
            add(issues, "HST-005", f"protected path {path} permits world write")
        if path_type == "file":
            digest = item.get("sha256")
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                add(issues, "HST-005", f"protected file {path} lacks an exact digest")
    if path_types != PATH_TYPES or len(protected_paths) < 5:
        add(issues, "HST-005", "protected path manifest is incomplete")

    access_policy = mapping(policy.get("access"), "policy.access")
    roles = validate_roles(access_policy.get("roles"), "policy access roles")
    for role in roles:
        if (
            "*" in role["subjects"]
            or "*" in role["node_pools"]
            or "*" in role["actions"]
            or not set(role["actions"]) <= ALLOWED_ROLE_ACTIONS
        ):
            add(issues, "HST-007", f"role {role['id']} contains wildcard or unsupported authority")
    required_events = set(
        strings(access_policy.get("required_audit_events"), "required audit events")
    )
    if not REQUIRED_AUDIT_EVENTS <= required_events:
        add(issues, "HST-007", "required host audit event coverage is incomplete")
    if access_policy.get("audit_rules_immutable") is not True:
        add(issues, "HST-007", "audit rules are not required to be immutable")

    hardware = mapping(policy.get("hardware_trust"), "policy.hardware_trust")
    for field, message in (
        ("require_secure_boot", "secure boot is not required"),
        ("require_measured_boot", "measured boot is not required"),
        ("require_tpm_backed_identity", "TPM-backed identity is not required"),
    ):
        if hardware.get(field) is not True:
            add(issues, "HST-008", message)
    if hardware.get("required_node_pool") in {None, "*"}:
        add(issues, "HST-008", "hardware trust node pool must be exact")
    attestation_age = integer(
        hardware.get("maximum_attestation_age_seconds"), "attestation maximum age"
    )
    if not 1 <= attestation_age <= 3600:
        add(issues, "HST-008", "attestation age must be between 1 and 3600 seconds")

    exception_policy = mapping(policy.get("exceptions"), "policy.exceptions")
    lifetime = integer(exception_policy.get("maximum_lifetime_days"), "exception lifetime")
    if not 1 <= lifetime <= 30:
        add(issues, "HST-004", "exception lifetime must be between 1 and 30 days")
    compensating = set(
        strings(
            exception_policy.get("required_compensating_controls"),
            "required compensating controls",
        )
    )
    if not REQUIRED_COMPENSATING_CONTROLS <= compensating:
        add(issues, "HST-004", "required exception compensating controls are incomplete")

    evidence = mapping(policy.get("evidence"), "policy.evidence")
    evidence_age = integer(evidence.get("maximum_age_seconds"), "evidence maximum age")
    if not 1 <= evidence_age <= 3600:
        add(issues, "HST-009", "evidence age must be between 1 and 3600 seconds")
    sources = set(strings(evidence.get("required_sources"), "required evidence sources"))
    if not REQUIRED_SOURCES <= sources:
        add(issues, "HST-009", "required evidence source inventory is incomplete")
    return issues


def validate_health(
    policy: dict[str, Any],
    health: dict[str, Any],
    evaluation_time: datetime,
    required_sources: set[str],
) -> int:
    schema(health, "psb-container-host-evidence-health/v1", "evidence health")
    configured = integer(
        mapping(policy.get("evidence"), "policy.evidence").get("maximum_age_seconds"),
        "evidence maximum age",
    )
    maximum_age = min(max(configured, 1), 3600)
    fresh(
        instant(health.get("observed_at"), "health observed_at"),
        evaluation_time,
        maximum_age,
        "evidence health manifest",
    )
    names: set[str] = set()
    for source in objects(health.get("sources"), "evidence health sources", non_empty=True):
        name = text(source.get("name"), "evidence source name")
        if name in names:
            raise InputError("evidence source names must be unique")
        names.add(name)
        if source.get("status") != "ok":
            raise InputError(f"required evidence source {name} is unavailable")
        if source.get("complete") is not True:
            raise InputError(f"required evidence source {name} is incomplete")
        fresh(
            instant(source.get("last_success_at"), f"source {name} last success"),
            evaluation_time,
            maximum_age,
            f"required evidence source {name}",
        )
    if not required_sources <= names:
        raise InputError("required evidence source health inventory is incomplete")
    return maximum_age


def check_scope(policy: dict[str, Any], evidence: dict[str, Any]) -> list[tuple[str, str]]:
    expected = mapping(policy.get("scope"), "policy.scope")
    actual = mapping(evidence.get("scope"), "host scope")
    issues: list[tuple[str, str]] = []
    if actual.get("purpose") != expected.get("required_purpose"):
        add(issues, "HST-001", "host purpose is not the dedicated production role")
    workload_classes = set(strings(actual.get("workload_classes"), "workload classes"))
    allowed = set(strings(expected.get("allowed_workload_classes"), "allowed workloads"))
    prohibited = set(
        strings(expected.get("prohibited_workload_classes"), "prohibited workloads")
    )
    if not workload_classes or not workload_classes <= allowed:
        add(issues, "HST-001", "host contains an unreviewed or mixed workload class")
    if workload_classes & prohibited:
        add(issues, "HST-001", "host contains an explicitly prohibited workload class")
    enabled = set(strings(actual.get("enabled_services"), "enabled services"))
    allowed_services = set(
        strings(expected.get("allowed_enabled_services"), "allowed services")
    )
    if not enabled <= allowed_services:
        add(issues, "HST-001", "host runs an enabled service outside the allowlist")
    return issues


def check_components(
    policy: dict[str, Any], evidence: dict[str, Any], evaluation_time: datetime
) -> list[tuple[str, str]]:
    component_policy = mapping(policy.get("components"), "policy.components")
    expected = {
        text(item.get("type"), "required component type"): item
        for item in objects(component_policy.get("required"), "required components")
    }
    actual: dict[str, dict[str, Any]] = {}
    for item in objects(evidence.get("components"), "host components", non_empty=True):
        item_type = text(item.get("type"), "observed component type")
        if item_type in actual:
            raise InputError("observed component types must be unique")
        actual[item_type] = item
    issues: list[tuple[str, str]] = []
    if set(actual) != set(expected):
        add(issues, "HST-002", "host component inventory is incomplete or unexpected")
    patch_days = integer(component_policy.get("maximum_patch_age_days"), "patch age")
    for component_type, required in expected.items():
        observed = actual.get(component_type)
        if observed is None:
            continue
        if (
            observed.get("name") != required.get("name")
            or observed.get("version") != required.get("version")
        ):
            add(issues, "HST-002", f"{component_type} does not match approved baseline")
        if observed.get("support_status") != "supported":
            add(issues, "HST-002", f"{component_type} is not supported")
        if observed.get("security_updates_current") is not True:
            add(issues, "HST-002", f"{component_type} security updates are not current")
        patched_at = instant(
            observed.get("last_security_patch_at"),
            f"{component_type} last security patch",
        )
        if evaluation_time - patched_at > timedelta(days=patch_days):
            add(issues, "HST-002", f"{component_type} patch evidence exceeded policy age")
    return issues


def check_management(
    policy: dict[str, Any], evidence: dict[str, Any]
) -> tuple[list[tuple[str, str]], list[str]]:
    expected = mapping(policy.get("management"), "policy.management")
    actual = mapping(evidence.get("management"), "host management")
    issues: list[tuple[str, str]] = []
    schemes = set(strings(expected.get("allowed_endpoint_schemes"), "allowed schemes"))
    paths = set(strings(expected.get("allowed_socket_paths"), "allowed sockets"))
    for endpoint in objects(actual.get("endpoints"), "daemon endpoints", non_empty=True):
        scheme_name = text(endpoint.get("scheme"), "daemon endpoint scheme")
        if scheme_name not in schemes:
            add(issues, "HST-003", "daemon endpoint uses an unreviewed scheme")
        if endpoint.get("authentication") != expected.get("required_authentication"):
            add(issues, "HST-003", "daemon endpoint authentication is insufficient")
        if endpoint.get("public") is not False:
            add(issues, "HST-003", "daemon endpoint is publicly exposed")
        if scheme_name == "unix" and endpoint.get("path") not in paths:
            add(issues, "HST-003", "daemon endpoint uses an unreviewed socket path")
        if scheme_name == "tcp":
            text(endpoint.get("address"), "daemon TCP address")
            port = integer(endpoint.get("port"), "daemon TCP port")
            if not 1 <= port <= 65535:
                raise InputError("daemon TCP port is invalid")
    mounts = integer(
        actual.get("workload_runtime_socket_mounts"), "workload socket mount count"
    )
    if mounts != 0:
        add(issues, "HST-003", "a workload mounts a host runtime socket")
    if actual.get("runtime_socket_owner") != "root":
        add(issues, "HST-003", "runtime socket owner is not root")
    if actual.get("runtime_socket_group") != "container-runtime":
        add(issues, "HST-003", "runtime socket group is not the reviewed operator group")
    socket_mode = mode(actual.get("runtime_socket_mode"), "runtime socket mode")
    if socket_mode & 0o007:
        add(issues, "HST-003", "runtime socket grants access to other users")
    sources = strings(
        actual.get("observed_source_addresses"), "observed management sources"
    )
    return issues, sources


def valid_isolation_exception(
    policy: dict[str, Any],
    exceptions: dict[str, Any],
    node_pool: str,
    evaluation_time: datetime,
    issues: list[tuple[str, str]],
) -> bool:
    schema(exceptions, "psb-container-host-exceptions/v1", "exceptions")
    records = objects(exceptions.get("exceptions"), "host exceptions")
    candidates = [
        item
        for item in records
        if item.get("check_id") == "HST-004" and item.get("node_pool") == node_pool
    ]
    if len(candidates) != 1:
        add(issues, "HST-004", "disabled isolation lacks one exact scoped exception")
        return False
    item = candidates[0]
    text(item.get("id"), "exception id")
    owner = text(item.get("owner"), "exception owner")
    approver = text(item.get("approved_by"), "exception approver")
    reason = text(item.get("reason"), "exception reason")
    created_at = instant(item.get("created_at"), "exception created_at")
    expires_at = instant(item.get("expires_at"), "exception expires_at")
    maximum_days = integer(
        mapping(policy.get("exceptions"), "policy.exceptions").get(
            "maximum_lifetime_days"
        ),
        "maximum exception lifetime",
    )
    valid = True
    if owner == approver:
        add(issues, "HST-004", "isolation exception is self-approved")
        valid = False
    if len(reason.strip()) < 10:
        add(issues, "HST-004", "isolation exception reason is not substantive")
        valid = False
    if not created_at <= evaluation_time < expires_at:
        add(issues, "HST-004", "isolation exception is not current")
        valid = False
    if expires_at > created_at + timedelta(days=maximum_days):
        add(issues, "HST-004", "isolation exception exceeds maximum lifetime")
        valid = False
    controls = set(
        strings(item.get("compensating_controls"), "exception compensating controls")
    )
    required = set(
        strings(
            mapping(policy.get("exceptions"), "policy.exceptions").get(
                "required_compensating_controls"
            ),
            "required compensating controls",
        )
    )
    if not required <= controls:
        add(issues, "HST-004", "isolation exception lacks compensating controls")
        valid = False
    return valid


def check_isolation(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    exceptions: dict[str, Any],
    evaluation_time: datetime,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    expected = mapping(policy.get("isolation"), "policy.isolation")
    actual = mapping(evidence.get("isolation"), "host isolation")
    issues: list[tuple[str, str]] = []
    not_checked: list[tuple[str, str]] = []
    rootless = actual.get("rootless_enabled") is True
    user_namespace = actual.get("user_namespace_enabled") is True
    if not (rootless or user_namespace):
        node_pool = text(evidence.get("node_pool"), "host node_pool")
        if valid_isolation_exception(
            policy, exceptions, node_pool, evaluation_time, issues
        ):
            not_checked.append(
                ("HST-004", "rootless and user namespace limitation has a valid exception")
            )
    lockdown = actual.get("kernel_lockdown")
    if lockdown not in set(
        strings(expected.get("allowed_kernel_lockdown"), "allowed lockdown")
    ):
        add(issues, "HST-004", "kernel lockdown is not in an approved enforcing mode")
    if actual.get("seccomp_default") != expected.get("required_seccomp_profile"):
        add(issues, "HST-006", "daemon default seccomp profile is not enforced")
    if actual.get("lsm") not in set(
        strings(expected.get("allowed_enforcing_lsm"), "allowed LSM")
    ):
        add(issues, "HST-006", "host LSM is not approved")
    if actual.get("lsm_mode") != "enforcing":
        add(issues, "HST-006", "host LSM is not enforcing")
    if actual.get("workload_profile_assigned") is not True:
        add(issues, "HST-006", "container workloads lack an assigned LSM profile")
    if actual.get("kernel_modules_restricted") is not True:
        add(issues, "HST-006", "kernel module loading is not restricted")
    return issues, not_checked


def check_paths(policy: dict[str, Any], evidence: dict[str, Any]) -> list[tuple[str, str]]:
    expected = {
        text(item.get("path"), "policy protected path"): item
        for item in objects(policy.get("protected_paths"), "policy protected paths")
    }
    actual: dict[str, dict[str, Any]] = {}
    for item in objects(evidence.get("protected_paths"), "observed protected paths"):
        path = text(item.get("path"), "observed protected path")
        if path in actual:
            raise InputError("observed protected paths must be unique")
        actual[path] = item
    issues: list[tuple[str, str]] = []
    for path, required in expected.items():
        observed = actual.get(path)
        if observed is None:
            add(issues, "HST-005", f"protected path is missing: {path}")
            continue
        for field in ("type", "owner", "group"):
            if observed.get(field) != required.get(field):
                add(issues, "HST-005", f"protected path {path} has wrong {field}")
        actual_mode = mode(observed.get("mode"), f"observed path {path} mode")
        maximum_mode = mode(required.get("maximum_mode"), f"policy path {path} mode")
        if actual_mode & ~maximum_mode:
            add(issues, "HST-005", f"protected path {path} is too permissive")
        if required.get("type") == "file" and observed.get("sha256") != required.get(
            "sha256"
        ):
            add(issues, "HST-005", f"protected file {path} digest does not match")
    return issues


def check_access(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    sources: list[str],
    evaluation_time: datetime,
    maximum_age: int,
) -> list[tuple[str, str]]:
    expected = mapping(policy.get("access"), "policy.access")
    actual = mapping(evidence.get("access"), "host access")
    issues: list[tuple[str, str]] = []
    if validate_roles(actual.get("roles"), "observed access roles") != validate_roles(
        expected.get("roles"), "policy access roles"
    ):
        add(issues, "HST-007", "effective operator roles differ from reviewed policy")
    cidrs = [
        network(item, "allowed management CIDR")
        for item in strings(
            mapping(policy.get("management"), "policy.management").get(
                "allowed_management_cidrs"
            ),
            "allowed management CIDRs",
        )
    ]
    for source in sources:
        parsed = address(source, "observed management source")
        if not any(parsed in allowed for allowed in cidrs):
            add(issues, "HST-007", "management access originated outside approved networks")

    audit = mapping(evidence.get("audit"), "host audit")
    if audit.get("collector_status") != "ok":
        raise InputError("host audit collector is unavailable")
    fresh(
        instant(audit.get("observed_at"), "host audit observed_at"),
        evaluation_time,
        maximum_age,
        "host audit evidence",
    )
    if audit.get("enabled") is not True:
        add(issues, "HST-007", "host audit is disabled")
    if audit.get("rules_immutable") is not True:
        add(issues, "HST-007", "host audit rules are mutable")
    events = set(strings(audit.get("events"), "host audit events"))
    required_events = set(
        strings(expected.get("required_audit_events"), "required audit events")
    )
    if not required_events <= events:
        add(issues, "HST-007", "host audit event coverage is incomplete")
    return issues


def check_hardware(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    evaluation_time: datetime,
) -> list[tuple[str, str]]:
    expected = mapping(policy.get("hardware_trust"), "policy.hardware_trust")
    actual = mapping(evidence.get("hardware_trust"), "host hardware trust")
    issues: list[tuple[str, str]] = []
    if actual.get("secure_boot") is not True:
        add(issues, "HST-008", "secure boot is not enabled")
    if actual.get("measured_boot") is not True:
        add(issues, "HST-008", "measured boot is not enabled")
    if actual.get("tpm_backed_identity") is not True:
        add(issues, "HST-008", "node identity is not TPM-backed")
    status = actual.get("attestation_status")
    if status == "error":
        raise InputError("hardware attestation service is unavailable")
    if status != "verified":
        add(issues, "HST-008", "hardware attestation is not verified")
    if actual.get("node_pool") != expected.get("required_node_pool"):
        add(issues, "HST-008", "hardware attestation is bound to the wrong node pool")
    maximum_age = integer(
        expected.get("maximum_attestation_age_seconds"), "attestation maximum age"
    )
    attested_at = instant(actual.get("attested_at"), "hardware attested_at")
    if attested_at > evaluation_time or evaluation_time - attested_at > timedelta(
        seconds=maximum_age
    ):
        add(issues, "HST-008", "hardware attestation is stale or future-dated")
    return issues


PASS_MESSAGES = {
    "HST-001": "dedicated minimal host scope verified",
    "HST-002": "supported patched host component baseline verified",
    "HST-003": "private authenticated daemon and socket boundary verified",
    "HST-004": "rootless or user namespace and kernel lockdown verified",
    "HST-005": "protected runtime path ownership mode and integrity verified",
    "HST-006": "default seccomp enforcing LSM and module policy verified",
    "HST-007": "operator network and immutable audit boundary verified",
    "HST-008": "hardware-backed boot node identity and attestation verified",
    "HST-009": "complete fresh host evidence sources verified",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify provider-neutral container host hardening evidence."
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--host-evidence", type=Path, required=True)
    parser.add_argument("--exceptions", type=Path, required=True)
    parser.add_argument("--evidence-health", type=Path, required=True)
    parser.add_argument("--evaluation-time", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        evaluation_time = instant(args.evaluation_time, "evaluation time")
        policy = load_json(args.policy, "policy")
        evidence = load_json(args.host_evidence, "host evidence")
        exceptions = load_json(args.exceptions, "exceptions")
        health = load_json(args.evidence_health, "evidence health")
        issues = validate_policy(policy)
        schema(evidence, "psb-container-host-evidence/v1", "host evidence")
        schema(exceptions, "psb-container-host-exceptions/v1", "exceptions")
        platform = text(evidence.get("platform"), "host platform")
        adapter_status = text(evidence.get("adapter_status"), "host adapter status")
        required_sources = REQUIRED_SOURCES if platform == "linux" else {"platform-inventory"}
        maximum_age = validate_health(
            policy, health, evaluation_time, required_sources
        )
        fresh(
            instant(evidence.get("observed_at"), "host evidence observed_at"),
            evaluation_time,
            maximum_age,
            "host evidence",
        )
        if platform != "linux":
            if adapter_status != "unsupported":
                raise InputError("non-Linux platform adapter state is inconsistent")
            print(
                "NOT_CHECKED PSB-CONTAINER-003 provider-specific adapter required "
                f"for {platform}"
            )
            return 3
        if adapter_status != "supported":
            raise InputError("Linux host adapter is unavailable")
        text(evidence.get("node_id"), "host node_id")
        text(evidence.get("node_pool"), "host node_pool")

        issues.extend(check_scope(policy, evidence))
        issues.extend(check_components(policy, evidence, evaluation_time))
        management_issues, management_sources = check_management(policy, evidence)
        issues.extend(management_issues)
        isolation_issues, not_checked = check_isolation(
            policy, evidence, exceptions, evaluation_time
        )
        issues.extend(isolation_issues)
        issues.extend(check_paths(policy, evidence))
        issues.extend(
            check_access(
                policy,
                evidence,
                management_sources,
                evaluation_time,
                maximum_age,
            )
        )
        issues.extend(check_hardware(policy, evidence, evaluation_time))
    except InputError as error:
        print(f"ERROR PSB-CONTAINER-003 host evaluation unavailable: {error}")
        return 2

    if issues:
        print("FAIL PSB-CONTAINER-003 host hardening rejected")
        for check_id, message in sorted(
            set(issues), key=lambda item: (CHECK_ORDER[item[0]], item[1])
        ):
            print(f"FAIL {check_id} {message}")
        return 1

    not_checked_ids = {check_id for check_id, _ in not_checked}
    if not_checked:
        print("NOT_CHECKED PSB-CONTAINER-003 host hardening has an approved limitation")
    else:
        print("PASS PSB-CONTAINER-003 host hardening accepted")
    for check_id in PASS_MESSAGES:
        if check_id in not_checked_ids:
            message = next(message for current, message in not_checked if current == check_id)
            print(f"NOT_CHECKED {check_id} {message}")
        else:
            print(f"PASS {check_id} {PASS_MESSAGES[check_id]}")
    return 3 if not_checked else 0


if __name__ == "__main__":
    sys.exit(main())
