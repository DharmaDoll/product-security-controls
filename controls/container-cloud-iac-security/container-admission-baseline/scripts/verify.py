#!/usr/bin/env python3
"""Evaluate a Kubernetes workload and bind admission to verified OCI provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_PROVENANCE_VERIFIER = (
    REPOSITORY_ROOT
    / "controls/release-integrity/signature-provenance-verification/scripts/verify.py"
)
IMAGE_RE = re.compile(
    r"^(?P<name>(?P<registry>[a-z0-9.-]+(?::[0-9]+)?)/"
    r"[a-z0-9._/-]+)@sha256:(?P<digest>[0-9a-f]{64})$"
)
IMMUTABLE_VERSION_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]+$")
CPU_RE = re.compile(r"^(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<milli>m)?$")
MEMORY_RE = re.compile(r"^(?P<number>[0-9]+)(?P<unit>Ki|Mi|Gi)$")
RUNTIME_SOCKET_PREFIXES = (
    "/var/run/docker.sock",
    "/run/containerd/",
    "/run/crio/",
    "/var/run/crio/",
)
ALLOWED_VOLUME_TYPES = {
    "emptyDir",
    "configMap",
    "secret",
    "projected",
    "downwardAPI",
    "persistentVolumeClaim",
}


class InputError(ValueError):
    """The admission decision could not be evaluated."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise InputError(f"{label} does not exist: {path}") from error
    except (OSError, UnicodeError) as error:
        raise InputError(f"cannot read {label} {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise InputError(f"invalid {label} JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def optional_mapping(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    return mapping(value, label)


def object_list(value: Any, label: str, *, non_empty: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise InputError(f"{label} must be a {qualifier}array")
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise InputError(f"{label}[{index}] must be an object")
        result.append(item)
    return result


def string_list(value: Any, label: str, *, non_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "non-empty " if non_empty else ""
        raise InputError(f"{label} must be a {qualifier}array")
    if not all(isinstance(item, str) and item for item in value):
        raise InputError(f"{label} must contain non-empty strings")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{label} must be non-empty text")
    return value


def add(issues: list[str], check_id: str, message: str) -> None:
    issues.append(f"{check_id} {message}")


def cpu_millicores(value: Any) -> int | None:
    if not isinstance(value, str) or (match := CPU_RE.fullmatch(value)) is None:
        return None
    number = float(match.group("number"))
    millicores = number if match.group("milli") else number * 1000
    if millicores <= 0 or not millicores.is_integer():
        return None
    return int(millicores)


def memory_mib(value: Any) -> int | None:
    if not isinstance(value, str) or (match := MEMORY_RE.fullmatch(value)) is None:
        return None
    number = int(match.group("number"))
    multipliers = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024}
    mebibytes = number * multipliers[match.group("unit")]
    if mebibytes <= 0 or not mebibytes.is_integer():
        return None
    return int(mebibytes)


def pod_from_admission(
    admission: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str, str, str]:
    if admission.get("apiVersion") != "admission.k8s.io/v1":
        raise InputError("AdmissionReview apiVersion must be admission.k8s.io/v1")
    if admission.get("kind") != "AdmissionReview":
        raise InputError("admission input kind must be AdmissionReview")
    request = mapping(admission.get("request"), "AdmissionReview.request")
    text(request.get("uid"), "AdmissionReview.request.uid")
    operation = text(request.get("operation"), "AdmissionReview.request.operation")
    resource = mapping(request.get("resource"), "AdmissionReview.request.resource")
    if resource != {"group": "apps", "version": "v1", "resource": "deployments"}:
        raise InputError("first slice accepts only apps/v1 deployments")
    workload = mapping(request.get("object"), "AdmissionReview.request.object")
    if workload.get("apiVersion") != "apps/v1" or workload.get("kind") != "Deployment":
        raise InputError("admitted object must be an apps/v1 Deployment")
    metadata = mapping(workload.get("metadata"), "Deployment.metadata")
    name = text(metadata.get("name"), "Deployment.metadata.name")
    namespace = text(
        request.get("namespace", metadata.get("namespace")),
        "AdmissionReview.request.namespace",
    )
    if metadata.get("namespace") not in {None, namespace}:
        raise InputError("request and workload namespaces do not match")
    spec = mapping(workload.get("spec"), "Deployment.spec")
    template = mapping(spec.get("template"), "Deployment.spec.template")
    pod = mapping(template.get("spec"), "Deployment.spec.template.spec")
    labels = mapping(
        mapping(template.get("metadata"), "Deployment.spec.template.metadata").get(
            "labels"
        ),
        "Deployment.spec.template.metadata.labels",
    )
    return pod, labels, namespace, name, operation


def all_containers(pod: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    for field in ("initContainers", "containers", "ephemeralContainers"):
        items = pod.get(field, [])
        if field == "containers":
            containers = object_list(items, f"pod.{field}", non_empty=True)
        else:
            containers = object_list(items, f"pod.{field}")
        for item in containers:
            name = text(item.get("name"), f"pod.{field} container name")
            result.append((f"{field}/{name}", item))
    return result


def validate_policy(policy: dict[str, Any]) -> list[str]:
    if policy.get("schema") != "psb-container-admission-policy/v1":
        raise InputError("unsupported container admission policy schema")
    issues: list[str] = []
    version = policy.get("policy_version")
    if not isinstance(version, str) or IMMUTABLE_VERSION_RE.fullmatch(version) is None:
        add(issues, "CNT-009", "policy_version must be an immutable reviewed version")

    registries = string_list(policy.get("trusted_registries"), "policy.trusted_registries")
    if not registries or "*" in registries:
        add(issues, "CNT-001", "trusted registry allowlist must be non-empty and exact")
    if policy.get("allowed_workload_kinds") != ["Deployment"]:
        add(issues, "CNT-009", "first-slice workload kind must be exactly Deployment")
    volume_types = set(
        string_list(policy.get("allowed_volume_types"), "policy.allowed_volume_types")
    )
    if volume_types != ALLOWED_VOLUME_TYPES:
        add(issues, "CNT-005", "allowed volume type set is incomplete or over-broad")

    security = mapping(policy.get("security_context"), "policy.security_context")
    minimum_user = security.get("minimum_run_as_user")
    if not isinstance(minimum_user, int) or isinstance(minimum_user, bool) or minimum_user < 1:
        add(issues, "CNT-003", "minimum runAsUser must be a non-root integer")
    if security.get("allow_privileged") is not False:
        add(issues, "CNT-003", "privileged containers are allowed by policy")
    if security.get("allow_privilege_escalation") is not False:
        add(issues, "CNT-003", "privilege escalation is allowed by policy")
    if security.get("require_read_only_root_filesystem") is not True:
        add(issues, "CNT-006", "read-only root filesystem is not required")
    if security.get("required_capability_drop") != ["ALL"]:
        add(issues, "CNT-004", "policy must require dropping ALL capabilities")
    if security.get("allowed_capability_add") != []:
        add(issues, "CNT-004", "first-slice policy must add no capabilities")
    if security.get("required_seccomp_profile") != "RuntimeDefault":
        add(issues, "CNT-006", "policy must require RuntimeDefault seccomp")

    resources = mapping(policy.get("resources"), "policy.resources")
    if set(string_list(resources.get("required_requests"), "policy required requests")) != {
        "cpu",
        "memory",
    }:
        add(issues, "CNT-007", "CPU and memory requests must be required")
    if set(string_list(resources.get("required_limits"), "policy required limits")) != {
        "cpu",
        "memory",
    }:
        add(issues, "CNT-007", "CPU and memory limits must be required")
    maximum_cpu = resources.get("maximum_cpu_millicores")
    if (
        not isinstance(maximum_cpu, int)
        or isinstance(maximum_cpu, bool)
        or not 1 <= maximum_cpu <= 4000
    ):
        add(issues, "CNT-007", "maximum CPU policy must be 1 through 4000 millicores")
    maximum_memory = resources.get("maximum_memory_mib")
    if (
        not isinstance(maximum_memory, int)
        or isinstance(maximum_memory, bool)
        or not 1 <= maximum_memory <= 4096
    ):
        add(issues, "CNT-007", "maximum memory policy must be 1 through 4096 MiB")
    maximum_pids = resources.get("maximum_pids")
    if (
        not isinstance(maximum_pids, int)
        or isinstance(maximum_pids, bool)
        or not 1 <= maximum_pids <= 256
    ):
        add(issues, "CNT-007", "maximum PID policy must be between 1 and 256")

    network = mapping(policy.get("network"), "policy.network")
    if network.get("require_default_deny_ingress") is not True:
        add(issues, "CNT-008", "default-deny ingress is not required")
    if network.get("require_default_deny_egress") is not True:
        add(issues, "CNT-008", "default-deny egress is not required")

    provenance = mapping(policy.get("provenance"), "policy.provenance")
    if provenance.get("required") is not True:
        add(issues, "CNT-002", "authenticated provenance is not required")
    if provenance.get("consumer_verifier_control") != "PSB-REL-001":
        add(issues, "CNT-002", "consumer verifier must be PSB-REL-001")
    if provenance.get("subject_digest_algorithm") != "sha256":
        add(issues, "CNT-002", "provenance subject digest must use sha256")
    if (
        provenance.get("artifact_media_type")
        != "application/vnd.oci.image.manifest.v1+json"
    ):
        add(issues, "CNT-002", "provenance artifact must be an OCI image manifest")

    admission = mapping(policy.get("admission"), "policy.admission")
    if admission.get("failure_policy") != "Fail":
        add(issues, "CNT-009", "admission failurePolicy must be Fail")
    if admission.get("unavailable_result") != "deny":
        add(issues, "CNT-009", "unavailable admission evaluator must deny")
    if set(string_list(admission.get("operations"), "policy admission operations")) != {
        "CREATE",
        "UPDATE",
    }:
        add(issues, "CNT-009", "admission must cover CREATE and UPDATE")
    timeout = admission.get("maximum_timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 10:
        add(issues, "CNT-009", "maximum admission timeout must be 1 through 10 seconds")
    return issues


def check_images(
    policy: dict[str, Any],
    containers: list[tuple[str, dict[str, Any]]],
    artifact_path: Path,
    provenance_policy: dict[str, Any],
) -> tuple[list[str], str | None]:
    issues: list[str] = []
    identities: set[tuple[str, str, str]] = set()
    registries = set(policy["trusted_registries"])
    for location, container in containers:
        image = container.get("image")
        if not isinstance(image, str) or (match := IMAGE_RE.fullmatch(image)) is None:
            add(issues, "CNT-001", f"{location} image is not pinned to an exact sha256 digest")
            continue
        registry = match.group("registry")
        if registry not in registries:
            add(issues, "CNT-001", f"{location} image registry is not trusted: {registry}")
        identities.add((match.group("name"), match.group("digest"), registry))

    if len(identities) != 1:
        add(
            issues,
            "CNT-001",
            "first-slice evidence must cover exactly one unique admitted image identity",
        )
        return issues, None

    image_name, image_digest, _ = next(iter(identities))
    try:
        artifact_bytes = artifact_path.read_bytes()
    except OSError as error:
        raise InputError(f"cannot read OCI manifest {artifact_path}: {error}") from error
    actual_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if image_digest != actual_digest:
        add(issues, "CNT-001", "admitted image digest does not match OCI manifest bytes")
    manifest = load_json(artifact_path, "OCI manifest")
    expected_media_type = mapping(policy.get("provenance"), "policy.provenance").get(
        "artifact_media_type"
    )
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != expected_media_type:
        add(issues, "CNT-001", "artifact is not the reviewed OCI image manifest type")
    if provenance_policy.get("expected_subject_name") != image_name:
        add(
            issues,
            "CNT-002",
            "provenance subject expectation does not match admitted image repository",
        )
    return issues, image_digest


def check_non_root(
    policy: dict[str, Any],
    pod: dict[str, Any],
    containers: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    issues: list[str] = []
    expected = mapping(policy.get("security_context"), "policy.security_context")
    pod_security = optional_mapping(pod.get("securityContext"), "pod.securityContext")
    minimum_user = expected.get("minimum_run_as_user")
    if pod.get("automountServiceAccountToken") is not False:
        add(issues, "CNT-003", "service account token automount must be disabled")
    if pod_security.get("runAsNonRoot") is not True:
        add(issues, "CNT-003", "pod runAsNonRoot must be true")
    pod_user = pod_security.get("runAsUser")
    if not isinstance(pod_user, int) or isinstance(pod_user, bool) or pod_user < minimum_user:
        add(issues, "CNT-003", "pod runAsUser is absent root or below policy minimum")
    for location, container in containers:
        security = optional_mapping(
            container.get("securityContext"), f"{location}.securityContext"
        )
        if security.get("runAsNonRoot") is not True:
            add(issues, "CNT-003", f"{location} runAsNonRoot must be true")
        user = security.get("runAsUser")
        if not isinstance(user, int) or isinstance(user, bool) or user < minimum_user:
            add(issues, "CNT-003", f"{location} runAsUser is absent root or below minimum")
        if security.get("privileged") is not False:
            add(issues, "CNT-003", f"{location} privileged must be false")
        if security.get("allowPrivilegeEscalation") is not False:
            add(issues, "CNT-003", f"{location} allowPrivilegeEscalation must be false")
    return issues


def check_capabilities(
    _: dict[str, Any],
    containers: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    issues: list[str] = []
    for location, container in containers:
        security = optional_mapping(
            container.get("securityContext"), f"{location}.securityContext"
        )
        capabilities = optional_mapping(
            security.get("capabilities"), f"{location}.capabilities"
        )
        if set(string_list(capabilities.get("drop"), f"{location} capability drop")) != {
            "ALL"
        }:
            add(issues, "CNT-004", f"{location} must drop ALL capabilities")
        if string_list(capabilities.get("add"), f"{location} capability add"):
            add(issues, "CNT-004", f"{location} must add no capabilities")
    return issues


def volume_type(volume: dict[str, Any]) -> str:
    candidates = [key for key in volume if key != "name"]
    if len(candidates) != 1:
        raise InputError("each volume must declare exactly one volume type")
    return candidates[0]


def check_host_isolation(
    policy: dict[str, Any],
    pod: dict[str, Any],
    containers: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    issues: list[str] = []
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(field) is not False:
            add(issues, "CNT-005", f"pod {field} must be explicitly false")

    allowed = set(policy.get("allowed_volume_types", []))
    volumes = object_list(pod.get("volumes", []), "pod.volumes")
    names: set[str] = set()
    for volume in volumes:
        name = text(volume.get("name"), "volume.name")
        names.add(name)
        kind = volume_type(volume)
        if kind not in allowed:
            add(issues, "CNT-005", f"volume {name} uses forbidden type {kind}")
        if kind == "hostPath":
            add(issues, "CNT-005", f"volume {name} exposes a host path")

    for location, container in containers:
        for port in object_list(container.get("ports", []), f"{location}.ports"):
            if port.get("hostPort") not in {None, 0}:
                add(issues, "CNT-005", f"{location} exposes hostPort")
        for mount in object_list(
            container.get("volumeMounts", []), f"{location}.volumeMounts"
        ):
            mount_name = text(mount.get("name"), f"{location} volume mount name")
            path = text(mount.get("mountPath"), f"{location} mountPath")
            if mount_name not in names:
                add(issues, "CNT-005", f"{location} references unknown volume {mount_name}")
            if any(path == prefix or path.startswith(prefix) for prefix in RUNTIME_SOCKET_PREFIXES):
                add(issues, "CNT-005", f"{location} mounts a container runtime socket")
    return issues


def check_filesystem_and_seccomp(
    policy: dict[str, Any],
    pod: dict[str, Any],
    containers: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    issues: list[str] = []
    expected = mapping(policy.get("security_context"), "policy.security_context")
    pod_security = optional_mapping(pod.get("securityContext"), "pod.securityContext")
    seccomp = optional_mapping(pod_security.get("seccompProfile"), "pod seccompProfile")
    if seccomp.get("type") != expected.get("required_seccomp_profile"):
        add(issues, "CNT-006", "pod seccomp profile must be RuntimeDefault")
    for location, container in containers:
        security = optional_mapping(
            container.get("securityContext"), f"{location}.securityContext"
        )
        if security.get("readOnlyRootFilesystem") is not True:
            add(issues, "CNT-006", f"{location} root filesystem must be read-only")
    return issues


def check_resources(
    policy: dict[str, Any],
    platform: dict[str, Any],
    containers: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    issues: list[str] = []
    expected = mapping(policy.get("resources"), "policy.resources")
    required_requests = set(expected.get("required_requests", []))
    required_limits = set(expected.get("required_limits", []))
    for location, container in containers:
        resources = optional_mapping(container.get("resources"), f"{location}.resources")
        requests = optional_mapping(
            resources.get("requests"), f"{location}.resources.requests"
        )
        limits = optional_mapping(resources.get("limits"), f"{location}.resources.limits")
        if not required_requests <= set(requests) or any(
            not isinstance(requests.get(key), str) or not requests[key]
            for key in required_requests
        ):
            add(issues, "CNT-007", f"{location} lacks CPU or memory requests")
        if not required_limits <= set(limits) or any(
            not isinstance(limits.get(key), str) or not limits[key]
            for key in required_limits
        ):
            add(issues, "CNT-007", f"{location} lacks CPU or memory limits")
        request_cpu = cpu_millicores(requests.get("cpu"))
        limit_cpu = cpu_millicores(limits.get("cpu"))
        if request_cpu is None or limit_cpu is None:
            add(issues, "CNT-007", f"{location} has invalid CPU quantities")
        elif request_cpu > limit_cpu or limit_cpu > expected.get("maximum_cpu_millicores"):
            add(issues, "CNT-007", f"{location} CPU request or limit violates bounds")
        request_memory = memory_mib(requests.get("memory"))
        limit_memory = memory_mib(limits.get("memory"))
        if request_memory is None or limit_memory is None:
            add(issues, "CNT-007", f"{location} has invalid memory quantities")
        elif (
            request_memory > limit_memory
            or limit_memory > expected.get("maximum_memory_mib")
        ):
            add(issues, "CNT-007", f"{location} memory request or limit violates bounds")
    runtime = mapping(platform.get("runtime"), "platform.runtime")
    if runtime.get("pids_limit_enforced") is not True:
        add(issues, "CNT-007", "runtime PID limit is not enforced")
    pids_limit = runtime.get("pids_limit")
    if (
        not isinstance(pids_limit, int)
        or isinstance(pids_limit, bool)
        or not 1 <= pids_limit <= expected.get("maximum_pids")
    ):
        add(issues, "CNT-007", "runtime PID limit is absent or exceeds policy")
    return issues


def check_network(
    platform: dict[str, Any],
    network_policy: dict[str, Any],
    labels: dict[str, Any],
    namespace: str,
) -> list[str]:
    issues: list[str] = []
    platform_network = mapping(platform.get("network_policy"), "platform.network_policy")
    if platform_network.get("enforcement_available") is not True:
        add(issues, "CNT-008", "network policy enforcement is unavailable")
    if (
        network_policy.get("apiVersion") != "networking.k8s.io/v1"
        or network_policy.get("kind") != "NetworkPolicy"
    ):
        raise InputError("network policy must be networking.k8s.io/v1 NetworkPolicy")
    metadata = mapping(network_policy.get("metadata"), "NetworkPolicy.metadata")
    if metadata.get("namespace") != namespace:
        add(issues, "CNT-008", "network policy namespace does not match workload")
    spec = mapping(network_policy.get("spec"), "NetworkPolicy.spec")
    selector = mapping(spec.get("podSelector"), "NetworkPolicy.spec.podSelector")
    match_labels = optional_mapping(
        selector.get("matchLabels"), "NetworkPolicy.spec.podSelector.matchLabels"
    )
    if not match_labels or any(labels.get(key) != value for key, value in match_labels.items()):
        add(issues, "CNT-008", "network policy selector does not target the workload")
    if set(string_list(spec.get("policyTypes"), "NetworkPolicy.spec.policyTypes")) != {
        "Ingress",
        "Egress",
    }:
        add(issues, "CNT-008", "network policy must cover ingress and egress")
    if spec.get("ingress") != []:
        add(issues, "CNT-008", "baseline network policy ingress is not default deny")
    if spec.get("egress") != []:
        add(issues, "CNT-008", "baseline network policy egress is not default deny")
    return issues


def check_admission(
    policy: dict[str, Any],
    platform: dict[str, Any],
    operation: str,
) -> list[str]:
    issues: list[str] = []
    if platform.get("status") != "completed":
        reason = platform.get("reason", "unknown")
        raise InputError(f"platform evidence is not complete: {reason}")
    if platform.get("schema") != "psb-container-platform-evidence/v1":
        raise InputError("unsupported platform evidence schema")
    if platform.get("policy_version") != policy.get("policy_version"):
        add(issues, "CNT-009", "platform policy version does not match reviewed policy")
    admission_policy = mapping(policy.get("admission"), "policy.admission")
    evidence = mapping(platform.get("admission_controller"), "platform admission controller")
    if evidence.get("enforced") is not True:
        add(issues, "CNT-009", "admission controller is not enforcing decisions")
    if evidence.get("failure_policy") != admission_policy.get("failure_policy"):
        add(issues, "CNT-009", "effective admission failurePolicy does not match policy")
    if evidence.get("unavailable_result") != admission_policy.get("unavailable_result"):
        add(issues, "CNT-009", "admission outage does not deny the request")
    operations = set(
        string_list(evidence.get("operations"), "platform admission operations")
    )
    if operations != {"CREATE", "UPDATE"} or operation not in operations:
        add(issues, "CNT-009", "admission operation coverage is incomplete")
    if set(string_list(evidence.get("resources"), "platform admission resources")) != {
        "deployments.apps"
    }:
        add(issues, "CNT-009", "admission resource coverage is incomplete")
    timeout = evidence.get("timeout_seconds")
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= admission_policy.get("maximum_timeout_seconds")
    ):
        add(issues, "CNT-009", "effective admission timeout exceeds policy")
    return issues


def verify_provenance(
    verifier: Path,
    policy_path: Path,
    artifact_path: Path,
    provenance_path: Path,
    signature_path: Path,
) -> list[str]:
    if not verifier.is_file():
        raise InputError(f"PSB-REL-001 verifier is unavailable: {verifier}")
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "--policy",
                str(policy_path),
                "--artifact",
                str(artifact_path),
                "--provenance",
                str(provenance_path),
                "--signature",
                str(signature_path),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InputError(f"cannot execute PSB-REL-001 verifier: {error}") from error
    output = result.stdout.strip()
    if result.returncode == 0:
        if output != "PASS artifact signature and SLSA provenance expectations verified":
            raise InputError("PSB-REL-001 verifier returned unexpected success output")
        return []
    if result.returncode == 1:
        details = [
            line.removeprefix("FAIL ")
            for line in output.splitlines()
            if line.startswith("FAIL ")
        ]
        detail = "; ".join(details) if details else "policy violation"
        return [f"CNT-002 PSB-REL-001 rejected image provenance: {detail}"]
    if result.returncode == 2:
        raise InputError(f"PSB-REL-001 verification unavailable: {output}")
    raise InputError(f"PSB-REL-001 verifier returned unexpected status {result.returncode}")


def verify(arguments: argparse.Namespace) -> list[str]:
    policy = load_json(arguments.policy, "policy")
    platform = load_json(arguments.platform_evidence, "platform evidence")
    admission = load_json(arguments.admission_review, "admission review")
    network_policy = load_json(arguments.network_policy, "network policy")
    provenance_policy = load_json(arguments.provenance_policy, "provenance policy")

    issues = validate_policy(policy)
    pod, labels, namespace, _, operation = pod_from_admission(admission)
    containers = all_containers(pod)
    issues.extend(check_admission(policy, platform, operation))
    image_issues, image_digest = check_images(
        policy, containers, arguments.oci_manifest, provenance_policy
    )
    issues.extend(image_issues)
    issues.extend(check_non_root(policy, pod, containers))
    issues.extend(check_capabilities(policy, containers))
    issues.extend(check_host_isolation(policy, pod, containers))
    issues.extend(check_filesystem_and_seccomp(policy, pod, containers))
    issues.extend(check_resources(policy, platform, containers))
    issues.extend(check_network(platform, network_policy, labels, namespace))

    if image_digest is None:
        add(issues, "CNT-002", "provenance cannot be bound without one exact image identity")
    else:
        issues.extend(
            verify_provenance(
                arguments.provenance_verifier,
                arguments.provenance_policy,
                arguments.oci_manifest,
                arguments.provenance,
                arguments.signature,
            )
        )
    return issues


PASS_MESSAGES = (
    "CNT-001 exact trusted OCI manifest digest verified",
    "CNT-002 PSB-REL-001 authenticity and exact image subject binding verified",
    "CNT-003 non-root and privilege-escalation protections verified",
    "CNT-004 all Linux capabilities dropped with no additions",
    "CNT-005 host namespaces paths ports and runtime sockets isolated",
    "CNT-006 read-only root filesystem and RuntimeDefault seccomp verified",
    "CNT-007 CPU memory and runtime PID bounds verified",
    "CNT-008 workload-targeted default-deny ingress and egress verified",
    "CNT-009 fail-closed CREATE and UPDATE admission enforcement verified",
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--policy", type=Path, required=True)
    result.add_argument("--platform-evidence", type=Path, required=True)
    result.add_argument("--admission-review", type=Path, required=True)
    result.add_argument("--network-policy", type=Path, required=True)
    result.add_argument("--oci-manifest", type=Path, required=True)
    result.add_argument("--provenance-policy", type=Path, required=True)
    result.add_argument("--provenance", type=Path, required=True)
    result.add_argument("--signature", type=Path, required=True)
    result.add_argument(
        "--provenance-verifier",
        type=Path,
        default=DEFAULT_PROVENANCE_VERIFIER,
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        issues = verify(arguments)
    except InputError as error:
        print(f"ERROR admission evaluation unavailable: {error}")
        return 2
    if issues:
        for issue in issues:
            print(f"FAIL {issue}")
        print(f"DECISION DENY {len(issues)} violation(s)")
        return 1
    for message in PASS_MESSAGES:
        print(f"PASS {message}")
    print(f"DECISION ALLOW {len(PASS_MESSAGES)} control checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
