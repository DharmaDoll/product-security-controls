#!/usr/bin/env python3
"""Search SBOM inventory and emit an approved dry-run incident response plan."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID


SERIAL_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
ARTIFACT_RE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
REQUIRED_ACTIONS = [
    "preserve-evidence",
    "suspend-workflows",
    "revoke-credentials",
    "quarantine-artifacts",
    "pin-safe-version",
    "clean-rebuild",
    "notify-stakeholders",
]


class InputError(ValueError):
    pass


class EvaluationError(RuntimeError):
    pass


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError(f"cannot load {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def validate_runbook(value: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[str] = []
    if value.get("dry_run_default") is not True:
        findings.append("runbook.dry_run_default must be true")
    actions = value.get("actions")
    if not isinstance(actions, list):
        raise InputError("runbook.actions must be a list")
    action_ids = [action.get("id") for action in actions if isinstance(action, dict)]
    if action_ids != REQUIRED_ACTIONS:
        findings.append("runbook actions must use the required evidence-first order")
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise InputError(f"runbook.actions[{index}] must be an object")
        if "command" in action:
            findings.append(f"runbook action {action.get('id')} must not embed a command")
        if action.get("requires_approval") is not True:
            findings.append(f"runbook action {action.get('id')} requires approval")
        owner = action.get("owner")
        if not isinstance(owner, str) or not owner:
            findings.append(f"runbook action {action.get('id')} requires an owner")
    return actions, findings


def validate_sbom(path: Path) -> tuple[dict[str, Any], list[str]]:
    sbom = load_json(path, "SBOM")
    findings: list[str] = []
    if sbom.get("bomFormat") != "CycloneDX":
        findings.append(f"{path.name} bomFormat must be CycloneDX")
    if sbom.get("specVersion") != "1.7":
        findings.append(f"{path.name} specVersion must be 1.7")
    serial = sbom.get("serialNumber")
    if not isinstance(serial, str) or not SERIAL_RE.fullmatch(serial):
        findings.append(f"{path.name} requires a valid unique serialNumber")
    version = sbom.get("version")
    if not isinstance(version, int) or version < 1:
        findings.append(f"{path.name} version must be a positive integer")
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict) or not all(
        isinstance(component.get(field), str) and component.get(field)
        for field in ("name", "version")
    ):
        findings.append(f"{path.name} metadata.component requires name and version")
    compositions = sbom.get("compositions")
    if (
        not isinstance(compositions, list)
        or not compositions
        or not all(
            isinstance(item, dict) and item.get("aggregate") == "complete"
            for item in compositions
        )
    ):
        findings.append(f"{path.name} component inventory must be marked complete")
    components = sbom.get("components")
    if not isinstance(components, list):
        raise InputError(f"{path.name} components must be a list")
    for index, item in enumerate(components):
        if not isinstance(item, dict):
            raise InputError(f"{path.name} components[{index}] must be an object")
        name, item_version, purl = item.get("name"), item.get("version"), item.get("purl")
        if not all(isinstance(field, str) and field for field in (name, item_version, purl)):
            findings.append(
                f"{path.name} component {index} requires exact name version and purl"
            )
        elif "*" in item_version or f"{name}@{item_version}" not in purl:
            findings.append(f"{path.name} component {name} has non-exact identity")
    return sbom, findings


def validate_records(
    value: dict[str, Any], serials: set[str]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records = value.get("records")
    if not isinstance(records, list):
        raise InputError("build-records.records must be a list")
    findings: list[str] = []
    by_serial: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise InputError(f"build record {index} must be an object")
        serial = record.get("sbom_serial")
        if not isinstance(serial, str) or serial in by_serial:
            findings.append(f"build record {index} has invalid or duplicate SBOM serial")
            continue
        by_serial[serial] = record
        for field in ("repository", "build_id", "artifact"):
            if not isinstance(record.get(field), str) or not record[field]:
                findings.append(f"build record {serial} missing {field}")
        if not ARTIFACT_RE.fullmatch(str(record.get("artifact", ""))):
            findings.append(f"build record {serial} artifact must use an exact digest")
        if not COMMIT_RE.fullmatch(str(record.get("source_commit", ""))):
            findings.append(f"build record {serial} source_commit must be immutable")
        for field in ("provenance_digest", "log_digest"):
            if not DIGEST_RE.fullmatch(str(record.get(field, ""))):
                findings.append(f"build record {serial} missing valid {field}")
        credentials = record.get("credential_ids")
        if not isinstance(credentials, list) or not all(
            isinstance(item, str) and item and "secret" not in item.lower()
            for item in credentials
        ):
            findings.append(f"build record {serial} credential_ids are invalid")
        project_uuid = record.get("dependency_track_project_uuid")
        project_version = record.get("dependency_track_project_version")
        if project_uuid is not None and not valid_uuid(project_uuid):
            findings.append(
                f"build record {serial} dependency_track_project_uuid is invalid"
            )
        if project_version is not None and (
            not isinstance(project_version, str) or not project_version
        ):
            findings.append(
                f"build record {serial} dependency_track_project_version is invalid"
            )
        deployments = record.get("deployments")
        if not isinstance(deployments, list) or not deployments:
            findings.append(f"build record {serial} requires deployment inventory")
            continue
        deployment_ids: set[str] = set()
        for deployment_index, deployment in enumerate(deployments):
            label = f"build record {serial} deployment {deployment_index}"
            if not isinstance(deployment, dict):
                raise InputError(f"{label} must be an object")
            deployment_id = deployment.get("deployment_id")
            if (
                not isinstance(deployment_id, str)
                or not deployment_id
                or "latest" in deployment_id
                or deployment_id in deployment_ids
            ):
                findings.append(f"{label} has invalid or duplicate deployment_id")
            else:
                deployment_ids.add(deployment_id)
            if deployment.get("artifact") != record.get("artifact"):
                findings.append(f"{label} artifact does not match the build record")
            if not isinstance(deployment.get("environment"), str) or not deployment.get(
                "environment"
            ):
                findings.append(f"{label} requires an environment")
            if deployment.get("status") != "active":
                findings.append(f"{label} is not an active deployment observation")
            try:
                parse_time(deployment.get("observed_at"), f"{label}.observed_at")
            except InputError:
                findings.append(f"{label} observed_at is invalid")
    missing = sorted(serials - set(by_serial))
    if missing:
        findings.append(f"build records missing SBOM serials: {', '.join(missing)}")
    return by_serial, findings


def valid_uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise InputError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InputError(f"{label} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise InputError(f"{label} must include a timezone")
    return parsed


def validate_dependency_track_policy(value: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if value.get("adapter_schema") != "psb-dependency-track-impact-policy/1.0":
        findings.append("Dependency-Track impact policy schema is unsupported")
    server = value.get("server")
    if not isinstance(server, dict):
        raise InputError("Dependency-Track policy.server must be an object")
    release = server.get("release")
    digest = server.get("apiserver_sha256")
    if not isinstance(release, str) or release in {"", "latest", "main", "master"}:
        findings.append("Dependency-Track impact server release is mutable")
    if not DIGEST_RE.fullmatch(str(digest or "")):
        findings.append("Dependency-Track impact server is not integrity pinned")
    endpoint = value.get("endpoint")
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith("/api/v1")
    ):
        findings.append("Dependency-Track impact endpoint is not exact authenticated HTTPS")
    if value.get("api_key_source") != "environment:DEPENDENCY_TRACK_READ_API_KEY":
        findings.append("Dependency-Track read API key source is not approved")
    if value.get("api_permissions") != ["VIEW_PORTFOLIO", "VIEW_VULNERABILITY"]:
        findings.append("Dependency-Track read API permissions are not exact")
    if value.get("query_mode") != "exact-component-and-vulnerability":
        findings.append("Dependency-Track query is not exact")
    if value.get("pagination") != "all-pages-required":
        findings.append("Dependency-Track pagination can omit projects")
    if value.get("unavailable_state") != "ERROR":
        findings.append("Dependency-Track query failure can appear as no impact")
    age = value.get("max_inventory_age_hours")
    if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 24:
        findings.append("Dependency-Track inventory freshness exceeds 24 hours")
    if value.get("evidence") != "sanitized-metadata-only":
        findings.append("Dependency-Track query evidence is not minimized")
    return findings


def validate_dependency_track_response(
    value: dict[str, Any],
    policy: dict[str, Any],
    package: str,
    version: str,
    vulnerability_id: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if value.get("response_schema") != "psb-dependency-track-impact-response/1.0":
        raise InputError("Dependency-Track response schema is unsupported")
    if value.get("status") != "SUCCESS":
        raise EvaluationError("Dependency-Track portfolio query is unavailable")
    query = value.get("query")
    if not isinstance(query, dict):
        raise InputError("Dependency-Track response.query must be an object")
    expected_query = {
        "package": package,
        "version": version,
        "vulnerability_id": vulnerability_id,
    }
    if query != expected_query:
        raise EvaluationError("Dependency-Track response does not match the exact query")
    pagination = value.get("pagination")
    if not isinstance(pagination, dict):
        raise InputError("Dependency-Track response.pagination must be an object")
    if pagination.get("complete") is not True:
        raise EvaluationError("Dependency-Track portfolio pagination is incomplete")
    pages_scanned = pagination.get("pages_scanned")
    total_pages = pagination.get("total_pages")
    if (
        not isinstance(pages_scanned, int)
        or isinstance(pages_scanned, bool)
        or not isinstance(total_pages, int)
        or isinstance(total_pages, bool)
        or pages_scanned < 1
        or pages_scanned != total_pages
    ):
        raise EvaluationError("Dependency-Track portfolio page coverage is incomplete")
    health = value.get("analysis_health")
    if not isinstance(health, dict):
        raise InputError("Dependency-Track response.analysis_health must be an object")
    if health.get("status") != "healthy":
        raise EvaluationError("Dependency-Track analyzer or mirror is unavailable")
    updated = parse_time(health.get("inventory_updated_at"), "inventory_updated_at")
    evaluated = parse_time(health.get("evaluated_at"), "evaluated_at")
    max_age = policy.get("max_inventory_age_hours")
    if not isinstance(max_age, int):
        raise InputError("max_inventory_age_hours must be an integer")
    if updated > evaluated or (evaluated - updated).total_seconds() > max_age * 3600:
        raise EvaluationError("Dependency-Track portfolio inventory is stale")
    projects = value.get("projects")
    if not isinstance(projects, list):
        raise InputError("Dependency-Track response.projects must be a list")
    if pagination.get("returned_count") != len(projects):
        raise EvaluationError("Dependency-Track returned count is incomplete")
    findings: list[str] = []
    by_serial: dict[str, dict[str, Any]] = {}
    for index, project in enumerate(projects):
        if not isinstance(project, dict):
            raise InputError(f"Dependency-Track project {index} must be an object")
        project_uuid = project.get("project_uuid")
        project_version = project.get("project_version")
        serial = project.get("sbom_serial")
        purl = project.get("component_purl")
        if not valid_uuid(project_uuid):
            findings.append(f"Dependency-Track project {index} UUID is invalid")
        if not isinstance(project_version, str) or not project_version:
            findings.append(f"Dependency-Track project {index} version is missing")
        if not isinstance(serial, str) or not SERIAL_RE.fullmatch(serial):
            findings.append(f"Dependency-Track project {index} SBOM serial is invalid")
            continue
        if serial in by_serial:
            findings.append(f"Dependency-Track duplicate SBOM serial: {serial}")
        by_serial[serial] = project
        if not isinstance(purl, str) or f"/{package}@{version}" not in purl:
            findings.append(
                f"Dependency-Track project {project_uuid} component identity is not exact"
            )
        if project.get("vulnerability_id") != vulnerability_id:
            findings.append(
                f"Dependency-Track project {project_uuid} vulnerability does not match"
            )
    return by_serial, findings


def run(
    package: str,
    version: str,
    inventory_dir: Path,
    records_path: Path,
    runbook_path: Path,
    dry_run: bool,
    dependency_track_policy_path: Path | None = None,
    dependency_track_response_path: Path | None = None,
    vulnerability_id: str | None = None,
) -> tuple[int, list[str]]:
    if not package or not version or "*" in package or "*" in version:
        raise InputError("package and version must be exact non-empty identifiers")
    runbook = load_json(runbook_path, "runbook")
    actions, findings = validate_runbook(runbook)
    if not dry_run:
        findings.append("reference responder only permits --dry-run")
    if (dependency_track_policy_path is None) != (
        dependency_track_response_path is None
    ):
        raise InputError(
            "Dependency-Track policy and response must be supplied together"
        )
    if dependency_track_policy_path is not None and not vulnerability_id:
        raise InputError(
            "Dependency-Track impact search requires --vulnerability-id"
        )

    try:
        paths = sorted(inventory_dir.glob("*.cdx.json"))
    except OSError as error:
        raise InputError(f"cannot enumerate inventory: {error}") from error
    if not paths:
        raise InputError("SBOM inventory is empty or unavailable")
    sboms: list[tuple[Path, dict[str, Any]]] = []
    serials: set[str] = set()
    for path in paths:
        sbom, sbom_findings = validate_sbom(path)
        findings.extend(sbom_findings)
        serial = sbom.get("serialNumber")
        if isinstance(serial, str):
            if serial in serials:
                findings.append(f"duplicate SBOM serialNumber: {serial}")
            serials.add(serial)
        sboms.append((path, sbom))
    records, record_findings = validate_records(
        load_json(records_path, "build records"), serials
    )
    findings.extend(record_findings)
    dependency_track_projects: dict[str, dict[str, Any]] | None = None
    if dependency_track_policy_path is not None and dependency_track_response_path is not None:
        dependency_track_policy = load_json(
            dependency_track_policy_path, "Dependency-Track policy"
        )
        findings.extend(validate_dependency_track_policy(dependency_track_policy))
        dependency_track_projects, dependency_track_findings = (
            validate_dependency_track_response(
                load_json(
                    dependency_track_response_path, "Dependency-Track response"
                ),
                dependency_track_policy,
                package,
                version,
                str(vulnerability_id),
            )
        )
        findings.extend(dependency_track_findings)
    if findings:
        return 1, [*(f"FAIL {finding}" for finding in findings), f"RESULT rejected with {len(findings)} finding(s)"]

    impacted: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    for path, sbom in sboms:
        if any(
            component.get("name") == package and component.get("version") == version
            for component in sbom["components"]
        ):
            impacted.append((path, sbom, records[sbom["serialNumber"]]))
    if dependency_track_projects is not None:
        local_serials = {sbom["serialNumber"] for _, sbom, _ in impacted}
        remote_serials = set(dependency_track_projects)
        missing_remote = sorted(local_serials - remote_serials)
        missing_local = sorted(remote_serials - local_serials)
        if missing_remote:
            findings.append(
                "Dependency-Track is missing impacted SBOM serials: "
                + ", ".join(missing_remote)
            )
        if missing_local:
            findings.append(
                "local evidence is missing Dependency-Track SBOM serials: "
                + ", ".join(missing_local)
            )
        for _, sbom, record in impacted:
            project = dependency_track_projects.get(sbom["serialNumber"])
            if project is None:
                continue
            matching_purls = {
                component.get("purl")
                for component in sbom["components"]
                if component.get("name") == package
                and component.get("version") == version
                and isinstance(component.get("purl"), str)
            }
            if project.get("component_purl") not in matching_purls:
                findings.append(
                    f"build record {sbom['serialNumber']} Dependency-Track PURL mismatch"
                )
            if record.get("dependency_track_project_uuid") != project.get(
                "project_uuid"
            ):
                findings.append(
                    f"build record {sbom['serialNumber']} Dependency-Track UUID mismatch"
                )
            if record.get("dependency_track_project_version") != project.get(
                "project_version"
            ):
                findings.append(
                    f"build record {sbom['serialNumber']} Dependency-Track version mismatch"
                )
    if findings:
        return 1, [
            *(f"FAIL {finding}" for finding in findings),
            f"RESULT rejected with {len(findings)} finding(s)",
        ]
    if not impacted:
        return 0, [f"CLEAN no inventory matches {package}@{version}"]

    query_suffix = (
        f" vulnerability={vulnerability_id}"
        if dependency_track_projects is not None
        else ""
    )
    output = [
        f"DETECTED {package}@{version} in {len(impacted)} product(s){query_suffix}"
    ]
    for path, sbom, record in impacted:
        dependency_track_suffix = ""
        if dependency_track_projects is not None:
            project = dependency_track_projects[sbom["serialNumber"]]
            dependency_track_suffix = (
                f" dependency_track_project={project['project_uuid']}"
                f" project_version={project['project_version']}"
            )
        output.append(
            "AFFECTED "
            f"repository={record['repository']} build={record['build_id']} "
            f"artifact={record['artifact']} sbom={path.name}"
            f"{dependency_track_suffix}"
        )
        output.append(
            "DEPLOYED "
            + ",".join(
                f"{deployment['environment']}:{deployment['deployment_id']}"
                for deployment in record["deployments"]
            )
        )
        output.append(
            "EVIDENCE "
            f"provenance={record['provenance_digest']} logs={record['log_digest']} "
            f"credentials={','.join(record['credential_ids'])}"
        )
    for index, action in enumerate(actions, 1):
        output.append(
            f"PLAN {index} {action['id']} owner={action['owner']} approval=required"
        )
    output.append("RESULT dry-run no external actions executed")
    return 1, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--inventory-dir", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--runbook", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--dependency-track-policy", type=Path)
    parser.add_argument("--dependency-track-response", type=Path)
    parser.add_argument("--vulnerability-id")
    args = parser.parse_args()
    try:
        status, output = run(
            args.package,
            args.version,
            args.inventory_dir,
            args.records,
            args.runbook,
            args.dry_run,
            args.dependency_track_policy,
            args.dependency_track_response,
            args.vulnerability_id,
        )
    except (InputError, EvaluationError) as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    print("\n".join(output))
    return status


if __name__ == "__main__":
    sys.exit(main())
