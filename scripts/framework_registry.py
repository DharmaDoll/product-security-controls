#!/usr/bin/env python3
"""Framework registry discovery and control-mapping validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from control_metadata import REPOSITORY_ROOT


REGISTRY_GLOB = "frameworks/*/registry.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ROLES = {
    "requirement-framework",
    "threat-taxonomy",
    "implementation-guidance",
    "negative-baseline",
}
SLSA_BUILD_RESPONSIBILITIES = {
    "software-producer",
    "build-platform",
    "consumer",
}


def discover_registries() -> dict[str, dict[str, Any]]:
    registries: dict[str, dict[str, Any]] = {}
    for path in sorted(REPOSITORY_ROOT.glob(REGISTRY_GLOB)):
        with path.open("r", encoding="utf-8") as handle:
            registry = json.load(handle)
        registry["_path"] = path
        name = registry.get("name")
        if isinstance(name, str):
            if name in registries:
                raise ValueError(f"duplicate framework registry name: {name}")
            registries[name] = registry
    return registries


def _valid_https_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def validate_registries(
    registries: dict[str, dict[str, Any]],
    controls: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    entries_by_framework: dict[str, dict[str, dict[str, Any]]] = {}

    if not registries:
        return ["no framework registries discovered"]

    for name, registry in sorted(registries.items()):
        path = registry["_path"]
        label = str(path.relative_to(REPOSITORY_ROOT))
        if path.parent.name != name:
            errors.append(
                f"{label}: registry name {name!r} does not match directory "
                f"{path.parent.name!r}"
            )

        for field in ("publisher", "release", "mapping_version", "review_date"):
            if not isinstance(registry.get(field), str) or not registry[field].strip():
                errors.append(f"{label}: {field} must be a non-empty string")
        if registry.get("role") not in ROLES:
            errors.append(f"{label}: unsupported role {registry.get('role')!r}")

        source = registry.get("source")
        if not isinstance(source, dict):
            errors.append(f"{label}: source must be a mapping")
        else:
            if not _valid_https_url(source.get("url")):
                errors.append(f"{label}: source.url must be an HTTPS URL")
            digest = source.get("sha256")
            if digest is not None and (
                not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)
            ):
                errors.append(f"{label}: source.sha256 must be a lowercase SHA-256")
            commit = source.get("commit")
            if commit is not None and (
                not isinstance(commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            ):
                errors.append(f"{label}: source.commit must be a full commit SHA")

        coverage = registry.get("coverage")
        if not isinstance(coverage, dict):
            errors.append(f"{label}: coverage must be a mapping")
        else:
            for field in ("scope", "completeness"):
                if (
                    not isinstance(coverage.get(field), str)
                    or not coverage[field].strip()
                ):
                    errors.append(
                        f"{label}: coverage.{field} must be a non-empty string"
                    )

        entries = registry.get("entries")
        if not isinstance(entries, list) or not entries:
            errors.append(f"{label}: entries must be a non-empty list")
            continue

        indexed: dict[str, dict[str, Any]] = {}
        for index, entry in enumerate(entries):
            entry_label = f"{label}: entries[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"{entry_label} must be a mapping")
                continue
            for field in ("id", "title", "type", "source_url"):
                if (
                    not isinstance(entry.get(field), str)
                    or not entry[field].strip()
                ):
                    errors.append(f"{entry_label}: {field} must be a non-empty string")
            entry_id = entry.get("id")
            if isinstance(entry_id, str):
                if entry_id in indexed:
                    errors.append(f"{entry_label}: duplicate identifier {entry_id}")
                indexed[entry_id] = entry
            if not _valid_https_url(entry.get("source_url")):
                errors.append(f"{entry_label}: source_url must be an HTTPS URL")
            if name == "slsa":
                if entry.get("track") != "build":
                    errors.append(f"{entry_label}: SLSA track must be 'build'")
                level_requirement = entry.get("level_requirement")
                if not isinstance(level_requirement, bool):
                    errors.append(
                        f"{entry_label}: SLSA level_requirement must be a boolean"
                    )
                elif level_requirement:
                    if entry.get("minimum_level") not in {1, 2, 3}:
                        errors.append(
                            f"{entry_label}: SLSA minimum_level must be 1, 2, or 3"
                        )
                    if (
                        entry.get("responsibility")
                        not in SLSA_BUILD_RESPONSIBILITIES
                    ):
                        errors.append(
                            f"{entry_label}: unsupported SLSA responsibility "
                            f"{entry.get('responsibility')!r}"
                        )
        entries_by_framework[name] = indexed

    for control in controls:
        control_label = str(control["_path"].relative_to(REPOSITORY_ROOT))
        for index, mapping in enumerate(control.get("mappings", [])):
            mapping_label = f"{control_label}: mappings[{index}]"
            framework = mapping.get("framework")
            registry = registries.get(framework)
            if registry is None:
                errors.append(
                    f"{mapping_label}: no registry exists for framework {framework!r}"
                )
                continue
            if mapping.get("version") != registry.get("mapping_version"):
                errors.append(
                    f"{mapping_label}: version {mapping.get('version')!r} does not "
                    f"match registry {registry.get('mapping_version')!r}"
                )
            entry = entries_by_framework.get(framework, {}).get(mapping.get("id"))
            if entry is None:
                errors.append(
                    f"{mapping_label}: unknown {framework} identifier "
                    f"{mapping.get('id')!r}"
                )
            elif entry.get("status", "active") != "active":
                errors.append(
                    f"{mapping_label}: identifier {mapping.get('id')!r} is not active"
                )

    return errors
