#!/usr/bin/env python3
"""Verify native dependency install-execution guardrails."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z-]+)+(?:\+[0-9A-Za-z.-]+)?$")
PACKAGE_RE = re.compile(r"^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$", re.IGNORECASE)


class InputError(ValueError):
    """Raised when input cannot be parsed and no reliable verdict is possible."""


def read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InputError(f"cannot read {label} {path}: {error}") from error


def parse_bool(value: str, label: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise InputError(f"{label} must be true or false")


def parse_npmrc(path: Path) -> dict[str, str]:
    settings: dict[str, str] = {}
    for number, raw_line in enumerate(read_text(path, "npm config").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            raise InputError(f"npm config line {number} must be key=value")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key or key in settings:
            raise InputError(f"npm config line {number} has empty or duplicate key")
        settings[key] = value
    return settings


def optional_bool(settings: dict[str, str], key: str, label: str) -> bool | None:
    if key not in settings:
        return None
    return parse_bool(settings[key], label)


def verify_npm(profile: Path) -> list[str]:
    settings = parse_npmrc(profile / "npm" / ".npmrc")
    ignore_scripts = optional_bool(settings, "ignore-scripts", "npm ignore-scripts")
    strict_allow = optional_bool(
        settings, "strict-allow-scripts", "npm strict-allow-scripts"
    )
    dangerous = optional_bool(
        settings,
        "dangerously-allow-all-scripts",
        "npm dangerously-allow-all-scripts",
    )

    findings: list[str] = []
    if dangerous is True:
        findings.append("npm dangerously-allow-all-scripts must not be true")
    if ignore_scripts is not True and strict_allow is not True:
        findings.append(
            "npm must set ignore-scripts=true or strict-allow-scripts=true"
        )
    return findings


def parse_pnpm(path: Path) -> tuple[dict[str, bool], dict[str, bool]]:
    root: dict[str, bool] = {}
    allow_builds: dict[str, bool] = {}
    in_allow_builds = False

    for number, raw_line in enumerate(read_text(path, "pnpm config").splitlines(), 1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line or ":" not in raw_line:
            raise InputError(f"pnpm config line {number} is not supported YAML")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        key, value = (part.strip() for part in raw_line.strip().split(":", 1))

        if indent == 0:
            in_allow_builds = key == "allowBuilds"
            if key in {"strictDepBuilds", "dangerouslyAllowAllBuilds"}:
                if key in root:
                    raise InputError(f"pnpm config line {number} duplicates {key}")
                root[key] = parse_bool(value, f"pnpm {key}")
            elif key == "allowBuilds":
                if value not in {"", "{}"}:
                    raise InputError(
                        f"pnpm config line {number} must use an allowBuilds map"
                    )
                if value == "{}":
                    in_allow_builds = False
            continue

        if in_allow_builds and indent == 2:
            if not key or key in allow_builds:
                raise InputError(f"pnpm config line {number} has invalid allowBuilds key")
            allow_builds[key] = parse_bool(value, f"pnpm allowBuilds.{key}")
        elif in_allow_builds:
            raise InputError(
                f"pnpm config line {number} has unsupported allowBuilds structure"
            )

    return root, allow_builds


def split_exact_selector(selector: str) -> tuple[str, str] | None:
    if selector.startswith("@"):
        slash = selector.find("/")
        split_at = selector.rfind("@")
        if slash < 0 or split_at <= slash:
            return None
    else:
        split_at = selector.rfind("@")
        if split_at <= 0:
            return None
    package, version = selector[:split_at], selector[split_at + 1 :]
    if not PACKAGE_RE.fullmatch(package) or not EXACT_VERSION_RE.fullmatch(version):
        return None
    return package, version


def verify_pnpm(profile: Path) -> list[str]:
    root, allow_builds = parse_pnpm(profile / "pnpm" / "pnpm-workspace.yaml")
    findings: list[str] = []
    if root.get("strictDepBuilds") is not True:
        findings.append("pnpm strictDepBuilds must be true")
    if root.get("dangerouslyAllowAllBuilds") is not False:
        findings.append("pnpm dangerouslyAllowAllBuilds must be false")
    for selector, allowed in allow_builds.items():
        if allowed and split_exact_selector(selector) is None:
            findings.append(
                f"pnpm allowBuilds true entry must pin exact version: {selector}"
            )
    return findings


def load_optional_json(path: Path, label: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(read_text(path, label))
    except json.JSONDecodeError as error:
        raise InputError(f"cannot parse {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must be a JSON object")
    return value


def verify_bun(profile: Path) -> list[str]:
    path = profile / "bun" / "bunfig.toml"
    try:
        config = tomllib.loads(read_text(path, "Bun config"))
    except tomllib.TOMLDecodeError as error:
        raise InputError(f"cannot parse Bun config {path}: {error}") from error
    install = config.get("install")
    if not isinstance(install, dict):
        raise InputError("Bun config missing [install] table")

    findings: list[str] = []
    ignore_scripts = install.get("ignoreScripts")
    if ignore_scripts is not True:
        findings.append("Bun strict profile must set install.ignoreScripts=true")

    package = load_optional_json(profile / "bun" / "package.json", "Bun package")
    if package is not None and ignore_scripts is not True:
        trusted = package.get("trustedDependencies", [])
        if not isinstance(trusted, list) or any(
            not isinstance(item, str) or not item for item in trusted
        ):
            raise InputError("Bun trustedDependencies must be a list of package names")
        for dependency in trusted:
            findings.append(
                f"Bun trustedDependencies can execute install scripts: {dependency}"
            )
    return findings


def logical_requirement_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        lines.append(pending)
        pending = ""
    if pending:
        raise InputError("pip requirements ends with an incomplete continuation")
    return lines


def verify_pip(profile: Path) -> list[str]:
    lines = logical_requirement_lines(
        read_text(profile / "pip" / "requirements.txt", "pip requirements")
    )
    options = {line.replace(" ", "") for line in lines if line.startswith("-")}
    findings: list[str] = []
    if not {"--only-binary=:all:", "--only-binary:all:"} & options:
        findings.append("pip requirements must set --only-binary=:all:")
    if any(option.startswith("--no-binary") for option in options):
        findings.append("pip requirements must not enable source distributions")
    return findings


def verify(profile: Path) -> list[str]:
    findings = verify_npm(profile)
    findings.extend(verify_pnpm(profile))
    findings.extend(verify_bun(profile))
    findings.extend(verify_pip(profile))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify native dependency install-execution guardrails."
    )
    parser.add_argument("--profile-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        findings = verify(args.profile_dir)
    except InputError as error:
        print(f"ERROR verification unavailable: {error}")
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        print(f"RESULT rejected with {len(findings)} finding(s)")
        return 1
    print("PASS install execution guardrails: npm pnpm Bun and pip profiles verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
