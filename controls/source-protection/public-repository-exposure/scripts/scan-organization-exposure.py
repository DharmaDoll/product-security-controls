#!/usr/bin/env python3
"""Scan all reachable file versions for organization-specific indicators."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Pattern


CONTROL_DIRECTORY = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = CONTROL_DIRECTORY.parents[2]
SCANNER_PATH = (
    REPOSITORY_ROOT
    / "controls"
    / "source-protection"
    / "git-hooks-baseline"
    / "secure"
    / ".githooks"
    / "scan-sensitive.py"
)
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
ID_RE = re.compile(r"^ORG-[A-Z0-9]+(?:-[A-Z0-9]+)*$")


class ConfigurationError(ValueError):
    """Raised when the indicator configuration is unsafe or malformed."""


def load_repository_scanner():
    specification = importlib.util.spec_from_file_location(
        "psb_repository_sensitive_scanner", SCANNER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("repository-owned scanner cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    for name in ("git", "ScanError"):
        if not hasattr(module, name):
            raise RuntimeError("repository-owned scanner interface is incomplete")
    return module


def load_configuration(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"cannot parse indicator configuration: {error}") from error
    if not isinstance(value, dict):
        raise ConfigurationError("indicator configuration must be an object")
    if value.get("schema_version") != "1.0":
        raise ConfigurationError("indicator schema_version must be 1.0")
    maximum = value.get("max_file_bytes")
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum < 1024
        or maximum > 100 * 1024 * 1024
    ):
        raise ConfigurationError(
            "max_file_bytes must be between 1024 and 104857600"
        )
    return value


def indicator_entries(
    configuration: dict[str, Any], key: str, domain_values: bool
) -> list[tuple[str, str]]:
    entries = configuration.get(key)
    if not isinstance(entries, list):
        raise ConfigurationError(f"{key} must be a list")
    normalized: list[tuple[str, str]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"id", "value"}:
            raise ConfigurationError(f"{key}[{index}] must contain id and value")
        indicator_id = entry.get("id")
        value = entry.get("value")
        if not isinstance(indicator_id, str) or ID_RE.fullmatch(indicator_id) is None:
            raise ConfigurationError(f"{key}[{index}].id is invalid")
        if not isinstance(value, str) or len(value) < 4:
            raise ConfigurationError(f"{key}[{index}].value is too short")
        if any(character in value for character in ("*", "?", "[", "]", "{", "}")):
            raise ConfigurationError(f"{key}[{index}].value cannot use wildcards")
        if domain_values and DOMAIN_RE.fullmatch(value) is None:
            raise ConfigurationError(f"{key}[{index}].value is not a domain")
        normalized.append((indicator_id, value.lower() if domain_values else value))
    if len({indicator_id for indicator_id, _ in normalized}) != len(normalized):
        raise ConfigurationError(f"{key} contains duplicate ids")
    return normalized


def compile_rules(configuration: dict[str, Any]) -> list[tuple[str, Pattern[bytes]]]:
    rules: list[tuple[str, Pattern[bytes]]] = []
    all_ids: list[str] = []
    for indicator_id, domain in indicator_entries(configuration, "domains", True):
        expression = (
            rb"(?i)(?<![a-z0-9-])(?:[a-z0-9-]+\.)*"
            + re.escape(domain.encode("ascii"))
            + rb"(?![a-z0-9.-])"
        )
        rules.append((indicator_id, re.compile(expression)))
        all_ids.append(indicator_id)
    for indicator_id, domain in indicator_entries(
        configuration, "email_domains", True
    ):
        expression = (
            rb"(?i)(?<![a-z0-9._%+-])[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)*"
            + re.escape(domain.encode("ascii"))
            + rb"(?![a-z0-9.-])"
        )
        rules.append((indicator_id, re.compile(expression)))
        all_ids.append(indicator_id)
    for indicator_id, marker in indicator_entries(
        configuration, "confidentiality_markers", False
    ):
        rules.append(
            (
                indicator_id,
                re.compile(re.escape(marker.encode("utf-8")), re.IGNORECASE),
            )
        )
        all_ids.append(indicator_id)
    if not rules:
        raise ConfigurationError("at least one organization indicator is required")
    if len(set(all_ids)) != len(all_ids):
        raise ConfigurationError("organization indicator ids must be globally unique")
    return rules


def changed_paths(scanner: Any, commit: str) -> list[str]:
    return [
        raw.decode("utf-8", errors="surrogateescape")
        for raw in scanner.git(
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "--diff-filter=ACMR",
            "-r",
            "-z",
            commit,
        ).split(b"\0")
        if raw
    ]


def scan(repository: Path, configuration: dict[str, Any]) -> tuple[
    list[tuple[str, str]], list[str]
]:
    scanner = load_repository_scanner()
    rules = compile_rules(configuration)
    maximum = configuration["max_file_bytes"]
    os.chdir(repository)
    commits = [
        commit
        for commit in scanner.git("rev-list", "--all").decode("ascii").splitlines()
        if commit
    ]
    findings: list[tuple[str, str]] = []
    errors: list[str] = []
    for commit in commits:
        for path in changed_paths(scanner, commit):
            label = f"{commit[:12]}:{path}"
            try:
                content = scanner.git("show", f"{commit}:{path}")
            except scanner.ScanError:
                errors.append(label)
                continue
            if len(content) > maximum:
                errors.append(label)
                continue
            for indicator_id, pattern in rules:
                if pattern.search(content):
                    findings.append((indicator_id, label))
    return findings, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--indicators", type=Path, required=True)
    args = parser.parse_args()
    try:
        repository = args.repository.resolve(strict=True)
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("target is not a readable Git repository")
        configuration = load_configuration(args.indicators)
        findings, errors = scan(repository, configuration)
    except (ConfigurationError, OSError, RuntimeError, UnicodeError) as error:
        print(f"ERROR organization exposure scan failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print(
            "ERROR organization exposure scan could not inspect every file version",
            file=sys.stderr,
        )
        return 2

    for indicator_id, label in findings:
        print(f"BLOCK {indicator_id} {json.dumps(label, ensure_ascii=True)}")
    if errors:
        for label in errors:
            print(
                f"ERROR unscanned-file {json.dumps(label, ensure_ascii=True)}",
                file=sys.stderr,
            )
        print(
            f"ERROR {len(errors)} file version(s) could not be scanned",
            file=sys.stderr,
        )
        return 2
    if findings:
        print(
            f"REJECTED {len(findings)} organization exposure finding(s); "
            "matched values suppressed"
        )
        return 1
    print("ACCEPTED no organization-specific exposure findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
