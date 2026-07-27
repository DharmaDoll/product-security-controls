#!/usr/bin/env python3
"""Verify the declarative Git security baseline and hook bundle."""

from __future__ import annotations

import argparse
import configparser
import json
import re
import sys
from pathlib import Path


REQUIRED = {
    ("core", "hookspath"): ".githooks",
    ("push", "default"): "simple",
    ("commit", "gpgsign"): "true",
    ("tag", "gpgsign"): "true",
    ("user", "useconfigonly"): "true",
}
REQUIRED_HOOKS = {
    "pre-commit",
    "commit-msg",
    "pre-push",
    "pre-push-pre-commit",
    "scan-sensitive.py",
}
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
GITLEAKS_REPOSITORY = "https://github.com/gitleaks/gitleaks"
GITLEAKS_COMMIT = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
PRE_COMMIT_HOOKS = {
    "psb-sensitive-staged": {
        "entry": "sh .githooks/pre-commit",
        "pass_filenames": False,
        "stage": "pre-commit",
    },
    "psb-sensitive-commit-message": {
        "entry": "sh .githooks/commit-msg",
        "pass_filenames": True,
        "stage": "commit-msg",
    },
    "psb-sensitive-push-history": {
        "entry": "sh .githooks/pre-push-pre-commit",
        "pass_filenames": False,
        "stage": "pre-push",
    },
}


def load_config(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError, configparser.Error) as error:
        raise ValueError(f"cannot parse {path}: {error}") from error
    return parser


def load_pre_commit_config(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a mapping")
    return value


def inspect_pre_commit_config(profile: Path) -> list[str]:
    path = profile / "pre-commit-framework" / ".pre-commit-config.yaml"
    config = load_pre_commit_config(path)
    findings: list[str] = []
    if config.get("minimum_pre_commit_version") != "4.2.0":
        findings.append("pre-commit minimum version must be 4.2.0")
    if config.get("default_install_hook_types") != [
        "pre-commit",
        "commit-msg",
        "pre-push",
    ]:
        findings.append(
            "pre-commit default install types must include "
            "pre-commit, commit-msg, and pre-push"
        )

    repositories = config.get("repos")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("pre-commit repos must be a non-empty list")
    configured_hooks: dict[str, dict[str, object]] = {}
    gitleaks_repository: dict[str, object] | None = None
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise ValueError(f"pre-commit repos[{index}] must be a mapping")
        source = repository.get("repo")
        if not isinstance(source, str) or not source:
            raise ValueError(f"pre-commit repos[{index}].repo must be text")
        if source != "local":
            revision = repository.get("rev")
            if not isinstance(revision, str) or FULL_COMMIT_RE.fullmatch(revision) is None:
                findings.append(
                    f"pre-commit external repo {source} must use a full commit SHA"
                )
        if source == GITLEAKS_REPOSITORY:
            gitleaks_repository = repository
        hooks = repository.get("hooks")
        if not isinstance(hooks, list):
            raise ValueError(f"pre-commit repos[{index}].hooks must be a list")
        for hook_index, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                raise ValueError(
                    f"pre-commit repos[{index}].hooks[{hook_index}] "
                    "must be a mapping"
                )
            hook_id = hook.get("id")
            if isinstance(hook_id, str):
                configured_hooks[hook_id] = hook

    for hook_id, expected in PRE_COMMIT_HOOKS.items():
        hook = configured_hooks.get(hook_id)
        if hook is None:
            findings.append(f"pre-commit hook {hook_id} is missing")
            continue
        if hook.get("entry") != expected["entry"]:
            findings.append(f"pre-commit hook {hook_id} entry is not repository-owned")
        if hook.get("language") != "system":
            findings.append(f"pre-commit hook {hook_id} language must be system")
        if hook.get("pass_filenames") is not expected["pass_filenames"]:
            findings.append(
                f"pre-commit hook {hook_id} pass_filenames is incorrect"
            )
        if hook.get("always_run") is not True:
            findings.append(f"pre-commit hook {hook_id} must always run")
        if hook.get("stages") != [expected["stage"]]:
            findings.append(f"pre-commit hook {hook_id} stage is incorrect")

    if gitleaks_repository is None:
        findings.append("Gitleaks pre-commit repository is missing")
    else:
        if gitleaks_repository.get("rev") != GITLEAKS_COMMIT:
            findings.append(
                "Gitleaks must be pinned to the reviewed v8.30.1 full commit SHA"
            )
        gitleaks_hooks = gitleaks_repository.get("hooks")
        gitleaks_hook = None
        if isinstance(gitleaks_hooks, list):
            gitleaks_hook = next(
                (
                    hook
                    for hook in gitleaks_hooks
                    if isinstance(hook, dict) and hook.get("id") == "gitleaks"
                ),
                None,
            )
        if gitleaks_hook is None:
            findings.append("Gitleaks pre-commit hook is missing")
        else:
            if gitleaks_hook.get("args") != ["--redact"]:
                findings.append("Gitleaks pre-commit output must redact secret values")
            if gitleaks_hook.get("pass_filenames") is not False:
                findings.append("Gitleaks must scan the staged Git state")
            if gitleaks_hook.get("always_run") is not True:
                findings.append("Gitleaks pre-commit hook must always run")
            if gitleaks_hook.get("stages") != ["pre-commit"]:
                findings.append("Gitleaks hook stage must be pre-commit")
    return findings


def inspect(profile: Path) -> list[str]:
    config_path = profile / "recommended.gitconfig"
    parser = load_config(config_path)
    findings: list[str] = []

    for (section, option), expected in REQUIRED.items():
        actual = parser.get(section, option, fallback="<missing>").strip()
        if actual != expected:
            findings.append(
                f"{section}.{option}: expected={expected} actual={actual}"
            )

    credential_helper = parser.get("credential", "helper", fallback="").strip()
    if credential_helper == "store":
        findings.append("credential.helper: plaintext store is prohibited")
    safe_directory = parser.get("safe", "directory", fallback="").strip()
    if safe_directory == "*":
        findings.append("safe.directory: wildcard trust is prohibited")

    hooks_path = profile / ".githooks"
    for name in sorted(REQUIRED_HOOKS):
        hook = hooks_path / name
        if not hook.is_file():
            findings.append(f"hook {name}: missing")
        elif not hook.stat().st_mode & 0o111:
            findings.append(f"hook {name}: not executable")
    findings.extend(inspect_pre_commit_config(profile))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    try:
        findings = inspect(args.profile)
    except ValueError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL {finding}")
    if findings:
        print(f"REJECTED {len(findings)} baseline finding(s)")
        return 1
    print("ACCEPTED Git hooks security baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
