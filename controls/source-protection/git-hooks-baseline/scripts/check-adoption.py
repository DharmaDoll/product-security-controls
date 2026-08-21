#!/usr/bin/env python3
"""Check whether PSB-SOURCE-002 is activated in a target repository."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


MINIMUM_PYTHON = (3, 10)
MINIMUM_PRE_COMMIT = (4, 2, 0)
GITLEAKS_COMMIT = "6eaad039603a4de39fddd1cf5f727391efe9974e"
REQUIRED_HOOKS = (
    "pre-commit",
    "commit-msg",
    "pre-push",
    "pre-push-pre-commit",
    "scan-sensitive.py",
)


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise RuntimeError(f"cannot execute {command[0]}: {error}") from error


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def check_common(repository: Path) -> tuple[list[str], list[str]]:
    passes: list[str] = []
    errors: list[str] = []
    if sys.version_info < MINIMUM_PYTHON:
        errors.append("Python 3.10 or newer is required")
    else:
        passes.append(
            f"Python {sys.version_info.major}.{sys.version_info.minor} is supported"
        )

    if shutil.which("git") is None:
        errors.append("git is not available on PATH")
        return passes, errors
    git_version = run(["git", "--version"], repository)
    if git_version.returncode != 0:
        errors.append("git version check failed")
    else:
        passes.append(git_version.stdout.strip())

    root = run(["git", "rev-parse", "--show-toplevel"], repository)
    if root.returncode != 0:
        errors.append("target is not a Git worktree")
        return passes, errors
    if Path(root.stdout.strip()).resolve() != repository.resolve():
        errors.append("--repository must point to the Git worktree root")
    else:
        passes.append("target Git worktree root verified")

    hook_directory = repository / ".githooks"
    for name in REQUIRED_HOOKS:
        path = hook_directory / name
        if not path.is_file():
            errors.append(f"missing repository-owned hook .githooks/{name}")
        elif name != "scan-sensitive.py" and not path.stat().st_mode & 0o111:
            errors.append(f"hook .githooks/{name} is not executable")
    if not any(".githooks/" in error for error in errors):
        passes.append("repository-owned hook bundle is present")
    return passes, errors


def check_native(repository: Path, passes: list[str], errors: list[str]) -> None:
    hooks_path = run(
        ["git", "config", "--local", "--get", "core.hooksPath"], repository
    )
    if hooks_path.returncode != 0 or hooks_path.stdout.strip() != ".githooks":
        errors.append("local core.hooksPath must be .githooks")
    else:
        passes.append("native core.hooksPath activation verified")


def check_framework(repository: Path, passes: list[str], errors: list[str]) -> None:
    config_path = repository / ".pre-commit-config.yaml"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(".pre-commit-config.yaml is missing or malformed")
        config = {}
    repositories = config.get("repos") if isinstance(config, dict) else None
    pinned = False
    if isinstance(repositories, list):
        for item in repositories:
            if (
                isinstance(item, dict)
                and item.get("repo") == "https://github.com/gitleaks/gitleaks"
                and item.get("rev") == GITLEAKS_COMMIT
            ):
                pinned = True
                break
    if not pinned:
        errors.append("Gitleaks v8.30.0 full commit SHA pin is missing")
    else:
        passes.append("Gitleaks source pin verified")

    executable = shutil.which("pre-commit")
    if executable is None:
        errors.append("pre-commit is not available on PATH")
        return
    version = run([executable, "--version"], repository)
    parsed = parse_version(version.stdout)
    if version.returncode != 0 or parsed is None:
        errors.append("pre-commit version check failed")
    elif parsed < MINIMUM_PRE_COMMIT:
        errors.append("pre-commit 4.2.0 or newer is required")
    else:
        passes.append(f"pre-commit {'.'.join(str(part) for part in parsed)} is supported")

    for hook_name in ("pre-commit", "commit-msg", "pre-push"):
        hook_path = run(
            ["git", "rev-parse", "--git-path", f"hooks/{hook_name}"], repository
        )
        if hook_path.returncode != 0:
            errors.append(f"cannot resolve installed {hook_name} hook")
            continue
        path = Path(hook_path.stdout.strip())
        if not path.is_absolute():
            path = repository / path
        if not path.is_file():
            errors.append(f"pre-commit framework {hook_name} hook is not installed")
    if not any("framework" in error for error in errors):
        passes.append("pre-commit commit-msg and pre-push hooks are installed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--mode", choices=("native", "framework"), required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    if not repository.is_dir():
        print("ERROR target repository directory does not exist", file=sys.stderr)
        return 2

    try:
        passes, errors = check_common(repository)
        if args.mode == "native":
            check_native(repository, passes, errors)
        else:
            check_framework(repository, passes, errors)
    except RuntimeError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    for message in passes:
        print(f"PASS {message}")
    for message in errors:
        print(f"ERROR {message}")
    if errors:
        print(f"NOT_READY {len(errors)} adoption prerequisite(s) failed")
        return 2
    print(f"READY PSB-SOURCE-002 {args.mode} activation verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
