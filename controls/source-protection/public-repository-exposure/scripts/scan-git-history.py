#!/usr/bin/env python3
"""Scan every reachable Git commit without printing matched secret values."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


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


def load_scanner():
    specification = importlib.util.spec_from_file_location(
        "psb_repository_sensitive_scanner", SCANNER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("repository-owned scanner cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    for name in ("git", "commit_findings", "emit", "ScanError"):
        if not hasattr(module, name):
            raise RuntimeError("repository-owned scanner interface is incomplete")
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    args = parser.parse_args()
    try:
        repository = args.repository.resolve(strict=True)
        scanner = load_scanner()
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("target is not a readable Git repository")
        os.chdir(repository)
        commits = [
            commit
            for commit in scanner.git("rev-list", "--all")
            .decode("ascii")
            .splitlines()
            if commit
        ]
        return scanner.emit(scanner.commit_findings(commits))
    except (OSError, RuntimeError, UnicodeError) as error:
        print(f"ERROR all-history scan failed: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        if "scanner" in locals() and isinstance(error, scanner.ScanError):
            print("ERROR all-history scan could not inspect every commit", file=sys.stderr)
            return 2
        print(f"ERROR all-history scan failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
