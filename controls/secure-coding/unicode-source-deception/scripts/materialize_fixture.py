#!/usr/bin/env python3
"""Materialize an escaped inert Unicode source fixture into a temporary directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "psb-unicode-source-fixture/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS = {"schema", "output_name", "content", "materialized_sha256"}


def load_fixture(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load fixture manifest: {error}") from error
    if not isinstance(data, dict) or set(data) != REQUIRED_FIELDS:
        raise ValueError("fixture manifest fields are incomplete or unknown")
    if data.get("schema") != SCHEMA:
        raise ValueError(f"fixture schema must be {SCHEMA}")
    output_name = data.get("output_name")
    if (
        not isinstance(output_name, str)
        or Path(output_name).name != output_name
        or not output_name.endswith(".py")
    ):
        raise ValueError("fixture output_name must be one basename ending in .py")
    content = data.get("content")
    digest = data.get("materialized_sha256")
    if not isinstance(content, str) or not content:
        raise ValueError("fixture content must be a non-empty string")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("fixture materialized_sha256 must be a lowercase SHA-256")
    actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if actual != digest:
        raise ValueError("fixture materialized SHA-256 mismatch")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        fixture = load_fixture(args.fixture)
        args.output_directory.mkdir(parents=True, exist_ok=True)
        output = args.output_directory / fixture["output_name"]
        if output.exists() or output.is_symlink():
            raise ValueError("fixture output already exists")
        output.write_text(fixture["content"], encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    print(
        f"MATERIALIZED {fixture['output_name']} "
        f"sha256={fixture['materialized_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
