#!/usr/bin/env python3
"""Import and reconcile an application vulnerability assessment source."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

from application_checklist_import import (
    ApplicationImportError,
    load_application_profile,
    write_application_profile,
)
from control_metadata import REPOSITORY_ROOT, discover_controls
from framework_registry import discover_registries


def _xlsx_writer():
    specification = importlib.util.spec_from_file_location(
        "psb_generate_checklists_for_application_import",
        REPOSITORY_ROOT / "scripts" / "generate-checklists.py",
    )
    if specification is None or specification.loader is None:
        raise ApplicationImportError("cannot load deterministic XLSX writer")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.write_xlsx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Write INPUT_REQUIRED status instead of failing when the manifest is absent.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = args.manifest.resolve()
    output = args.output.resolve()
    if not manifest.exists() and not args.allow_missing:
        print("ERROR application checklist source manifest is missing", file=sys.stderr)
        return 2
    try:
        result = load_application_profile(
            manifest,
            REPOSITORY_ROOT,
            discover_registries(),
            {control["id"] for control in discover_controls()},
        )
        write_application_profile(output, result, _xlsx_writer())
    except ApplicationImportError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    status = result["status_document"]
    if result["status"] == "INPUT_REQUIRED":
        print("INPUT_REQUIRED no application checklist profile was generated")
        return 0
    print(
        "GENERATED "
        f"{status['source_rows']} source rows and {status['public_atomic_rows']} public atomic rows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
