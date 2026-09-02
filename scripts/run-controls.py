#!/usr/bin/env python3
"""Run executable control verification and report external verification state."""

from __future__ import annotations

import argparse
import subprocess

from control_metadata import (
    REPOSITORY_ROOT,
    controls_by_id,
    discover_controls,
    validate_controls,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run or report control verification.")
    parser.add_argument("--control", help="Run only this control ID.")
    args = parser.parse_args()

    controls = discover_controls()
    errors = validate_controls(controls)
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 2

    if args.control:
        selected = controls_by_id(controls).get(args.control)
        if selected is None:
            print(f"unknown control: {args.control}")
            return 2
        controls = [selected]

    verified = 0
    not_checked = 0
    for control in sorted(controls, key=lambda item: item["id"]):
        verification = control["verification"]
        verification_type = verification.get("type", "automated")
        if verification_type in {"manual", "external-evidence"}:
            procedure = verification["procedure"]
            procedure_file, separator, anchor = procedure.partition("#")
            relative_procedure = (
                control["_directory"] / procedure_file
            ).relative_to(REPOSITORY_ROOT)
            anchor_suffix = f"#{anchor}" if separator else ""
            print(f"==> {control['id']}: {control['title']}", flush=True)
            print(
                f"NOT_CHECKED {control['id']} requires "
                f"{verification_type} verification"
            )
            print(f"See: {relative_procedure}{anchor_suffix}")
            not_checked += 1
            continue

        test_script = control["_directory"] / "tests" / "test.sh"
        print(f"==> {control['id']}: {control['title']}", flush=True)
        result = subprocess.run(
            ["bash", str(test_script)],
            cwd=REPOSITORY_ROOT,
            check=False,
        )
        if result.returncode != 0:
            print(f"{control['id']} verification failed with exit {result.returncode}")
            return 1
        verified += 1

    print(f"verified {verified} control(s); NOT_CHECKED {not_checked} control(s)")
    if args.control and not_checked:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
