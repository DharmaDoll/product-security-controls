#!/usr/bin/env python3
"""Run all control tests, or one selected by control ID."""

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
    parser = argparse.ArgumentParser(description="Run control verification tests.")
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

    automated_count = 0
    not_checked_count = 0
    for control in sorted(controls, key=lambda item: item["id"]):
        print(f"==> {control['id']}: {control['title']}", flush=True)
        verification_type = control["verification"].get("type", "automated")
        if verification_type in {"manual", "external-evidence"}:
            readme = (control["_directory"] / "README.md").relative_to(
                REPOSITORY_ROOT
            )
            print(
                f"NOT_CHECKED {control['id']} uses {verification_type} verification; "
                f"follow {readme}"
            )
            not_checked_count += 1
            continue

        test_script = control["_directory"] / "tests" / "test.sh"
        result = subprocess.run(
            ["bash", str(test_script)],
            cwd=REPOSITORY_ROOT,
            check=False,
        )
        if result.returncode != 0:
            print(f"{control['id']} verification failed with exit {result.returncode}")
            return 1
        automated_count += 1

    print(
        f"verified {automated_count} automated/hybrid control(s); "
        f"{not_checked_count} manual/external control(s) NOT_CHECKED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
