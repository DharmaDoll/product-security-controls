#!/usr/bin/env python3
"""Run a read-only control assessment and write sanitized result artifacts."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from control_metadata import (
    REPOSITORY_ROOT,
    controls_by_id,
    discover_controls,
    validate_controls,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", required=True, help="Control ID to assess.")
    args = parser.parse_args()

    controls = discover_controls()
    errors = validate_controls(controls)
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 2

    control = controls_by_id(controls).get(args.control)
    if control is None:
        print(f"ERROR unknown control: {args.control}")
        return 2
    assessment = control.get("assessment")
    if not isinstance(assessment, dict):
        print(f"ERROR {args.control} has no read-only assessment implementation")
        return 2

    output_directory = REPOSITORY_ROOT / "generated" / "assessments"
    output_directory.mkdir(parents=True, exist_ok=True)
    command = control["_directory"] / assessment["command"]
    json_output = output_directory / f"{args.control}.json"
    csv_output = output_directory / f"{args.control}.csv"
    with tempfile.TemporaryDirectory(
        prefix=f"{args.control}-", dir=output_directory
    ) as temporary:
        temporary_directory = Path(temporary)
        candidate_json = temporary_directory / "result.json"
        candidate_csv = temporary_directory / "result.csv"
        result = subprocess.run(
            [
                sys.executable,
                str(command),
                "--workspace",
                str(REPOSITORY_ROOT),
                "--json-output",
                str(candidate_json),
                "--csv-output",
                str(candidate_csv),
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
        )
        produced_json = candidate_json.is_file()
        produced_csv = candidate_csv.is_file()
        if produced_json:
            candidate_json.replace(json_output)
        if produced_csv:
            candidate_csv.replace(csv_output)
    if produced_json:
        print(f"JSON {json_output.relative_to(REPOSITORY_ROOT)}")
    else:
        print("ERROR assessment did not produce JSON output")
    if produced_csv:
        print(f"CSV {csv_output.relative_to(REPOSITORY_ROOT)}")
    else:
        print("ERROR assessment did not produce CSV output")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
