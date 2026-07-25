#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from typing import Any

from control_metadata import REPOSITORY_ROOT, discover_controls, validate_controls


def markdown_cell(value: Any) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def generate_mappings(controls: list[dict[str, Any]]) -> int:
    by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        for mapping in control.get("mappings", []):
            by_framework[mapping["framework"]].append(
                {
                    "control_id": control["id"],
                    "title": control["title"],
                    "mapping": mapping,
                }
            )

    output_directory = REPOSITORY_ROOT / "generated" / "mappings"
    output_directory.mkdir(parents=True, exist_ok=True)
    expected_files = {f"{framework}.md" for framework in by_framework}
    for existing in output_directory.glob("*.md"):
        if existing.name not in expected_files:
            existing.unlink()

    for framework, rows in sorted(by_framework.items()):
        lines = [
            f"# {framework} mappings",
            "",
            "| Control | Framework version | Identifier | Relationship | Confidence | Rationale |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for row in sorted(rows, key=lambda row: (row["mapping"]["id"], row["control_id"])):
            mapping = row["mapping"]
            control = f"{row['control_id']} - {row['title']}"
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(control),
                        markdown_cell(mapping["version"]),
                        markdown_cell(mapping["id"]),
                        markdown_cell(mapping["relationship"]),
                        markdown_cell(mapping["confidence"]),
                        markdown_cell(mapping["rationale"]),
                    ]
                )
                + " |"
            )

        output = output_directory / f"{framework}.md"
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return len(by_framework)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate framework mapping indexes from control metadata.")
    parser.add_argument("--check-only", action="store_true", help="Parse control metadata without writing files.")
    args = parser.parse_args()

    controls = discover_controls()
    errors = validate_controls(controls)
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    if args.check_only:
        print(f"control metadata parsed: {len(controls)} controls")
        return 0

    count = generate_mappings(controls)
    print(f"generated {count} framework mapping index files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
