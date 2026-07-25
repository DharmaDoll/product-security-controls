#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import os
import re
from collections import defaultdict
from typing import Any


_SCALAR_RE = re.compile(r"^-?\d+$")


def parse_scalar(value: str) -> Any:
    if value == "":
        return ""
    if value in {"true", "false"}:
        return value == "true"
    if _SCALAR_RE.match(value):
        return int(value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_yaml_subset(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        entries = [
            (
                line_number,
                len(raw_line.rstrip("\n")) - len(raw_line.rstrip("\n").lstrip(" ")),
                raw_line.strip(),
            )
            for line_number, raw_line in enumerate(handle, start=1)
            if raw_line.strip() and not raw_line.lstrip().startswith("#")
        ]

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(entries):
            return {}, index

        is_list = entries[index][2].startswith("- ")
        value: list[Any] | dict[str, Any] = [] if is_list else {}

        while index < len(entries):
            line_number, current_indent, text = entries[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                raise ValueError(f"{path}:{line_number}: unexpected indentation")

            if is_list:
                if not text.startswith("- "):
                    break
                item_text = text[2:]
                if ": " in item_text:
                    key, scalar = item_text.split(": ", 1)
                    item: dict[str, Any] = {key: parse_scalar(scalar)}
                    index += 1
                    while index < len(entries) and entries[index][1] > current_indent:
                        nested_line, nested_indent, nested_text = entries[index]
                        if nested_indent != current_indent + 2 or ": " not in nested_text:
                            raise ValueError(f"{path}:{nested_line}: unsupported list mapping syntax")
                        nested_key, nested_scalar = nested_text.split(": ", 1)
                        item[nested_key] = parse_scalar(nested_scalar)
                        index += 1
                    value.append(item)
                elif item_text.endswith(":"):
                    key = item_text[:-1]
                    nested, index = parse_block(index + 1, current_indent + 2)
                    value.append({key: nested})
                else:
                    value.append(parse_scalar(item_text))
                    index += 1
                continue

            if text.startswith("- "):
                break
            if ": " in text:
                key, scalar = text.split(": ", 1)
                value[key] = parse_scalar(scalar)
                index += 1
                continue
            if text.endswith(":"):
                key = text[:-1]
                nested, index = parse_block(index + 1, current_indent + 2)
                value[key] = nested
                continue

            raise ValueError(f"{path}:{line_number}: unsupported YAML syntax")

        return value, index

    parsed, next_index = parse_block(0, 0)
    if next_index != len(entries) or not isinstance(parsed, dict):
        raise ValueError(f"{path}: unsupported YAML document")
    return parsed


def load_controls() -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    for path in sorted(glob.glob("controls/*/*/control.yaml")):
        data = parse_yaml_subset(path)
        data["_path"] = path
        controls.append(data)
    return controls


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

    os.makedirs("generated/mappings", exist_ok=True)
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

        with open(f"generated/mappings/{framework}.md", "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    return len(by_framework)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate framework mapping indexes from control metadata.")
    parser.add_argument("--check-only", action="store_true", help="Parse control metadata without writing files.")
    args = parser.parse_args()

    controls = load_controls()
    if args.check_only:
        print(f"control metadata parsed: {len(controls)} controls")
        return 0

    count = generate_mappings(controls)
    print(f"generated {count} framework mapping index files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
