#!/usr/bin/env python3
"""Generate the control catalog from control metadata."""

from __future__ import annotations

from control_metadata import REPOSITORY_ROOT, discover_controls, validate_controls


def markdown_cell(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def main() -> int:
    controls = discover_controls()
    errors = validate_controls(controls)
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1

    lines = [
        "# Control Index",
        "",
        "Generated control catalog. Do not edit manually.",
        "",
        "| ID | Domain | Title | Checks | Status | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for control in sorted(controls, key=lambda item: item["id"]):
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in (
                    control["id"],
                    control["domain"],
                    control["title"],
                    len(control["checks"]),
                    control["status"],
                    control["evidence_level"],
                )
            )
            + " |"
        )

    output = REPOSITORY_ROOT / "generated" / "CONTROL_INDEX.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(output.relative_to(REPOSITORY_ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
