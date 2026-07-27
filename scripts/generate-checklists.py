#!/usr/bin/env python3
"""Generate deterministic adoption checklist views from control metadata."""

from __future__ import annotations

import argparse
import csv
import io
import shutil
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from control_metadata import REPOSITORY_ROOT, discover_controls, validate_controls
from framework_registry import discover_registries, validate_registries


GUIDELINE_HEADERS = [
    "Control ID",
    "Check ID",
    "Domain",
    "Control Title",
    "Control Path",
    "Control Summary",
    "Check Title",
    "Security Functions",
    "Threat Scenarios",
    "Threat Actor or Source",
    "Row Attack or Failure Scenario",
    "Why This Check Is Required",
    "Secure Examples",
    "Required State",
    "Responsible Role",
    "Applies To",
    "Verification Type",
    "Verification Method",
    "Expected Result",
    "Required Evidence",
    "Assessment Command",
    "Assessment Platforms",
    "SLSA Track",
    "SLSA Requirement Levels",
    "SLSA Minimum Level",
    "SLSA Responsibility",
    "SLSA Build L2 Scope",
    "Framework Mappings",
    "Mapping Status",
    "Limitations",
]
ASSESSMENT_HEADERS = GUIDELINE_HEADERS + [
    "Implementation Status",
    "Assessment Result",
    "Evidence URL",
    "Assignee",
    "Due Date",
    "Exception ID",
    "Notes",
]
MAPPING_HEADERS = [
    "Control ID",
    "Check ID",
    "Framework",
    "Version",
    "Identifier",
    "Relationship",
    "Confidence",
    "Rationale",
    "Reviewer",
    "Review Date",
    "SLSA Track",
    "SLSA Minimum Level",
    "SLSA Responsibility",
    "SLSA Level Requirement",
]
EVIDENCE_HEADERS = [
    "Control ID",
    "Check ID",
    "Responsible Role",
    "Verification Type",
    "Required Evidence",
]
EXCEPTION_HEADERS = [
    "Control ID",
    "Check ID",
    "Exception ID",
    "Owner",
    "Justification",
    "Compensating Controls",
    "Approved By",
    "Expiry Date",
    "Status",
]
SLSA_COVERAGE_HEADERS = [
    "Profile",
    "Framework Version",
    "Track",
    "Target Level",
    "Requirement ID",
    "Requirement Minimum Level",
    "Responsibility",
    "Requirement",
    "Status",
    "Mapped Checks",
    "Mapping Rationale",
]
FIXED_ZIP_TIME = (2026, 7, 27, 0, 0, 0)


def _joined(values: Iterable[Any]) -> str:
    return "; ".join(str(value) for value in values)


def _mapping_summary(mapping: dict[str, Any]) -> str:
    return (
        f"{mapping['framework']} {mapping['version']} / {mapping['id']} / "
        f"{mapping['relationship']} / {mapping['confidence']}"
    )


def build_rows(
    controls: list[dict[str, Any]],
    registries: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    if registries is None:
        registries = discover_registries()
    slsa_entries = {
        entry["id"]: entry
        for entry in registries.get("slsa", {}).get("entries", [])
    }
    checklist_rows: list[dict[str, str]] = []
    mapping_rows: list[dict[str, str]] = []
    evidence_rows: list[dict[str, str]] = []

    for control in sorted(controls, key=lambda item: item["id"]):
        mappings_by_check: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for mapping in control["mappings"]:
            for check_id in mapping["applies_to"]:
                mappings_by_check[check_id].append(mapping)

        for check in control["checks"]:
            full_check_id = f"{control['id']}-{check['id']}"
            check_mappings = sorted(
                mappings_by_check.get(check["id"], []),
                key=lambda item: (item["framework"], item["id"]),
            )
            if check_mappings:
                mapping_summary = _joined(_mapping_summary(item) for item in check_mappings)
            else:
                mapping_summary = "UNMAPPED — framework review required"

            verification = check["verification"]
            context = check.get("context", {})
            assessment = control.get("assessment", {})
            slsa_mappings = [
                mapping
                for mapping in check_mappings
                if mapping["framework"] == "slsa"
            ]
            slsa_check_entries = [
                slsa_entries[mapping["id"]]
                for mapping in slsa_mappings
                if mapping["id"] in slsa_entries
            ]
            slsa_level_entries = [
                entry
                for entry in slsa_check_entries
                if entry.get("level_requirement") is True
            ]
            slsa_levels = sorted(
                {
                    int(entry["minimum_level"])
                    for entry in slsa_level_entries
                }
            )
            if slsa_levels:
                slsa_l2_scope = (
                    "included"
                    if any(level <= 2 for level in slsa_levels)
                    else "excluded-higher-level"
                )
            elif slsa_check_entries:
                slsa_l2_scope = "related-no-level"
            else:
                slsa_l2_scope = ""
            checklist_rows.append(
                {
                    "Control ID": control["id"],
                    "Check ID": full_check_id,
                    "Domain": control["domain"],
                    "Control Title": control["title"],
                    "Control Path": str(
                        control["_directory"].relative_to(REPOSITORY_ROOT) / "README.md"
                    ),
                    "Control Summary": control["summary"],
                    "Check Title": check["title"],
                    "Security Functions": _joined(control["security_functions"]),
                    "Threat Scenarios": _joined(
                        f"{threat['id']}: {threat['description']}"
                        for threat in control["threats"]
                    ),
                    "Threat Actor or Source": context.get("threat_actor", ""),
                    "Row Attack or Failure Scenario": context.get(
                        "attack_or_failure_scenario", ""
                    ),
                    "Why This Check Is Required": context.get("why_required", ""),
                    "Secure Examples": _joined(
                        str(control["_directory"].relative_to(REPOSITORY_ROOT) / path)
                        for path in control["implementations"]["secure"]
                    ),
                    "Required State": check["required_state"],
                    "Responsible Role": check["responsible_role"],
                    "Applies To": _joined(check["applies_to"]),
                    "Verification Type": verification["type"],
                    "Verification Method": verification["method"],
                    "Expected Result": verification["expected"],
                    "Required Evidence": _joined(verification["evidence"]),
                    "Assessment Command": (
                        f"make assess-control CONTROL={control['id']}"
                        if assessment
                        else ""
                    ),
                    "Assessment Platforms": _joined(
                        assessment.get("platforms", [])
                        if isinstance(assessment, dict)
                        else []
                    ),
                    "SLSA Track": _joined(
                        sorted(
                            {
                                entry["track"]
                                for entry in slsa_check_entries
                                if entry.get("track")
                            }
                        )
                    ),
                    "SLSA Requirement Levels": _joined(
                        f"L{level}" for level in slsa_levels
                    ),
                    "SLSA Minimum Level": (
                        str(min(slsa_levels)) if slsa_levels else ""
                    ),
                    "SLSA Responsibility": _joined(
                        sorted(
                            {
                                entry["responsibility"]
                                for entry in slsa_level_entries
                                if entry.get("responsibility")
                            }
                        )
                    ),
                    "SLSA Build L2 Scope": slsa_l2_scope,
                    "Framework Mappings": mapping_summary,
                    "Mapping Status": check["mapping_status"],
                    "Limitations": _joined(control["limitations"]),
                }
            )
            for evidence in verification["evidence"]:
                evidence_rows.append(
                    {
                        "Control ID": control["id"],
                        "Check ID": full_check_id,
                        "Responsible Role": check["responsible_role"],
                        "Verification Type": verification["type"],
                        "Required Evidence": evidence,
                    }
                )
            for mapping in check_mappings:
                slsa_entry = (
                    slsa_entries.get(mapping["id"], {})
                    if mapping["framework"] == "slsa"
                    else {}
                )
                mapping_rows.append(
                    {
                        "Control ID": control["id"],
                        "Check ID": full_check_id,
                        "Framework": mapping["framework"],
                        "Version": mapping["version"],
                        "Identifier": mapping["id"],
                        "Relationship": mapping["relationship"],
                        "Confidence": mapping["confidence"],
                        "Rationale": mapping["rationale"],
                        "Reviewer": mapping["reviewer"],
                        "Review Date": mapping["review_date"],
                        "SLSA Track": str(slsa_entry.get("track", "")),
                        "SLSA Minimum Level": str(
                            slsa_entry.get("minimum_level", "")
                        ),
                        "SLSA Responsibility": str(
                            slsa_entry.get("responsibility", "")
                        ),
                        "SLSA Level Requirement": (
                            "true"
                            if slsa_entry.get("level_requirement") is True
                            else "false"
                            if slsa_entry
                            else ""
                        ),
                    }
                )

    return checklist_rows, mapping_rows, evidence_rows


def build_slsa_l2_profile(
    controls: list[dict[str, Any]],
    checklist_rows: list[dict[str, str]],
    slsa_registry: dict[str, Any],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    selected_checks = [
        row for row in checklist_rows if row["SLSA Build L2 Scope"] == "included"
    ]
    mappings_by_requirement: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(
        list
    )
    for control in controls:
        for mapping in control["mappings"]:
            if mapping["framework"] != "slsa":
                continue
            for check_id in mapping["applies_to"]:
                mappings_by_requirement[mapping["id"]].append(
                    (f"{control['id']}-{check_id}", mapping)
                )

    coverage_rows: list[dict[str, str]] = []
    for entry in sorted(
        slsa_registry["entries"],
        key=lambda item: (item.get("minimum_level", 99), item["id"]),
    ):
        if (
            entry.get("track") != "build"
            or entry.get("level_requirement") is not True
            or int(entry["minimum_level"]) > 2
        ):
            continue
        mapped = mappings_by_requirement.get(entry["id"], [])
        coverage_rows.append(
            {
                "Profile": "slsa-build-l2",
                "Framework Version": slsa_registry["mapping_version"],
                "Track": "build",
                "Target Level": "2",
                "Requirement ID": entry["id"],
                "Requirement Minimum Level": str(entry["minimum_level"]),
                "Responsibility": entry["responsibility"],
                "Requirement": entry["title"],
                "Status": "mapped-evidence" if mapped else "gap",
                "Mapped Checks": _joined(
                    sorted({check_id for check_id, _ in mapped})
                ),
                "Mapping Rationale": _joined(
                    sorted({mapping["rationale"] for _, mapping in mapped})
                ),
            }
        )
    return selected_checks, coverage_rows


def write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=headers,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    header: _csv_safe_text(row.get(header, ""))
                    for header in headers
                }
            )


def _csv_safe_text(value: Any) -> str:
    """Prevent generated CSV fields from being interpreted as formulas."""

    rendered = str(value)
    if rendered.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + rendered
    return rendered


def _markdown_cell(value: str) -> str:
    return value.replace("\n", " ").replace("|", "\\|")


def write_markdown(path: Path, rows: list[dict[str, str]]) -> None:
    headers = [
        "Control ID",
        "Check ID",
        "Domain",
        "Check Title",
        "Threat Actor or Source",
        "Row Attack or Failure Scenario",
        "Why This Check Is Required",
        "Responsible Role",
        "Verification Type",
        "Mapping Status",
        "Framework Mappings",
    ]
    lines = [
        "# Product Security Adoption Checklist",
        "",
        "Generated from control metadata. Do not edit manually.",
        "",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append(
            "| " + " | ".join(_markdown_cell(row[header]) for header in headers) + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _column_name(index: int) -> str:
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _sheet_xml(headers: list[str], rows: list[list[str]]) -> str:
    all_rows = [headers, *rows]
    row_xml: list[str] = []
    for row_index, row in enumerate(all_rows, start=1):
        cells: list[str] = []
        for column_index, value in enumerate(row, start=1):
            reference = f"{_column_name(column_index)}{row_index}"
            style = ' s="1"' if row_index == 1 else ""
            text = "".join(
                character
                for character in str(value)
                if character in "\t\n\r" or ord(character) >= 32
            )
            rendered = escape(text, {'"': "&quot;"})
            cells.append(
                f'<c r="{reference}" t="inlineStr"{style}>'
                f'<is><t xml:space="preserve">{rendered}</t></is></c>'
            )
        row_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    widths = []
    for index, header in enumerate(headers, start=1):
        width = min(max(len(header) + 2, 14), 42)
        widths.append(
            f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        )
    final_cell = f"{_column_name(len(headers))}{max(len(all_rows), 1)}"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        '<sheetFormatPr defaultRowHeight="15"/>'
        f'<cols>{"".join(widths)}</cols>'
        f'<sheetData>{"".join(row_xml)}</sheetData>'
        f'<autoFilter ref="A1:{final_cell}"/>'
        "</worksheet>"
    )


def _zip_member(archive: zipfile.ZipFile, name: str, content: str) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, content.encode("utf-8"))


def write_xlsx(path: Path, sheets: list[tuple[str, list[str], list[list[str]]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'spreadsheetml.worksheet+xml"/>'
        for index in range(1, len(sheets) + 1)
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{content_overrides}</Types>"
    )
    root_relationships = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    workbook_sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _, _) in enumerate(sheets, start=1)
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{workbook_sheets}</sheets></workbook>"
    )
    workbook_relationships = "".join(
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(sheets) + 1)
    )
    workbook_relationships += (
        f'<Relationship Id="rId{len(sheets) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{workbook_relationships}</Relationships>"
    )
    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font/><font><b/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border/></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        "</cellXfs></styleSheet>"
    )

    with zipfile.ZipFile(path, "w") as archive:
        _zip_member(archive, "[Content_Types].xml", content_types)
        _zip_member(archive, "_rels/.rels", root_relationships)
        _zip_member(archive, "xl/workbook.xml", workbook)
        _zip_member(archive, "xl/_rels/workbook.xml.rels", workbook_rels)
        _zip_member(archive, "xl/styles.xml", styles)
        for index, (_, headers, rows) in enumerate(sheets, start=1):
            _zip_member(
                archive,
                f"xl/worksheets/sheet{index}.xml",
                _sheet_xml(headers, rows),
            )


def _dict_rows(rows: list[dict[str, str]], headers: list[str]) -> list[list[str]]:
    return [[row.get(header, "") for header in headers] for row in rows]


def _readme_rows() -> list[list[str]]:
    return [
        ["Purpose", "Repository-owned Product Security adoption guidance generated from control.yaml."],
        ["Source of truth", "Edit control.yaml files and regenerate; do not edit this workbook."],
        ["PASS", "The required state was verified with the required evidence."],
        ["FAIL", "Verification ran and the required state was not met."],
        ["NOT_CHECKED", "Manual or external evidence has not been supplied."],
        ["ERROR", "Verification failed to execute or could not establish a result; never treat as clean."],
        ["N/A", "A reviewed, owned, justified, and time-bound exception establishes non-applicability."],
        ["Mappings", "Relationships support traceability and are not automatic compliance claims."],
        ["Assessment", "A listed assessment command is read only; NOT_CHECKED and ERROR are not PASS."],
    ]


def generate_checklists(controls: list[dict[str, Any]], output: Path) -> None:
    registries = discover_registries()
    checklist_rows, mapping_rows, evidence_rows = build_rows(controls, registries)
    slsa_l2_rows, slsa_l2_coverage = build_slsa_l2_profile(
        controls,
        checklist_rows,
        registries["slsa"],
    )
    output.mkdir(parents=True, exist_ok=True)

    write_csv(output / "product-security-checklist.csv", ASSESSMENT_HEADERS, checklist_rows)
    write_csv(output / "framework-mappings.csv", MAPPING_HEADERS, mapping_rows)
    write_csv(output / "required-evidence.csv", EVIDENCE_HEADERS, evidence_rows)
    write_markdown(output / "product-security-checklist.md", checklist_rows)
    write_csv(
        output / "profiles" / "slsa-build-l2.csv",
        ASSESSMENT_HEADERS,
        slsa_l2_rows,
    )
    write_csv(
        output / "profiles" / "slsa-build-l2-coverage.csv",
        SLSA_COVERAGE_HEADERS,
        slsa_l2_coverage,
    )

    domains: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in checklist_rows:
        domains[row["Domain"]].append(row)
    for domain, rows in sorted(domains.items()):
        write_csv(output / "domains" / f"{domain}.csv", ASSESSMENT_HEADERS, rows)

    mapping_table = _dict_rows(mapping_rows, MAPPING_HEADERS)
    evidence_table = _dict_rows(evidence_rows, EVIDENCE_HEADERS)
    domain_sheets = [
        (domain[:31], GUIDELINE_HEADERS, _dict_rows(rows, GUIDELINE_HEADERS))
        for domain, rows in sorted(domains.items())
    ]
    guideline_sheets = [
        ("README", ["Field", "Guidance"], _readme_rows()),
        ("Checklist", GUIDELINE_HEADERS, _dict_rows(checklist_rows, GUIDELINE_HEADERS)),
        ("Framework Mappings", MAPPING_HEADERS, mapping_table),
        ("Evidence", EVIDENCE_HEADERS, evidence_table),
        (
            "SLSA Build L2",
            GUIDELINE_HEADERS,
            _dict_rows(slsa_l2_rows, GUIDELINE_HEADERS),
        ),
        (
            "SLSA L2 Coverage",
            SLSA_COVERAGE_HEADERS,
            _dict_rows(slsa_l2_coverage, SLSA_COVERAGE_HEADERS),
        ),
        *domain_sheets,
    ]
    assessment_sheets = [
        ("README", ["Field", "Guidance"], _readme_rows()),
        ("Checklist", ASSESSMENT_HEADERS, _dict_rows(checklist_rows, ASSESSMENT_HEADERS)),
        ("Framework Mappings", MAPPING_HEADERS, mapping_table),
        ("Evidence", EVIDENCE_HEADERS, evidence_table),
        (
            "SLSA Build L2",
            ASSESSMENT_HEADERS,
            _dict_rows(slsa_l2_rows, ASSESSMENT_HEADERS),
        ),
        (
            "SLSA L2 Coverage",
            SLSA_COVERAGE_HEADERS,
            _dict_rows(slsa_l2_coverage, SLSA_COVERAGE_HEADERS),
        ),
        ("Exceptions", EXCEPTION_HEADERS, []),
    ]
    write_xlsx(output / "product-security-guideline.xlsx", guideline_sheets)
    write_xlsx(output / "product-security-assessment-template.xlsx", assessment_sheets)

    readme = (
        "# Generated adoption checklists\n\n"
        "These files are generated from `controls/*/*/control.yaml`. Do not edit "
        "them manually.\n\n"
        "Regenerate from the repository root:\n\n"
        "```bash\nmake generate-checklists\n```\n\n"
        "Copy `product-security-assessment-template.xlsx` outside this generated "
        "directory before recording organization-owned results. Regeneration "
        "replaces the blank template.\n\n"
        "`profiles/slsa-build-l2.csv` is the cumulative L1+L2 check view. "
        "`profiles/slsa-build-l2-coverage.csv` keeps unmapped requirements "
        "visible as gaps; mapped evidence is not a SLSA level claim.\n"
    )
    (output / "README.md").write_text(readme, encoding="utf-8")


def compare_directories(expected: Path, actual: Path) -> list[str]:
    expected_files = {
        path.relative_to(expected): path for path in expected.rglob("*") if path.is_file()
    }
    actual_files = {
        path.relative_to(actual): path for path in actual.rglob("*") if path.is_file()
    }
    errors = []
    for relative in sorted(expected_files.keys() - actual_files.keys()):
        errors.append(f"missing generated file: {relative}")
    for relative in sorted(actual_files.keys() - expected_files.keys()):
        errors.append(f"unexpected generated file: {relative}")
    for relative in sorted(expected_files.keys() & actual_files.keys()):
        if expected_files[relative].read_bytes() != actual_files[relative].read_bytes():
            errors.append(f"stale generated file: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed checklist outputs are current without changing them.",
    )
    args = parser.parse_args()

    controls = discover_controls()
    errors = validate_controls(controls)
    registries = discover_registries()
    errors.extend(validate_registries(registries, controls))
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1

    output = REPOSITORY_ROOT / "generated" / "checklists"
    if args.check:
        with tempfile.TemporaryDirectory(prefix="psb-checklists-") as temporary:
            candidate = Path(temporary) / "checklists"
            generate_checklists(controls, candidate)
            differences = compare_directories(candidate, output)
        if differences:
            for difference in differences:
                print(f"ERROR {difference}")
            return 1
        print(f"checklists are current: {len(controls)} controls")
        return 0

    if output.exists():
        shutil.rmtree(output)
    generate_checklists(controls, output)
    print(f"generated checklists for {len(controls)} controls in {output.relative_to(REPOSITORY_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
