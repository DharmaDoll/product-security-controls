from __future__ import annotations

import csv
import importlib.util
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "generate_checklists",
    REPOSITORY_ROOT / "scripts" / "generate-checklists.py",
)
assert SPEC and SPEC.loader
generate_checklists = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_checklists)


class GenerateChecklistsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()

    def test_every_atomic_check_is_exported_once(self) -> None:
        checklist, mappings, evidence = generate_checklists.build_rows(self.controls)
        expected = sum(len(control["checks"]) for control in self.controls)
        self.assertEqual(len(checklist), expected)
        self.assertEqual(len({row["Check ID"] for row in checklist}), expected)
        self.assertTrue(mappings)
        self.assertGreaterEqual(len(evidence), expected)

    def test_unmapped_checks_are_explicit(self) -> None:
        checklist, _, _ = generate_checklists.build_rows(self.controls)
        unmapped = [row for row in checklist if row["Mapping Status"] == "unmapped"]
        self.assertTrue(unmapped)
        for row in unmapped:
            self.assertEqual(
                row["Framework Mappings"],
                "UNMAPPED — framework review required",
            )

    def test_generation_is_deterministic_and_xlsx_is_valid_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            generate_checklists.generate_checklists(self.controls, first)
            generate_checklists.generate_checklists(self.controls, second)
            self.assertEqual(
                generate_checklists.compare_directories(first, second),
                [],
            )
            workbook = first / "product-security-guideline.xlsx"
            with zipfile.ZipFile(workbook) as archive:
                self.assertIn("xl/workbook.xml", archive.namelist())
                workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
                self.assertIn('name="Checklist"', workbook_xml)
                self.assertIn('name="Framework Mappings"', workbook_xml)
                self.assertIn('name="Governance Summary"', workbook_xml)
                self.assertIn('name="Catalog Governance"', workbook_xml)
                self.assertIn('name="SSC Integration"', workbook_xml)
                self.assertIn('name="PSIRT Capability"', workbook_xml)
                for name in archive.namelist():
                    if name.endswith((".xml", ".rels")):
                        ET.fromstring(archive.read(name))

    def test_csv_is_excel_friendly_and_contains_framework_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            generate_checklists.generate_checklists(self.controls, output)
            path = output / "product-security-checklist.csv"
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))
            with path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            reviewed = next(row for row in rows if row["Mapping Status"] == "reviewed")
            self.assertIn(" / ", reviewed["Framework Mappings"])

    def test_context_is_exported_for_every_checklist_row(self) -> None:
        checklist, _, _ = generate_checklists.build_rows(self.controls)
        self.assertTrue(checklist)
        for row in checklist:
            self.assertTrue(row["Threat Actor or Source"])
            self.assertTrue(row["Row Attack or Failure Scenario"])
            self.assertTrue(row["Why This Check Is Required"])

    def test_governance_view_keeps_catalog_maturity_separate_from_adoption(self) -> None:
        rows, summary = generate_checklists.build_governance_rows(self.controls)
        self.assertEqual(len(rows), len(self.controls))
        self.assertEqual(
            {row["Control ID"] for row in rows},
            {control["id"] for control in self.controls},
        )
        for row in rows:
            self.assertEqual(row["Catalog Claim Boundary"], "REFERENCE_IMPLEMENTATION_ONLY")
            self.assertEqual(row["Organization Adoption"], "NOT_CHECKED")
            self.assertEqual(row["Evidence Freshness"], "NOT_CHECKED")
            self.assertEqual(row["Active Exceptions"], "NOT_CHECKED")
            self.assertEqual(row["Expiring Exceptions"], "NOT_CHECKED")
            self.assertEqual(row["Expired or Invalid Exceptions"], "NOT_CHECKED")
            self.assertEqual(row["Governance Result"], "NOT_CHECKED")
            self.assertEqual(
                int(row["Reviewed Mapping Checks"])
                + int(row["Provisional Mapping Checks"])
                + int(row["Unmapped Checks"]),
                int(row["Atomic Checks"]),
            )
        summary_by_metric = {item["Metric"]: item for item in summary}
        self.assertEqual(
            summary_by_metric["Organization adoption"]["Value"], "NOT_CHECKED"
        )
        self.assertEqual(
            summary_by_metric["Evidence freshness"]["Value"], "NOT_CHECKED"
        )
        self.assertEqual(summary_by_metric["Exception debt"]["Value"], "NOT_CHECKED")
        self.assertEqual(
            int(summary_by_metric["Reviewed mapping checks"]["Value"])
            + int(summary_by_metric["Provisional mapping checks"]["Value"])
            + int(summary_by_metric["Unmapped checks"]["Value"]),
            int(summary_by_metric["Atomic checks"]["Value"]),
        )

    def test_governance_csv_and_assessment_sheet_are_filterable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            generate_checklists.generate_checklists(self.controls, output)
            governance_csv = output / "governance" / "control-readiness.csv"
            self.assertTrue(governance_csv.read_bytes().startswith(b"\xef\xbb\xbf"))
            with governance_csv.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), len(self.controls))
            self.assertTrue(all(row["Governance Result"] == "NOT_CHECKED" for row in rows))

            workbook = output / "product-security-assessment-template.xlsx"
            with zipfile.ZipFile(workbook) as archive:
                workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
                self.assertIn('name="Governance Assessment"', workbook_xml)
                worksheet_names = [
                    name
                    for name in archive.namelist()
                    if name.startswith("xl/worksheets/") and name.endswith(".xml")
                ]
                self.assertTrue(
                    any(b"Governance Result" in archive.read(name) for name in worksheet_names)
                )
                self.assertTrue(
                    any(b"autoFilter" in archive.read(name) for name in worksheet_names)
                )

    def test_csv_formula_prefixes_are_neutralized(self) -> None:
        for value in ("=cmd()", "+SUM(A1:A2)", "-1+2", "@example"):
            with self.subTest(value=value):
                self.assertEqual(generate_checklists._csv_safe_text(value), "'" + value)

    def test_slsa_build_l2_profile_is_cumulative_and_excludes_l3(self) -> None:
        checklist, _, _ = generate_checklists.build_rows(self.controls)
        registries = generate_checklists.discover_registries()
        selected, coverage = generate_checklists.build_slsa_l2_profile(
            self.controls,
            checklist,
            registries["slsa"],
        )
        selected_ids = {row["Check ID"] for row in selected}
        self.assertIn("PSB-BUILD-002-HCB-001", selected_ids)
        self.assertIn("PSB-BUILD-002-HCB-002", selected_ids)
        self.assertIn("PSB-BUILD-002-HCB-003", selected_ids)
        self.assertIn("PSB-BUILD-002-HCB-004", selected_ids)
        self.assertIn("PSB-BUILD-003-PPG-001", selected_ids)
        self.assertIn("PSB-BUILD-003-PPG-002", selected_ids)
        self.assertIn("PSB-BUILD-003-PPG-003", selected_ids)
        self.assertIn("PSB-BUILD-003-PPG-004", selected_ids)
        self.assertIn("PSB-REL-001-REL-001", selected_ids)
        self.assertIn("PSB-REL-001-REL-002", selected_ids)
        self.assertIn("PSB-REL-002-RPD-001", selected_ids)
        self.assertIn("PSB-REL-002-RPD-002", selected_ids)
        self.assertIn("PSB-REL-002-RPD-003", selected_ids)
        self.assertIn("PSB-REL-002-RPD-004", selected_ids)
        self.assertNotIn("PSB-BUILD-001-BLD-001", selected_ids)
        self.assertEqual(
            {row["Requirement Minimum Level"] for row in coverage},
            {"1", "2"},
        )
        self.assertEqual(len(coverage), 7)
        self.assertEqual(
            sum(row["Status"] == "mapped-evidence" for row in coverage),
            7,
        )
        self.assertEqual(sum(row["Status"] == "gap" for row in coverage), 0)

    def test_supply_chain_reconciliation_is_generated_with_all_dispositions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            generate_checklists.generate_checklists(self.controls, output)
            csv_path = (
                output
                / "profiles"
                / "supply-chain-integration"
                / "reconciliation.csv"
            )
            markdown_path = csv_path.with_suffix(".md")
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 12)
            self.assertEqual(
                {row["Disposition"] for row in rows},
                {"implemented", "planned", "gap", "out-of-scope"},
            )
            self.assertTrue(
                all(row["Claim Boundary"] for row in rows)
            )
            self.assertNotIn("complies-with", markdown_path.read_text(encoding="utf-8"))

    def test_psirt_profile_keeps_organization_results_not_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            generate_checklists.generate_checklists(self.controls, output)
            csv_path = output / "profiles" / "first-psirt-capability" / "assessment.csv"
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 18)
            self.assertTrue(all(row["Assessment Result"] == "NOT_CHECKED" for row in rows))
            self.assertTrue(all(row["Evidence Freshness"] == "NOT_CHECKED" for row in rows))
            self.assertEqual(
                {row["Cumulative Minimum Level"] for row in rows}, {"1", "2", "3"}
            )


if __name__ == "__main__":
    unittest.main()
