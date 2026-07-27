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
        self.assertIn("PSB-REL-001-REL-001", selected_ids)
        self.assertIn("PSB-REL-001-REL-002", selected_ids)
        self.assertNotIn("PSB-BUILD-001-BLD-001", selected_ids)
        self.assertEqual(
            {row["Requirement Minimum Level"] for row in coverage},
            {"1", "2"},
        )
        self.assertEqual(len(coverage), 6)
        self.assertEqual(
            sum(row["Status"] == "mapped-evidence" for row in coverage),
            1,
        )
        self.assertEqual(sum(row["Status"] == "gap" for row in coverage), 5)


if __name__ == "__main__":
    unittest.main()
