from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from application_checklist_import import (  # noqa: E402
    ApplicationImportError,
    load_application_profile,
    write_application_profile,
)
from control_metadata import discover_controls  # noqa: E402
from framework_registry import discover_registries  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "generate_checklists_for_application_test",
    REPOSITORY_ROOT / "scripts" / "generate-checklists.py",
)
assert SPEC and SPEC.loader
generate_checklists = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_checklists)


FIXTURE = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "application-checklist-import"
    / "secure"
)


class ApplicationChecklistImportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registries = discover_registries()
        self.control_ids = {control["id"] for control in discover_controls()}

    def _load(self, manifest: Path, repository_root: Path = REPOSITORY_ROOT):
        return load_application_profile(
            manifest,
            repository_root,
            self.registries,
            self.control_ids,
        )

    def _copy_fixture(self, root: Path) -> Path:
        target = root / "fixture"
        shutil.copytree(FIXTURE, target)
        return target / "source-manifest.json"

    @staticmethod
    def _update_manifest_digest(manifest_path: Path, section: str, file_path: Path) -> None:
        manifest = json.loads(manifest_path.read_text())
        manifest[section]["sha256"] = hashlib.sha256(file_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    def test_missing_source_is_input_required_not_empty_checklist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "inputs" / "application" / "source-manifest.json"
            result = self._load(manifest, root)
            self.assertEqual(result["status"], "INPUT_REQUIRED")
            output = root / "output"
            write_application_profile(output, result, generate_checklists.write_xlsx)
            self.assertTrue((output / "status.json").is_file())
            self.assertFalse((output / "profile.csv").exists())
            status = json.loads((output / "status.json").read_text())
            self.assertEqual(status["status"], "INPUT_REQUIRED")
            self.assertIn("no empty checklist", status["message"])

    def test_csv_import_preserves_public_rows_and_redacts_private_wording(self) -> None:
        result = self._load(FIXTURE / "source-manifest.json")
        self.assertEqual(result["status"], "GENERATED")
        self.assertEqual(result["status_document"]["source_rows"], 3)
        self.assertEqual(result["status_document"]["atomic_rows"], 4)
        self.assertEqual(result["status_document"]["public_atomic_rows"], 3)
        self.assertEqual(
            {row["Relationship"] for row in result["profile_rows"]},
            {"same-as-source", "split-from"},
        )
        self.assertTrue(all(row["Framework Mappings"] for row in result["profile_rows"]))
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("この非公開診断項目", serialized)
        self.assertNotIn("organization-only atomic wording", serialized)
        private = next(
            row
            for row in result["reconciliation_rows"]
            if row["Publication"] == "organization-only"
        )
        self.assertTrue(private["Source Row ID"].startswith("REDACTED-"))

    def test_generation_is_deterministic_and_xlsx_is_filterable(self) -> None:
        result = self._load(FIXTURE / "source-manifest.json")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            write_application_profile(first, result, generate_checklists.write_xlsx)
            write_application_profile(second, result, generate_checklists.write_xlsx)
            first_files = {path.relative_to(first): path.read_bytes() for path in first.rglob("*") if path.is_file()}
            second_files = {path.relative_to(second): path.read_bytes() for path in second.rglob("*") if path.is_file()}
            self.assertEqual(first_files, second_files)
            with (first / "profile.csv").open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 3)
            workbook = first / "application-vulnerability-assessment.xlsx"
            with zipfile.ZipFile(workbook) as archive:
                workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
                self.assertIn('name="Application Profile"', workbook_xml)
                for name in archive.namelist():
                    if name.endswith((".xml", ".rels")):
                        ET.fromstring(archive.read(name))
                worksheets = [name for name in archive.namelist() if name.startswith("xl/worksheets/")]
                self.assertTrue(any(b"autoFilter" in archive.read(name) for name in worksheets))

    def test_xlsx_source_import_uses_exact_sheet_and_same_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            with (manifest_path.parent / "source.csv").open(encoding="utf-8") as handle:
                source_rows = list(csv.reader(handle))
            workbook = manifest_path.parent / "source.xlsx"
            generate_checklists.write_xlsx(
                workbook,
                [("Assessment", source_rows[0], source_rows[1:])],
            )
            manifest = json.loads(manifest_path.read_text())
            manifest["input"] = {
                "path": "source.xlsx",
                "format": "xlsx",
                "sheet": "Assessment",
                "sha256": hashlib.sha256(workbook.read_bytes()).hexdigest(),
            }
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            result = self._load(manifest_path)
            self.assertEqual(result["status_document"]["public_atomic_rows"], 3)

    def test_duplicate_ids_unknown_columns_and_missing_version_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            source = manifest_path.parent / "source.csv"
            source.write_text(source.read_text() + "APP-001,duplicate,Other,public\n")
            self._update_manifest_digest(manifest_path, "input", source)
            with self.assertRaisesRegex(ApplicationImportError, "duplicate source row ID"):
                self._load(manifest_path)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            source = manifest_path.parent / "source.csv"
            with source.open() as handle:
                rows = list(csv.reader(handle))
            rows[0].append("Unknown")
            for row in rows[1:]:
                row.append("value")
            with source.open("w", newline="") as handle:
                csv.writer(handle, lineterminator="\n").writerows(rows)
            self._update_manifest_digest(manifest_path, "input", source)
            with self.assertRaisesRegex(ApplicationImportError, "unknown Unknown"):
                self._load(manifest_path)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            manifest = json.loads(manifest_path.read_text())
            del manifest["source"]["version"]
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            with self.assertRaisesRegex(ApplicationImportError, "missing fields: version"):
                self._load(manifest_path)

    def test_formula_malformed_workbook_and_mapping_version_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            source = manifest_path.parent / "source.csv"
            source.write_text(source.read_text().replace("APP-001,", "=cmd(),", 1))
            self._update_manifest_digest(manifest_path, "input", source)
            with self.assertRaisesRegex(ApplicationImportError, "formula-like cell"):
                self._load(manifest_path)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            workbook = manifest_path.parent / "source.xlsx"
            workbook.write_bytes(b"not-an-xlsx")
            manifest = json.loads(manifest_path.read_text())
            manifest["input"] = {
                "path": "source.xlsx",
                "format": "xlsx",
                "sheet": "Assessment",
                "sha256": hashlib.sha256(workbook.read_bytes()).hexdigest(),
            }
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            with self.assertRaisesRegex(ApplicationImportError, "cannot parse.*XLSX"):
                self._load(manifest_path)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            reconciliation = manifest_path.parent / "reconciliation.csv"
            reconciliation.write_text(reconciliation.read_text().replace("owasp-asvs|5.0.0|", "owasp-asvs|latest|", 1))
            self._update_manifest_digest(manifest_path, "reconciliation", reconciliation)
            with self.assertRaisesRegex(ApplicationImportError, "unsupported owasp-asvs version"):
                self._load(manifest_path)

    def test_missing_reconciliation_is_not_interpreted_as_empty_or_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = self._copy_fixture(root)
            reconciliation = manifest_path.parent / "reconciliation.csv"
            with reconciliation.open() as handle:
                rows = list(csv.reader(handle))
            with reconciliation.open("w", newline="") as handle:
                csv.writer(handle, lineterminator="\n").writerows(
                    row for row in rows if not row or row[0] != "APP-PRIVATE-001"
                )
            self._update_manifest_digest(manifest_path, "reconciliation", reconciliation)
            with self.assertRaisesRegex(ApplicationImportError, "source rows lack reconciliation"):
                self._load(manifest_path)


if __name__ == "__main__":
    unittest.main()
