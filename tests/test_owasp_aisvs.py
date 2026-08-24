from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402
from framework_registry import discover_registries, validate_registries  # noqa: E402


EXTRACTOR_SPEC = importlib.util.spec_from_file_location(
    "extract_framework_entries",
    REPOSITORY_ROOT / "scripts" / "extract-framework-entries.py",
)
assert EXTRACTOR_SPEC and EXTRACTOR_SPEC.loader
extract_framework_entries = importlib.util.module_from_spec(EXTRACTOR_SPEC)
EXTRACTOR_SPEC.loader.exec_module(extract_framework_entries)


EXPECTED_CHAPTER_COUNTS = {
    "C1": 13,
    "C2": 12,
    "C3": 15,
    "C4": 14,
    "C5": 11,
    "C6": 7,
    "C7": 13,
    "C8": 11,
    "C9": 34,
    "C10": 23,
    "C11": 17,
    "C12": 21,
}


class OwaspAisvsRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registries = discover_registries()
        self.registry = self.registries["owasp-aisvs"]
        self.controls = discover_controls()

    def test_complete_v1_inventory_is_versioned_and_levelled(self) -> None:
        entries = self.registry["entries"]
        self.assertEqual(self.registry["role"], "requirement-framework")
        self.assertEqual(self.registry["mapping_version"], "1.0")
        self.assertEqual(len(entries), 191)
        self.assertEqual(Counter(entry["chapter"] for entry in entries), EXPECTED_CHAPTER_COUNTS)
        self.assertEqual(Counter(entry["level"] for entry in entries), {1: 51, 2: 95, 3: 45})
        self.assertEqual(len({entry["section"] for entry in entries}), 44)
        for entry in entries:
            self.assertRegex(entry["id"], r"^v1\.0-C\d+\.\d+\.\d+$")
            self.assertIn(entry["level"], {1, 2, 3})
            self.assertNotIn("Verify that", entry["title"])

    def test_source_is_official_immutable_and_integrity_recorded(self) -> None:
        source = self.registry["source"]
        commit = "78775233666a2022dcfb82037e5e029116955c00"
        self.assertEqual(source["commit"], commit)
        self.assertEqual(source["requirements_tree"], "a8102d4e67cdf92348a32a18bbee2417d633a075")
        self.assertEqual(source["git_blob"], "78e871719bd94e37dc33ec29a326903302a56f7f")
        self.assertEqual(source["sha256"], "ff15584843a53d4fd2b52940c98cb15f9ebe1340151d90d54bb74db9cf8468f6")
        self.assertEqual(source["license"], "CC BY-SA 4.0")
        self.assertIn(f"/OWASP/AISVS/{commit}/1.0/", source["url"])
        self.assertTrue(
            all(f"/OWASP/AISVS/blob/{commit}/1.0/en/" in entry["source_url"] for entry in self.registry["entries"])
        )

    def test_markdown_extractor_requires_versioned_structure_and_full_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "1.0" / "en"
            source.mkdir(parents=True)
            (source / "0x10-C01-Test.md").write_text(
                "# C1 Test Chapter\n\n"
                "## C1.1 Test Section\n\n"
                "| # | Description | Level |\n"
                "|---|---|---|\n"
                "| **1.1.1** | **Verify that** one condition is true. | 1 |\n"
                "| **1.1.2** | **Verify that** another condition is true. | 3 |\n",
                encoding="utf-8",
            )
            commit = "1" * 40
            entries = extract_framework_entries.aisvs_entries(source, commit)
            self.assertEqual(
                [(entry["id"], entry["level"]) for entry in entries],
                [("v1.0-C1.1.1", 1), ("v1.0-C1.1.2", 3)],
            )
            self.assertTrue(all(f"/blob/{commit}/1.0/en/" in entry["source_url"] for entry in entries))
            with self.assertRaisesRegex(ValueError, "full commit SHA"):
                extract_framework_entries.aisvs_entries(source, "main")

    def test_mapping_rows_are_direct_versioned_and_non_compliance_claims(self) -> None:
        mappings = [
            (control["id"], mapping)
            for control in self.controls
            for mapping in control["mappings"]
            if mapping["framework"] == "owasp-aisvs"
        ]
        self.assertTrue(mappings)
        known_ids = {entry["id"] for entry in self.registry["entries"]}
        for _, mapping in mappings:
            self.assertEqual(mapping["version"], "1.0")
            self.assertIn(mapping["id"], known_ids)
            self.assertNotIn("complies", mapping["relationship"])
            self.assertTrue(mapping["applies_to"])
            self.assertTrue(mapping["rationale"])

    def test_invalid_aisvs_level_is_rejected(self) -> None:
        registries = copy.deepcopy(self.registries)
        registries["owasp-aisvs"]["entries"][0]["level"] = 0
        errors = validate_registries(registries, self.controls)
        self.assertTrue(any("AISVS level" in error for error in errors))

    def test_unversioned_aisvs_identifier_is_rejected(self) -> None:
        registries = copy.deepcopy(self.registries)
        registries["owasp-aisvs"]["entries"][0]["id"] = "C1.1.1"
        errors = validate_registries(registries, self.controls)
        self.assertTrue(any("AISVS identifier must be version-qualified" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
