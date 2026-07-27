from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402
from framework_registry import (  # noqa: E402
    discover_registries,
    validate_registries,
)


class FrameworkRegistryValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()
        self.registries = discover_registries()

    def test_repository_registries_and_mappings_are_valid(self) -> None:
        self.assertEqual(validate_registries(self.registries, self.controls), [])

    def test_every_used_framework_has_a_registry(self) -> None:
        used = {
            mapping["framework"]
            for control in self.controls
            for mapping in control["mappings"]
        }
        self.assertTrue(used)
        self.assertTrue(used.issubset(self.registries))

    def test_unknown_mapping_identifier_is_rejected(self) -> None:
        controls = copy.deepcopy(self.controls)
        controls[0]["mappings"][0]["id"] = "UNKNOWN-FRAMEWORK-ID"
        errors = validate_registries(self.registries, controls)
        self.assertTrue(any("unknown" in error and "identifier" in error for error in errors))

    def test_mapping_version_mismatch_is_rejected(self) -> None:
        controls = copy.deepcopy(self.controls)
        controls[0]["mappings"][0]["version"] = "floating-latest"
        errors = validate_registries(self.registries, controls)
        self.assertTrue(any("does not match registry" in error for error in errors))

    def test_registry_entries_are_unique(self) -> None:
        for name, registry in self.registries.items():
            with self.subTest(framework=name):
                identifiers = [entry["id"] for entry in registry["entries"]]
                self.assertEqual(len(identifiers), len(set(identifiers)))


if __name__ == "__main__":
    unittest.main()
