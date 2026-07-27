from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls, validate_controls  # noqa: E402


class ControlMetadataValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()
        self.assertGreaterEqual(len(self.controls), 1)

    def test_repository_controls_are_valid(self) -> None:
        self.assertEqual(validate_controls(self.controls), [])

    def test_control_schema_is_valid_json(self) -> None:
        with (REPOSITORY_ROOT / "schemas" / "control.schema.json").open(
            "r", encoding="utf-8"
        ) as handle:
            schema = json.load(handle)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_assessment_schema_is_valid_json(self) -> None:
        with (REPOSITORY_ROOT / "schemas" / "assessment-result.schema.json").open(
            "r", encoding="utf-8"
        ) as handle:
            schema = json.load(handle)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_duplicate_control_id_is_rejected(self) -> None:
        duplicate = copy.deepcopy(self.controls[0])
        errors = validate_controls([self.controls[0], duplicate])
        self.assertTrue(any("duplicate control id" in error for error in errors))

    def test_missing_implementation_is_rejected(self) -> None:
        control = copy.deepcopy(self.controls[0])
        control["implementations"]["secure"] = ["secure/does-not-exist"]
        errors = validate_controls([control])
        self.assertTrue(any("missing implementation file" in error for error in errors))

    def test_invalid_mapping_relationship_is_rejected(self) -> None:
        control = copy.deepcopy(self.controls[0])
        control["mappings"][0]["relationship"] = "complies-with"
        errors = validate_controls([control])
        self.assertTrue(any("unsupported relationship" in error for error in errors))

    def test_unknown_mapping_check_is_rejected(self) -> None:
        control = copy.deepcopy(self.controls[0])
        control["mappings"][0]["applies_to"] = ["UNKNOWN-CHECK"]
        errors = validate_controls([control])
        self.assertTrue(any("unknown check id" in error for error in errors))

    def test_reviewed_check_requires_mapping(self) -> None:
        control = copy.deepcopy(self.controls[0])
        check_id = control["checks"][0]["id"]
        for mapping in control["mappings"]:
            mapping["applies_to"] = [
                candidate for candidate in mapping["applies_to"] if candidate != check_id
            ]
            if not mapping["applies_to"]:
                mapping["applies_to"] = [control["checks"][1]["id"]]
        errors = validate_controls([control])
        self.assertTrue(any("has no mapping" in error for error in errors))

    def test_unknown_assessment_platform_is_rejected(self) -> None:
        control = copy.deepcopy(
            next(item for item in self.controls if item.get("assessment"))
        )
        control["assessment"]["platforms"] = ["plan9"]
        errors = validate_controls([control])
        self.assertTrue(any("unsupported platforms" in error for error in errors))

    def test_missing_assessment_command_is_rejected(self) -> None:
        control = copy.deepcopy(
            next(item for item in self.controls if item.get("assessment"))
        )
        control["assessment"]["command"] = "assessment/missing.py"
        errors = validate_controls([control])
        self.assertTrue(any("missing assessment command" in error for error in errors))

    def test_metadata_domain_must_match_directory(self) -> None:
        control = copy.deepcopy(self.controls[0])
        control["domain"] = "secure-design"
        errors = validate_controls([control])
        self.assertTrue(any("does not match directory" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
