from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import (  # noqa: E402
    README_OVERVIEW_HEADING,
    README_OVERVIEW_ROWS,
    discover_controls,
    validate_controls,
    validate_readme_overview,
)


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

    def test_external_evidence_control_requires_a_real_procedure(self) -> None:
        control = copy.deepcopy(
            next(
                item
                for item in self.controls
                if item.get("verification", {}).get("type")
                == "external-evidence"
            )
        )
        control["verification"].pop("procedure")
        errors = validate_controls([control])
        self.assertTrue(
            any("verification.procedure must be" in error for error in errors)
        )

    def test_external_evidence_control_is_not_reported_as_verified(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "run-controls.py"),
                "--control",
                "PSB-CICD-007",
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("NOT_CHECKED PSB-CICD-007", result.stdout)
        self.assertIn("docs/ADOPTION.md#live-verification", result.stdout)
        self.assertNotIn("verified 1 control(s)", result.stdout)

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

    def test_versioned_check_context_is_required_for_every_row(self) -> None:
        control = copy.deepcopy(
            next(
                item
                for item in self.controls
                if item.get("check_context_version") == "1.0"
            )
        )
        control["checks"][0].pop("context")
        errors = validate_controls([control])
        self.assertTrue(any("context is required" in error for error in errors))

    def test_check_context_version_is_required(self) -> None:
        control = copy.deepcopy(self.controls[0])
        control.pop("check_context_version", None)
        errors = validate_controls([control])
        self.assertTrue(
            any("check_context_version must be" in error for error in errors)
        )

    def test_readme_overview_contract_accepts_all_rows(self) -> None:
        rows = "\n".join(f"| {row} | reviewed content |" for row in README_OVERVIEW_ROWS)
        readme = (
            "# PSB-TEST-001\n\n"
            f"{README_OVERVIEW_HEADING}\n\n"
            "| 観点 | 内容 |\n"
            "|---|---|\n"
            f"{rows}\n\n"
            "## Details\n"
        )
        self.assertEqual(validate_readme_overview(readme, "test"), [])

    def test_readme_overview_contract_accepts_labeled_prose(self) -> None:
        items = "\n\n".join(
            f"### {row}\n\nReviewed content for {row}."
            for row in README_OVERVIEW_ROWS
        )
        readme = (
            f"# PSB-TEST-001\n\n"
            f"{README_OVERVIEW_HEADING}\n\n"
            f"{items}\n\n"
            "## Details\n"
        )
        self.assertEqual(validate_readme_overview(readme, "test"), [])

    def test_readme_overview_must_be_first_h2(self) -> None:
        rows = "\n".join(f"| {row} | reviewed content |" for row in README_OVERVIEW_ROWS)
        readme = (
            "# PSB-TEST-001\n\n"
            "## Goal\n\nSomething\n\n"
            f"{README_OVERVIEW_HEADING}\n\n"
            f"{rows}\n"
        )
        errors = validate_readme_overview(readme, "test")
        self.assertTrue(any("must be the first H2" in error for error in errors))

    def test_readme_overview_rejects_missing_and_placeholder_rows(self) -> None:
        rows = "\n".join(
            f"| {row} | {'TBD' if row == README_OVERVIEW_ROWS[0] else 'reviewed content'} |"
            for row in README_OVERVIEW_ROWS[:-1]
        )
        readme = f"# PSB-TEST-001\n\n{README_OVERVIEW_HEADING}\n\n{rows}\n"
        errors = validate_readme_overview(readme, "test")
        self.assertTrue(any("must be substantive" in error for error in errors))
        self.assertTrue(
            any(README_OVERVIEW_ROWS[-1] in error for error in errors)
        )


if __name__ == "__main__":
    unittest.main()
