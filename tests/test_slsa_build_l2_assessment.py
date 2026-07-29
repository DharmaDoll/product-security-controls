from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY_ROOT / "scripts" / "assess-slsa-build-l2.py"
POLICY = (
    REPOSITORY_ROOT
    / "policies"
    / "framework-assessments"
    / "slsa-build-l2.json"
)
COVERAGE = (
    REPOSITORY_ROOT
    / "generated"
    / "checklists"
    / "profiles"
    / "slsa-build-l2-coverage.csv"
)
FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures" / "slsa-build-l2-assessment"
NOW = "2026-07-29T12:30:00Z"
SCOPE_DIGEST = (
    "e75cbce01b89a8593197db87886d68ad7f7475e2c7bba3c454c528ddb92fc812"
)


class SlsaBuildL2AssessmentTest(unittest.TestCase):
    def run_assessment(
        self,
        fixture: str,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path, tempfile.TemporaryDirectory]:
        temporary = tempfile.TemporaryDirectory()
        output = Path(temporary.name)
        json_output = output / "assessment.json"
        csv_output = output / "assessment.csv"
        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--policy",
                str(POLICY),
                "--coverage",
                str(COVERAGE),
                "--evidence",
                str(FIXTURES / fixture),
                "--json-output",
                str(json_output),
                "--csv-output",
                str(csv_output),
                "--now",
                NOW,
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        return process, json_output, csv_output, temporary

    def test_complete_reviewed_evidence_passes_all_requirements(self) -> None:
        process, json_output, csv_output, temporary = self.run_assessment(
            "secure.json"
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(json_output.read_text(encoding="utf-8"))
        self.assertEqual(result["conclusion"], "PASS")
        self.assertEqual(
            result["summary"],
            {"PASS": 7, "FAIL": 0, "NOT_CHECKED": 0, "ERROR": 0},
        )
        self.assertEqual(result["scope_sha256"], SCOPE_DIGEST)
        self.assertEqual(len(result["results"]), 7)
        self.assertEqual({row["status"] for row in result["results"]}, {"PASS"})

        with csv_output.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 7)
        self.assertEqual({row["Status"] for row in rows}, {"PASS"})
        self.assertIn("RESULT PASS profile=slsa-build-l2", process.stdout)

    def test_findings_wrong_issuer_and_missing_evidence_are_not_pass(self) -> None:
        process, json_output, _, temporary = self.run_assessment("insecure.json")
        self.addCleanup(temporary.cleanup)

        self.assertEqual(process.returncode, 1)
        result = json.loads(json_output.read_text(encoding="utf-8"))
        self.assertEqual(result["conclusion"], "FAIL")
        self.assertEqual(
            result["summary"],
            {"PASS": 2, "FAIL": 4, "NOT_CHECKED": 1, "ERROR": 0},
        )
        statuses = {
            row["requirement_id"]: row["status"] for row in result["results"]
        }
        self.assertEqual(
            statuses["build-l1#producer-distributes-provenance"],
            "NOT_CHECKED",
        )

    def test_absent_evidence_is_incomplete(self) -> None:
        process, json_output, _, temporary = self.run_assessment(
            "unavailable.json"
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(process.returncode, 1)
        result = json.loads(json_output.read_text(encoding="utf-8"))
        self.assertEqual(result["conclusion"], "INCOMPLETE")
        self.assertEqual(result["summary"]["NOT_CHECKED"], 7)

    def test_collection_failure_is_error_and_never_clean(self) -> None:
        process, json_output, _, temporary = self.run_assessment("error.json")
        self.addCleanup(temporary.cleanup)

        self.assertEqual(process.returncode, 2)
        result = json.loads(json_output.read_text(encoding="utf-8"))
        self.assertEqual(result["conclusion"], "ERROR")
        self.assertEqual(result["summary"]["ERROR"], 1)
        self.assertIn("RESULT ERROR profile=slsa-build-l2", process.stdout)

    def test_malformed_input_fails_without_assessment_artifacts(self) -> None:
        process, json_output, csv_output, temporary = self.run_assessment(
            "malformed.json"
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(process.returncode, 2)
        self.assertFalse(json_output.exists())
        self.assertFalse(csv_output.exists())
        self.assertIn("assessment unavailable", process.stdout)

    def test_outputs_do_not_disclose_scope_identities_or_evidence_uris(self) -> None:
        process, json_output, csv_output, temporary = self.run_assessment(
            "secure.json"
        )
        self.addCleanup(temporary.cleanup)

        output_text = (
            process.stdout
            + json_output.read_text(encoding="utf-8")
            + csv_output.read_text(encoding="utf-8-sig")
        )
        self.assertNotIn("producer.example.invalid", output_text)
        self.assertNotIn("evidence.example.invalid", output_text)
        self.assertNotIn("product-v1.2.3", output_text)

    def test_machine_readable_contracts_are_valid_json(self) -> None:
        paths = [
            POLICY,
            REPOSITORY_ROOT / "schemas" / "framework-assessment-result.schema.json",
            REPOSITORY_ROOT
            / "schemas"
            / "slsa-build-l2-assessment-input.schema.json",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertIsInstance(
                    json.loads(path.read_text(encoding="utf-8")),
                    dict,
                )


if __name__ == "__main__":
    unittest.main()
