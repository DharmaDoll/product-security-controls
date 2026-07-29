from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ADAPTER = REPOSITORY_ROOT / "scripts" / "build-slsa-build-l2-evidence.py"
ASSESSOR = REPOSITORY_ROOT / "scripts" / "assess-slsa-build-l2.py"
ASSESSMENT_POLICY = (
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
FIXTURE = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "slsa-build-l2-adapter"
    / "secure"
)
NOW = "2026-07-29T12:30:00Z"


class SlsaBuildL2EvidenceAdapterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "adapter"
        shutil.copytree(FIXTURE, self.root)
        self.policy_path = self.root / "policy.json"
        self.catalog_path = Path(self.temporary.name) / "catalog.json"

    def run_adapter(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ADAPTER),
                "--assessment-policy",
                str(ASSESSMENT_POLICY),
                "--adapter-policy",
                str(self.policy_path),
                "--output",
                str(self.catalog_path),
                "--now",
                NOW,
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def run_assessor(self) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        result_path = Path(self.temporary.name) / "result.json"
        csv_path = Path(self.temporary.name) / "result.csv"
        process = subprocess.run(
            [
                sys.executable,
                str(ASSESSOR),
                "--policy",
                str(ASSESSMENT_POLICY),
                "--coverage",
                str(COVERAGE),
                "--evidence",
                str(self.catalog_path),
                "--json-output",
                str(result_path),
                "--csv-output",
                str(csv_path),
                "--now",
                NOW,
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        return process, json.loads(result_path.read_text(encoding="utf-8"))

    def mutate_bundle(
        self,
        role: str,
        mutation: Callable[[dict[str, Any]], None],
        *,
        refresh_pin: bool,
    ) -> None:
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        trust = next(
            item
            for item in policy["trusted_bundles"]
            if item["issuer_role"] == role
        )
        bundle_path = self.root / "bundles" / trust["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        mutation(bundle)
        bundle_path.write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if refresh_pin:
            trust["sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
            self.policy_path.write_text(
                json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

    def test_pinned_role_bundles_build_a_passing_catalog(self) -> None:
        process = self.run_adapter()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        self.assertEqual(catalog["source"], "test-fixture")
        self.assertEqual(len(catalog["evidence_catalog"]), 11)
        self.assertEqual(
            {item["issuer_role"] for item in catalog["evidence_catalog"]},
            {
                "build-platform",
                "consumer",
                "security-monitor",
                "security-review",
                "software-producer",
            },
        )
        self.assertTrue(
            all(
                item["authenticated"] and item["reviewed"]
                for item in catalog["evidence_catalog"]
            )
        )

        assessment, result = self.run_assessor()
        self.assertEqual(assessment.returncode, 0)
        self.assertEqual(result["conclusion"], "PASS")
        self.assertEqual(result["summary"]["PASS"], 7)

    def test_unreviewed_bundle_tampering_is_rejected_before_output(self) -> None:
        self.mutate_bundle(
            "consumer",
            lambda bundle: bundle["evidence"][0].update({"result": "finding"}),
            refresh_pin=False,
        )
        process = self.run_adapter()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.catalog_path.exists())
        self.assertIn("digest mismatch", process.stdout)
        self.assertNotIn("evidence.example.invalid", process.stdout)

    def test_reviewed_finding_reaches_assessor_as_fail(self) -> None:
        self.mutate_bundle(
            "consumer",
            lambda bundle: bundle["evidence"][0].update({"result": "finding"}),
            refresh_pin=True,
        )
        self.assertEqual(self.run_adapter().returncode, 0)
        assessment, result = self.run_assessor()
        self.assertEqual(assessment.returncode, 1)
        self.assertEqual(result["conclusion"], "FAIL")
        self.assertEqual(result["summary"]["FAIL"], 1)

    def test_upstream_verifier_error_remains_error(self) -> None:
        self.mutate_bundle(
            "consumer",
            lambda bundle: bundle["evidence"][0].update({"result": "error"}),
            refresh_pin=True,
        )
        self.assertEqual(self.run_adapter().returncode, 0)
        assessment, result = self.run_assessor()
        self.assertEqual(assessment.returncode, 2)
        self.assertEqual(result["conclusion"], "ERROR")
        self.assertEqual(result["summary"]["ERROR"], 1)

    def test_wrong_scope_is_rejected_even_when_bundle_is_repinned(self) -> None:
        self.mutate_bundle(
            "build-platform",
            lambda bundle: bundle.update({"scope_sha256": "0" * 64}),
            refresh_pin=True,
        )
        process = self.run_adapter()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.catalog_path.exists())
        self.assertIn("identity is invalid", process.stdout)

    def test_missing_required_evidence_type_is_rejected(self) -> None:
        self.mutate_bundle(
            "software-producer",
            lambda bundle: bundle["evidence"].pop(),
            refresh_pin=True,
        )
        process = self.run_adapter()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.catalog_path.exists())
        self.assertIn("evidence set is incomplete", process.stdout)

    def test_self_reviewed_trust_entry_is_rejected(self) -> None:
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        trust = next(
            item
            for item in policy["trusted_bundles"]
            if item["issuer_role"] == "security-review"
        )
        trust["reviewed_by"] = "security-review"
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        process = self.run_adapter()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.catalog_path.exists())
        self.assertIn("roles are malformed", process.stdout)

    def test_symlinked_bundle_is_rejected(self) -> None:
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        trust = next(
            item
            for item in policy["trusted_bundles"]
            if item["issuer_role"] == "consumer"
        )
        original = self.root / "bundles" / trust["path"]
        link = self.root / "bundles" / "consumer-link.json"
        link.symlink_to(original)
        trust["path"] = link.name
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        process = self.run_adapter()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.catalog_path.exists())
        self.assertIn("uses a symlink", process.stdout)

    def test_contract_files_are_valid_json(self) -> None:
        paths = [
            REPOSITORY_ROOT
            / "schemas"
            / "slsa-build-l2-evidence-adapter-policy.schema.json",
            REPOSITORY_ROOT
            / "schemas"
            / "slsa-build-l2-issuer-bundle.schema.json",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertIsInstance(
                    json.loads(path.read_text(encoding="utf-8")),
                    dict,
                )


if __name__ == "__main__":
    unittest.main()
