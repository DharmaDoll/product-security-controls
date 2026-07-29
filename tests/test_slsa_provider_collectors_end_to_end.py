from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
NOW = "2026-07-29T12:30:00Z"
ADAPTER = ROOT / "scripts" / "build-slsa-build-l2-evidence.py"
ASSESSOR = ROOT / "scripts" / "assess-slsa-build-l2.py"
ASSESSMENT_POLICY = (
    ROOT / "policies" / "framework-assessments" / "slsa-build-l2.json"
)
COVERAGE = (
    ROOT
    / "generated"
    / "checklists"
    / "profiles"
    / "slsa-build-l2-coverage.csv"
)


class SlsaProviderCollectorsEndToEndTest(unittest.TestCase):
    def test_all_five_collected_roles_produce_passing_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            adapter_root = temporary_root / "adapter"
            shutil.copytree(
                ROOT / "tests" / "fixtures" / "slsa-build-l2-adapter" / "secure",
                adapter_root,
            )
            bundle_root = adapter_root / "bundles"
            receipt_root = temporary_root / "receipts"
            receipt_root.mkdir()

            actions_fixture = (
                ROOT
                / "tests"
                / "fixtures"
                / "github-actions-build-platform-collector"
                / "secure"
            )
            releases_fixture = (
                ROOT
                / "tests"
                / "fixtures"
                / "github-releases-collector"
                / "secure"
            )
            consumer_fixture = (
                ROOT
                / "tests"
                / "fixtures"
                / "slsa-consumer-collector"
                / "secure"
            )
            review_fixture = (
                ROOT
                / "tests"
                / "fixtures"
                / "slsa-security-review-collector"
                / "secure"
            )
            commands = [
                [
                    sys.executable,
                    str(ROOT / "scripts" / "collect-github-actions-build-platform.py"),
                    "--policy",
                    str(actions_fixture / "policy.json"),
                    "--output",
                    str(bundle_root / "build-platform.json"),
                    "--receipt-output",
                    str(receipt_root / "build-record.json"),
                    "--now",
                    NOW,
                ],
                [
                    sys.executable,
                    str(ROOT / "scripts" / "collect-github-releases-evidence.py"),
                    "--policy",
                    str(releases_fixture / "software-producer-policy.json"),
                    "--output",
                    str(bundle_root / "software-producer.json"),
                    "--receipt-output",
                    str(receipt_root / "publication-manifest.json"),
                    "--now",
                    NOW,
                ],
                [
                    sys.executable,
                    str(ROOT / "scripts" / "collect-github-releases-evidence.py"),
                    "--policy",
                    str(releases_fixture / "security-monitor-policy.json"),
                    "--output",
                    str(bundle_root / "security-monitor.json"),
                    "--receipt-output",
                    str(receipt_root / "storage-probe.json"),
                    "--now",
                    NOW,
                ],
                [
                    sys.executable,
                    str(ROOT / "scripts" / "collect-slsa-consumer-evidence.py"),
                    "--policy",
                    str(consumer_fixture / "policy.json"),
                    "--output",
                    str(bundle_root / "consumer.json"),
                    "--receipt-output",
                    str(receipt_root / "consumer-verification.json"),
                    "--now",
                    NOW,
                ],
                [
                    sys.executable,
                    str(
                        ROOT
                        / "scripts"
                        / "collect-slsa-security-review-evidence.py"
                    ),
                    "--policy",
                    str(review_fixture / "policy.json"),
                    "--output",
                    str(bundle_root / "security-review.json"),
                    "--receipt-output",
                    str(receipt_root / "security-review.json"),
                    "--now",
                    NOW,
                ],
            ]
            for command in commands:
                process = subprocess.run(
                    command,
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    process.returncode,
                    0,
                    process.stdout + process.stderr,
                )

            adapter_policy_path = adapter_root / "policy.json"
            adapter_policy = json.loads(
                adapter_policy_path.read_text(encoding="utf-8")
            )
            for trust in adapter_policy["trusted_bundles"]:
                bundle_path = bundle_root / trust["path"]
                trust["sha256"] = hashlib.sha256(
                    bundle_path.read_bytes()
                ).hexdigest()
            adapter_policy_path.write_text(
                json.dumps(adapter_policy, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            catalog_path = temporary_root / "catalog.json"
            adapter = subprocess.run(
                [
                    sys.executable,
                    str(ADAPTER),
                    "--assessment-policy",
                    str(ASSESSMENT_POLICY),
                    "--adapter-policy",
                    str(adapter_policy_path),
                    "--output",
                    str(catalog_path),
                    "--now",
                    NOW,
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(adapter.returncode, 0, adapter.stdout + adapter.stderr)

            result_path = temporary_root / "assessment.json"
            csv_path = temporary_root / "assessment.csv"
            assessment = subprocess.run(
                [
                    sys.executable,
                    str(ASSESSOR),
                    "--policy",
                    str(ASSESSMENT_POLICY),
                    "--coverage",
                    str(COVERAGE),
                    "--evidence",
                    str(catalog_path),
                    "--json-output",
                    str(result_path),
                    "--csv-output",
                    str(csv_path),
                    "--now",
                    NOW,
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                assessment.returncode,
                0,
                assessment.stdout + assessment.stderr,
            )
            result = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(result["conclusion"], "PASS")
            self.assertEqual(result["summary"]["PASS"], 7)
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            self.assertEqual(len(catalog["evidence_catalog"]), 11)


if __name__ == "__main__":
    unittest.main()
