from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "scripts" / "collect-slsa-consumer-evidence.py"
FIXTURE = (
    ROOT / "tests" / "fixtures" / "slsa-consumer-collector" / "secure"
)
NOW = "2026-07-29T12:30:00Z"


class SlsaConsumerEvidenceCollectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "consumer"
        shutil.copytree(FIXTURE, self.root)
        self.policy_path = self.root / "policy.json"
        self.output_path = Path(self.temporary.name) / "consumer.json"
        self.receipt_path = Path(self.temporary.name) / "receipt.json"

    def run_collector(
        self,
        *,
        openssl_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(COLLECTOR),
            "--policy",
            str(self.policy_path),
            "--output",
            str(self.output_path),
            "--receipt-output",
            str(self.receipt_path),
            "--now",
            NOW,
        ]
        if openssl_path is not None:
            command.extend(["--openssl", str(openssl_path)])
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def mutate_fixture(
        self,
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        path = self.root / "verification-result.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_fixture_emits_complete_consumer_bundle(self) -> None:
        process = self.run_collector()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(bundle["issuer_role"], "consumer")
        self.assertEqual(
            {item["type"] for item in bundle["evidence"]},
            {
                "consumer-verification-result",
                "consumer-trust-policy",
                "provenance-signature-verification",
            },
        )
        self.assertEqual(
            {item["result"] for item in bundle["evidence"]},
            {"pass"},
        )
        receipt_digest = hashlib.sha256(self.receipt_path.read_bytes()).hexdigest()
        receipt_records = [
            item
            for item in bundle["evidence"]
            if item["type"] != "consumer-trust-policy"
        ]
        self.assertTrue(
            all(item["sha256"] == receipt_digest for item in receipt_records)
        )
        self.assertNotIn("consumer.example.invalid", process.stdout)

    def test_verifier_rejection_is_a_finding(self) -> None:
        self.mutate_fixture(
            lambda value: value.update(
                {
                    "verifier_exit_code": 1,
                    "reason_codes": ["consumer-verification-rejected"],
                }
            )
        )
        process = self.run_collector()
        self.assertEqual(process.returncode, 0)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {item["result"] for item in bundle["evidence"]},
            {"finding"},
        )
        self.assertIn("reason_codes=consumer-verification-rejected", process.stdout)

    def test_verifier_unavailable_does_not_replace_old_outputs(self) -> None:
        self.mutate_fixture(
            lambda value: value.update(
                {
                    "verifier_exit_code": 2,
                    "reason_codes": ["verifier-unavailable"],
                }
            )
        )
        self.output_path.write_text("old bundle\n", encoding="utf-8")
        self.receipt_path.write_text("old receipt\n", encoding="utf-8")
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(
            self.output_path.read_text(encoding="utf-8"),
            "old bundle\n",
        )
        self.assertEqual(
            self.receipt_path.read_text(encoding="utf-8"),
            "old receipt\n",
        )

    def test_artifact_pin_mismatch_is_collection_error(self) -> None:
        (self.root / "release.bin").write_text("tampered\n", encoding="utf-8")
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.receipt_path.exists())
        self.assertIn("artifact digest mismatch", process.stdout)

    def test_scope_revision_must_match_consumer_policy(self) -> None:
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["scope"]["source_revision"] = "f" * 40
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertIn("source revision does not match scope", process.stdout)

    def test_live_mode_runs_pinned_psb_rel_001_verifier(self) -> None:
        openssl = Path(shutil.which("openssl") or "")
        if not openssl.is_absolute() or openssl.is_symlink():
            self.skipTest("non-symlink absolute OpenSSL is unavailable")
        version_process = subprocess.run(
            [str(openssl), "version"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(version_process.returncode, 0)
        version = version_process.stdout.split()[1]
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["source"] = "live"
        policy.pop("verification_fixture")
        policy["openssl"] = {
            "version": version,
            "sha256": hashlib.sha256(openssl.read_bytes()).hexdigest(),
            "timeout_seconds": 20,
        }
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        process = self.run_collector(openssl_path=openssl)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["verifier_exit_code"], 0)
        self.assertEqual(receipt["result"], "pass")

    def test_schemas_are_valid_json(self) -> None:
        for name in (
            "slsa-consumer-collector-policy.schema.json",
            "slsa-consumer-receipt.schema.json",
        ):
            with self.subTest(name=name):
                value = json.loads((ROOT / "schemas" / name).read_text())
                self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")


if __name__ == "__main__":
    unittest.main()
