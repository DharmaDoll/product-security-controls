from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "scripts" / "collect-slsa-security-review-evidence.py"
FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "slsa-security-review-collector"
    / "secure"
)
NOW = "2026-07-29T12:30:00Z"


class SlsaSecurityReviewEvidenceCollectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "review"
        shutil.copytree(FIXTURE, self.root)
        self.policy_path = self.root / "policy.json"
        self.output_path = Path(self.temporary.name) / "security-review.json"
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

    def mutate_review(
        self,
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        review_path = self.root / "review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        mutation(review)
        review_path.write_text(
            json.dumps(review, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["review_sha256"] = hashlib.sha256(
            review_path.read_bytes()
        ).hexdigest()
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def mutate_verification(self, exit_code: int) -> None:
        path = self.root / "signature-verification.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["verifier_exit_code"] = exit_code
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_fixture_emits_complete_security_review_bundle(self) -> None:
        process = self.run_collector()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(bundle["issuer_role"], "security-review")
        self.assertEqual(
            {item["type"] for item in bundle["evidence"]},
            {
                "platform-capability-assessment",
                "signer-ownership-assessment",
            },
        )
        self.assertEqual(
            {item["result"] for item in bundle["evidence"]},
            {"pass"},
        )
        receipt_digest = hashlib.sha256(self.receipt_path.read_bytes()).hexdigest()
        self.assertTrue(
            all(
                item["sha256"] == receipt_digest
                for item in bundle["evidence"]
            )
        )
        self.assertEqual(bundle["observed_at"], "2026-07-29T12:00:00Z")
        self.assertNotIn("security.example.invalid", process.stdout)

    def test_platform_capability_failure_is_scoped_finding(self) -> None:
        self.mutate_review(
            lambda review: review["platform_capability_assessment"].update(
                {"hosted_execution": False}
            )
        )
        process = self.run_collector()
        self.assertEqual(process.returncode, 0)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        results = {item["type"]: item["result"] for item in bundle["evidence"]}
        self.assertEqual(results["platform-capability-assessment"], "finding")
        self.assertEqual(results["signer-ownership-assessment"], "pass")
        self.assertIn("reason_codes=hosted-execution", process.stdout)

    def test_tenant_signing_capability_is_a_finding(self) -> None:
        self.mutate_review(
            lambda review: review["signer_ownership_assessment"].update(
                {"tenant_signing_capability": True}
            )
        )
        process = self.run_collector()
        self.assertEqual(process.returncode, 0)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        signer = next(
            item
            for item in bundle["evidence"]
            if item["type"] == "signer-ownership-assessment"
        )
        self.assertEqual(signer["result"], "finding")
        self.assertIn("tenant-signing-capability", process.stdout)

    def test_invalid_review_signature_marks_both_records_finding(self) -> None:
        self.mutate_verification(1)
        process = self.run_collector()
        self.assertEqual(process.returncode, 0)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {item["result"] for item in bundle["evidence"]},
            {"finding"},
        )
        self.assertIn("review-signature-invalid", process.stdout)

    def test_expired_review_is_not_refreshed_by_collection_time(self) -> None:
        self.mutate_review(
            lambda review: review.update(
                {"expires_at": "2026-07-29T12:15:00Z"}
            )
        )
        process = self.run_collector()
        self.assertEqual(process.returncode, 0)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {item["result"] for item in bundle["evidence"]},
            {"finding"},
        )
        self.assertEqual(bundle["observed_at"], "2026-07-29T12:00:00Z")
        self.assertIn("review-expired", process.stdout)

    def test_verifier_unavailable_preserves_existing_outputs(self) -> None:
        self.mutate_verification(2)
        self.output_path.write_text("old bundle\n", encoding="utf-8")
        self.receipt_path.write_text("old receipt\n", encoding="utf-8")
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(self.output_path.read_text(), "old bundle\n")
        self.assertEqual(self.receipt_path.read_text(), "old receipt\n")

    def test_live_mode_verifies_the_real_fixture_signature(self) -> None:
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
        self.assertTrue(receipt["signature_verified"])

    def make_live_policy_and_fake_openssl(
        self,
        *,
        verify_exit: int,
    ) -> tuple[Path, Path]:
        arguments = self.root / "openssl-arguments.txt"
        fake = self.root / "openssl"
        body = (
            "#!/bin/sh\n"
            "if [ \"$1\" = \"version\" ]; then\n"
            "  printf 'OpenSSL 3.0.0 fixture\\n'\n"
            "  exit 0\n"
            "fi\n"
            f"printf '%s\\n' \"$@\" > '{arguments}'\n"
            "printf 'SENSITIVE_REVIEW_VERIFIER_ERROR' >&2\n"
            f"exit {verify_exit}\n"
        )
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["source"] = "live"
        policy.pop("verification_fixture")
        policy["openssl"] = {
            "version": "3.0.0",
            "sha256": hashlib.sha256(fake.read_bytes()).hexdigest(),
            "timeout_seconds": 10,
        }
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return fake, arguments

    def test_live_mode_uses_pinned_local_signature_verification(self) -> None:
        fake, arguments = self.make_live_policy_and_fake_openssl(verify_exit=0)
        process = self.run_collector(openssl_path=fake)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        invoked = arguments.read_text(encoding="utf-8").splitlines()
        for required in (
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            "-rawin",
            "-in",
            "-sigfile",
        ):
            with self.subTest(required=required):
                self.assertIn(required, invoked)

    def test_live_verifier_error_is_sanitized_and_not_clean(self) -> None:
        fake, _ = self.make_live_policy_and_fake_openssl(verify_exit=2)
        process = self.run_collector(openssl_path=fake)
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.receipt_path.exists())
        self.assertNotIn("SENSITIVE_REVIEW_VERIFIER_ERROR", process.stdout)
        self.assertNotIn("SENSITIVE_REVIEW_VERIFIER_ERROR", process.stderr)

    def test_schemas_are_valid_json(self) -> None:
        for name in (
            "slsa-security-review-collector-policy.schema.json",
            "slsa-build-platform-security-review.schema.json",
            "slsa-security-review-receipt.schema.json",
        ):
            with self.subTest(name=name):
                value = json.loads((ROOT / "schemas" / name).read_text())
                self.assertEqual(
                    value["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )


if __name__ == "__main__":
    unittest.main()
