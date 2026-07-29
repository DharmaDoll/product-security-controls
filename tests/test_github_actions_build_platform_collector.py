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


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = (
    REPOSITORY_ROOT / "scripts" / "collect-github-actions-build-platform.py"
)
CATALOG_BUILDER = (
    REPOSITORY_ROOT / "scripts" / "build-slsa-build-l2-evidence.py"
)
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
    / "github-actions-build-platform-collector"
    / "secure"
)
ADAPTER_FIXTURE = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "slsa-build-l2-adapter"
    / "secure"
)
NOW = "2026-07-29T12:30:00Z"


class GitHubActionsBuildPlatformCollectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "collector"
        shutil.copytree(FIXTURE, self.root)
        self.policy_path = self.root / "policy.json"
        self.output_path = Path(self.temporary.name) / "build-platform.json"
        self.receipt_path = Path(self.temporary.name) / "build-record.json"

    def run_collector(
        self,
        *,
        gh_path: Path | None = None,
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
        if gh_path is not None:
            command.extend(["--gh", str(gh_path)])
        return subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def mutate_verification(
        self,
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        path = self.root / "verification.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_verified_fixture_builds_compatible_issuer_bundle(self) -> None:
        process = self.run_collector()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(bundle["issuer_role"], "build-platform")
        self.assertEqual(
            {item["type"] for item in bundle["evidence"]},
            {"platform-policy", "build-record"},
        )
        self.assertEqual(
            {item["result"] for item in bundle["evidence"]},
            {"pass"},
        )
        record = next(
            item for item in bundle["evidence"] if item["type"] == "build-record"
        )
        self.assertEqual(
            record["sha256"],
            hashlib.sha256(self.receipt_path.read_bytes()).hexdigest(),
        )
        self.assertNotIn("example/product", process.stdout)

    def test_wrong_builder_becomes_finding_not_collection_error(self) -> None:
        def mutation(value: dict[str, Any]) -> None:
            value["results"][0]["verificationResult"]["statement"]["predicate"][
                "runDetails"
            ]["builder"]["id"] = "https://attacker.example.invalid/builder"

        self.mutate_verification(mutation)
        process = self.run_collector()
        self.assertEqual(process.returncode, 0)
        bundle = json.loads(self.output_path.read_text(encoding="utf-8"))
        record = next(
            item for item in bundle["evidence"] if item["type"] == "build-record"
        )
        self.assertEqual(record["result"], "finding")
        self.assertIn("reason_codes=builder-identity", process.stdout)

    def test_artifact_tampering_stops_before_bundle_output(self) -> None:
        (self.root / "release.bin").write_text("tampered\n", encoding="utf-8")
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.receipt_path.exists())
        self.assertIn("artifact digest mismatch", process.stdout)

    def test_malformed_verification_is_error_not_clean(self) -> None:
        (self.root / "verification.json").write_text(
            '{"results": "unavailable"}\n',
            encoding="utf-8",
        )
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.receipt_path.exists())
        self.assertIn("attestation set", process.stdout)

    def test_other_workflow_run_is_not_accepted_for_scope(self) -> None:
        def mutation(value: dict[str, Any]) -> None:
            value["results"][0]["verificationResult"]["statement"]["predicate"][
                "runDetails"
            ]["metadata"]["invocationId"] = (
                "https://github.com/example/product/actions/runs/999/attempts/1"
            )

        self.mutate_verification(mutation)
        process = self.run_collector()
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.receipt_path.exists())
        self.assertIn("no unique verified attestation", process.stdout)

    def make_live_policy_and_fake_gh(
        self,
        *,
        fail_verification: bool,
    ) -> tuple[Path, Path]:
        verification = self.root / "verification.json"
        live_output = self.root / "verification-results.json"
        fixture_value = json.loads(verification.read_text(encoding="utf-8"))
        live_output.write_text(
            json.dumps(
                fixture_value["results"],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        arguments = self.root / "gh-arguments.txt"
        fake_gh = self.root / "gh"
        if fail_verification:
            body = (
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  printf 'gh version 2.80.0 (fixture)\\n'\n"
                "  exit 0\n"
                "fi\n"
                "printf 'SENSITIVE_PROVIDER_ERROR' >&2\n"
                "exit 1\n"
            )
        else:
            body = (
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  printf 'gh version 2.80.0 (fixture)\\n'\n"
                "  exit 0\n"
                "fi\n"
                f"printf '%s\\n' \"$@\" > '{arguments}'\n"
                f"exec /bin/cat '{live_output}'\n"
            )
        fake_gh.write_text(body, encoding="utf-8")
        fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)

        policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        policy["source"] = "live"
        policy.pop("verification_fixture")
        policy["github_cli"] = {
            "version": "2.80.0",
            "sha256": hashlib.sha256(fake_gh.read_bytes()).hexdigest(),
            "timeout_seconds": 10,
            "allow_public_good": True,
        }
        self.policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return fake_gh, arguments

    def test_live_mode_uses_pinned_strict_attestation_flags(self) -> None:
        fake_gh, arguments = self.make_live_policy_and_fake_gh(
            fail_verification=False
        )
        process = self.run_collector(gh_path=fake_gh)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        invoked = arguments.read_text(encoding="utf-8").splitlines()
        for required in (
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref",
            "--deny-self-hosted-runners",
            "--predicate-type",
            "--cert-oidc-issuer",
            "--format",
        ):
            with self.subTest(required=required):
                self.assertIn(required, invoked)

    def test_live_verifier_failure_is_sanitized_error(self) -> None:
        fake_gh, _ = self.make_live_policy_and_fake_gh(
            fail_verification=True
        )
        process = self.run_collector(gh_path=fake_gh)
        self.assertEqual(process.returncode, 2)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.receipt_path.exists())
        self.assertNotIn("SENSITIVE_PROVIDER_ERROR", process.stdout)
        self.assertNotIn("SENSITIVE_PROVIDER_ERROR", process.stderr)

    def test_collector_bundle_reaches_cumulative_assessment(self) -> None:
        self.assertEqual(self.run_collector().returncode, 0)
        adapter_root = Path(self.temporary.name) / "adapter"
        shutil.copytree(ADAPTER_FIXTURE, adapter_root)
        destination = adapter_root / "bundles" / "build-platform.json"
        shutil.copyfile(self.output_path, destination)
        adapter_policy_path = adapter_root / "policy.json"
        adapter_policy = json.loads(
            adapter_policy_path.read_text(encoding="utf-8")
        )
        trust = next(
            item
            for item in adapter_policy["trusted_bundles"]
            if item["issuer_role"] == "build-platform"
        )
        trust["sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
        adapter_policy_path.write_text(
            json.dumps(adapter_policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        catalog = Path(self.temporary.name) / "catalog.json"
        build = subprocess.run(
            [
                sys.executable,
                str(CATALOG_BUILDER),
                "--assessment-policy",
                str(ASSESSMENT_POLICY),
                "--adapter-policy",
                str(adapter_policy_path),
                "--output",
                str(catalog),
                "--now",
                NOW,
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        result_path = Path(self.temporary.name) / "assessment.json"
        assessment = subprocess.run(
            [
                sys.executable,
                str(ASSESSOR),
                "--policy",
                str(ASSESSMENT_POLICY),
                "--coverage",
                str(COVERAGE),
                "--evidence",
                str(catalog),
                "--json-output",
                str(result_path),
                "--csv-output",
                str(Path(self.temporary.name) / "assessment.csv"),
                "--now",
                NOW,
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(assessment.returncode, 0)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(result["conclusion"], "PASS")

    def test_collector_contract_schemas_are_valid_json(self) -> None:
        schemas = [
            REPOSITORY_ROOT
            / "schemas"
            / "github-actions-build-platform-collector-policy.schema.json",
            REPOSITORY_ROOT
            / "schemas"
            / "github-actions-build-platform-receipt.schema.json",
        ]
        for schema in schemas:
            with self.subTest(schema=schema):
                self.assertIsInstance(
                    json.loads(schema.read_text(encoding="utf-8")),
                    dict,
                )


if __name__ == "__main__":
    unittest.main()
