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
COLLECTOR = ROOT / "scripts" / "collect-github-releases-evidence.py"
CATALOG_BUILDER = ROOT / "scripts" / "build-slsa-build-l2-evidence.py"
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
FIXTURE = ROOT / "tests" / "fixtures" / "github-releases-collector" / "secure"
ADAPTER_FIXTURE = (
    ROOT / "tests" / "fixtures" / "slsa-build-l2-adapter" / "secure"
)
NOW = "2026-07-29T12:30:00Z"


class GitHubReleasesEvidenceCollectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "collector"
        shutil.copytree(FIXTURE, self.root)

    def run_collector(
        self,
        role: str,
        *,
        gh_path: Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        policy = self.root / f"{role}-policy.json"
        bundle = Path(self.temporary.name) / f"{role}-bundle.json"
        receipt = Path(self.temporary.name) / f"{role}-receipt.json"
        command = [
            sys.executable,
            str(COLLECTOR),
            "--policy",
            str(policy),
            "--output",
            str(bundle),
            "--receipt-output",
            str(receipt),
            "--now",
            NOW,
        ]
        if gh_path is not None:
            command.extend(["--gh", str(gh_path)])
        process = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        return process, bundle, receipt

    def mutate_release(self, mutation: Callable[[dict[str, Any]], None]) -> None:
        path = self.root / "release.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_separate_producer_and_monitor_bundles_are_complete(self) -> None:
        producer, producer_bundle, producer_receipt = self.run_collector(
            "software-producer"
        )
        monitor, monitor_bundle, monitor_receipt = self.run_collector(
            "security-monitor"
        )
        self.assertEqual(producer.returncode, 0, producer.stdout + producer.stderr)
        self.assertEqual(monitor.returncode, 0, monitor.stdout + monitor.stderr)
        producer_value = json.loads(producer_bundle.read_text(encoding="utf-8"))
        monitor_value = json.loads(monitor_bundle.read_text(encoding="utf-8"))
        self.assertEqual(
            {item["type"] for item in producer_value["evidence"]},
            {"producer-policy", "build-policy", "publication-manifest"},
        )
        self.assertEqual(
            {item["type"] for item in monitor_value["evidence"]},
            {"storage-probe"},
        )
        publication = next(
            item
            for item in producer_value["evidence"]
            if item["type"] == "publication-manifest"
        )
        self.assertEqual(
            publication["sha256"],
            hashlib.sha256(producer_receipt.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            monitor_value["evidence"][0]["sha256"],
            hashlib.sha256(monitor_receipt.read_bytes()).hexdigest(),
        )

    def test_missing_provenance_is_a_finding(self) -> None:
        self.mutate_release(lambda value: value["assets"].pop())
        process, bundle, _ = self.run_collector("software-producer")
        self.assertEqual(process.returncode, 0)
        value = json.loads(bundle.read_text(encoding="utf-8"))
        publication = next(
            item
            for item in value["evidence"]
            if item["type"] == "publication-manifest"
        )
        self.assertEqual(publication["result"], "finding")
        self.assertIn("required-assets", process.stdout)

    def test_mutable_release_is_a_finding_for_monitor(self) -> None:
        self.mutate_release(lambda value: value.update({"immutable": False}))
        process, bundle, _ = self.run_collector("security-monitor")
        self.assertEqual(process.returncode, 0)
        value = json.loads(bundle.read_text(encoding="utf-8"))
        self.assertEqual(value["evidence"][0]["result"], "finding")
        self.assertIn("release-mutable", process.stdout)

    def test_wrong_asset_digest_is_a_finding(self) -> None:
        self.mutate_release(
            lambda value: value["assets"][0].update({"digest": "sha256:" + "0" * 64})
        )
        process, bundle, _ = self.run_collector("security-monitor")
        self.assertEqual(process.returncode, 0)
        value = json.loads(bundle.read_text(encoding="utf-8"))
        self.assertEqual(value["evidence"][0]["result"], "finding")
        self.assertIn("artifact-digest", process.stdout)

    def test_malformed_api_result_is_error_without_outputs(self) -> None:
        (self.root / "release.json").write_text(
            '{"assets": "unavailable"}\n',
            encoding="utf-8",
        )
        process, bundle, receipt = self.run_collector("security-monitor")
        self.assertEqual(process.returncode, 2)
        self.assertFalse(bundle.exists())
        self.assertFalse(receipt.exists())
        self.assertIn("timestamp", process.stdout)

    def make_live_policy_and_fake_gh(
        self,
        *,
        fail: bool,
    ) -> tuple[Path, Path]:
        fake = self.root / "gh"
        arguments = self.root / "gh-arguments.txt"
        release = self.root / "release.json"
        if fail:
            body = (
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  printf 'gh version 2.80.0 (fixture)\\n'\n"
                "  exit 0\n"
                "fi\n"
                "printf 'SENSITIVE_RELEASE_ERROR' >&2\n"
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
                f"exec /bin/cat '{release}'\n"
            )
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        policy_path = self.root / "software-producer-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["source"] = "live"
        policy.pop("release_fixture")
        policy["github_cli"] = {
            "version": "2.80.0",
            "sha256": hashlib.sha256(fake.read_bytes()).hexdigest(),
            "timeout_seconds": 10,
        }
        policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return fake, arguments

    def test_live_mode_uses_versioned_read_only_release_endpoint(self) -> None:
        fake, arguments = self.make_live_policy_and_fake_gh(fail=False)
        process, _, _ = self.run_collector("software-producer", gh_path=fake)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        invoked = arguments.read_text(encoding="utf-8").splitlines()
        self.assertIn("api", invoked)
        self.assertIn("GET", invoked)
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", invoked)
        self.assertIn("--hostname", invoked)
        self.assertTrue(
            any(
                value.endswith(
                    "/releases/tags/product-v1.2.3"
                )
                for value in invoked
            )
        )

    def test_live_api_failure_is_sanitized_error(self) -> None:
        fake, _ = self.make_live_policy_and_fake_gh(fail=True)
        process, bundle, receipt = self.run_collector(
            "software-producer",
            gh_path=fake,
        )
        self.assertEqual(process.returncode, 2)
        self.assertFalse(bundle.exists())
        self.assertFalse(receipt.exists())
        self.assertNotIn("SENSITIVE_RELEASE_ERROR", process.stdout)
        self.assertNotIn("SENSITIVE_RELEASE_ERROR", process.stderr)

    def test_both_bundles_reach_cumulative_assessment(self) -> None:
        _, producer_bundle, _ = self.run_collector("software-producer")
        _, monitor_bundle, _ = self.run_collector("security-monitor")
        adapter_root = Path(self.temporary.name) / "adapter"
        shutil.copytree(ADAPTER_FIXTURE, adapter_root)
        replacements = {
            "software-producer": producer_bundle,
            "security-monitor": monitor_bundle,
        }
        adapter_policy_path = adapter_root / "policy.json"
        policy = json.loads(adapter_policy_path.read_text(encoding="utf-8"))
        for role, source in replacements.items():
            trust = next(
                item
                for item in policy["trusted_bundles"]
                if item["issuer_role"] == role
            )
            destination = adapter_root / "bundles" / trust["path"]
            shutil.copyfile(source, destination)
            trust["sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
        adapter_policy_path.write_text(
            json.dumps(policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        catalog = Path(self.temporary.name) / "catalog.json"
        built = subprocess.run(
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
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        result_path = Path(self.temporary.name) / "result.json"
        assessed = subprocess.run(
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
                str(Path(self.temporary.name) / "result.csv"),
                "--now",
                NOW,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(assessed.returncode, 0)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(result["conclusion"], "PASS")

    def test_contract_schemas_are_valid_json(self) -> None:
        schemas = [
            ROOT / "schemas" / "github-releases-collector-policy.schema.json",
            ROOT / "schemas" / "github-releases-receipt.schema.json",
        ]
        for schema in schemas:
            with self.subTest(schema=schema):
                self.assertIsInstance(
                    json.loads(schema.read_text(encoding="utf-8")),
                    dict,
                )


if __name__ == "__main__":
    unittest.main()
