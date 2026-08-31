#!/usr/bin/env python3
"""Negative and positive verification for PSB-DETECT-003."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path(__file__).resolve().parents[1]
VERIFY = CONTROL / "scripts" / "verify.py"
POLICY = CONTROL / "secure" / "policy.json"
SECURE_INVENTORY = CONTROL / "secure" / "inventory.json"
SECURE_OBSERVATIONS = CONTROL / "secure" / "observations.json"
SECURE_STATE = CONTROL / "secure" / "state.json"


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class ReconciliationTests(unittest.TestCase):
    maxDiff = None

    def run_verify(
        self,
        *,
        policy: Path = POLICY,
        inventory: Path = SECURE_INVENTORY,
        observations: Path = SECURE_OBSERVATIONS,
        state: Path = SECURE_STATE,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(VERIFY),
                "--policy",
                str(policy),
                "--inventory",
                str(inventory),
                "--observations",
                str(observations),
                "--state",
                str(state),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def write_document(self, directory: Path, name: str, value: dict[str, Any]) -> Path:
        path = directory / name
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def test_secure_inventory_and_observations_pass(self) -> None:
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout,
            (CONTROL / "expected-results" / "secure.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(result.stderr, "")

    def test_unknown_reappeared_and_private_assets_are_findings(self) -> None:
        result = self.run_verify(
            inventory=CONTROL / "insecure" / "inventory.json",
            observations=CONTROL / "insecure" / "observations.json",
            state=CONTROL / "insecure" / "state.json",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout,
            (CONTROL / "expected-results" / "insecure.txt").read_text(encoding="utf-8"),
        )
        self.assertNotIn("admin.example.invalid", result.stdout)
        self.assertNotIn("staging.example.invalid", result.stdout)

    def test_unhealthy_or_stale_source_is_error(self) -> None:
        for mutation, message in (
            (("status", "ERROR"), "ERROR observation source is incomplete or unhealthy\n"),
            (("collected_at", "2026-08-29T00:00:00Z"), "ERROR observation source is stale\n"),
        ):
            with self.subTest(field=mutation[0]), tempfile.TemporaryDirectory() as temporary:
                document = load(SECURE_OBSERVATIONS)
                document["sources"][0][mutation[0]] = mutation[1]
                path = self.write_document(Path(temporary), "observations.json", document)
                result = self.run_verify(observations=path)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stdout, message)

    def test_third_party_asset_is_not_pulled_into_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(SECURE_OBSERVATIONS)
            document["assets"][0]["name"] = "third-party.invalid"
            path = self.write_document(Path(temporary), "observations.json", document)
            result = self.run_verify(observations=path)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout,
                "ERROR observed asset is outside the authorized owned roots\n",
            )

    def test_sensitive_metadata_is_rejected_without_value_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(SECURE_OBSERVATIONS)
            document["assets"][0]["signals"][0]["banner"] = "SYNTHETIC_SECRET_VALUE_DO_NOT_USE"
            path = self.write_document(Path(temporary), "observations.json", document)
            result = self.run_verify(observations=path)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("forbidden sensitive field", result.stdout)
            self.assertNotIn("SYNTHETIC_SECRET_VALUE_DO_NOT_USE", result.stdout)
            self.assertNotIn("SYNTHETIC_SECRET_VALUE_DO_NOT_USE", result.stderr)

    def test_personal_identifier_cannot_be_stored_as_state_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(CONTROL / "insecure" / "state.json")
            document["entries"][0]["owner"] = "person@example.invalid"
            path = self.write_document(Path(temporary), "state.json", document)
            result = self.run_verify(
                inventory=CONTROL / "insecure" / "inventory.json",
                observations=CONTROL / "insecure" / "observations.json",
                state=path,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout,
                "ERROR state entry owner is not a safe stable label\n",
            )
            self.assertNotIn("person@example.invalid", result.stdout)

    def test_unsafe_active_reconnaissance_policy_is_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(POLICY)
            document["active_validation"]["allow_login_attempts"] = True
            path = self.write_document(Path(temporary), "policy.json", document)
            result = self.run_verify(policy=path)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout,
                "FINDING control reason=unsafe-active-validation-policy\n"
                "REJECTED findings=1\n",
            )

    def test_scope_mismatch_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(SECURE_OBSERVATIONS)
            document["scope_id"] = "external-surface@sha256:" + "9" * 64
            path = self.write_document(Path(temporary), "observations.json", document)
            result = self.run_verify(observations=path)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout,
                "ERROR observations scope does not match the approved inventory\n",
            )

    def test_expired_asset_review_is_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(SECURE_INVENTORY)
            document["assets"][0]["review_expires_at"] = "2026-08-31T11:59:59Z"
            path = self.write_document(Path(temporary), "inventory.json", document)
            result = self.run_verify(inventory=path)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(
                "FINDING asset=AST-API-001 reason=inventory-review-expired",
                result.stdout,
            )

    def test_delegated_service_target_drift_is_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = load(SECURE_OBSERVATIONS)
            document["assets"][1]["signals"][1]["target_name"] = "other.identity.invalid"
            path = self.write_document(Path(temporary), "observations.json", document)
            result = self.run_verify(observations=path)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(
                "FINDING asset=AST-LOGIN-001 reason=delegation-target-drift",
                result.stdout,
            )


if __name__ == "__main__":
    unittest.main()
