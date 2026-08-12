from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402
from psirt_capability_profile import (  # noqa: E402
    PsirtProfileError,
    build_rows,
    load_profile,
    validate_profile,
)


class PsirtCapabilityProfileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()
        self.path = (
            REPOSITORY_ROOT
            / "policies"
            / "organization-assessments"
            / "first-psirt-capability.json"
        )
        self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def test_profile_is_valid_cumulative_and_not_checked(self) -> None:
        self.assertEqual(validate_profile(self.data, self.controls), [])
        rows = build_rows(load_profile(self.path, self.controls))
        self.assertEqual(len(rows), 18)
        self.assertEqual(
            {row["Cumulative Minimum Level"] for row in rows}, {"1", "2", "3"}
        )
        self.assertTrue(all(row["Assessment Result"] == "NOT_CHECKED" for row in rows))
        self.assertTrue(all(row["Evidence Freshness"] == "NOT_CHECKED" for row in rows))
        self.assertTrue(all("sha256:" in row["Source Snapshot Identity"] for row in rows))

    def test_unknown_repository_check_fails_closed(self) -> None:
        changed = copy.deepcopy(self.data)
        changed["rows"][0]["repository_check_refs"] = ["PSB-GOV-003-NOT-A-CHECK"]
        errors = validate_profile(changed, self.controls)
        self.assertTrue(any("repository_check_refs" in error for error in errors))

    def test_missing_source_integrity_fails_closed(self) -> None:
        changed = copy.deepcopy(self.data)
        changed["source_snapshots"][0]["sha256"] = ""
        errors = validate_profile(changed, self.controls)
        self.assertTrue(any("sha256" in error for error in errors))

    def test_public_profile_cannot_claim_pass(self) -> None:
        changed = copy.deepcopy(self.data)
        changed["rows"][0]["assessment_result"] = "PASS"
        errors = validate_profile(changed, self.controls)
        self.assertTrue(any("must remain NOT_CHECKED" in error for error in errors))

    def test_missing_and_malformed_input_are_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.json"
            with self.assertRaises(PsirtProfileError):
                load_profile(missing, self.controls)
            malformed = Path(temporary) / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaises(PsirtProfileError):
                load_profile(malformed, self.controls)


if __name__ == "__main__":
    unittest.main()
