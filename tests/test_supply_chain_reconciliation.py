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
from supply_chain_reconciliation import (  # noqa: E402
    ReconciliationError,
    build_reconciliation_rows,
    load_reconciliation,
    validate_reconciliation,
)


class SupplyChainReconciliationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()
        self.path = (
            REPOSITORY_ROOT
            / "policies"
            / "integration"
            / "supply-chain-reconciliation.json"
        )
        self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def test_repository_profile_is_valid_and_resolves_exact_checks(self) -> None:
        self.assertEqual(validate_reconciliation(self.data, self.controls), [])
        loaded = load_reconciliation(self.path, self.controls)
        rows = build_reconciliation_rows(loaded)
        self.assertEqual(len(rows), len(self.data["rows"]))
        self.assertEqual(
            {row["Disposition"] for row in rows},
            {"implemented", "planned", "out-of-scope"},
        )

    def test_unknown_check_reference_fails_closed(self) -> None:
        changed = copy.deepcopy(self.data)
        changed["rows"][0]["check_refs"] = ["PSB-SOURCE-001-NOT-A-CHECK"]
        errors = validate_reconciliation(changed, self.controls)
        self.assertTrue(any("unknown check reference" in error for error in errors))

    def test_implemented_row_requires_exact_current_evidence(self) -> None:
        changed = copy.deepcopy(self.data)
        changed["rows"][0]["check_refs"] = []
        errors = validate_reconciliation(changed, self.controls)
        self.assertTrue(any("implemented requires exact check_refs" in error for error in errors))

    def test_gap_requires_an_owner_and_description(self) -> None:
        changed = copy.deepcopy(self.data)
        gap = changed["rows"][0]
        gap["disposition"] = "gap"
        gap["check_refs"] = []
        gap["gap_owner"] = ""
        gap["gap_description"] = ""
        errors = validate_reconciliation(changed, self.controls)
        self.assertTrue(any("gap requires owner and description" in error for error in errors))

    def test_profile_may_close_its_last_gap(self) -> None:
        self.assertNotIn("gap", {row["disposition"] for row in self.data["rows"]})
        self.assertEqual(validate_reconciliation(self.data, self.controls), [])

    def test_missing_or_malformed_source_is_not_an_empty_clean_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.json"
            with self.assertRaises(ReconciliationError):
                load_reconciliation(missing, self.controls)
            malformed = Path(temporary) / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaises(ReconciliationError):
                load_reconciliation(malformed, self.controls)


if __name__ == "__main__":
    unittest.main()
