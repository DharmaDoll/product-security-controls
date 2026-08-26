from __future__ import annotations

import copy
import json
import sys
import unittest
from collections import Counter
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402
from framework_registry import discover_registries  # noqa: E402
from sitf_coverage import (  # noqa: E402
    build_attack_flow_rows,
    build_coverage_rows,
    load_profiles,
    validate_attack_flows,
    validate_coverage,
)


class SitfCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()
        self.registry = discover_registries()["sitf"]
        self.coverage_path = (
            REPOSITORY_ROOT / "policies" / "integration" / "sitf-coverage.json"
        )
        self.flow_path = (
            REPOSITORY_ROOT / "policies" / "integration" / "sitf-attack-flows.json"
        )
        self.coverage = json.loads(self.coverage_path.read_text(encoding="utf-8"))
        self.flows = json.loads(self.flow_path.read_text(encoding="utf-8"))

    def test_repository_profile_covers_all_81_pinned_techniques(self) -> None:
        self.assertEqual(validate_coverage(self.coverage, self.registry, self.controls), [])
        self.assertEqual(
            validate_attack_flows(self.flows, self.registry, self.coverage), []
        )
        coverage, flows = load_profiles(
            self.coverage_path, self.flow_path, self.registry, self.controls
        )
        rows = build_coverage_rows(coverage, self.registry)
        self.assertEqual(len(rows), 81)
        self.assertEqual(len({row["Technique ID"] for row in rows}), 81)
        self.assertEqual(
            {row["Disposition"] for row in rows}, {"implemented", "gap"}
        )
        self.assertEqual(
            Counter(row["Disposition"] for row in rows),
            Counter({"implemented": 43, "gap": 38}),
        )
        self.assertTrue(build_attack_flow_rows(flows, coverage, self.registry))

    def test_registry_identity_and_component_inventory_are_fixed(self) -> None:
        self.assertEqual(
            self.registry["source"]["commit"],
            "d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59",
        )
        self.assertEqual(
            self.registry["source"]["sha256"],
            "3f45ca1033e09deab0b66e432969c0b489b35965a4bf2f3299f5a3b24943887e",
        )
        self.assertEqual(
            Counter(entry["component"] for entry in self.registry["entries"]),
            Counter({"endpoint": 19, "vcs": 12, "cicd": 21, "registry": 13, "production": 16}),
        )

    def test_missing_technique_fails_closed(self) -> None:
        changed = copy.deepcopy(self.coverage)
        changed["techniques"].pop()
        errors = validate_coverage(changed, self.registry, self.controls)
        self.assertTrue(any("missing SITF techniques" in error for error in errors))

    def test_unknown_check_reference_fails_closed(self) -> None:
        changed = copy.deepcopy(self.coverage)
        changed["techniques"][0]["check_refs"] = ["PSB-UNKNOWN-999-NOPE-999"]
        errors = validate_coverage(changed, self.registry, self.controls)
        self.assertTrue(any("unknown check reference" in error for error in errors))

    def test_implemented_requires_exact_check_evidence(self) -> None:
        changed = copy.deepcopy(self.coverage)
        implemented = next(
            row for row in changed["techniques"] if row["disposition"] == "implemented"
        )
        implemented["check_refs"] = []
        errors = validate_coverage(changed, self.registry, self.controls)
        self.assertTrue(any("implemented requires exact check_refs" in error for error in errors))

    def test_gap_requires_owned_remaining_work(self) -> None:
        changed = copy.deepcopy(self.coverage)
        gap = next(row for row in changed["techniques"] if row["disposition"] == "gap")
        gap["remaining_work"] = ""
        errors = validate_coverage(changed, self.registry, self.controls)
        self.assertTrue(any("gap requires remaining work" in error for error in errors))

    def test_attack_flow_rejects_unknown_or_single_component_steps(self) -> None:
        changed = copy.deepcopy(self.flows)
        changed["flows"][0]["steps"][0]["technique_id"] = "T-X999"
        errors = validate_attack_flows(changed, self.registry, self.coverage)
        self.assertTrue(any("unknown SITF technique" in error for error in errors))

        changed = copy.deepcopy(self.flows)
        changed["flows"][0]["steps"] = [
            {"technique_id": "T-E001", "objective": "Execute"},
            {"technique_id": "T-E003", "objective": "Harvest"},
            {"technique_id": "T-E004", "objective": "Collect"},
        ]
        errors = validate_attack_flows(changed, self.registry, self.coverage)
        self.assertTrue(any("cross at least three" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
