from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402
from framework_registry import discover_registries  # noqa: E402


EXPECTED_RISKS = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


class OwaspAgenticTop10RegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = discover_registries()["owasp-agentic-top10"]

    def test_complete_released_2026_risk_list_is_pinned(self) -> None:
        self.assertEqual(self.registry["role"], "threat-taxonomy")
        self.assertEqual(self.registry["mapping_version"], "2026")
        self.assertEqual(self.registry["coverage"]["completeness"], "complete-risk-list")
        self.assertEqual(
            {entry["id"]: entry["title"] for entry in self.registry["entries"]},
            EXPECTED_RISKS,
        )

    def test_source_is_official_and_integrity_deferral_is_explicit(self) -> None:
        source = self.registry["source"]
        self.assertTrue(source["url"].startswith("https://genai.owasp.org/"))
        self.assertTrue(
            source["announcement_url"].startswith("https://genai.owasp.org/")
        )
        self.assertEqual(source["published_at"], "2025-12-09")
        self.assertEqual(
            source["artifact_integrity"],
            "not-recorded-vendor-download-monitor-denied-automated-retrieval",
        )
        self.assertNotIn("sha256", source)

    def test_only_reviewed_direct_control_rows_are_mapped(self) -> None:
        mappings = [
            (control["id"], mapping)
            for control in discover_controls()
            for mapping in control["mappings"]
            if mapping["framework"] == "owasp-agentic-top10"
        ]
        self.assertEqual(
            {control_id for control_id, _ in mappings},
            {
                "PSB-AI-001",
                "PSB-AI-002",
                "PSB-AI-003",
                "PSB-AI-004",
                "PSB-AI-005",
                "PSB-AI-006",
                "PSB-AI-007",
                "PSB-AI-008",
                "PSB-AI-009",
                "PSB-AI-010",
                "PSB-AI-011",
                "PSB-DETECT-002",
                "PSB-SOURCE-004",
            },
        )
        self.assertEqual(
            {mapping["id"] for _, mapping in mappings},
            {"ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"},
        )
        for _, mapping in mappings:
            self.assertEqual(mapping["version"], "2026")
            self.assertNotIn("complies", mapping["relationship"])
            self.assertTrue(mapping["applies_to"])


if __name__ == "__main__":
    unittest.main()
