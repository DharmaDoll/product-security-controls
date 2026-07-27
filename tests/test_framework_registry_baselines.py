from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from framework_registry import discover_registries  # noqa: E402


EXPECTED_BASELINES = {
    "cisa-product-security-bad-practices": {
        "version": "2 (January 2025)",
        "count": 13,
        "known_id": "CISA-PSBP-PP-08",
    },
    "github-security-guidance": {
        "version": "github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24)",
        "count": 15,
        "known_id": "GHAS-CONCEPT-SCRIPT-INJECTIONS",
    },
    "mitre-atlas": {
        "version": "2026.05 (format 6.0.0)",
        "count": 278,
        "known_id": "AML.T0005",
    },
    "mitre-attack": {
        "version": "v19.1",
        "count": 1751,
        "known_id": "T1195.001",
    },
    "nist-ssdf": {
        "version": "1.1 (SP 800-218, 2022)",
        "count": 6,
        "known_id": "PW.4.1",
    },
    "openssf-osps-baseline": {
        "version": "2026.02.19",
        "count": 65,
        "known_id": "OSPS-BR-01.01",
    },
    "owasp-asvs": {
        "version": "5.0.0",
        "count": 345,
        "known_id": "v5.0.0-1.2.5",
    },
    "slsa": {
        "version": "1.2",
        "count": 2,
        "known_id": "build-provenance",
    },
}


class FrameworkRegistryBaselineTest(unittest.TestCase):
    def test_pinned_versions_counts_and_known_ids(self) -> None:
        registries = discover_registries()
        self.assertEqual(set(registries), set(EXPECTED_BASELINES))
        for name, expected in EXPECTED_BASELINES.items():
            with self.subTest(framework=name):
                registry = registries[name]
                self.assertEqual(registry["mapping_version"], expected["version"])
                self.assertEqual(len(registry["entries"]), expected["count"])
                self.assertIn(
                    expected["known_id"],
                    {entry["id"] for entry in registry["entries"]},
                )


if __name__ == "__main__":
    unittest.main()
