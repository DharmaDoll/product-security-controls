from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402


REGISTRY_PATH = (
    REPOSITORY_ROOT
    / "frameworks"
    / "github-security-guidance"
    / "registry.json"
)

EXPECTED_COLLECTION_PAGES = {
    "GH-SUPPLY-CHAIN-BEST-PRACTICES": {
        "GHSC-END-TO-END",
        "GHSC-SECURE-ACCOUNTS",
        "GHSC-SECURE-CODE",
        "GHSC-SECURE-BUILDS",
    },
    "GH-ACTIONS-SECURITY-CONCEPTS": {
        "GHAS-CONCEPT-SECRETS",
        "GHAS-CONCEPT-GITHUB-TOKEN",
        "GHAS-CONCEPT-OIDC",
        "GHAS-CONCEPT-ARTIFACT-ATTESTATIONS",
        "GHAS-CONCEPT-SCRIPT-INJECTIONS",
        "GHAS-CONCEPT-COMPROMISED-RUNNERS",
        "GHAS-CONCEPT-KUBERNETES-ADMISSION",
    },
    "GH-ACTIONS-SECURITY-REFERENCE": {
        "GHAS-REF-SECURE-USE",
        "GHAS-REF-PULL-REQUEST-TARGET",
        "GHAS-REF-SECRETS",
        "GHAS-REF-OIDC",
    },
    "GH-ADMINISTRATION-SECURITY": {
        "GH-ADMIN-ACTIONS-REPOSITORY",
        "GH-ADMIN-ACTIONS-ORGANIZATION",
        "GH-ADMIN-CODEOWNERS",
        "GH-ADMIN-RULESETS",
        "GH-ADMIN-RULESET-RULES",
        "GH-ADMIN-SAML-IAM",
        "GH-ADMIN-SCIM-ORGANIZATIONS",
        "GH-ADMIN-AUDIT-EVENTS",
        "GH-ADMIN-CREDENTIAL-TYPES",
    },
}


class GitHubSecurityGuidanceRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with REGISTRY_PATH.open("r", encoding="utf-8") as handle:
            cls.registry = json.load(handle)

    def test_source_is_pinned_to_full_commit(self) -> None:
        self.assertRegex(self.registry["source_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(
            self.registry["source_commit_date"], r"^\d{4}-\d{2}-\d{2}$"
        )
        self.assertRegex(self.registry["review_date"], r"^\d{4}-\d{2}-\d{2}$")

    def test_all_pinned_collection_pages_are_registered(self) -> None:
        collections = {
            collection["id"]: set(collection["page_ids"])
            for collection in self.registry["collections"]
        }
        self.assertEqual(collections, EXPECTED_COLLECTION_PAGES)

        registered_ids = {page["id"] for page in self.registry["entries"]}
        expected_ids = set().union(*EXPECTED_COLLECTION_PAGES.values())
        self.assertEqual(registered_ids, expected_ids)

    def test_ids_and_urls_are_unique_and_official(self) -> None:
        pages = self.registry["entries"]
        ids = [page["id"] for page in pages]
        urls = [page["source_url"] for page in pages]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(urls), len(set(urls)))

        all_urls = [
            *(collection["index_url"] for collection in self.registry["collections"]),
            *urls,
            *(reference["url"] for reference in self.registry["supporting_references"]),
        ]
        for url in all_urls:
            parsed = urlparse(url)
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.netloc, "docs.github.com")
            self.assertFalse(parsed.query)
            self.assertFalse(parsed.fragment)

    def test_mapping_ids_use_stable_format(self) -> None:
        for page in self.registry["entries"]:
            self.assertIsNotNone(re.fullmatch(r"[A-Z0-9-]+", page["id"]))

    def test_administration_pages_bind_pinned_source_bytes(self) -> None:
        administration_ids = EXPECTED_COLLECTION_PAGES[
            "GH-ADMINISTRATION-SECURITY"
        ]
        pages = {
            page["id"]: page
            for page in self.registry["entries"]
            if page["id"] in administration_ids
        }
        self.assertEqual(set(pages), administration_ids)
        source_paths = []
        for page in pages.values():
            self.assertRegex(page["source_path"], r"^content/.+\.md$")
            self.assertRegex(page["source_sha256"], r"^[0-9a-f]{64}$")
            source_paths.append(page["source_path"])
        self.assertEqual(len(source_paths), len(set(source_paths)))

    def test_control_mappings_reference_registered_pages_and_version(self) -> None:
        registered_ids = {page["id"] for page in self.registry["entries"]}
        mappings = [
            mapping
            for control in discover_controls()
            for mapping in control["mappings"]
            if mapping["framework"] == self.registry["name"]
        ]
        self.assertGreaterEqual(len(mappings), 1)
        for mapping in mappings:
            self.assertIn(mapping["id"], registered_ids)
            self.assertEqual(mapping["version"], self.registry["mapping_version"])


if __name__ == "__main__":
    unittest.main()
