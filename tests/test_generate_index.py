from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from control_metadata import discover_controls  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "generate_index",
    REPOSITORY_ROOT / "scripts" / "generate-index.py",
)
assert SPEC and SPEC.loader
generate_index = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_index)


class GenerateIndexTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controls = discover_controls()

    def test_human_catalog_links_every_control_once(self) -> None:
        catalog = generate_index.render_control_catalog(self.controls)
        for control in self.controls:
            with self.subTest(control=control["id"]):
                self.assertEqual(catalog.count(f"[{control['id']}]("), 1)
                relative = control["_directory"].relative_to(
                    REPOSITORY_ROOT / "controls"
                )
                self.assertIn(
                    f"({relative.as_posix()}/README.md)",
                    catalog,
                )

    def test_human_catalog_keeps_all_canonical_domains_visible(self) -> None:
        catalog = generate_index.render_control_catalog(self.controls)
        for domain, label, _ in generate_index.DOMAIN_CATALOG:
            with self.subTest(domain=domain):
                self.assertIn(f"[{label}](#domain-{domain})", catalog)
                self.assertIn(f'<a id="domain-{domain}"></a>', catalog)
                self.assertIn(f"## {label}", catalog)

    def test_human_catalog_lists_unique_framework_links(self) -> None:
        catalog = generate_index.render_control_catalog(self.controls)
        for control in self.controls:
            with self.subTest(control=control["id"]):
                expected = generate_index.framework_links(control)
                self.assertIn(expected, catalog)
                frameworks = {
                    mapping["framework"] for mapping in control["mappings"]
                }
                for framework in frameworks:
                    self.assertIn(
                        f"../generated/mappings/{framework}.md",
                        expected,
                    )
                    self.assertEqual(
                        expected.count(f"../generated/mappings/{framework}.md"),
                        1,
                    )
                    self.assertTrue(
                        (
                            REPOSITORY_ROOT
                            / "generated"
                            / "mappings"
                            / f"{framework}.md"
                        ).is_file()
                    )

    def test_framework_links_show_unmapped_state(self) -> None:
        self.assertEqual(generate_index.framework_links({"mappings": []}), "—")

    def test_flat_index_control_links_resolve(self) -> None:
        index = generate_index.render_flat_index(self.controls)
        links = re.findall(r"\[[^\]]+\]\((\.\./controls/[^)]+/README\.md)\)", index)
        self.assertEqual(len(links), len(self.controls))
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((REPOSITORY_ROOT / "generated" / link).resolve().is_file())

    def test_catalog_generation_is_deterministic(self) -> None:
        first = generate_index.expected_outputs(self.controls)
        second = generate_index.expected_outputs(discover_controls())
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
