from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "collect_github_branch_protection.py"
)
SPEC = importlib.util.spec_from_file_location("collect_github_branch_protection", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


OBSERVED = datetime(2026, 8, 12, 3, 32, tzinfo=timezone.utc)
REPOSITORY = {
    "id": 19001,
    "node_id": "R_kgDOProductApi",
    "full_name": "example-org/product-api",
    "private": True,
    "owner": {"login": "example-org"},
}
PROTECTION = {
    "url": "https://api.github.com/repos/example-org/product-api/branches/main/protection",
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
    "enforce_admins": {"enabled": True},
    "required_pull_request_reviews": {"require_code_owner_reviews": True},
    "required_status_checks": {"strict": True, "contexts": ["test"]},
}


class GithubBranchProtectionCollectorTest(unittest.TestCase):
    def valid_fetcher(self):
        def fetcher(url: str, token: str, timeout: int):
            self.assertEqual(token, "synthetic-token")
            self.assertEqual(timeout, 10)
            if url.endswith("/repos/example-org/product-api"):
                return copy.deepcopy(REPOSITORY), "repository-request"
            if url.endswith("/branches/main/protection"):
                return copy.deepcopy(PROTECTION), "protection-request"
            self.fail(f"unexpected URL {url}")

        return fetcher

    def collect(self, fetcher=None, branch="main"):
        return collector.collect(
            "example-org",
            "product-api",
            branch,
            OBSERVED,
            "synthetic-token",
            10,
            fetcher or self.valid_fetcher(),
        )

    def test_collects_exact_legacy_settings_and_stable_repository(self) -> None:
        output = self.collect()
        self.assertTrue(output["complete"])
        self.assertEqual(output["repository"]["id"], 19001)
        self.assertEqual(output["branch"], {"name": "main"})
        self.assertEqual(
            output["protection"],
            {
                "allow_force_pushes": False,
                "allow_deletions": False,
                "enforce_admins": True,
                "require_code_owner_reviews": True,
            },
        )
        self.assertNotIn("required_status_checks", str(output))

    def test_branch_slash_is_path_encoded(self) -> None:
        calls: list[str] = []

        def fetcher(url: str, token: str, timeout: int):
            calls.append(url)
            if url.endswith("/repos/example-org/product-api"):
                return copy.deepcopy(REPOSITORY), "repository-request"
            if url.endswith("/branches/release%2Fstable/protection"):
                return copy.deepcopy(PROTECTION), "protection-request"
            self.fail(f"unexpected URL {url}")

        output = self.collect(fetcher, "release/stable")
        self.assertEqual(output["branch"]["name"], "release/stable")
        self.assertIn("release%2Fstable", calls[1])

    def test_missing_setting_and_repository_substitution_fail_closed(self) -> None:
        base = self.valid_fetcher()

        def missing(url: str, token: str, timeout: int):
            value, request_id = base(url, token, timeout)
            if url.endswith("/protection"):
                value.pop("allow_force_pushes")
            return value, request_id

        with self.assertRaisesRegex(collector.CollectorError, "force-push setting"):
            self.collect(missing)

        def missing_deletions(url: str, token: str, timeout: int):
            value, request_id = base(url, token, timeout)
            if url.endswith("/protection"):
                value.pop("allow_deletions")
            return value, request_id

        with self.assertRaisesRegex(collector.CollectorError, "deletion setting"):
            self.collect(missing_deletions)

        def missing_admin(url: str, token: str, timeout: int):
            value, request_id = base(url, token, timeout)
            if url.endswith("/protection"):
                value.pop("enforce_admins")
            return value, request_id

        with self.assertRaisesRegex(collector.CollectorError, "admin-enforcement setting"):
            self.collect(missing_admin)

        def missing_code_owner_review(url: str, token: str, timeout: int):
            value, request_id = base(url, token, timeout)
            if url.endswith("/protection"):
                value["required_pull_request_reviews"].pop(
                    "require_code_owner_reviews"
                )
            return value, request_id

        with self.assertRaisesRegex(collector.CollectorError, "code-owner-review setting"):
            self.collect(missing_code_owner_review)

        def substituted(url: str, token: str, timeout: int):
            value, request_id = base(url, token, timeout)
            if url.endswith("/product-api"):
                value["id"] = 19002
                value["full_name"] = "other-org/product-api"
            return value, request_id

        with self.assertRaisesRegex(collector.CollectorError, "stable identity"):
            self.collect(substituted)

    def test_invalid_branch_url_escape_and_symlink_fail_closed(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "branch name"):
            self.collect(branch="release/*")
        with self.assertRaisesRegex(collector.CollectorError, "approved endpoint"):
            collector.validate_url(
                "https://evil.example/repos/example-org/product-api",
                "example-org",
                "product-api",
                "main",
                "repository",
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_text("preserve", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(collector.CollectorError, "symlink"):
                collector.write_output(link, {"complete": True})
            self.assertEqual(real.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
