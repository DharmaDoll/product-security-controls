from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_github_ruleset.py"
SPEC = importlib.util.spec_from_file_location("collect_github_ruleset", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


OBSERVED = datetime(2026, 8, 12, 3, 25, tzinfo=timezone.utc)
BASE_STATE = {
    "id": 73,
    "node_id": "RRS_lADOPROTECTMAIN",
    "name": "protect-main",
    "target": "branch",
    "source_type": "Repository",
    "source": "example-org/product-api",
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
    "rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}],
    "created_at": "2026-07-01T02:00:00Z",
    "updated_at": "2026-07-20T02:00:00Z",
}
AFTER_STATE = copy.deepcopy(BASE_STATE)
AFTER_STATE["rules"][0]["parameters"]["required_approving_review_count"] = 2
AFTER_STATE["updated_at"] = "2026-08-12T03:24:00Z"


def response(value, request_id="request-id", link=None):
    return value, link, request_id


class GithubRulesetCollectorTest(unittest.TestCase):
    def valid_fetcher(self, later=False):
        def fetcher(url: str, token: str, timeout: int):
            self.assertEqual(token, "synthetic-token")
            if url.endswith("/repos/example-org/product-api"):
                return response(
                    {"id": 19001, "node_id": "R_kgDOProductApi", "full_name": "example-org/product-api"},
                    "repository-request",
                )
            if "?includes_parents=false" in url:
                return response(copy.deepcopy(AFTER_STATE), "ruleset-request")
            if url.endswith("/history?per_page=100"):
                history = [
                    {"version_id": 5, "actor": {"id": 17021, "type": "User"}, "updated_at": "2026-08-12T03:24:00Z"},
                    {"version_id": 4, "actor": {"id": 17018, "type": "User"}, "updated_at": "2026-07-20T02:00:00Z"},
                ]
                if later:
                    history.insert(0, {"version_id": 6, "actor": {"id": 17022, "type": "User"}, "updated_at": "2026-08-12T03:24:30Z"})
                return response(history, "history-request")
            if url.endswith("/history/4"):
                return response(
                    {"version_id": 4, "actor": {"id": 17018, "type": "User"}, "updated_at": "2026-07-20T02:00:00Z", "state": copy.deepcopy(BASE_STATE)},
                    "before-request",
                )
            if url.endswith("/history/5"):
                return response(
                    {"version_id": 5, "actor": {"id": 17021, "type": "User"}, "updated_at": "2026-08-12T03:24:00Z", "state": copy.deepcopy(AFTER_STATE)},
                    "after-request",
                )
            self.fail(f"unexpected URL {url}")

        return fetcher

    def collect(self, fetcher=None):
        return collector.collect(
            "example-org", "product-api", 73, 4, 5, OBSERVED,
            "synthetic-token", 10, fetcher or self.valid_fetcher()
        )

    def test_collects_repository_current_and_exact_history_states(self) -> None:
        output = self.collect()
        self.assertTrue(output["complete"])
        self.assertEqual(output["repository"]["id"], 19001)
        self.assertEqual(output["ruleset"]["node_id"], "RRS_lADOPROTECTMAIN")
        self.assertEqual([item["version_id"] for item in output["ruleset"]["versions"]], [4, 5])
        self.assertEqual(output["ruleset"]["current"], AFTER_STATE)

    def test_collects_tag_and_push_targets_for_downstream_scope_binding(self) -> None:
        base = self.valid_fetcher()

        def targeted(target: str):
            def fetcher(url: str, token: str, timeout: int):
                value, link, request_id = base(url, token, timeout)
                if isinstance(value, dict) and value.get("target") == "branch":
                    value = copy.deepcopy(value)
                    value["target"] = target
                if isinstance(value, dict) and isinstance(value.get("state"), dict):
                    value = copy.deepcopy(value)
                    value["state"]["target"] = target
                return value, link, request_id

            return fetcher

        output = self.collect(targeted("tag"))
        self.assertEqual(output["ruleset"]["current"]["target"], "tag")
        push = self.collect(targeted("push"))
        self.assertEqual(push["ruleset"]["current"]["target"], "push")

    def test_target_change_across_versions_fails_closed(self) -> None:
        base = self.valid_fetcher()

        def changed(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if url.endswith("/history/4"):
                value = copy.deepcopy(value)
                value["state"]["target"] = "tag"
            return value, link, request_id

        with self.assertRaisesRegex(collector.CollectorError, "target changed"):
            self.collect(changed)

    def test_later_version_fails_closed(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "later version"):
            self.collect(self.valid_fetcher(later=True))

    def test_current_state_and_history_mismatch_fail_closed(self) -> None:
        base = self.valid_fetcher()

        def tampered(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if "?includes_parents=false" in url:
                value = copy.deepcopy(value)
                value["enforcement"] = "disabled"
            return value, link, request_id

        with self.assertRaisesRegex(collector.CollectorError, "latest requested version"):
            self.collect(tampered)

        def recreated(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if url.endswith("/history/5"):
                value = copy.deepcopy(value)
                value["state"]["created_at"] = "2026-08-01T00:00:00Z"
            if "?includes_parents=false" in url:
                value = copy.deepcopy(value)
                value["created_at"] = "2026-08-01T00:00:00Z"
            return value, link, request_id

        with self.assertRaisesRegex(collector.CollectorError, "generation changed"):
            self.collect(recreated)

    def test_url_escape_and_invalid_arguments_fail_before_publication(self) -> None:
        initial = self.valid_fetcher()

        def escaped(url: str, token: str, timeout: int):
            if url.endswith("/history?per_page=100"):
                value, _, request_id = initial(url, token, timeout)
                return value, "https://evil.example/history?page=2", request_id
            return initial(url, token, timeout)

        with self.assertRaisesRegex(collector.CollectorError, "approved endpoint"):
            self.collect(escaped)
        with self.assertRaises(collector.CollectorError):
            collector.collect("bad/org", "repo", 73, 4, 5, OBSERVED, "token", 10, initial)

    def test_atomic_writer_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_text("preserve", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(collector.CollectorError, "symlink"):
                collector.write_output(link, {"complete": True})
            self.assertEqual(real.read_text(encoding="utf-8"), "preserve")


class GithubOrganizationRulesetCollectorTest(unittest.TestCase):
    def fetcher(self, later=False):
        organization_before = copy.deepcopy(BASE_STATE)
        organization_before["source_type"] = "Organization"
        organization_before["source"] = "example-org"
        organization_before["conditions"]["repository_name"] = {
            "include": ["product-*"], "exclude": [], "protected": True
        }
        organization_after = copy.deepcopy(AFTER_STATE)
        organization_after["source_type"] = "Organization"
        organization_after["source"] = "example-org"
        organization_after["conditions"]["repository_name"] = {
            "include": ["product-*"], "exclude": [], "protected": True
        }

        def fetcher(url: str, token: str, timeout: int):
            if url.endswith("/orgs/example-org"):
                return response(
                    {"id": 88001, "node_id": "O_kgDOExampleOrg", "login": "example-org"},
                    "organization-request",
                )
            if url.endswith("/orgs/example-org/rulesets/73"):
                return response(copy.deepcopy(organization_after), "ruleset-request")
            if url.endswith("/history?per_page=100"):
                values = [
                    {"version_id": 5, "actor": {"id": 17021, "type": "User"}, "updated_at": "2026-08-12T03:24:00Z"},
                    {"version_id": 4, "actor": {"id": 17018, "type": "User"}, "updated_at": "2026-07-20T02:00:00Z"},
                ]
                if later:
                    values.insert(0, {"version_id": 6, "actor": {"id": 17022, "type": "User"}, "updated_at": "2026-08-12T03:24:30Z"})
                return response(values, "history-request")
            if url.endswith("/history/4"):
                return response(
                    {"version_id": 4, "actor": {"id": 17018, "type": "User"}, "updated_at": "2026-07-20T02:00:00Z", "state": copy.deepcopy(organization_before)},
                    "before-request",
                )
            if url.endswith("/history/5"):
                return response(
                    {"version_id": 5, "actor": {"id": 17021, "type": "User"}, "updated_at": "2026-08-12T03:24:00Z", "state": copy.deepcopy(organization_after)},
                    "after-request",
                )
            self.fail(f"unexpected URL {url}")

        return fetcher

    def test_collects_stable_organization_and_exact_history(self) -> None:
        output = collector.collect_organization(
            "example-org", 73, 4, 5, OBSERVED, "synthetic-token", 10, self.fetcher()
        )
        self.assertEqual(output["schema"], "psb-github-organization-ruleset-snapshot/v1")
        self.assertEqual(output["organization_identity"]["id"], 88001)
        self.assertEqual(output["ruleset"]["current"]["source_type"], "Organization")

    def test_collects_organization_tag_target(self) -> None:
        base = self.fetcher()

        def tag_target(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if isinstance(value, dict) and value.get("target") == "branch":
                value = copy.deepcopy(value)
                value["target"] = "tag"
            if isinstance(value, dict) and isinstance(value.get("state"), dict):
                value = copy.deepcopy(value)
                value["state"]["target"] = "tag"
            return value, link, request_id

        output = collector.collect_organization(
            "example-org", 73, 4, 5, OBSERVED, "synthetic-token", 10, tag_target
        )
        self.assertEqual(output["ruleset"]["current"]["target"], "tag")

    def test_later_organization_version_fails_closed(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "later version"):
            collector.collect_organization(
                "example-org", 73, 4, 5, OBSERVED, "synthetic-token", 10,
                self.fetcher(later=True),
            )


if __name__ == "__main__":
    unittest.main()
