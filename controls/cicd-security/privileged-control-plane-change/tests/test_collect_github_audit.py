from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_github_audit.py"
SPEC = importlib.util.spec_from_file_location("collect_github_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


ORG = "example-org"
SINCE = datetime(2026, 8, 12, 3, 0, tzinfo=timezone.utc)
UNTIL = datetime(2026, 8, 12, 4, 0, tzinfo=timezone.utc)
COLLECTED = datetime(2026, 8, 12, 4, 1, tzinfo=timezone.utc)
EVENT = {
    "_document_id": "audit-doc-551",
    "action": "environment.update_protection_rule",
    "actor": "release-admin-17",
    "actor_id": 17017,
    "actor_is_bot": False,
    "org": ORG,
    "repo": "example-org/product-api",
    "repository_id": 19001,
    "environment_name": "production",
    "request_id": "github-request-551",
    "operation_type": "modify",
    "@timestamp": "2026-08-12T03:16:00Z",
    "old_value": {"prevent_self_review": False, "required_reviewers": 1},
    "new_value": {"prevent_self_review": True, "required_reviewers": 2},
    "hashed_token": "must-not-survive",
    "actor_ip": "192.0.2.10",
    "token_scopes": "admin:org",
    "user_agent": "sensitive-client-detail",
}
RUNNER_EVENT = {
    "_document_id": "audit-doc-552",
    "action": "org.runner_group_updated",
    "actor": "release-admin-17",
    "actor_id": 17017,
    "actor_is_bot": False,
    "org": ORG,
    "request_id": "github-request-552",
    "operation_type": "modify",
    "@timestamp": "2026-08-12T03:20:00Z",
    "runner_group_id": 42,
    "runner_group_name": "release-runners",
    "runner_group_allow_public": False,
    "runner_group_restricted_to_workflows": True,
    "runner_group_selected_workflow_refs": [
        "example-org/product-api/.github/workflows/release.yml@refs/heads/main"
    ],
    "network_configuration_id": None,
}
RULESET_EVENT = {
    "_document_id": "audit-doc-553",
    "action": "repository_ruleset.update",
    "actor": "repository-admin-21",
    "actor_id": 17021,
    "actor_is_bot": False,
    "org": ORG,
    "repo": "example-org/product-api",
    "repository_id": 19001,
    "request_id": "github-request-553",
    "operation_type": "modify",
    "@timestamp": "2026-08-12T03:24:00Z",
    "ruleset_id": 73,
    "ruleset_name": "protect-main",
    "ruleset_old_name": "protect-main",
    "ruleset_enforcement": "active",
    "ruleset_old_enforcement": "active",
    "ruleset_source_type": "Repository",
    "ruleset_rules_updated": ["pull_request"],
    "hashed_token": "must-not-survive",
}
ORGANIZATION_RULESET_EVENT = {
    "_document_id": "audit-doc-554",
    "action": "repository_ruleset.update",
    "actor": "organization-rules-admin-22",
    "actor_id": 17022,
    "actor_is_bot": False,
    "org": ORG,
    "org_id": 88001,
    "request_id": "github-request-554",
    "operation_type": "modify",
    "@timestamp": "2026-08-12T03:27:00Z",
    "ruleset_id": 74,
    "ruleset_name": "organization-protect-main",
    "ruleset_old_name": "organization-protect-main",
    "ruleset_enforcement": "active",
    "ruleset_old_enforcement": "active",
    "ruleset_source_type": "Organization",
    "ruleset_rules_updated": ["pull_request", "required_status_checks"],
}
BRANCH_PROTECTION_EVENT = {
    "_document_id": "audit-doc-555",
    "action": "protected_branch.update_allow_force_pushes_enforcement_level",
    "actor": "repository-admin-21",
    "actor_id": 17021,
    "actor_is_bot": False,
    "org": ORG,
    "repo": "example-org/product-api",
    "repository_id": 19001,
    "request_id": "github-request-555",
    "operation_type": "modify",
    "@timestamp": "2026-08-12T03:30:00Z",
    "name": "main",
    "allow_force_pushes_enforcement_level": 0,
    "hashed_token": "must-not-survive",
}


class GithubAuditCollectorTest(unittest.TestCase):
    def collect_with(self, fetcher):
        return collector.collect(
            ORG, SINCE, UNTIL, COLLECTED, "synthetic-token", 10, fetcher
        )

    def test_complete_pagination_is_recorded_and_sensitive_fields_are_removed(self) -> None:
        initial = collector.first_url(ORG, SINCE, UNTIL)
        next_url = initial + "&after=cursor-2"
        calls: list[str] = []

        def fetcher(url: str, token: str, timeout: int):
            calls.append(url)
            self.assertEqual(token, "synthetic-token")
            self.assertEqual(timeout, 10)
            if len(calls) == 1:
                return ([{"action": "repo.access", "org": ORG}], next_url)
            return ([copy.deepcopy(EVENT)], None)

        output = self.collect_with(fetcher)
        self.assertEqual(calls, [initial, next_url])
        self.assertTrue(output["complete"])
        self.assertEqual(output["collection"]["pages"], 2)
        self.assertEqual(output["collection"]["raw_events"], 2)
        self.assertEqual(output["collection"]["selected_events"], 1)
        self.assertTrue(output["collection"]["pagination_complete"])
        serialized = json.dumps(output)
        for forbidden in ("must-not-survive", "actor_ip", "hashed_token", "token_scopes", "user_agent"):
            self.assertNotIn(forbidden, serialized)

    def test_pagination_loop_fails_closed(self) -> None:
        initial = collector.first_url(ORG, SINCE, UNTIL)

        def fetcher(url: str, token: str, timeout: int):
            return ([], initial)

        with self.assertRaisesRegex(collector.CollectorError, "pagination loop"):
            self.collect_with(fetcher)

    def test_pagination_cannot_change_host_or_query_window(self) -> None:
        def evil_host(url: str, token: str, timeout: int):
            return ([], "https://evil.example/orgs/example-org/audit-log?per_page=100")

        with self.assertRaisesRegex(collector.CollectorError, "approved endpoint"):
            self.collect_with(evil_host)

        def weak_query(url: str, token: str, timeout: int):
            return ([], "https://api.github.com/orgs/example-org/audit-log?per_page=100&after=x")

        with self.assertRaisesRegex(collector.CollectorError, "bounded query"):
            self.collect_with(weak_query)

    def test_duplicate_or_malformed_target_event_fails_closed(self) -> None:
        duplicate = copy.deepcopy(EVENT)

        def duplicates(url: str, token: str, timeout: int):
            return ([copy.deepcopy(EVENT), duplicate], None)

        with self.assertRaisesRegex(collector.CollectorError, "duplicate document ID"):
            self.collect_with(duplicates)

        malformed = copy.deepcopy(EVENT)
        malformed.pop("new_value")

        def malformed_event(url: str, token: str, timeout: int):
            return ([malformed], None)

        with self.assertRaisesRegex(collector.CollectorError, "exact old or new settings"):
            self.collect_with(malformed_event)

        malformed_runner = copy.deepcopy(RUNNER_EVENT)
        malformed_runner.pop("runner_group_id")

        def malformed_runner_event(url: str, token: str, timeout: int):
            return ([malformed_runner], None)

        with self.assertRaisesRegex(collector.CollectorError, "stable group ID"):
            self.collect_with(malformed_runner_event)

        malformed_ruleset = copy.deepcopy(RULESET_EVENT)
        malformed_ruleset.pop("repository_id")

        def malformed_ruleset_event(url: str, token: str, timeout: int):
            return ([malformed_ruleset], None)

        with self.assertRaisesRegex(collector.CollectorError, "stable repository"):
            self.collect_with(malformed_ruleset_event)

    def test_ruleset_event_keeps_only_documented_join_fields(self) -> None:
        event = copy.deepcopy(RULESET_EVENT)
        event["actor_ip"] = "192.0.2.50"
        event["token_scopes"] = "admin:repo_hook"

        def fetcher(url: str, token: str, timeout: int):
            return ([event], None)

        output = self.collect_with(fetcher)
        selected = output["events"][0]
        self.assertEqual(selected["ruleset_id"], 73)
        self.assertEqual(selected["repository_id"], 19001)
        serialized = json.dumps(output)
        for forbidden in ("must-not-survive", "actor_ip", "token_scopes", "hashed_token"):
            self.assertNotIn(forbidden, serialized)

    def test_organization_ruleset_uses_stable_org_id_without_repository_scope(self) -> None:
        def fetcher(url: str, token: str, timeout: int):
            return ([copy.deepcopy(ORGANIZATION_RULESET_EVENT)], None)

        output = self.collect_with(fetcher)
        selected = output["events"][0]
        self.assertEqual(selected["org_id"], 88001)
        self.assertEqual(selected["ruleset_source_type"], "Organization")
        self.assertNotIn("repo", selected)
        self.assertNotIn("repository_id", selected)

        malformed = copy.deepcopy(ORGANIZATION_RULESET_EVENT)
        malformed["repo"] = "example-org/product-api"
        malformed["repository_id"] = 19001

        def contaminated(url: str, token: str, timeout: int):
            return ([malformed], None)

        with self.assertRaisesRegex(collector.CollectorError, "stable organization identity"):
            self.collect_with(contaminated)

    def test_legacy_branch_event_keeps_exact_target_and_enforcement_only(self) -> None:
        def fetcher(url: str, token: str, timeout: int):
            return ([copy.deepcopy(BRANCH_PROTECTION_EVENT)], None)

        output = self.collect_with(fetcher)
        selected = output["events"][0]
        self.assertEqual(selected["repository_id"], 19001)
        self.assertEqual(selected["name"], "main")
        self.assertEqual(selected["allow_force_pushes_enforcement_level"], 0)
        self.assertNotIn("hashed_token", str(output))

        malformed = copy.deepcopy(BRANCH_PROTECTION_EVENT)
        malformed["allow_force_pushes_enforcement_level"] = True

        def malformed_fetcher(url: str, token: str, timeout: int):
            return ([malformed], None)

        with self.assertRaisesRegex(collector.CollectorError, "enforcement identity"):
            self.collect_with(malformed_fetcher)

    def test_invalid_arguments_fail_before_network(self) -> None:
        def unexpected(url: str, token: str, timeout: int):
            self.fail("fetcher must not be called")

        with self.assertRaises(collector.CollectorError):
            collector.collect("bad/org", SINCE, UNTIL, COLLECTED, "token", 10, unexpected)
        with self.assertRaises(collector.CollectorError):
            collector.collect(ORG, SINCE, UNTIL, COLLECTED, "", 10, unexpected)
        with self.assertRaises(collector.CollectorError):
            collector.collect(
                ORG,
                SINCE,
                SINCE.replace(day=13, hour=4),
                SINCE.replace(day=13, hour=4),
                "token",
                10,
                unexpected,
            )

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


if __name__ == "__main__":
    unittest.main()
