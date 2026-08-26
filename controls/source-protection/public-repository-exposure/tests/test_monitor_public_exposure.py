from __future__ import annotations

import base64
import importlib.util
import json
import os
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse


CONTROL_DIR = Path(__file__).resolve().parent.parent
SCANNER_PATH = CONTROL_DIR / "scripts" / "monitor-public-exposure.py"
SPEC = importlib.util.spec_from_file_location("psb_source_003_monitor", SCANNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("scanner module cannot be loaded")
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class QueueTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("unexpected provider request")
        return self.responses.pop(0)


def response(value, headers=None, status=200):
    return status, headers or {}, json.dumps(value).encode("utf-8")


def sample_observation(resource_id="123:config/app.yml:" + "a" * 40):
    return {
        "provider": "github",
        "surface": "github-code",
        "resource_id": resource_id,
        "indicator_id": "ORG-DOMAIN-PRIMARY",
        "query_ids": ["ORG-DOMAIN-PRIMARY-API-CODE-DOMAIN"],
        "resource": "outside/example",
        "path": "config/app.yml",
        "public_url": "https://github.com/outside/example/blob/" + "a" * 40 + "/config/app.yml",
    }


def observation_document(observations, collected_at="2026-08-26T00:00:00Z"):
    return {
        "schema_version": "1.0",
        "provider": "github",
        "query_catalog_version": monitor.QUERY_CATALOG_VERSION,
        "collected_at": collected_at,
        "cursors": {"github_public_gists_since": collected_at},
        "observations": sorted(observations, key=monitor.observation_fingerprint),
    }


class ConfigurationAndQueryTests(unittest.TestCase):
    def test_domain_only_configuration_generates_anchored_queries(self):
        domains = monitor.load_configuration(CONTROL_DIR / "secure" / "domain-monitor.json")
        self.assertEqual(domains[0]["id"], "ORG-DOMAIN-PRIMARY")

        automatic = monitor.automatic_queries(domains)
        self.assertEqual(len(automatic), 6)
        for query in automatic:
            self.assertIn("corp.example.invalid", query["query"])
        self.assertTrue(any(item["query"].endswith(" is:issue") for item in automatic))
        self.assertTrue(any(item["query"].endswith(" is:pr") for item in automatic))
        self.assertFalse(any("is:public" in item["query"] for item in automatic))

        rendered = monitor.render_browser_queries(domains)
        self.assertIn("https://github.com/search?", rendered)
        self.assertIn("https://gist.github.com/search?", rendered)
        self.assertIn("site:gist.github.com", rendered)
        self.assertIn("not executed by the scanner", rendered)

    def test_unsafe_and_duplicate_domains_are_rejected(self):
        with self.assertRaises(monitor.MonitorError):
            monitor.load_configuration(CONTROL_DIR / "insecure" / "domain-monitor.json")
        invalid_values = [
            "https://example.invalid",
            "*.example.invalid",
            "person@example.invalid",
            "127.0.0.1",
            "localhost",
        ]
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(monitor.MonitorError):
                monitor.normalize_domain(value)


class ProviderNormalizationTests(unittest.TestCase):
    def test_code_query_deduplicates_query_matches(self):
        item = {
            "sha": "a" * 40,
            "path": "config/app.yml",
            "html_url": "https://github.com/outside/example/blob/" + "a" * 40 + "/config/app.yml",
            "repository": {
                "id": 123,
                "full_name": "outside/example",
                "private": False,
            },
        }
        transport = QueueTransport(
            [
                response({"total_count": 1, "incomplete_results": False, "items": [item]}),
                response({"total_count": 1, "incomplete_results": False, "items": [item]}),
            ]
        )
        client = monitor.GitHubClient("public-token", transport=transport, search_interval=0)
        domains = [{"id": "ORG-DOMAIN-PRIMARY", "value": "corp.example.invalid"}]
        queries = [query for query in monitor.automatic_queries(domains) if query["surface"] == "github-code"]
        observations = {}
        for query in queries:
            monitor.collect_search_query(client, query, observations)
        self.assertEqual(len(observations), 1)
        observation = next(iter(observations.values()))
        self.assertEqual(len(observation["query_ids"]), 2)
        self.assertNotIn("corp.example.invalid", json.dumps(observation))

    def test_issue_and_pull_request_items_are_distinct_surfaces(self):
        issue_query = {
            "id": "ORG-DOMAIN-PRIMARY-API-ISSUE-DOMAIN",
            "indicator_id": "ORG-DOMAIN-PRIMARY",
            "surface": "github-issue",
        }
        issue = {
            "id": 77,
            "number": 4,
            "updated_at": "2026-08-26T00:00:00Z",
            "repository_url": "https://api.github.com/repos/outside/example",
            "html_url": "https://github.com/outside/example/issues/4",
        }
        normalized = monitor.normalize_issue_item(issue, issue_query)
        self.assertEqual(normalized["surface"], "github-issue")
        self.assertEqual(normalized["path"], "issues/4")

        pull_query = dict(issue_query, surface="github-pull-request")
        pull = dict(issue, pull_request={"url": "https://api.github.com/pulls/4"})
        normalized = monitor.normalize_issue_item(pull, pull_query)
        self.assertEqual(normalized["surface"], "github-pull-request")
        self.assertEqual(normalized["path"], "pull/4")

    def test_issue_repository_visibility_is_verified_and_cached(self):
        repository_url = "https://api.github.com/repos/outside/example"
        transport = QueueTransport(
            [
                response(
                    {
                        "id": 123,
                        "full_name": "outside/example",
                        "private": False,
                    }
                )
            ]
        )
        client = monitor.GitHubClient(
            "public-token", transport=transport, search_interval=0
        )
        cache = {}
        self.assertEqual(
            monitor.verify_public_repository(client, repository_url, cache),
            "outside/example",
        )
        self.assertEqual(
            monitor.verify_public_repository(client, repository_url, cache),
            "outside/example",
        )
        self.assertEqual(len(transport.requests), 1)

        private_transport = QueueTransport(
            [
                response(
                    {
                        "id": 123,
                        "full_name": "outside/example",
                        "private": True,
                    }
                )
            ]
        )
        private_client = monitor.GitHubClient(
            "overprivileged-token", transport=private_transport, search_interval=0
        )
        with self.assertRaises(monitor.MonitorError):
            monitor.verify_public_repository(private_client, repository_url, {})

    def test_incomplete_private_and_malformed_results_fail_closed(self):
        with self.assertRaises(monitor.MonitorError):
            monitor.validate_search_page(
                {"total_count": 1, "incomplete_results": True, "items": []}, None
            )
        query = {
            "id": "ORG-DOMAIN-PRIMARY-API-CODE-DOMAIN",
            "indicator_id": "ORG-DOMAIN-PRIMARY",
        }
        private_item = {
            "sha": "a" * 40,
            "path": "a.txt",
            "html_url": "https://github.com/private/example/blob/" + "a" * 40 + "/a.txt",
            "repository": {"id": 1, "full_name": "private/example", "private": True},
        }
        with self.assertRaises(monitor.MonitorError):
            monitor.normalize_code_item(private_item, query)
        with self.assertRaises(monitor.MonitorError):
            monitor.next_link({"link": '<https://evil.example/page=2>; rel="next"'})
        with self.assertRaises(monitor.MonitorError):
            monitor.validate_public_url(
                "https://github.com/outside/example/issues/4)bad", "github.com"
            )


class GistDeltaTests(unittest.TestCase):
    def test_first_gist_cursor_uses_one_hour_lookback(self):
        collected_at = datetime(2026, 8, 26, 2, 0, tzinfo=timezone.utc)
        self.assertEqual(
            monitor.gist_since_from_state(monitor.empty_state(), collected_at),
            datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc),
        )

    def test_gist_content_match_is_normalized_without_content(self):
        observations = {}
        detail = {
            "id": "abc123",
            "public": True,
            "truncated": False,
            "html_url": "https://gist.github.com/user/abc123",
            "description": "configuration sample",
            "history": [{"version": "b" * 40}],
            "files": {
                "notes.txt": {
                    "filename": "notes.txt",
                    "truncated": False,
                    "content": "contact alice@corp.example.invalid password=NOT_A_REAL_SECRET",
                }
            },
        }
        patterns = monitor.domain_patterns(
            [{"id": "ORG-DOMAIN-PRIMARY", "value": "corp.example.invalid"}]
        )
        monitor.collect_gist_detail(detail, patterns, observations)
        self.assertEqual(len(observations), 1)
        serialized = json.dumps(next(iter(observations.values())))
        self.assertNotIn("corp.example.invalid", serialized)
        self.assertNotIn("alice@", serialized)
        self.assertNotIn("NOT_A_REAL_SECRET", serialized)
        self.assertIn("gist/abc123", serialized)

    def test_truncated_gist_is_not_treated_as_clean(self):
        detail = {
            "id": "abc123",
            "public": True,
            "truncated": True,
            "html_url": "https://gist.github.com/user/abc123",
            "history": [{"version": "b" * 40}],
            "files": {},
        }
        with self.assertRaises(monitor.MonitorError):
            monitor.collect_gist_detail(detail, [], {})

    def test_gist_delta_uses_since_cursor_and_public_api(self):
        gist_list = [{"id": "abc123"}]
        detail = {
            "id": "abc123",
            "public": True,
            "truncated": False,
            "html_url": "https://gist.github.com/user/abc123",
            "description": "corp.example.invalid",
            "history": [{"version": "b" * 40}],
            "files": {},
        }
        transport = QueueTransport([response(gist_list), response(detail)])
        client = monitor.GitHubClient("public-token", transport=transport, search_interval=0)
        observations = {}
        monitor.collect_gist_delta(
            client,
            [{"id": "ORG-DOMAIN-PRIMARY", "value": "corp.example.invalid"}],
            datetime(2026, 8, 26, tzinfo=timezone.utc),
            observations,
        )
        first_url = transport.requests[0].full_url
        self.assertEqual(urlparse(first_url).path, "/gists/public")
        self.assertEqual(
            parse_qs(urlparse(first_url).query)["since"], ["2026-08-26T00:00:00Z"]
        )
        self.assertEqual(len(observations), 1)


class ReconciliationTests(unittest.TestCase):
    def test_new_then_known_finding_notifies_once(self):
        document = observation_document([sample_observation()])
        first_state, first_events, known = monitor.reconcile_state(
            monitor.empty_state(), document
        )
        self.assertEqual([event["event_type"] for event in first_events], ["NEW"])
        self.assertEqual(known, 0)

        second_document = observation_document(
            [sample_observation()], "2026-08-27T00:00:00Z"
        )
        second_state, second_events, known = monitor.reconcile_state(
            first_state, second_document
        )
        self.assertEqual(second_events, [])
        self.assertEqual(known, 1)
        self.assertEqual(
            second_state["findings"][0]["last_notified"], "2026-08-26T00:00:00Z"
        )

    def test_expired_review_and_remediated_recurrence_reopen(self):
        state, _, _ = monitor.reconcile_state(
            monitor.empty_state(), observation_document([sample_observation()])
        )
        reviewed = deepcopy(state)
        finding = reviewed["findings"][0]
        finding["disposition"] = "accepted-public"
        finding["review"] = {
            "owner": "security-team",
            "reason": "Intentional public sample",
            "reviewed_at": "2026-08-26T00:00:00Z",
            "expires_at": "2026-08-27T00:00:00Z",
        }
        document = observation_document(
            [sample_observation()], "2026-08-28T00:00:00Z"
        )
        reopened_state, events, _ = monitor.reconcile_state(reviewed, document)
        self.assertEqual([event["event_type"] for event in events], ["REOPENED"])
        self.assertEqual(reopened_state["findings"][0]["disposition"], "open")

        remediated = deepcopy(state)
        remediated["findings"][0]["disposition"] = "remediated"
        remediated["findings"][0]["review"] = None
        _, events, _ = monitor.reconcile_state(remediated, document)
        self.assertEqual([event["event_type"] for event in events], ["REOPENED"])

    def test_review_owner_and_reason_cannot_store_email_addresses(self):
        for field in ("owner", "reason"):
            review = {
                "owner": "security-team",
                "reason": "Intentional public sample",
                "reviewed_at": "2026-08-26T00:00:00Z",
                "expires_at": "2026-08-27T00:00:00Z",
            }
            review[field] = "reviewer@corp.example.invalid"
            with self.subTest(field=field), self.assertRaises(monitor.MonitorError):
                monitor.validate_review(review, "accepted-public")

    def test_changed_object_identity_is_new(self):
        state, _, _ = monitor.reconcile_state(
            monitor.empty_state(), observation_document([sample_observation()])
        )
        changed = sample_observation("123:config/app.yml:" + "c" * 40)
        changed["public_url"] = (
            "https://github.com/outside/example/blob/" + "c" * 40 + "/config/app.yml"
        )
        _, events, _ = monitor.reconcile_state(
            state, observation_document([changed], "2026-08-27T00:00:00Z")
        )
        self.assertEqual([event["event_type"] for event in events], ["NEW"])


class StateApiAndWorkflowTests(unittest.TestCase):
    def test_reconcile_prepares_output_before_state_and_gates_on_output_failure(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            state_path = temporary / "snapshot.json"
            observations_path = temporary / "observations.json"
            state_path.write_bytes(
                monitor.json_bytes(
                    {
                        "schema_version": "1.0",
                        "repository": "owner/private-monitor",
                        "branch": monitor.STATE_BRANCH,
                        "path": monitor.STATE_PATH,
                        "base_blob_sha": "d" * 40,
                        "state": monitor.empty_state(),
                    }
                )
            )
            observations_path.write_bytes(
                monitor.json_bytes(observation_document([sample_observation()]))
            )
            args = SimpleNamespace(
                state_snapshot=state_path,
                observations=observations_path,
                output_dir=temporary / "assessment",
            )
            order = []
            with (
                patch.dict(os.environ, {"GITHUB_TOKEN": "workflow-token"}),
                patch.object(
                    monitor,
                    "write_assessment",
                    side_effect=lambda *unused: order.append("output"),
                ),
                patch.object(
                    monitor,
                    "write_remote_state",
                    side_effect=lambda *unused: order.append("state"),
                ),
            ):
                self.assertEqual(monitor.command_reconcile(args), 1)
            self.assertEqual(order, ["output", "state"])

            with (
                patch.dict(os.environ, {"GITHUB_TOKEN": "workflow-token"}),
                patch.object(
                    monitor,
                    "write_assessment",
                    side_effect=monitor.MonitorError("output cannot be written"),
                ),
                patch.object(monitor, "write_remote_state") as state_write,
            ):
                with self.assertRaises(monitor.MonitorError):
                    monitor.command_reconcile(args)
                state_write.assert_not_called()

    def test_state_read_and_write_use_exact_blob_sha(self):
        state = monitor.empty_state()
        blob_sha = "d" * 40
        get_value = {
            "type": "file",
            "encoding": "base64",
            "sha": blob_sha,
            "content": "\n".join(
                [
                    base64.b64encode(monitor.json_bytes(state)).decode("ascii")[:40],
                    base64.b64encode(monitor.json_bytes(state)).decode("ascii")[40:],
                ]
            ),
        }
        transport = QueueTransport([response(get_value), response({"content": {}, "commit": {}})])
        client = monitor.GitHubClient("workflow-token", transport=transport, search_interval=0)
        snapshot = monitor.read_remote_state(client, "owner/private-monitor")
        monitor.write_remote_state(client, snapshot, state, "12345")
        put_request = transport.requests[1]
        self.assertEqual(put_request.method, "PUT")
        payload = json.loads(put_request.data.decode("utf-8"))
        self.assertEqual(payload["sha"], blob_sha)
        self.assertEqual(payload["branch"], monitor.STATE_BRANCH)
        self.assertEqual(payload["message"], "chore(psb-source-003): update exposure state 12345")

    def test_workflow_has_trusted_trigger_and_minimal_permissions(self):
        workflow = (
            CONTROL_DIR
            / "secure"
            / ".github"
            / "workflows"
            / "public-exposure-monitor.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("permissions: {}", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertIn(
            "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", workflow
        )
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes: 60", workflow)
        self.assertIn(
            "if: github.ref_name == github.event.repository.default_branch", workflow
        )
        self.assertNotIn("curl ", workflow)


if __name__ == "__main__":
    unittest.main()
