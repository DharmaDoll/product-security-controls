from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_github_runner_group.py"
SPEC = importlib.util.spec_from_file_location("collect_github_runner_group", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


ORG = "example-org"
GROUP_ID = 42
OBSERVED = datetime(2026, 8, 12, 3, 21, tzinfo=timezone.utc)
GROUP = {
    "id": GROUP_ID,
    "name": "release-runners",
    "visibility": "selected",
    "default": False,
    "inherited": False,
    "allows_public_repositories": False,
    "restricted_to_workflows": True,
    "selected_workflows": [
        "example-org/product-api/.github/workflows/release.yml@refs/heads/main"
    ],
    "workflow_restrictions_read_only": False,
    "network_configuration_id": None,
    "runners_url": "must-not-survive",
}


class GithubRunnerGroupCollectorTest(unittest.TestCase):
    def test_complete_repository_pagination_and_field_allowlist(self) -> None:
        group_url = collector.group_url(ORG, GROUP_ID)
        repositories_url = collector.repositories_url(ORG, GROUP_ID)
        page_two = repositories_url + "?page=2"
        calls: list[str] = []

        def fetcher(url: str, token: str, timeout: int):
            calls.append(url)
            self.assertEqual(token, "synthetic-token")
            self.assertEqual(timeout, 10)
            if url == group_url:
                return (copy.deepcopy(GROUP), None)
            if url == repositories_url:
                return ({"total_count": 2, "repositories": [{"id": 19002}]}, page_two)
            return ({"total_count": 2, "repositories": [{"id": 19001}]}, None)

        output = collector.collect(
            ORG, GROUP_ID, OBSERVED, "synthetic-token", 10, fetcher
        )
        self.assertEqual(calls, [group_url, repositories_url, page_two])
        self.assertTrue(output["complete"])
        self.assertEqual(output["collection"]["repository_pages"], 2)
        configuration = output["runner_groups"][0]["configuration"]
        self.assertEqual(configuration["selected_repository_ids"], [19001, 19002])
        self.assertNotIn("must-not-survive", json.dumps(output))

    def test_id_mismatch_and_incomplete_pagination_fail_closed(self) -> None:
        def wrong_group(url: str, token: str, timeout: int):
            value = copy.deepcopy(GROUP)
            value["id"] = 99
            return (value, None)

        with self.assertRaisesRegex(collector.CollectorError, "different stable ID"):
            collector.collect(ORG, GROUP_ID, OBSERVED, "token", 10, wrong_group)

        def incomplete(url: str, token: str, timeout: int):
            if url == collector.group_url(ORG, GROUP_ID):
                return (copy.deepcopy(GROUP), None)
            return ({"total_count": 2, "repositories": [{"id": 19001}]}, None)

        with self.assertRaisesRegex(collector.CollectorError, "pagination is incomplete"):
            collector.collect(ORG, GROUP_ID, OBSERVED, "token", 10, incomplete)

    def test_pagination_cannot_escape_host_or_repeat(self) -> None:
        def evil_host(url: str, token: str, timeout: int):
            if url == collector.group_url(ORG, GROUP_ID):
                return (copy.deepcopy(GROUP), None)
            return (
                {"total_count": 0, "repositories": []},
                "https://evil.example/orgs/example-org/actions/runner-groups/42/repositories?page=2",
            )

        with self.assertRaisesRegex(collector.CollectorError, "approved endpoint"):
            collector.collect(ORG, GROUP_ID, OBSERVED, "token", 10, evil_host)

        repositories_url = collector.repositories_url(ORG, GROUP_ID)

        def loop(url: str, token: str, timeout: int):
            if url == collector.group_url(ORG, GROUP_ID):
                return (copy.deepcopy(GROUP), None)
            return ({"total_count": 0, "repositories": []}, repositories_url)

        with self.assertRaisesRegex(collector.CollectorError, "pagination loop"):
            collector.collect(ORG, GROUP_ID, OBSERVED, "token", 10, loop)

    def test_invalid_arguments_and_symlink_output_fail_closed(self) -> None:
        def unexpected(url: str, token: str, timeout: int):
            self.fail("fetcher must not be called")

        with self.assertRaises(collector.CollectorError):
            collector.collect("bad/org", GROUP_ID, OBSERVED, "token", 10, unexpected)
        with self.assertRaises(collector.CollectorError):
            collector.collect(ORG, 0, OBSERVED, "token", 10, unexpected)
        with self.assertRaises(collector.CollectorError):
            collector.collect(ORG, GROUP_ID, OBSERVED, "", 10, unexpected)

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
