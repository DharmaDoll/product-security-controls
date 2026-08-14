from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_github_fork_network.py"
SPEC = importlib.util.spec_from_file_location("collect_github_fork_network", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

OBSERVED = datetime(2026, 8, 12, 3, 36, tzinfo=timezone.utc)
ROOT = {
    "id": 19001,
    "node_id": "R_kgDOProductApi",
    "full_name": "example-org/product-api",
    "fork": False,
    "visibility": "private",
    "network_count": 2,
}


def fork(repository_id: int, name: str):
    return {
        "id": repository_id,
        "node_id": f"R_{repository_id}",
        "full_name": name,
        "fork": True,
        "source": {
            "id": ROOT["id"],
            "node_id": ROOT["node_id"],
            "full_name": ROOT["full_name"],
        },
    }


class GithubForkNetworkCollectorTest(unittest.TestCase):
    def fetcher(self, wrong_source=False, partial=False):
        def fetcher(url: str, token: str, timeout: int):
            self.assertEqual(token, "synthetic-token")
            if url.endswith("/repos/example-org/product-api"):
                return copy.deepcopy(ROOT), None, "root-request"
            if "/forks?" in url:
                values = [fork(19101, "example-org/product-api-integration")]
                if not partial:
                    values.append(fork(19201, "partner-org/product-api-review"))
                if wrong_source:
                    values[0]["source"]["id"] = 99999
                return values, None, "fork-request"
            self.fail(f"unexpected URL {url}")

        return fetcher

    def collect(self, fetcher=None):
        return collector.collect(
            "example-org", "product-api", OBSERVED, "synthetic-token", 10,
            fetcher or self.fetcher(),
        )

    def test_collects_complete_sorted_fork_network(self) -> None:
        output = self.collect()
        self.assertEqual(output["root"]["id"], 19001)
        self.assertEqual([item["id"] for item in output["forks"]], [19101, 19201])
        self.assertTrue(all(item["root_id"] == 19001 for item in output["forks"]))
        self.assertTrue(output["collection"]["forks_complete"])

    def test_partial_and_wrong_root_fail_closed(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "incomplete"):
            self.collect(self.fetcher(partial=True))
        with self.assertRaisesRegex(collector.CollectorError, "root repository"):
            self.collect(self.fetcher(wrong_source=True))

    def test_root_must_not_be_a_fork_or_public(self) -> None:
        base = self.fetcher()

        def invalid_root(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if url.endswith("/repos/example-org/product-api"):
                value["fork"] = True
                value["parent"] = {"id": 18001}
            return value, link, request_id

        with self.assertRaisesRegex(collector.CollectorError, "root identity"):
            self.collect(invalid_root)

        def public_root(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if url.endswith("/repos/example-org/product-api"):
                value["visibility"] = "public"
            return value, link, request_id

        with self.assertRaisesRegex(collector.CollectorError, "visibility"):
            self.collect(public_root)

    def test_url_escape_and_symlink_fail_closed(self) -> None:
        base = self.fetcher()

        def escaped(url: str, token: str, timeout: int):
            value, link, request_id = base(url, token, timeout)
            if "/forks?" in url:
                return value, "https://evil.example/forks?page=2", request_id
            return value, link, request_id

        with self.assertRaisesRegex(collector.CollectorError, "approved endpoint"):
            self.collect(escaped)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_text("preserve", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(collector.CollectorError, "symlink"):
                collector.write_output(link, {"complete": True})


if __name__ == "__main__":
    unittest.main()
