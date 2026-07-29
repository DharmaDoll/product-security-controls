#!/usr/bin/env python3
"""Collect reviewed GitHub Actions advisories into a bounded local snapshot."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


API_URL = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100"
API_VERSION = "2022-11-28"
SNAPSHOT_SCHEMA = "psb-github-actions-advisory-snapshot/v1"


class CollectorError(ValueError):
    """The advisory collection did not complete safely."""


def fetch_page(url: str, token: str | None, timeout: int) -> tuple[Any, str | None]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "product-security-controls-action-advisory-collector",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
            link = response.headers.get("Link")
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        urllib.error.HTTPError,
        urllib.error.URLError,
    ) as error:
        raise CollectorError("GitHub advisory API request failed") from error
    next_url: str | None = None
    if link:
        for item in link.split(","):
            parts = [part.strip() for part in item.split(";")]
            if len(parts) == 2 and parts[1] == 'rel="next"':
                next_url = parts[0].removeprefix("<").removesuffix(">")
    return payload, next_url


def normalize(raw_advisories: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, advisory in enumerate(raw_advisories):
        if not isinstance(advisory, dict):
            raise CollectorError(f"advisory[{index}] is malformed")
        vulnerabilities: list[dict[str, Any]] = []
        for vulnerability in advisory.get("vulnerabilities", []):
            package = vulnerability.get("package", {})
            if package.get("ecosystem") != "actions":
                continue
            vulnerabilities.append(
                {
                    "ecosystem": "actions",
                    "package": package.get("name"),
                    "vulnerable_version_range": vulnerability.get(
                        "vulnerable_version_range"
                    ),
                    "patched_versions": vulnerability.get("patched_versions"),
                }
            )
        normalized.append(
            {
                "ghsa_id": advisory.get("ghsa_id"),
                "html_url": advisory.get("html_url"),
                "severity": advisory.get("severity"),
                "updated_at": advisory.get("updated_at"),
                "withdrawn_at": advisory.get("withdrawn_at"),
                "vulnerabilities": vulnerabilities,
            }
        )
    return sorted(normalized, key=lambda item: str(item["ghsa_id"]))


def write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise CollectorError("cannot write advisory snapshot") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    try:
        if args.timeout < 1 or args.output.is_symlink():
            raise CollectorError("collector arguments are invalid")
        token = os.environ.get(args.token_env)
        advisories: list[Any] = []
        next_url: str | None = API_URL
        pages = 0
        while next_url is not None:
            if not next_url.startswith("https://api.github.com/advisories?"):
                raise CollectorError("pagination escaped the reviewed API boundary")
            page, next_url = fetch_page(next_url, token, args.timeout)
            if not isinstance(page, list):
                raise CollectorError("GitHub advisory API response is malformed")
            advisories.extend(page)
            pages += 1
            if pages > 20:
                raise CollectorError("GitHub advisory pagination exceeded the limit")
        snapshot = {
            "schema_version": SNAPSHOT_SCHEMA,
            "source": {
                "api_url": "https://api.github.com/advisories",
                "api_version": API_VERSION,
                "ecosystem": "actions",
                "type": "reviewed",
                "retrieved_at": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "complete": True,
            },
            "advisories": normalize(advisories),
        }
        write_snapshot(args.output, snapshot)
    except (CollectorError, OSError, ValueError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    print(
        f"COLLECTED {len(snapshot['advisories'])} reviewed GitHub Actions "
        f"advisory record(s) across {pages} page(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
