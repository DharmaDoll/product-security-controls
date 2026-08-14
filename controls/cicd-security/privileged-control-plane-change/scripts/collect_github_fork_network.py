#!/usr/bin/env python3
"""Collect the bounded fork-network identity for one GitHub root repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "psb-github-fork-network-snapshot/v1"
API_VERSION = "2026-03-10"
API_HOST = "api.github.com"
MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_PAGES = 100
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class CollectorError(ValueError):
    """Fork-network identity could not be collected completely."""


Fetcher = Callable[[str, str, int], tuple[Any, str | None, str]]


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def repository_url(owner: str, repository: str) -> str:
    return f"https://{API_HOST}/repos/{owner}/{repository}"


def forks_url(owner: str, repository: str) -> str:
    return repository_url(owner, repository) + "/forks?per_page=100&sort=oldest"


def validate_url(value: str, owner: str, repository: str, endpoint: str) -> None:
    try:
        parsed = urllib.parse.urlparse(value)
        query = (
            urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            if parsed.query
            else {}
        )
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise CollectorError("GitHub fork-network URL is malformed") from error
    base = f"/repos/{owner}/{repository}"
    expected_path = base if endpoint == "repository" else base + "/forks"
    if not all(
        (
            parsed.scheme == "https",
            parsed.hostname == API_HOST,
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            parsed.path == expected_path,
            parsed.fragment == "",
            parsed.params == "",
        )
    ):
        raise CollectorError("GitHub fork-network request escaped the approved endpoint")
    if endpoint == "repository" and query:
        raise CollectorError("GitHub root repository request added an unsupported query")
    if endpoint == "forks":
        if (
            not set(query) <= {"per_page", "sort", "page"}
            or query.get("per_page") != ["100"]
            or query.get("sort") != ["oldest"]
        ):
            raise CollectorError("GitHub fork listing changed the bounded query")
        page = query.get("page")
        if page is not None and (
            len(page) != 1 or not page[0].isdigit() or not 1 <= int(page[0]) <= MAX_PAGES
        ):
            raise CollectorError("GitHub fork listing page is malformed")


def next_link(header: str | None) -> str | None:
    if not header:
        return None
    found: str | None = None
    for item in header.split(","):
        parts = [part.strip() for part in item.split(";")]
        if len(parts) < 2 or parts[-1] != 'rel="next"':
            continue
        candidate = parts[0]
        if not candidate.startswith("<") or not candidate.endswith(">") or found is not None:
            raise CollectorError("GitHub fork pagination Link header is malformed")
        found = candidate[1:-1]
    return found


def fetch(url: str, token: str, timeout: int) -> tuple[Any, str | None, str]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "product-security-controls-fork-network-collector",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(MAX_PAGE_BYTES + 1)
            link = response.headers.get("Link")
            request_id = response.headers.get("x-github-request-id", "")
    except urllib.error.HTTPError as error:
        raise CollectorError("GitHub fork-network API denied or failed collection") from error
    except (OSError, urllib.error.URLError) as error:
        raise CollectorError("GitHub fork-network API request failed") from error
    if len(payload) > MAX_PAGE_BYTES:
        raise CollectorError("GitHub fork-network API response exceeds the size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError("GitHub fork-network API response is malformed") from error
    if not request_id:
        raise CollectorError("GitHub fork-network response lacks a request identity")
    return value, next_link(link), request_id


def stable_repository(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CollectorError(f"{label} must be an object")
    repository_id = value.get("id")
    node_id = value.get("node_id")
    full_name = value.get("full_name")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
        or not isinstance(node_id, str)
        or not node_id
        or not isinstance(full_name, str)
        or "/" not in full_name
    ):
        raise CollectorError(f"{label} lacks stable identity")
    return {"id": repository_id, "node_id": node_id, "full_name": full_name}


def collect(
    owner: str,
    repository: str,
    observed_at: datetime,
    token: str,
    timeout: int,
    fetcher: Fetcher = fetch,
) -> dict[str, Any]:
    if (
        NAME_RE.fullmatch(owner) is None
        or NAME_RE.fullmatch(repository) is None
        or not 1 <= timeout <= 120
        or not token
        or any(character.isspace() for character in token)
    ):
        raise CollectorError("GitHub fork-network collector arguments are invalid")
    full_name = f"{owner}/{repository}"
    root_endpoint = repository_url(owner, repository)
    validate_url(root_endpoint, owner, repository, "repository")
    raw_root, link, root_request_id = fetcher(root_endpoint, token, timeout)
    if link is not None:
        raise CollectorError("GitHub root repository unexpectedly paginated")
    root = stable_repository(raw_root, "GitHub root repository")
    network_count = raw_root.get("network_count") if isinstance(raw_root, dict) else None
    if (
        root["full_name"].lower() != full_name.lower()
        or raw_root.get("fork") is not False
        or raw_root.get("visibility") not in {"private", "internal"}
        or not isinstance(network_count, int)
        or isinstance(network_count, bool)
        or network_count < 0
        or "parent" in raw_root
        or "source" in raw_root
    ):
        raise CollectorError("GitHub push-ruleset root identity or visibility is invalid")

    first = forks_url(owner, repository)
    url: str | None = first
    seen_urls: set[str] = set()
    forks: list[dict[str, Any]] = []
    request_ids: list[str] = []
    seen_ids: set[int] = set()
    while url is not None:
        validate_url(url, owner, repository, "forks")
        if url in seen_urls or len(seen_urls) >= MAX_PAGES:
            raise CollectorError("GitHub fork pagination loop or limit")
        seen_urls.add(url)
        page, next_url, request_id = fetcher(url, token, timeout)
        request_ids.append(request_id)
        if not isinstance(page, list):
            raise CollectorError("GitHub fork listing response must be an array")
        for raw_fork in page:
            fork = stable_repository(raw_fork, "GitHub fork")
            source = stable_repository(raw_fork.get("source"), "GitHub fork source")
            if (
                raw_fork.get("fork") is not True
                or fork["id"] in seen_ids
                or fork["id"] == root["id"]
                or source != root
            ):
                raise CollectorError("GitHub fork does not bind uniquely to the root repository")
            seen_ids.add(fork["id"])
            forks.append(
                {
                    **fork,
                    "root_id": source["id"],
                    "root_node_id": source["node_id"],
                }
            )
        if next_url is not None:
            validate_url(next_url, owner, repository, "forks")
        url = next_url
    if len(forks) != network_count:
        raise CollectorError("GitHub fork listing is incomplete against root network_count")
    forks.sort(key=lambda item: item["id"])
    return {
        "schema": SCHEMA,
        "organization": owner,
        "collected_at": timestamp(observed_at),
        "complete": True,
        "collection": {
            "api_version": API_VERSION,
            "root_endpoint": root_endpoint,
            "forks_endpoint": first,
            "fork_pages": len(seen_urls),
            "forks_complete": True,
            "root_request_id": root_request_id,
            "fork_request_ids": request_ids,
        },
        "root": {**root, "visibility": raw_root["visibility"], "network_count": network_count},
        "forks": forks,
    }


def write_output(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise CollectorError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = handle.name
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
        raise CollectorError("cannot write GitHub fork-network snapshot") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    try:
        output = collect(
            args.organization,
            args.repository,
            datetime.now(timezone.utc),
            os.environ.get(args.token_env, ""),
            args.timeout,
        )
        write_output(args.output, output)
    except CollectorError as error:
        print(f"ERROR GitHub fork-network collection unavailable: {error}", file=sys.stderr)
        return 2
    print(
        f"COLLECTED GitHub fork network {output['root']['full_name']} "
        f"with {len(output['forks'])} fork(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
