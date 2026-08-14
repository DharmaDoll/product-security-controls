#!/usr/bin/env python3
"""Collect one sanitized GitHub organization runner-group state snapshot."""

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


SCHEMA = "psb-github-runner-group-snapshot/v1"
API_VERSION = "2026-03-10"
API_HOST = "api.github.com"
MAX_PAGES = 100
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_REPOSITORIES = 10_000
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")


class CollectorError(ValueError):
    """Runner-group state could not be collected safely."""


PageFetcher = Callable[[str, str, int], tuple[Any, str | None]]


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def group_url(organization: str, runner_group_id: int) -> str:
    return (
        f"https://{API_HOST}/orgs/{organization}/actions/runner-groups/"
        f"{runner_group_id}"
    )


def repositories_url(organization: str, runner_group_id: int) -> str:
    return group_url(organization, runner_group_id) + "/repositories"


def validate_url(
    value: str, organization: str, runner_group_id: int, endpoint: str
) -> None:
    try:
        parsed = urllib.parse.urlparse(value)
        query = (
            urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            if parsed.query
            else {}
        )
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise CollectorError("GitHub runner-group pagination URL is malformed") from error
    base_path = f"/orgs/{organization}/actions/runner-groups/{runner_group_id}"
    expected_path = base_path if endpoint == "group" else base_path + "/repositories"
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
        raise CollectorError("GitHub runner-group pagination escaped the approved endpoint")
    if endpoint == "group" and query:
        raise CollectorError("GitHub runner-group request added an unsupported query")
    if endpoint == "repositories":
        if not set(query) <= {"page"}:
            raise CollectorError("GitHub repository pagination added an unsupported query")
        page = query.get("page")
        if page is not None and (
            len(page) != 1 or not page[0].isdigit() or not 1 <= int(page[0]) <= MAX_PAGES
        ):
            raise CollectorError("GitHub repository pagination page is malformed")


def next_link(header: str | None) -> str | None:
    if not header:
        return None
    found: str | None = None
    for item in header.split(","):
        parts = [part.strip() for part in item.split(";")]
        if len(parts) < 2 or parts[-1] != 'rel="next"':
            continue
        candidate = parts[0]
        if not candidate.startswith("<") or not candidate.endswith(">"):
            raise CollectorError("GitHub runner-group pagination Link header is malformed")
        if found is not None:
            raise CollectorError("GitHub runner-group pagination has duplicate next links")
        found = candidate[1:-1]
    return found


def fetch_page(url: str, token: str, timeout: int) -> tuple[Any, str | None]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "product-security-controls-runner-group-collector",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(MAX_PAGE_BYTES + 1)
            link = response.headers.get("Link")
    except urllib.error.HTTPError as error:
        if error.code in {403, 429}:
            raise CollectorError(
                "GitHub runner-group API rate limit or access policy denied collection"
            ) from error
        raise CollectorError("GitHub runner-group API request failed") from error
    except (OSError, urllib.error.URLError) as error:
        raise CollectorError("GitHub runner-group API request failed") from error
    if len(payload) > MAX_PAGE_BYTES:
        raise CollectorError("GitHub runner-group API page exceeds the size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError("GitHub runner-group API response is malformed") from error
    return value, next_link(link)


def boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise CollectorError(f"runner-group {label} must be boolean")
    return value


def collect_repositories(
    organization: str,
    runner_group_id: int,
    token: str,
    timeout: int,
    fetcher: PageFetcher,
) -> tuple[list[int], int]:
    url: str | None = repositories_url(organization, runner_group_id)
    seen_urls: set[str] = set()
    repository_ids: list[int] = []
    expected_total: int | None = None
    pages = 0
    while url is not None:
        validate_url(url, organization, runner_group_id, "repositories")
        if url in seen_urls:
            raise CollectorError("GitHub repository pagination loop detected")
        seen_urls.add(url)
        if pages >= MAX_PAGES:
            raise CollectorError("GitHub repository pagination exceeded the page limit")
        page, next_url = fetcher(url, token, timeout)
        pages += 1
        if not isinstance(page, dict):
            raise CollectorError("GitHub repository access response must be an object")
        total = page.get("total_count")
        repositories = page.get("repositories")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or not isinstance(repositories, list)
        ):
            raise CollectorError("GitHub repository access response is malformed")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise CollectorError("GitHub repository access total changed during pagination")
        for repository in repositories:
            if not isinstance(repository, dict):
                raise CollectorError("GitHub repository access item is malformed")
            repository_id = repository.get("id")
            if not isinstance(repository_id, int) or isinstance(repository_id, bool):
                raise CollectorError("GitHub repository access item lacks a stable ID")
            repository_ids.append(repository_id)
            if len(repository_ids) > MAX_REPOSITORIES:
                raise CollectorError("GitHub repository access exceeds the item limit")
        if next_url is not None:
            validate_url(next_url, organization, runner_group_id, "repositories")
        url = next_url
    if expected_total is None or expected_total != len(repository_ids):
        raise CollectorError("GitHub repository pagination is incomplete")
    if len(set(repository_ids)) != len(repository_ids):
        raise CollectorError("GitHub repository access contains duplicate stable IDs")
    return sorted(repository_ids), pages


def collect(
    organization: str,
    runner_group_id: int,
    observed_at: datetime,
    token: str,
    timeout: int,
    fetcher: PageFetcher = fetch_page,
) -> dict[str, Any]:
    if ORG_RE.fullmatch(organization) is None:
        raise CollectorError("GitHub organization is malformed")
    if (
        not isinstance(runner_group_id, int)
        or isinstance(runner_group_id, bool)
        or runner_group_id < 1
    ):
        raise CollectorError("GitHub runner-group ID must be a positive integer")
    if not 1 <= timeout <= 120:
        raise CollectorError("collector timeout is outside 1..120 seconds")
    if not token or any(character.isspace() for character in token):
        raise CollectorError("GitHub runner-group token is unavailable or malformed")

    url = group_url(organization, runner_group_id)
    validate_url(url, organization, runner_group_id, "group")
    raw_group, next_url = fetcher(url, token, timeout)
    if next_url is not None:
        raise CollectorError("GitHub runner-group detail unexpectedly paginated")
    if not isinstance(raw_group, dict):
        raise CollectorError("GitHub runner-group detail must be an object")
    if raw_group.get("id") != runner_group_id:
        raise CollectorError("GitHub runner-group detail returned a different stable ID")
    name = raw_group.get("name")
    visibility = raw_group.get("visibility")
    if not isinstance(name, str) or not name:
        raise CollectorError("GitHub runner-group name must be non-empty text")
    if visibility not in {"all", "private", "selected"}:
        raise CollectorError("GitHub runner-group visibility is unsupported")
    selected_workflows = raw_group.get("selected_workflows")
    if not isinstance(selected_workflows, list) or not all(
        isinstance(workflow, str) and workflow for workflow in selected_workflows
    ):
        raise CollectorError("GitHub selected workflows are malformed")
    if len(set(selected_workflows)) != len(selected_workflows):
        raise CollectorError("GitHub selected workflows contain duplicates")
    network_id = raw_group.get("network_configuration_id")
    if network_id is not None and (not isinstance(network_id, str) or not network_id):
        raise CollectorError("GitHub runner-group network ID is malformed")

    repository_ids: list[int] = []
    repository_pages = 0
    if visibility == "selected":
        repository_ids, repository_pages = collect_repositories(
            organization, runner_group_id, token, timeout, fetcher
        )
    configuration = {
        "runner_group_id": runner_group_id,
        "name": name,
        "visibility": visibility,
        "default": boolean(raw_group.get("default"), "default"),
        "inherited": boolean(raw_group.get("inherited"), "inherited"),
        "allows_public_repositories": boolean(
            raw_group.get("allows_public_repositories"), "allows_public_repositories"
        ),
        "restricted_to_workflows": boolean(
            raw_group.get("restricted_to_workflows"), "restricted_to_workflows"
        ),
        "selected_workflows": sorted(selected_workflows),
        "workflow_restrictions_read_only": boolean(
            raw_group.get("workflow_restrictions_read_only"),
            "workflow_restrictions_read_only",
        ),
        "network_configuration_id": network_id,
        "selected_repository_ids": repository_ids,
    }
    return {
        "schema": SCHEMA,
        "organization": organization,
        "collected_at": timestamp(observed_at),
        "complete": True,
        "collection": {
            "api_version": API_VERSION,
            "group_endpoint": group_url(organization, runner_group_id),
            "repository_endpoint": repositories_url(organization, runner_group_id),
            "repository_pages": repository_pages,
            "pagination_complete": True,
        },
        "runner_groups": [{"configuration": configuration}],
    }


def write_output(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise CollectorError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
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
        raise CollectorError("cannot write GitHub runner-group snapshot") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization", required=True)
    parser.add_argument("--runner-group-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    try:
        output = collect(
            organization=args.organization,
            runner_group_id=args.runner_group_id,
            observed_at=datetime.now(timezone.utc),
            token=os.environ.get(args.token_env, ""),
            timeout=args.timeout,
        )
        write_output(args.output, output)
    except CollectorError as error:
        print(f"ERROR GitHub runner-group collection unavailable: {error}", file=sys.stderr)
        return 2
    print(f"COLLECTED GitHub runner-group {args.runner_group_id} current state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
