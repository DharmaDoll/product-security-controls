#!/usr/bin/env python3
"""Monitor public GitHub exposure for organization-owned domains."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen


CONTROL_ID = "PSB-SOURCE-003"
CONFIG_SCHEMA_VERSION = "1.0"
STATE_SCHEMA_VERSION = "1.0"
OBSERVATION_SCHEMA_VERSION = "1.0"
QUERY_CATALOG_VERSION = "1.1"
STATE_BRANCH = "psb-source-003-state"
STATE_PATH = "state/findings.json"
API_VERSION = "2026-03-10"
USER_AGENT = "psb-source-003-public-exposure-monitor/1.0"
SEARCH_INTERVAL_SECONDS = 6.5
MAX_SEARCH_PAGES = 10
MAX_GIST_PAGES = 10
MAX_GISTS_PER_RUN = 1000
INITIAL_GIST_LOOKBACK_HOURS = 1
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

ID_RE = re.compile(r"^ORG-[A-Z0-9][A-Z0-9-]{2,62}$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIST_ID_RE = re.compile(r"^[0-9a-fA-F]+$")
DISPOSITIONS = {"open", "accepted-public", "false-positive", "remediated"}
SURFACES = {"github-code", "github-issue", "github-pull-request", "github-gist"}


class MonitorError(RuntimeError):
    """Raised when a scan cannot complete reliably."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise MonitorError("timestamp is missing a timezone")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MonitorError(f"{label} must be a UTC RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise MonitorError(f"{label} must be a UTC RFC 3339 timestamp") from error
    if parsed.microsecond:
        raise MonitorError(f"{label} must use second precision")
    return parsed


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MonitorError(f"{label} cannot be parsed") from error
    if not isinstance(value, dict):
        raise MonitorError(f"{label} must contain a JSON object")
    return value


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def atomic_write(path: Path, content: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except OSError as error:
        raise MonitorError("output cannot be written") from error


def normalize_domain(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise MonitorError("domain value is invalid")
    if any(character in value for character in ("*", ":", "/", "@", "?", "#")):
        raise MonitorError("domain value is invalid")
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise MonitorError("domain value is invalid") from error
    if len(normalized.encode("ascii")) > 253:
        raise MonitorError("domain value is invalid")
    labels = normalized.split(".")
    if len(labels) < 2 or normalized == "localhost":
        raise MonitorError("domain value is invalid")
    if not all(LABEL_RE.fullmatch(label) for label in labels):
        raise MonitorError("domain value is invalid")
    if all(label.isdigit() for label in labels):
        raise MonitorError("domain value is invalid")
    return normalized


def load_configuration(path: Path) -> list[dict[str, str]]:
    configuration = load_json(path, "domain configuration")
    if set(configuration) != {"schema_version", "domains"}:
        raise MonitorError("domain configuration has unexpected fields")
    if configuration.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise MonitorError("domain configuration schema_version is unsupported")
    values = configuration.get("domains")
    if not isinstance(values, list) or not 1 <= len(values) <= 50:
        raise MonitorError("domain configuration must contain 1 to 50 domains")
    domains: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    seen_values: set[str] = set()
    for entry in values:
        if not isinstance(entry, dict) or set(entry) != {"id", "value"}:
            raise MonitorError("domain entry is invalid")
        indicator_id = entry.get("id")
        if not isinstance(indicator_id, str) or ID_RE.fullmatch(indicator_id) is None:
            raise MonitorError("domain indicator id is invalid")
        domain = normalize_domain(entry.get("value"))
        if indicator_id in seen_ids or domain in seen_values:
            raise MonitorError("domain configuration contains a duplicate")
        seen_ids.add(indicator_id)
        seen_values.add(domain)
        domains.append({"id": indicator_id, "value": domain})
    return sorted(domains, key=lambda item: item["id"])


def quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def automatic_queries(domains: list[dict[str, str]]) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []
    for entry in domains:
        indicator_id = entry["id"]
        domain = entry["value"]
        email_domain = "@" + domain
        queries.extend(
            [
                {
                    "id": f"{indicator_id}-API-CODE-DOMAIN",
                    "indicator_id": indicator_id,
                    "surface": "github-code",
                    "endpoint": "search/code",
                    "query": f"{quoted(domain)} in:file",
                },
                {
                    "id": f"{indicator_id}-API-CODE-EMAIL",
                    "indicator_id": indicator_id,
                    "surface": "github-code",
                    "endpoint": "search/code",
                    "query": f"{quoted(email_domain)} in:file",
                },
                {
                    "id": f"{indicator_id}-API-ISSUE-DOMAIN",
                    "indicator_id": indicator_id,
                    "surface": "github-issue",
                    "endpoint": "search/issues",
                    "query": f"{quoted(domain)} is:issue",
                },
                {
                    "id": f"{indicator_id}-API-ISSUE-EMAIL",
                    "indicator_id": indicator_id,
                    "surface": "github-issue",
                    "endpoint": "search/issues",
                    "query": f"{quoted(email_domain)} is:issue",
                },
                {
                    "id": f"{indicator_id}-API-PR-DOMAIN",
                    "indicator_id": indicator_id,
                    "surface": "github-pull-request",
                    "endpoint": "search/issues",
                    "query": f"{quoted(domain)} is:pr",
                },
                {
                    "id": f"{indicator_id}-API-PR-EMAIL",
                    "indicator_id": indicator_id,
                    "surface": "github-pull-request",
                    "endpoint": "search/issues",
                    "query": f"{quoted(email_domain)} is:pr",
                },
            ]
        )
    return queries


def github_search_url(query: str, search_type: str) -> str:
    return "https://github.com/search?" + urlencode(
        [("q", query), ("type", search_type)]
    )


def gist_search_url(query: str) -> str:
    return "https://gist.github.com/search?" + urlencode([("q", query)])


def browser_queries(domains: list[dict[str, str]]) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []
    for entry in domains:
        indicator_id = entry["id"]
        domain = entry["value"]
        email_domain = "@" + domain
        regex_domain = re.escape(domain).replace("/", r"\/")
        code_queries = [
            ("WEB-CODE-DOMAIN", f"content:{quoted(domain)} NOT is:generated NOT is:vendored"),
            ("WEB-CODE-EMAIL", f"content:{quoted(email_domain)} NOT is:generated NOT is:vendored"),
            (
                "WEB-CODE-CREDENTIAL",
                f"content:{quoted(domain)} AND (password OR token OR secret OR api_key OR client_secret OR credential)",
            ),
            (
                "WEB-CODE-CONFIG",
                f"content:{quoted(domain)} AND (path:*.env OR path:*.yml OR path:*.yaml OR path:*.json OR path:*.properties OR path:*.tf OR path:*.conf)",
            ),
            (
                "WEB-CODE-SERVICE",
                f"content:{quoted(domain)} AND (admin OR vpn OR sso OR api OR staging OR dev OR internal)",
            ),
            (
                "WEB-CODE-INFRA",
                f"content:{quoted(domain)} AND (terraform OR kubernetes OR ingress OR cname OR dns)",
            ),
            ("WEB-CODE-URL", rf"/https?:\/\/[A-Za-z0-9._-]*{regex_domain}/"),
        ]
        for suffix, query in code_queries:
            queries.append(
                {
                    "id": f"{indicator_id}-{suffix}",
                    "surface": "GitHub Code Search",
                    "query": query,
                    "url": github_search_url(query, "code"),
                }
            )
        for suffix, query, search_type in (
            ("WEB-ISSUE-DOMAIN", f"{quoted(domain)} is:issue", "issues"),
            ("WEB-PR-DOMAIN", f"{quoted(domain)} is:pr", "pullrequests"),
            ("WEB-GIST-DOMAIN", quoted(domain), "gist"),
            ("WEB-GIST-EMAIL", quoted(email_domain), "gist"),
        ):
            url = (
                gist_search_url(query)
                if search_type == "gist"
                else github_search_url(query, search_type)
            )
            queries.append(
                {
                    "id": f"{indicator_id}-{suffix}",
                    "surface": "GitHub Gist Search" if search_type == "gist" else "GitHub Issue/PR Search",
                    "query": query,
                    "url": url,
                }
            )
        generic = [
            ("WEB-GENERIC-GITHUB", f"site:github.com {quoted(domain)}"),
            ("WEB-GENERIC-EMAIL", f"site:github.com {quoted(email_domain)}"),
            ("WEB-GENERIC-GIST", f"site:gist.github.com {quoted(domain)}"),
            ("WEB-GENERIC-RAW", f"site:raw.githubusercontent.com {quoted(domain)}"),
            (
                "WEB-GENERIC-CREDENTIAL",
                f"site:github.com {quoted(domain)} (\"password\" OR \"token\" OR \"secret\" OR \"api_key\")",
            ),
        ]
        for suffix, query in generic:
            queries.append(
                {
                    "id": f"{indicator_id}-{suffix}",
                    "surface": "Generic Web Search",
                    "query": query,
                    "url": "",
                }
            )
    return queries


def render_browser_queries(domains: list[dict[str, str]]) -> str:
    lines = [
        "# Manual browser reconnaissance",
        "",
        "> These GET links are generated for a human reviewer. The scanner does not fetch or scrape their HTML results.",
        "",
        "Actual organization domains appear below. Keep this summary in the private monitor repository.",
        "",
        "| Query ID | Surface | Link or query |",
        "| --- | --- | --- |",
    ]
    for query in browser_queries(domains):
        rendered = (
            f"[Open search]({query['url']})<br>`{query['query']}`"
            if query["url"]
            else f"`{query['query']}`"
        )
        lines.append(
            f"| `{escape(query['id'])}` | {escape(query['surface'])} | {rendered} |"
        )
    lines.extend(
        [
            "",
            "Browser queries were generated but not executed by the scanner.",
            "Gist delta monitoring through the official REST API covers only new or updated public Gists since the stored cursor; these browser links remain the historical baseline check.",
            "",
        ]
    )
    return "\n".join(lines)


Transport = Callable[[Request, float], tuple[int, dict[str, str], bytes]]


def default_transport(request: Request, timeout: float) -> tuple[int, dict[str, str], bytes]:
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise MonitorError("provider response exceeds the safe size limit")
            return response.status, dict(response.headers.items()), body
    except HTTPError as error:
        raise MonitorError(f"provider returned HTTP {error.code}") from error
    except (OSError, URLError) as error:
        raise MonitorError("provider request failed") from error


class GitHubClient:
    def __init__(
        self,
        token: str,
        transport: Transport = default_transport,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        search_interval: float = SEARCH_INTERVAL_SECONDS,
    ) -> None:
        if not token or any(character.isspace() for character in token):
            raise MonitorError("required GitHub token is unavailable")
        self._token = token
        self._transport = transport
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._search_interval = search_interval
        self._last_search: float | None = None

    def request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        payload: object | None = None,
        search_request: bool = False,
        expected_status: set[int] | None = None,
    ) -> tuple[object, dict[str, str], int]:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com":
            raise MonitorError("provider URL escaped the approved host")
        if search_request:
            current = self._monotonic()
            if self._last_search is not None:
                remaining = self._search_interval - (current - self._last_search)
                if remaining > 0:
                    self._sleeper(remaining)
            self._last_search = self._monotonic()
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=headers, method=method)
        status, response_headers, body = self._transport(request, 30.0)
        allowed = expected_status or {200}
        if status not in allowed:
            raise MonitorError(f"provider returned HTTP {status}")
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise MonitorError("provider returned malformed JSON") from error
        return value, {key.lower(): value for key, value in response_headers.items()}, status


def next_link(headers: dict[str, str]) -> str | None:
    value = headers.get("link")
    if not value:
        return None
    matches: list[str] = []
    for part in value.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', part)
        if match is None:
            raise MonitorError("provider pagination header is malformed")
        if match.group(2) == "next":
            matches.append(match.group(1))
    if len(matches) > 1:
        raise MonitorError("provider pagination contains duplicate next links")
    if not matches:
        return None
    parsed = urlparse(matches[0])
    if parsed.scheme != "https" or parsed.hostname != "api.github.com":
        raise MonitorError("provider pagination escaped the approved host")
    return matches[0]


def validate_public_url(url: object, host: str) -> str:
    if not isinstance(url, str):
        raise MonitorError("provider item has an invalid public URL")
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != host
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or not parsed.path.startswith("/")
        or any(character.isspace() or character in "<>[]()\\\"'" for character in url)
    ):
        raise MonitorError("provider item has an invalid public URL")
    return url


def markdown_cell(value: str) -> str:
    return escape(value).replace("|", "&#124;").replace("`", "&#96;")


def merge_observation(
    observations: dict[tuple[str, str, str, str], dict[str, Any]],
    observation: dict[str, Any],
) -> None:
    key = (
        observation["provider"],
        observation["surface"],
        observation["resource_id"],
        observation["indicator_id"],
    )
    existing = observations.get(key)
    if existing is None:
        observation["query_ids"] = sorted(set(observation["query_ids"]))
        observations[key] = observation
        return
    if any(
        existing[field] != observation[field]
        for field in ("resource", "path", "public_url")
    ):
        raise MonitorError("provider returned inconsistent duplicate results")
    existing["query_ids"] = sorted(
        set(existing["query_ids"]) | set(observation["query_ids"])
    )


def validate_search_page(value: object, expected_total: int | None) -> tuple[dict[str, Any], int]:
    if not isinstance(value, dict):
        raise MonitorError("search response must be an object")
    total = value.get("total_count")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise MonitorError("search response has an invalid total_count")
    if expected_total is not None and total != expected_total:
        raise MonitorError("search total_count changed during pagination")
    if value.get("incomplete_results") is not False:
        raise MonitorError("search results are incomplete")
    if total > 1000:
        raise MonitorError("search result cap was exceeded")
    if not isinstance(value.get("items"), list):
        raise MonitorError("search response items are invalid")
    return value, total


def collect_search_query(
    client: GitHubClient,
    query: dict[str, str],
    observations: dict[tuple[str, str, str, str], dict[str, Any]],
    repository_cache: dict[str, str] | None = None,
) -> None:
    if repository_cache is None:
        repository_cache = {}
    url = "https://api.github.com/" + query["endpoint"] + "?" + urlencode(
        [("q", query["query"]), ("per_page", "100"), ("page", "1")]
    )
    expected_total: int | None = None
    page = 0
    seen_urls: set[str] = set()
    while url:
        if url in seen_urls or page >= MAX_SEARCH_PAGES:
            raise MonitorError("search pagination did not complete")
        seen_urls.add(url)
        page += 1
        value, headers, _ = client.request_json(url, search_request=True)
        response, expected_total = validate_search_page(value, expected_total)
        for item in response["items"]:
            if query["surface"] == "github-code":
                observation = normalize_code_item(item, query)
            else:
                observation = normalize_issue_item(item, query)
                repository_url = item.get("repository_url")
                repository = verify_public_repository(
                    client, repository_url, repository_cache
                )
                if observation["resource"] != repository:
                    raise MonitorError("issue search repository identity changed")
            merge_observation(observations, observation)
        url = next_link(headers)


def normalize_code_item(item: object, query: dict[str, str]) -> dict[str, Any]:
    if not isinstance(item, dict) or not isinstance(item.get("repository"), dict):
        raise MonitorError("code search item is malformed")
    repository = item["repository"]
    repository_id = repository.get("id")
    full_name = repository.get("full_name")
    path = item.get("path")
    object_id = item.get("sha")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id <= 0
        or not isinstance(full_name, str)
        or REPOSITORY_RE.fullmatch(full_name) is None
        or repository.get("private") is not False
        or not isinstance(path, str)
        or not path
        or any(ord(character) < 32 for character in path)
        or not isinstance(object_id, str)
        or SHA1_RE.fullmatch(object_id) is None
    ):
        raise MonitorError("code search item is malformed")
    public_url = validate_public_url(item.get("html_url"), "github.com")
    return {
        "provider": "github",
        "surface": "github-code",
        "resource_id": f"{repository_id}:{path}:{object_id}",
        "indicator_id": query["indicator_id"],
        "query_ids": [query["id"]],
        "resource": full_name,
        "path": path,
        "public_url": public_url,
    }


def repository_from_api_url(value: object) -> str:
    if not isinstance(value, str):
        raise MonitorError("issue search item is malformed")
    parsed = urlparse(value)
    parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or len(parts) != 3
        or parts[0] != "repos"
    ):
        raise MonitorError("issue search item is malformed")
    repository = f"{parts[1]}/{parts[2]}"
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise MonitorError("issue search item is malformed")
    return repository


def verify_public_repository(
    client: GitHubClient,
    repository_url: object,
    repository_cache: dict[str, str],
) -> str:
    repository = repository_from_api_url(repository_url)
    assert isinstance(repository_url, str)
    cached = repository_cache.get(repository_url)
    if cached is not None:
        if cached != repository:
            raise MonitorError("repository cache is inconsistent")
        return cached

    value, _, _ = client.request_json(repository_url)
    if not isinstance(value, dict):
        raise MonitorError("repository response is malformed")
    repository_id = value.get("id")
    full_name = value.get("full_name")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id <= 0
        or full_name != repository
        or value.get("private") is not False
    ):
        raise MonitorError("issue search result is not from a verified public repository")
    repository_cache[repository_url] = repository
    return repository


def normalize_issue_item(item: object, query: dict[str, str]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise MonitorError("issue search item is malformed")
    item_id = item.get("id")
    number = item.get("number")
    updated_at = item.get("updated_at")
    if (
        not isinstance(item_id, int)
        or isinstance(item_id, bool)
        or item_id <= 0
        or not isinstance(number, int)
        or isinstance(number, bool)
        or number <= 0
    ):
        raise MonitorError("issue search item is malformed")
    parse_timestamp(updated_at, "issue updated_at")
    is_pull_request = isinstance(item.get("pull_request"), dict)
    expected_pull_request = query["surface"] == "github-pull-request"
    if is_pull_request != expected_pull_request:
        raise MonitorError("issue search returned the wrong surface")
    repository = repository_from_api_url(item.get("repository_url"))
    public_url = validate_public_url(item.get("html_url"), "github.com")
    path = f"pull/{number}" if expected_pull_request else f"issues/{number}"
    return {
        "provider": "github",
        "surface": query["surface"],
        "resource_id": f"{item_id}:{updated_at}",
        "indicator_id": query["indicator_id"],
        "query_ids": [query["id"]],
        "resource": repository,
        "path": path,
        "public_url": public_url,
    }


def domain_patterns(domains: list[dict[str, str]]) -> list[tuple[str, re.Pattern[str]]]:
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for entry in domains:
        pattern = re.compile(
            rf"(?<![a-z0-9-])(?:[a-z0-9-]+\.)*{re.escape(entry['value'])}(?![a-z0-9-])",
            re.IGNORECASE,
        )
        patterns.append((entry["id"], pattern))
    return patterns


def collect_gist_delta(
    client: GitHubClient,
    domains: list[dict[str, str]],
    since: datetime,
    observations: dict[tuple[str, str, str, str], dict[str, Any]],
) -> None:
    url = "https://api.github.com/gists/public?" + urlencode(
        [("since", format_timestamp(since)), ("per_page", "100"), ("page", "1")]
    )
    gist_ids: list[str] = []
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()
    page = 0
    while url:
        if url in seen_urls or page >= MAX_GIST_PAGES:
            raise MonitorError("public Gist delta exceeded the safe pagination limit")
        seen_urls.add(url)
        page += 1
        value, headers, _ = client.request_json(url)
        if not isinstance(value, list):
            raise MonitorError("public Gist list is malformed")
        for item in value:
            if not isinstance(item, dict):
                raise MonitorError("public Gist list item is malformed")
            gist_id = item.get("id")
            if not isinstance(gist_id, str) or GIST_ID_RE.fullmatch(gist_id) is None:
                raise MonitorError("public Gist list item is malformed")
            if gist_id not in seen_ids:
                seen_ids.add(gist_id)
                gist_ids.append(gist_id)
            if len(gist_ids) > MAX_GISTS_PER_RUN:
                raise MonitorError("public Gist delta exceeded the safe item limit")
        url = next_link(headers)

    patterns = domain_patterns(domains)
    for gist_id in gist_ids:
        value, _, _ = client.request_json(
            "https://api.github.com/gists/" + quote(gist_id, safe="")
        )
        collect_gist_detail(value, patterns, observations)


def collect_gist_detail(
    value: object,
    patterns: list[tuple[str, re.Pattern[str]]],
    observations: dict[tuple[str, str, str, str], dict[str, Any]],
) -> None:
    if not isinstance(value, dict) or value.get("public") is not True:
        raise MonitorError("public Gist detail is malformed")
    gist_id = value.get("id")
    files = value.get("files")
    history = value.get("history")
    if (
        not isinstance(gist_id, str)
        or GIST_ID_RE.fullmatch(gist_id) is None
        or value.get("truncated") is not False
        or not isinstance(files, dict)
        or len(files) > 300
        or not isinstance(history, list)
        or not history
        or not isinstance(history[0], dict)
        or not isinstance(history[0].get("version"), str)
    ):
        raise MonitorError("public Gist detail is incomplete")
    revision = history[0]["version"]
    public_url = validate_public_url(value.get("html_url"), "gist.github.com")
    description = value.get("description")
    if description is not None and not isinstance(description, str):
        raise MonitorError("public Gist detail is malformed")
    candidates: list[tuple[str, str]] = []
    if description:
        candidates.append(("[description]", description))
    for file_key, file_value in sorted(files.items()):
        if not isinstance(file_key, str) or not isinstance(file_value, dict):
            raise MonitorError("public Gist file is malformed")
        filename = file_value.get("filename")
        content = file_value.get("content")
        if (
            not isinstance(filename, str)
            or not filename
            or file_value.get("truncated") is not False
            or not isinstance(content, str)
        ):
            raise MonitorError("public Gist file is incomplete")
        candidates.append((filename, filename + "\n" + content))
    for path, content in candidates:
        for indicator_id, pattern in patterns:
            if pattern.search(content) is None:
                continue
            merge_observation(
                observations,
                {
                    "provider": "github",
                    "surface": "github-gist",
                    "resource_id": f"{gist_id}:{revision}:{path}",
                    "indicator_id": indicator_id,
                    "query_ids": [f"{indicator_id}-API-GIST-DELTA"],
                    "resource": f"gist/{gist_id}",
                    "path": path,
                    "public_url": public_url,
                },
            )


def validate_observation(observation: object) -> dict[str, Any]:
    required = {
        "provider",
        "surface",
        "resource_id",
        "indicator_id",
        "query_ids",
        "resource",
        "path",
        "public_url",
    }
    if not isinstance(observation, dict) or set(observation) != required:
        raise MonitorError("observation is malformed")
    if observation.get("provider") != "github" or observation.get("surface") not in SURFACES:
        raise MonitorError("observation is malformed")
    for field in ("resource_id", "resource", "path"):
        value = observation.get(field)
        if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
            raise MonitorError("observation is malformed")
    indicator_id = observation.get("indicator_id")
    if not isinstance(indicator_id, str) or ID_RE.fullmatch(indicator_id) is None:
        raise MonitorError("observation is malformed")
    query_ids = observation.get("query_ids")
    if (
        not isinstance(query_ids, list)
        or not query_ids
        or query_ids != sorted(set(query_ids))
        or not all(isinstance(query_id, str) and query_id.startswith(indicator_id + "-") for query_id in query_ids)
    ):
        raise MonitorError("observation is malformed")
    host = "gist.github.com" if observation["surface"] == "github-gist" else "github.com"
    validate_public_url(observation.get("public_url"), host)
    return observation


def load_observations(path: Path) -> dict[str, Any]:
    document = load_json(path, "observation document")
    if set(document) != {
        "schema_version",
        "provider",
        "query_catalog_version",
        "collected_at",
        "cursors",
        "observations",
    }:
        raise MonitorError("observation document has unexpected fields")
    if (
        document.get("schema_version") != OBSERVATION_SCHEMA_VERSION
        or document.get("provider") != "github"
        or document.get("query_catalog_version") != QUERY_CATALOG_VERSION
    ):
        raise MonitorError("observation document version is unsupported")
    parse_timestamp(document.get("collected_at"), "collected_at")
    cursors = document.get("cursors")
    if not isinstance(cursors, dict) or set(cursors) != {"github_public_gists_since"}:
        raise MonitorError("observation cursor is malformed")
    parse_timestamp(cursors.get("github_public_gists_since"), "Gist cursor")
    observations = document.get("observations")
    if not isinstance(observations, list):
        raise MonitorError("observation list is malformed")
    fingerprints: set[str] = set()
    for observation in observations:
        validate_observation(observation)
        key = observation_fingerprint(observation)
        if key in fingerprints:
            raise MonitorError("observation list contains a duplicate")
        fingerprints.add(key)
    if observations != sorted(observations, key=observation_fingerprint):
        raise MonitorError("observation list is not deterministically ordered")
    return document


def observation_fingerprint(observation: dict[str, Any]) -> str:
    source = {
        "indicator_id": observation["indicator_id"],
        "provider": observation["provider"],
        "resource_id": observation["resource_id"],
        "surface": observation["surface"],
    }
    canonical = json.dumps(
        source, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def empty_state() -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "query_catalog_version": QUERY_CATALOG_VERSION,
        "updated_at": None,
        "cursors": {"github_public_gists_since": None},
        "findings": [],
    }


def validate_review(value: object, disposition: str) -> None:
    if disposition in {"open", "remediated"}:
        if value is not None:
            raise MonitorError("state review is invalid")
        return
    if not isinstance(value, dict) or set(value) != {
        "owner",
        "reason",
        "reviewed_at",
        "expires_at",
    }:
        raise MonitorError("state review is invalid")
    owner = value.get("owner")
    reason = value.get("reason")
    if (
        not isinstance(owner, str)
        or not 1 <= len(owner) <= 128
        or not owner.isprintable()
        or "@" in owner
        or not isinstance(reason, str)
        or not 1 <= len(reason) <= 500
        or not reason.isprintable()
        or "@" in reason
    ):
        raise MonitorError("state review is invalid")
    reviewed_at = parse_timestamp(value.get("reviewed_at"), "reviewed_at")
    expires_at = parse_timestamp(value.get("expires_at"), "expires_at")
    if expires_at <= reviewed_at or expires_at - reviewed_at > timedelta(days=180):
        raise MonitorError("state review expiry is invalid")


def validate_state(state: object) -> dict[str, Any]:
    if not isinstance(state, dict) or set(state) != {
        "schema_version",
        "query_catalog_version",
        "updated_at",
        "cursors",
        "findings",
    }:
        raise MonitorError("state document is malformed")
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise MonitorError("state schema_version is unsupported")
    if state.get("query_catalog_version") != QUERY_CATALOG_VERSION:
        raise MonitorError("state query catalog version is unsupported")
    if state.get("updated_at") is not None:
        parse_timestamp(state.get("updated_at"), "state updated_at")
    cursors = state.get("cursors")
    if not isinstance(cursors, dict) or set(cursors) != {"github_public_gists_since"}:
        raise MonitorError("state cursor is malformed")
    cursor = cursors.get("github_public_gists_since")
    if cursor is not None:
        parse_timestamp(cursor, "state Gist cursor")
    findings = state.get("findings")
    if not isinstance(findings, list):
        raise MonitorError("state findings are malformed")
    seen: set[str] = set()
    for finding in findings:
        validate_finding(finding)
        fingerprint = finding["fingerprint"]
        if fingerprint in seen:
            raise MonitorError("state contains duplicate fingerprints")
        seen.add(fingerprint)
    if findings != sorted(findings, key=lambda item: item["fingerprint"]):
        raise MonitorError("state findings are not deterministically ordered")
    return state


def validate_finding(finding: object) -> None:
    required = {
        "fingerprint",
        "provider",
        "surface",
        "resource_id",
        "indicator_id",
        "query_ids",
        "resource",
        "path",
        "public_url",
        "first_seen",
        "last_seen",
        "last_notified",
        "disposition",
        "review",
    }
    if not isinstance(finding, dict) or set(finding) != required:
        raise MonitorError("state finding is malformed")
    validate_observation({key: finding[key] for key in required if key in {
        "provider", "surface", "resource_id", "indicator_id", "query_ids", "resource", "path", "public_url"
    }})
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise MonitorError("state fingerprint is invalid")
    if fingerprint != observation_fingerprint(finding):
        raise MonitorError("state fingerprint does not match its source")
    first_seen = parse_timestamp(finding.get("first_seen"), "first_seen")
    last_seen = parse_timestamp(finding.get("last_seen"), "last_seen")
    last_notified = parse_timestamp(finding.get("last_notified"), "last_notified")
    if first_seen > last_seen or first_seen > last_notified:
        raise MonitorError("state finding timestamps are invalid")
    disposition = finding.get("disposition")
    if disposition not in DISPOSITIONS:
        raise MonitorError("state disposition is invalid")
    validate_review(finding.get("review"), disposition)


def load_state_snapshot(path: Path) -> dict[str, Any]:
    snapshot = load_json(path, "state snapshot")
    if set(snapshot) != {
        "schema_version",
        "repository",
        "branch",
        "path",
        "base_blob_sha",
        "state",
    }:
        raise MonitorError("state snapshot is malformed")
    if (
        snapshot.get("schema_version") != STATE_SCHEMA_VERSION
        or not isinstance(snapshot.get("repository"), str)
        or REPOSITORY_RE.fullmatch(snapshot["repository"]) is None
        or snapshot.get("branch") != STATE_BRANCH
        or snapshot.get("path") != STATE_PATH
        or not isinstance(snapshot.get("base_blob_sha"), str)
        or SHA1_RE.fullmatch(snapshot["base_blob_sha"]) is None
    ):
        raise MonitorError("state snapshot is malformed")
    validate_state(snapshot.get("state"))
    return snapshot


def read_remote_state(client: GitHubClient, repository: str) -> dict[str, Any]:
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise MonitorError("monitor repository is invalid")
    url = (
        f"https://api.github.com/repos/{repository}/contents/{STATE_PATH}?"
        + urlencode([("ref", STATE_BRANCH)])
    )
    value, _, _ = client.request_json(url)
    if not isinstance(value, dict):
        raise MonitorError("state response is malformed")
    encoded = value.get("content")
    sha = value.get("sha")
    if (
        value.get("type") != "file"
        or value.get("encoding") != "base64"
        or not isinstance(encoded, str)
        or not isinstance(sha, str)
        or SHA1_RE.fullmatch(sha) is None
    ):
        raise MonitorError("state response is malformed")
    try:
        encoded_bytes = encoded.encode("ascii")
        raw = base64.b64decode(b"".join(encoded_bytes.split()), validate=True)
        state = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise MonitorError("state content is malformed") from error
    validate_state(state)
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "repository": repository,
        "branch": STATE_BRANCH,
        "path": STATE_PATH,
        "base_blob_sha": sha,
        "state": state,
    }


def write_remote_state(
    client: GitHubClient,
    snapshot: dict[str, Any],
    state: dict[str, Any],
    run_id: str,
) -> None:
    repository = snapshot["repository"]
    url = f"https://api.github.com/repos/{repository}/contents/{STATE_PATH}"
    payload = {
        "message": f"chore(psb-source-003): update exposure state {run_id}",
        "content": base64.b64encode(json_bytes(state)).decode("ascii"),
        "sha": snapshot["base_blob_sha"],
        "branch": STATE_BRANCH,
    }
    client.request_json(url, method="PUT", payload=payload, expected_status={200})


def gist_since_from_state(state: dict[str, Any], collected_at: datetime) -> datetime:
    cursor = state["cursors"]["github_public_gists_since"]
    if cursor is None:
        return collected_at - timedelta(hours=INITIAL_GIST_LOOKBACK_HOURS)
    return parse_timestamp(cursor, "state Gist cursor")


def collect_all(
    client: GitHubClient,
    domains: list[dict[str, str]],
    state: dict[str, Any],
    collected_at: datetime,
) -> dict[str, Any]:
    observations: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    repository_cache: dict[str, str] = {}
    for query in automatic_queries(domains):
        collect_search_query(client, query, observations, repository_cache)
    collect_gist_delta(
        client,
        domains,
        gist_since_from_state(state, collected_at),
        observations,
    )
    ordered = sorted(observations.values(), key=observation_fingerprint)
    return {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "provider": "github",
        "query_catalog_version": QUERY_CATALOG_VERSION,
        "collected_at": format_timestamp(collected_at),
        "cursors": {"github_public_gists_since": format_timestamp(collected_at)},
        "observations": ordered,
    }


def event_from_finding(event_type: str, finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "fingerprint": finding["fingerprint"],
        "surface": finding["surface"],
        "indicator_id": finding["indicator_id"],
        "query_ids": finding["query_ids"],
        "resource": finding["resource"],
        "path": finding["path"],
        "public_url": finding["public_url"],
        "first_seen": finding["first_seen"],
        "last_seen": finding["last_seen"],
    }


def reconcile_state(
    state: dict[str, Any], observation_document: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    validate_state(state)
    now = parse_timestamp(observation_document["collected_at"], "collected_at")
    now_text = format_timestamp(now)
    existing = {finding["fingerprint"]: dict(finding) for finding in state["findings"]}
    events: list[dict[str, Any]] = []
    known = 0
    for observation in observation_document["observations"]:
        fingerprint = observation_fingerprint(observation)
        finding = existing.get(fingerprint)
        if finding is None:
            finding = {
                "fingerprint": fingerprint,
                **observation,
                "first_seen": now_text,
                "last_seen": now_text,
                "last_notified": now_text,
                "disposition": "open",
                "review": None,
            }
            existing[fingerprint] = finding
            events.append(event_from_finding("NEW", finding))
            continue
        finding["last_seen"] = now_text
        finding["query_ids"] = sorted(
            set(finding["query_ids"]) | set(observation["query_ids"])
        )
        finding["resource"] = observation["resource"]
        finding["path"] = observation["path"]
        finding["public_url"] = observation["public_url"]
        reopen = finding["disposition"] == "remediated"
        if finding["disposition"] in {"accepted-public", "false-positive"}:
            expires_at = parse_timestamp(finding["review"]["expires_at"], "expires_at")
            reopen = expires_at <= now
        if reopen:
            finding["disposition"] = "open"
            finding["review"] = None
            finding["last_notified"] = now_text
            events.append(event_from_finding("REOPENED", finding))
        else:
            known += 1
    next_state = {
        "schema_version": STATE_SCHEMA_VERSION,
        "query_catalog_version": QUERY_CATALOG_VERSION,
        "updated_at": now_text,
        "cursors": dict(observation_document["cursors"]),
        "findings": sorted(existing.values(), key=lambda item: item["fingerprint"]),
    }
    validate_state(next_state)
    return next_state, sorted(events, key=lambda item: item["fingerprint"]), known


def render_summary(
    observation_document: dict[str, Any], events: list[dict[str, Any]], known: int
) -> str:
    new_count = sum(event["event_type"] == "NEW" for event in events)
    reopened_count = sum(event["event_type"] == "REOPENED" for event in events)
    status = "FINDINGS" if events else "CLEAN"
    lines = [
        f"# {CONTROL_ID} Public Exposure Monitor",
        "",
        f"- Scan status: **{status}**",
        f"- Completed at: `{observation_document['collected_at']}`",
        f"- Current observations: `{len(observation_document['observations'])}`",
        f"- NEW: `{new_count}`",
        f"- REOPENED: `{reopened_count}`",
        f"- Known/suppressed: `{known}`",
        "",
    ]
    if events:
        lines.extend(
            [
                "## Notification-ready findings",
                "",
                "| Event | Surface | Indicator | Resource | Path | Link |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for event in events:
            lines.append(
                "| {event_type} | {surface} | `{indicator}` | `{resource}` | `{path}` | [Open]({url}) |".format(
                    event_type=markdown_cell(event["event_type"]),
                    surface=markdown_cell(event["surface"]),
                    indicator=markdown_cell(event["indicator_id"]),
                    resource=markdown_cell(event["resource"]),
                    path=markdown_cell(event["path"]),
                    url=event["public_url"],
                )
            )
        lines.append("")
    lines.extend(
        [
            "The scanner stores no matched snippet, domain value, email local part derived from content, credential, or raw provider response.",
            "A CLEAN API run does not cover historical Git content or browser-only search surfaces.",
            "",
        ]
    )
    return "\n".join(lines)


def write_assessment(
    output_directory: Path,
    observation_document: dict[str, Any],
    state: dict[str, Any],
    events: list[dict[str, Any]],
    known: int,
) -> None:
    status = "FINDINGS" if events else "CLEAN"
    event_document = {
        "schema_version": "1.0",
        "control_id": CONTROL_ID,
        "scan_status": status,
        "generated_at": observation_document["collected_at"],
        "events": events,
    }
    atomic_write(output_directory / "new-findings.json", json_bytes(event_document))
    atomic_write(output_directory / "updated-state.json", json_bytes(state))
    atomic_write(
        output_directory / "summary.md",
        (render_summary(observation_document, events, known) + "\n").encode("utf-8"),
    )


def require_token(name: str) -> str:
    token = os.environ.get(name, "")
    if not token:
        raise MonitorError(f"required environment credential {name} is unavailable")
    return token


def command_queries(args: argparse.Namespace) -> int:
    domains = load_configuration(args.config)
    atomic_write(args.output, render_browser_queries(domains).encode("utf-8"))
    print(f"WROTE {args.output}")
    return 0


def command_state_read(args: argparse.Namespace) -> int:
    client = GitHubClient(require_token("GITHUB_TOKEN"))
    snapshot = read_remote_state(client, args.repository)
    atomic_write(args.output, json_bytes(snapshot))
    print(f"WROTE {args.output}")
    return 0


def command_collect(args: argparse.Namespace) -> int:
    domains = load_configuration(args.config)
    snapshot = load_state_snapshot(args.state_snapshot)
    client = GitHubClient(require_token("PUBLIC_SEARCH_TOKEN"))
    document = collect_all(client, domains, snapshot["state"], utc_now())
    atomic_write(args.output, json_bytes(document))
    print(f"WROTE {args.output}")
    return 0


def command_reconcile(args: argparse.Namespace) -> int:
    snapshot = load_state_snapshot(args.state_snapshot)
    observations = load_observations(args.observations)
    next_state, events, known = reconcile_state(snapshot["state"], observations)
    client = GitHubClient(require_token("GITHUB_TOKEN"))
    run_id = os.environ.get("GITHUB_RUN_ID", "manual")
    # Prepare notifier output before changing durable state. Consumers must still
    # gate delivery on this command's final exit status, which is produced only
    # after the compare-and-swap update succeeds.
    write_assessment(args.output_dir, observations, next_state, events, known)
    write_remote_state(client, snapshot, next_state, run_id)
    print(
        f"COMPLETE new={sum(event['event_type'] == 'NEW' for event in events)} "
        f"reopened={sum(event['event_type'] == 'REOPENED' for event in events)} known={known}"
    )
    return 1 if events else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    queries_parser = subparsers.add_parser("queries", help="Generate manual browser GET links")
    queries_parser.add_argument("--config", type=Path, required=True)
    queries_parser.add_argument("--output", type=Path, required=True)
    queries_parser.set_defaults(handler=command_queries)

    state_parser = subparsers.add_parser("state-read", help="Read the dedicated state branch")
    state_parser.add_argument("--repository", required=True)
    state_parser.add_argument("--output", type=Path, required=True)
    state_parser.set_defaults(handler=command_state_read)

    collect_parser = subparsers.add_parser("collect", help="Collect public GitHub observations")
    collect_parser.add_argument("--config", type=Path, required=True)
    collect_parser.add_argument("--state-snapshot", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.set_defaults(handler=command_collect)

    reconcile_parser = subparsers.add_parser("reconcile", help="Reconcile and persist findings")
    reconcile_parser.add_argument("--state-snapshot", type=Path, required=True)
    reconcile_parser.add_argument("--observations", type=Path, required=True)
    reconcile_parser.add_argument("--output-dir", type=Path, required=True)
    reconcile_parser.set_defaults(handler=command_reconcile)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.handler(args)
    except MonitorError as error:
        print(f"ERROR {args.command}: {error}", file=sys.stderr)
        return 2
    except Exception:
        print(f"ERROR {args.command}: unexpected scanner failure", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
