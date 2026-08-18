#!/usr/bin/env python3
"""Collect a bounded sanitized GitHub organization audit-log export."""

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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "psb-github-audit-export/v1"
API_VERSION = "2026-03-10"
API_HOST = "api.github.com"
MAX_PAGES = 100
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_EVENTS = 10_000
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
TARGET_ACTIONS = {
    "environment.update_protection_rule",
    "org.runner_group_updated",
    "protected_branch.update_allow_force_pushes_enforcement_level",
    "protected_branch.update_allow_deletions_enforcement_level",
    "protected_branch.update_admin_enforced",
    "protected_branch.update_require_code_owner_review",
    "repository_ruleset.update",
}
SAFE_EVENT_FIELDS = {
    "@timestamp",
    "_document_id",
    "action",
    "actor",
    "actor_id",
    "actor_is_bot",
    "allow_force_pushes_enforcement_level",
    "allow_deletions_enforcement_level",
    "admin_enforced",
    "environment_name",
    "name",
    "new_value",
    "network_configuration_id",
    "old_value",
    "operation_type",
    "org",
    "org_id",
    "repo",
    "repository_id",
    "request_id",
    "require_code_owner_review",
    "ruleset_bypass_actors_added",
    "ruleset_bypass_actors_deleted",
    "ruleset_bypass_actors_updated",
    "ruleset_conditions_added",
    "ruleset_conditions_deleted",
    "ruleset_conditions_updated",
    "ruleset_enforcement",
    "ruleset_id",
    "ruleset_name",
    "ruleset_old_enforcement",
    "ruleset_old_name",
    "ruleset_rules_added",
    "ruleset_rules_deleted",
    "ruleset_rules_updated",
    "ruleset_source_type",
    "runner_group_allow_public",
    "runner_group_id",
    "runner_group_name",
    "runner_group_restricted_to_workflows",
    "runner_group_selected_workflow_refs",
}


class CollectorError(ValueError):
    """GitHub audit evidence could not be collected safely."""


PageFetcher = Callable[[str, str, int], tuple[list[Any], str | None]]


def parse_time(value: str, label: str) -> datetime:
    if not value.endswith("Z"):
        raise CollectorError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CollectorError(f"{label} must be RFC3339 UTC") from error
    return parsed


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def first_url(organization: str, since: datetime, until: datetime) -> str:
    phrase = f"created:>={timestamp(since)} created:<={timestamp(until)}"
    query = urllib.parse.urlencode(
        {
            "phrase": phrase,
            "include": "all",
            "order": "asc",
            "per_page": "100",
        }
    )
    return f"https://{API_HOST}/orgs/{organization}/audit-log?{query}"


def validate_page_url(
    value: str, organization: str, since: datetime, until: datetime
) -> None:
    try:
        parsed = urllib.parse.urlparse(value)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise CollectorError("GitHub audit pagination URL is malformed") from error
    expected_phrase = f"created:>={timestamp(since)} created:<={timestamp(until)}"
    if not all(
        (
            parsed.scheme == "https",
            parsed.hostname == API_HOST,
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            parsed.path == f"/orgs/{organization}/audit-log",
            parsed.fragment == "",
            parsed.params == "",
        )
    ):
        raise CollectorError("GitHub audit pagination escaped the approved endpoint")
    if not set(query) <= {"phrase", "include", "order", "per_page", "after"}:
        raise CollectorError("GitHub audit pagination added an unsupported query")
    expected = {
        "phrase": [expected_phrase],
        "include": ["all"],
        "order": ["asc"],
        "per_page": ["100"],
    }
    if any(query.get(key) != expected_value for key, expected_value in expected.items()):
        raise CollectorError("GitHub audit pagination changed the bounded query")
    after = query.get("after")
    if after is not None and (len(after) != 1 or not after[0] or len(after[0]) > 512):
        raise CollectorError("GitHub audit pagination cursor is malformed")


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
            raise CollectorError("GitHub audit pagination Link header is malformed")
        if found is not None:
            raise CollectorError("GitHub audit pagination has duplicate next links")
        found = candidate[1:-1]
    return found


def fetch_page(url: str, token: str, timeout: int) -> tuple[list[Any], str | None]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "product-security-controls-cicd-control-plane-collector",
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
            raise CollectorError("GitHub audit API rate limit or access policy denied collection") from error
        raise CollectorError("GitHub audit API request failed") from error
    except (OSError, urllib.error.URLError) as error:
        raise CollectorError("GitHub audit API request failed") from error
    if len(payload) > MAX_PAGE_BYTES:
        raise CollectorError("GitHub audit API page exceeds the size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError("GitHub audit API response is malformed") from error
    if not isinstance(value, list):
        raise CollectorError("GitHub audit API response must be an array")
    return value, next_link(link)


def sanitize_event(raw: Any, organization: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        raise CollectorError("GitHub audit event is malformed")
    action = raw.get("action")
    if not isinstance(action, str) or not action:
        raise CollectorError("GitHub audit event lacks an action")
    if action not in TARGET_ACTIONS:
        return None
    if raw.get("org") != organization:
        raise CollectorError("GitHub audit event organization is mismatched")
    sanitized = {key: raw[key] for key in SAFE_EVENT_FIELDS if key in raw}
    for field in ("_document_id", "actor", "request_id"):
        if not isinstance(sanitized.get(field), str) or not sanitized[field]:
            raise CollectorError(f"target GitHub audit event lacks {field}")
    actor_id = sanitized.get("actor_id")
    if not isinstance(actor_id, int) or isinstance(actor_id, bool):
        raise CollectorError("target GitHub audit event lacks a stable actor ID")
    if sanitized.get("actor_is_bot") is not False:
        raise CollectorError("target GitHub audit event is not an attributable human event")
    event_time = sanitized.get("@timestamp")
    if not isinstance(event_time, (str, int)) or isinstance(event_time, bool):
        raise CollectorError("target GitHub audit event lacks a timestamp")
    if action == "environment.update_protection_rule" and not all(
        isinstance(sanitized.get(field), expected)
        for field, expected in (
            ("repo", str),
            ("environment_name", str),
            ("old_value", dict),
            ("new_value", dict),
        )
    ):
        raise CollectorError("GitHub environment event lacks exact old or new settings")
    if action == "org.runner_group_updated":
        runner_group_id = sanitized.get("runner_group_id")
        if not isinstance(runner_group_id, int) or isinstance(runner_group_id, bool):
            raise CollectorError("GitHub runner-group event lacks a stable group ID")
        if not isinstance(sanitized.get("runner_group_name"), str) or not sanitized[
            "runner_group_name"
        ]:
            raise CollectorError("GitHub runner-group event lacks a group name")
        for field in (
            "runner_group_allow_public",
            "runner_group_restricted_to_workflows",
        ):
            if not isinstance(sanitized.get(field), bool):
                raise CollectorError(f"GitHub runner-group event lacks boolean {field}")
        workflows = sanitized.get("runner_group_selected_workflow_refs")
        if not isinstance(workflows, list) or not all(
            isinstance(workflow, str) and workflow for workflow in workflows
        ):
            raise CollectorError("GitHub runner-group event lacks selected workflow refs")
        network_id = sanitized.get("network_configuration_id")
        if network_id is not None and (
            not isinstance(network_id, str) or not network_id
        ):
            raise CollectorError("GitHub runner-group event has a malformed network ID")
    if action == "repository_ruleset.update":
        ruleset_id = sanitized.get("ruleset_id")
        repository_id = sanitized.get("repository_id")
        source_type = sanitized.get("ruleset_source_type")
        if (
            not isinstance(ruleset_id, int)
            or isinstance(ruleset_id, bool)
            or ruleset_id < 1
            or source_type not in {"Repository", "Organization"}
            or sanitized.get("operation_type") != "modify"
        ):
            raise CollectorError("GitHub ruleset event lacks stable repository or ruleset identity")
        if source_type == "Repository" and (
            not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id < 1
            or not isinstance(sanitized.get("repo"), str)
            or not sanitized["repo"]
        ):
            raise CollectorError("GitHub repository ruleset event lacks stable repository identity")
        org_id = sanitized.get("org_id")
        if source_type == "Organization" and (
            not isinstance(org_id, int)
            or isinstance(org_id, bool)
            or org_id < 1
            or "repo" in sanitized
            or "repository_id" in sanitized
        ):
            raise CollectorError("GitHub organization ruleset event lacks stable organization identity")
    if action in {
        "protected_branch.update_allow_force_pushes_enforcement_level",
        "protected_branch.update_allow_deletions_enforcement_level",
        "protected_branch.update_admin_enforced",
        "protected_branch.update_require_code_owner_review",
    }:
        repository_id = sanitized.get("repository_id")
        if action in {
            "protected_branch.update_allow_force_pushes_enforcement_level",
            "protected_branch.update_allow_deletions_enforcement_level",
        }:
            field = (
                "allow_force_pushes_enforcement_level"
                if action == "protected_branch.update_allow_force_pushes_enforcement_level"
                else "allow_deletions_enforcement_level"
            )
            enforcement = sanitized.get(field)
            valid_enforcement = (
                isinstance(enforcement, int)
                and not isinstance(enforcement, bool)
                and enforcement in {0, 1, 2}
            )
        elif action == "protected_branch.update_admin_enforced":
            enforcement = sanitized.get("admin_enforced")
            valid_enforcement = isinstance(enforcement, bool)
        else:
            enforcement = sanitized.get("require_code_owner_review")
            valid_enforcement = isinstance(enforcement, bool)
        if (
            not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id < 1
            or not isinstance(sanitized.get("repo"), str)
            or not sanitized["repo"]
            or not isinstance(sanitized.get("name"), str)
            or not sanitized["name"]
            or sanitized.get("operation_type") != "modify"
            or not valid_enforcement
        ):
            raise CollectorError(
                "GitHub protected-branch event lacks exact repository branch or enforcement identity"
            )
    return sanitized


def collect(
    organization: str,
    since: datetime,
    until: datetime,
    collected_at: datetime,
    token: str,
    timeout: int,
    fetcher: PageFetcher = fetch_page,
) -> dict[str, Any]:
    if ORG_RE.fullmatch(organization) is None:
        raise CollectorError("GitHub organization is malformed")
    if not 1 <= timeout <= 120:
        raise CollectorError("collector timeout is outside 1..120 seconds")
    if not token or any(character.isspace() for character in token):
        raise CollectorError("GitHub audit token is unavailable or malformed")
    if not since < until <= collected_at:
        raise CollectorError("collector time window is invalid or from the future")
    if until - since > timedelta(hours=24):
        raise CollectorError("collector time window exceeds 24 hours")

    url: str | None = first_url(organization, since, until)
    seen_urls: set[str] = set()
    raw_count = 0
    pages = 0
    events: list[dict[str, Any]] = []
    document_ids: set[str] = set()
    while url is not None:
        validate_page_url(url, organization, since, until)
        if url in seen_urls:
            raise CollectorError("GitHub audit pagination loop detected")
        seen_urls.add(url)
        if pages >= MAX_PAGES:
            raise CollectorError("GitHub audit pagination exceeded the page limit")
        page, next_url = fetcher(url, token, timeout)
        pages += 1
        raw_count += len(page)
        if raw_count > MAX_EVENTS:
            raise CollectorError("GitHub audit collection exceeded the event limit")
        for raw in page:
            event = sanitize_event(raw, organization)
            if event is None:
                continue
            document_id = event["_document_id"]
            if document_id in document_ids:
                raise CollectorError("GitHub audit collection contains a duplicate document ID")
            document_ids.add(document_id)
            events.append(event)
        if next_url is not None:
            validate_page_url(next_url, organization, since, until)
        url = next_url

    return {
        "schema": SCHEMA,
        "organization": organization,
        "collected_at": timestamp(collected_at),
        "complete": True,
        "collection": {
            "api_endpoint": f"https://{API_HOST}/orgs/{organization}/audit-log",
            "api_version": API_VERSION,
            "include": "all",
            "order": "asc",
            "per_page": 100,
            "window_start": timestamp(since),
            "window_end": timestamp(until),
            "pages": pages,
            "raw_events": raw_count,
            "selected_events": len(events),
            "pagination_complete": True,
        },
        "events": sorted(events, key=lambda event: (str(event["@timestamp"]), event["_document_id"])),
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
        raise CollectorError("cannot write GitHub audit export") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization", required=True)
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    try:
        output = collect(
            organization=args.organization,
            since=parse_time(args.since, "since"),
            until=parse_time(args.until, "until"),
            collected_at=datetime.now(timezone.utc),
            token=os.environ.get(args.token_env, ""),
            timeout=args.timeout,
        )
        write_output(args.output, output)
    except CollectorError as error:
        print(f"ERROR GitHub audit collection unavailable: {error}", file=sys.stderr)
        return 2
    print(
        f"COLLECTED {output['collection']['selected_events']} selected GitHub audit event(s) "
        f"across {output['collection']['pages']} complete page(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
