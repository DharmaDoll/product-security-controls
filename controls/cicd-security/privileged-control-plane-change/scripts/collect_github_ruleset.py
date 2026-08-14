#!/usr/bin/env python3
"""Collect one GitHub branch or tag ruleset and exact before/after history states."""

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


SCHEMA = "psb-github-repository-ruleset-snapshot/v1"
API_VERSION = "2026-03-10"
API_HOST = "api.github.com"
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 100
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class CollectorError(ValueError):
    """Repository ruleset state could not be collected safely."""


Fetcher = Callable[[str, str, int], tuple[Any, str | None, str]]


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CollectorError(f"{label} must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CollectorError(f"{label} must be RFC3339 UTC") from error


def repository_url(owner: str, repository: str) -> str:
    return f"https://{API_HOST}/repos/{owner}/{repository}"


def ruleset_url(owner: str, repository: str, ruleset_id: int) -> str:
    return repository_url(owner, repository) + f"/rulesets/{ruleset_id}?includes_parents=false"


def history_url(owner: str, repository: str, ruleset_id: int) -> str:
    return repository_url(owner, repository) + f"/rulesets/{ruleset_id}/history?per_page=100"


def version_url(owner: str, repository: str, ruleset_id: int, version_id: int) -> str:
    return repository_url(owner, repository) + f"/rulesets/{ruleset_id}/history/{version_id}"


def validate_url(
    value: str, owner: str, repository: str, ruleset_id: int, endpoint: str
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
        raise CollectorError("GitHub ruleset URL is malformed") from error
    base = f"/repos/{owner}/{repository}"
    allowed_paths = {
        "repository": base,
        "ruleset": base + f"/rulesets/{ruleset_id}",
        "history": base + f"/rulesets/{ruleset_id}/history",
    }
    path_ok = parsed.path == allowed_paths.get(endpoint)
    if endpoint == "version":
        prefix = base + f"/rulesets/{ruleset_id}/history/"
        suffix = parsed.path.removeprefix(prefix)
        path_ok = parsed.path.startswith(prefix) and suffix.isdigit() and int(suffix) > 0
    if not all(
        (
            parsed.scheme == "https",
            parsed.hostname == API_HOST,
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            path_ok,
            parsed.fragment == "",
            parsed.params == "",
        )
    ):
        raise CollectorError("GitHub ruleset request escaped the approved endpoint")
    if endpoint == "ruleset":
        if query != {"includes_parents": ["false"]}:
            raise CollectorError("GitHub ruleset request changed parent inclusion")
    elif endpoint == "history":
        if not set(query) <= {"per_page", "page"} or query.get("per_page") != ["100"]:
            raise CollectorError("GitHub ruleset history changed the bounded query")
        page = query.get("page")
        if page is not None and (
            len(page) != 1 or not page[0].isdigit() or not 1 <= int(page[0]) <= MAX_PAGES
        ):
            raise CollectorError("GitHub ruleset history page is malformed")
    elif query:
        raise CollectorError("GitHub ruleset request added an unsupported query")


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
            raise CollectorError("GitHub ruleset pagination Link header is malformed")
        found = candidate[1:-1]
    return found


def fetch(url: str, token: str, timeout: int) -> tuple[Any, str | None, str]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "product-security-controls-ruleset-collector",
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
        raise CollectorError("GitHub ruleset API denied or failed collection") from error
    except (OSError, urllib.error.URLError) as error:
        raise CollectorError("GitHub ruleset API request failed") from error
    if len(payload) > MAX_PAGE_BYTES:
        raise CollectorError("GitHub ruleset API response exceeds the size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError("GitHub ruleset API response is malformed") from error
    if not request_id:
        raise CollectorError("GitHub ruleset API response lacks a request identity")
    return value, next_link(link), request_id


def ruleset_state(
    raw: Any,
    expected_id: int,
    source: str,
    source_type: str = "Repository",
    allowed_targets: frozenset[str] = frozenset({"branch", "tag"}),
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CollectorError("GitHub ruleset state must be an object")
    required = {
        "id": int,
        "node_id": str,
        "name": str,
        "target": str,
        "source_type": str,
        "source": str,
        "enforcement": str,
        "bypass_actors": list,
        "rules": list,
        "created_at": str,
        "updated_at": str,
    }
    if (
        any(not isinstance(raw.get(key), kind) for key, kind in required.items())
        or not (isinstance(raw.get("conditions"), dict) or raw.get("conditions") is None)
    ):
        raise CollectorError("GitHub ruleset state is incomplete")
    if (
        raw["id"] != expected_id
        or raw["source_type"] != source_type
        or raw["source"].lower() != source.lower()
        or raw["target"] not in allowed_targets
        or raw["enforcement"] not in {"active", "evaluate", "disabled"}
        or not raw["node_id"]
        or not raw["name"]
    ):
        raise CollectorError("GitHub ruleset identity or supported target is mismatched")
    parse_time(raw["created_at"], "GitHub ruleset created_at")
    parse_time(raw["updated_at"], "GitHub ruleset updated_at")
    return {key: raw[key] for key in (*required, "conditions")}


def organization_url(organization: str) -> str:
    return f"https://{API_HOST}/orgs/{organization}"


def organization_ruleset_url(organization: str, ruleset_id: int) -> str:
    return organization_url(organization) + f"/rulesets/{ruleset_id}"


def organization_history_url(organization: str, ruleset_id: int) -> str:
    return organization_ruleset_url(organization, ruleset_id) + "/history?per_page=100"


def organization_version_url(
    organization: str, ruleset_id: int, version_id: int
) -> str:
    return organization_ruleset_url(organization, ruleset_id) + f"/history/{version_id}"


def validate_organization_url(
    value: str, organization: str, ruleset_id: int, endpoint: str
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
        raise CollectorError("GitHub organization ruleset URL is malformed") from error
    base = f"/orgs/{organization}"
    allowed = {
        "organization": base,
        "ruleset": base + f"/rulesets/{ruleset_id}",
        "history": base + f"/rulesets/{ruleset_id}/history",
    }
    path_ok = parsed.path == allowed.get(endpoint)
    if endpoint == "version":
        prefix = base + f"/rulesets/{ruleset_id}/history/"
        suffix = parsed.path.removeprefix(prefix)
        path_ok = parsed.path.startswith(prefix) and suffix.isdigit() and int(suffix) > 0
    if not all(
        (
            parsed.scheme == "https",
            parsed.hostname == API_HOST,
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            path_ok,
            parsed.fragment == "",
            parsed.params == "",
        )
    ):
        raise CollectorError("GitHub organization ruleset request escaped the approved endpoint")
    if endpoint == "history":
        if not set(query) <= {"per_page", "page"} or query.get("per_page") != ["100"]:
            raise CollectorError("GitHub organization ruleset history changed the bounded query")
        page = query.get("page")
        if page is not None and (
            len(page) != 1 or not page[0].isdigit() or not 1 <= int(page[0]) <= MAX_PAGES
        ):
            raise CollectorError("GitHub organization ruleset history page is malformed")
    elif query:
        raise CollectorError("GitHub organization ruleset request added an unsupported query")


def collect(
    owner: str,
    repository: str,
    ruleset_id: int,
    before_version_id: int,
    after_version_id: int,
    observed_at: datetime,
    token: str,
    timeout: int,
    fetcher: Fetcher = fetch,
) -> dict[str, Any]:
    if (
        NAME_RE.fullmatch(owner) is None
        or NAME_RE.fullmatch(repository) is None
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in (ruleset_id, before_version_id, after_version_id)
        )
        or before_version_id >= after_version_id
        or not 1 <= timeout <= 120
        or not token
        or any(character.isspace() for character in token)
    ):
        raise CollectorError("GitHub ruleset collector arguments are invalid")
    full_name = f"{owner}/{repository}"
    repo_endpoint = repository_url(owner, repository)
    validate_url(repo_endpoint, owner, repository, ruleset_id, "repository")
    raw_repo, link, repo_request_id = fetcher(repo_endpoint, token, timeout)
    if link is not None or not isinstance(raw_repo, dict):
        raise CollectorError("GitHub repository identity response is malformed")
    repository_id = raw_repo.get("id")
    repository_node_id = raw_repo.get("node_id")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
        or not isinstance(repository_node_id, str)
        or not repository_node_id
        or str(raw_repo.get("full_name", "")).lower() != full_name.lower()
    ):
        raise CollectorError("GitHub repository lacks stable identity")

    current_endpoint = ruleset_url(owner, repository, ruleset_id)
    validate_url(current_endpoint, owner, repository, ruleset_id, "ruleset")
    raw_current, link, current_request_id = fetcher(current_endpoint, token, timeout)
    if link is not None:
        raise CollectorError("GitHub current ruleset unexpectedly paginated")
    current = ruleset_state(
        raw_current,
        ruleset_id,
        full_name,
        allowed_targets=frozenset({"branch", "tag", "push"}),
    )

    history_endpoint = history_url(owner, repository, ruleset_id)
    url: str | None = history_endpoint
    seen: set[str] = set()
    history: list[dict[str, Any]] = []
    history_request_ids: list[str] = []
    while url is not None:
        validate_url(url, owner, repository, ruleset_id, "history")
        if url in seen or len(seen) >= MAX_PAGES:
            raise CollectorError("GitHub ruleset history pagination loop or limit")
        seen.add(url)
        raw_page, next_url, request_id = fetcher(url, token, timeout)
        history_request_ids.append(request_id)
        if not isinstance(raw_page, list):
            raise CollectorError("GitHub ruleset history response must be an array")
        for entry in raw_page:
            if not isinstance(entry, dict):
                raise CollectorError("GitHub ruleset history entry is malformed")
            version_id = entry.get("version_id")
            actor = entry.get("actor")
            if (
                not isinstance(version_id, int)
                or isinstance(version_id, bool)
                or version_id < 1
                or not isinstance(actor, dict)
                or not isinstance(actor.get("id"), int)
                or isinstance(actor.get("id"), bool)
                or actor.get("type") != "User"
                or not isinstance(entry.get("updated_at"), str)
            ):
                raise CollectorError("GitHub ruleset history entry lacks version actor or time")
            history.append(
                {"version_id": version_id, "actor_id": actor["id"], "updated_at": entry["updated_at"]}
            )
        if next_url is not None:
            validate_url(next_url, owner, repository, ruleset_id, "history")
        url = next_url
    version_ids = [entry["version_id"] for entry in history]
    if (
        len(version_ids) != len(set(version_ids))
        or not history
        or max(version_ids) != after_version_id
        or before_version_id not in version_ids
        or after_version_id not in version_ids
    ):
        raise CollectorError("GitHub ruleset history is incomplete or has a later version")

    versions: list[dict[str, Any]] = []
    version_request_ids: list[str] = []
    for version_id in (before_version_id, after_version_id):
        endpoint = version_url(owner, repository, ruleset_id, version_id)
        validate_url(endpoint, owner, repository, ruleset_id, "version")
        raw_version, link, request_id = fetcher(endpoint, token, timeout)
        if link is not None or not isinstance(raw_version, dict):
            raise CollectorError("GitHub ruleset version response is malformed")
        if raw_version.get("version_id") != version_id:
            raise CollectorError("GitHub ruleset version identity is mismatched")
        history_entry = next(entry for entry in history if entry["version_id"] == version_id)
        actor = raw_version.get("actor")
        if (
            not isinstance(actor, dict)
            or actor.get("id") != history_entry["actor_id"]
            or actor.get("type") != "User"
            or raw_version.get("updated_at") != history_entry["updated_at"]
        ):
            raise CollectorError("GitHub ruleset version does not match history")
        state = ruleset_state(
            raw_version.get("state"),
            ruleset_id,
            full_name,
            allowed_targets=frozenset({"branch", "tag", "push"}),
        )
        if state["updated_at"] != raw_version["updated_at"]:
            raise CollectorError("GitHub ruleset version state timestamp is mismatched")
        versions.append(
            {
                "version_id": version_id,
                "actor_id": actor["id"],
                "updated_at": raw_version["updated_at"],
                "state": state,
            }
        )
        version_request_ids.append(request_id)
    if versions[1]["state"] != current:
        raise CollectorError("GitHub current ruleset does not match the latest requested version")
    if versions[0]["state"]["created_at"] != versions[1]["state"]["created_at"]:
        raise CollectorError("GitHub ruleset generation changed across requested versions")
    if versions[0]["state"]["target"] != versions[1]["state"]["target"]:
        raise CollectorError("GitHub ruleset target changed across requested versions")

    return {
        "schema": SCHEMA,
        "organization": owner,
        "collected_at": timestamp(observed_at),
        "complete": True,
        "collection": {
            "api_version": API_VERSION,
            "repository_endpoint": repo_endpoint,
            "ruleset_endpoint": current_endpoint,
            "history_endpoint": history_endpoint,
            "history_pages": len(seen),
            "history_complete": True,
            "repository_request_id": repo_request_id,
            "ruleset_request_id": current_request_id,
            "history_request_ids": history_request_ids,
            "version_request_ids": version_request_ids,
        },
        "repository": {
            "id": repository_id,
            "node_id": repository_node_id,
            "full_name": full_name,
        },
        "ruleset": {
            "id": ruleset_id,
            "node_id": current["node_id"],
            "before_version_id": before_version_id,
            "after_version_id": after_version_id,
            "history": history,
            "versions": versions,
            "current": current,
        },
    }


def collect_organization(
    organization: str,
    ruleset_id: int,
    before_version_id: int,
    after_version_id: int,
    observed_at: datetime,
    token: str,
    timeout: int,
    fetcher: Fetcher = fetch,
) -> dict[str, Any]:
    if (
        NAME_RE.fullmatch(organization) is None
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in (ruleset_id, before_version_id, after_version_id)
        )
        or before_version_id >= after_version_id
        or not 1 <= timeout <= 120
        or not token
        or any(character.isspace() for character in token)
    ):
        raise CollectorError("GitHub organization ruleset collector arguments are invalid")

    org_endpoint = organization_url(organization)
    validate_organization_url(org_endpoint, organization, ruleset_id, "organization")
    raw_org, link, org_request_id = fetcher(org_endpoint, token, timeout)
    if link is not None or not isinstance(raw_org, dict):
        raise CollectorError("GitHub organization identity response is malformed")
    organization_id = raw_org.get("id")
    organization_node_id = raw_org.get("node_id")
    if (
        not isinstance(organization_id, int)
        or isinstance(organization_id, bool)
        or organization_id < 1
        or not isinstance(organization_node_id, str)
        or not organization_node_id
        or str(raw_org.get("login", "")).lower() != organization.lower()
    ):
        raise CollectorError("GitHub organization lacks stable identity")

    current_endpoint = organization_ruleset_url(organization, ruleset_id)
    validate_organization_url(current_endpoint, organization, ruleset_id, "ruleset")
    raw_current, link, current_request_id = fetcher(current_endpoint, token, timeout)
    if link is not None:
        raise CollectorError("GitHub current organization ruleset unexpectedly paginated")
    current = ruleset_state(raw_current, ruleset_id, organization, "Organization")

    history_endpoint = organization_history_url(organization, ruleset_id)
    url: str | None = history_endpoint
    seen: set[str] = set()
    history: list[dict[str, Any]] = []
    history_request_ids: list[str] = []
    while url is not None:
        validate_organization_url(url, organization, ruleset_id, "history")
        if url in seen or len(seen) >= MAX_PAGES:
            raise CollectorError("GitHub organization ruleset history pagination loop or limit")
        seen.add(url)
        raw_page, next_url, request_id = fetcher(url, token, timeout)
        history_request_ids.append(request_id)
        if not isinstance(raw_page, list):
            raise CollectorError("GitHub organization ruleset history response must be an array")
        for entry in raw_page:
            if not isinstance(entry, dict):
                raise CollectorError("GitHub organization ruleset history entry is malformed")
            version_id = entry.get("version_id")
            actor = entry.get("actor")
            if (
                not isinstance(version_id, int)
                or isinstance(version_id, bool)
                or version_id < 1
                or not isinstance(actor, dict)
                or not isinstance(actor.get("id"), int)
                or isinstance(actor.get("id"), bool)
                or actor.get("type") != "User"
                or not isinstance(entry.get("updated_at"), str)
            ):
                raise CollectorError(
                    "GitHub organization ruleset history entry lacks version actor or time"
                )
            parse_time(entry["updated_at"], "organization ruleset history updated_at")
            history.append(
                {"version_id": version_id, "actor_id": actor["id"], "updated_at": entry["updated_at"]}
            )
        if next_url is not None:
            validate_organization_url(next_url, organization, ruleset_id, "history")
        url = next_url
    version_ids = [entry["version_id"] for entry in history]
    if (
        len(version_ids) != len(set(version_ids))
        or not history
        or max(version_ids) != after_version_id
        or before_version_id not in version_ids
        or after_version_id not in version_ids
    ):
        raise CollectorError(
            "GitHub organization ruleset history is incomplete or has a later version"
        )

    versions: list[dict[str, Any]] = []
    version_request_ids: list[str] = []
    for version_id in (before_version_id, after_version_id):
        endpoint = organization_version_url(organization, ruleset_id, version_id)
        validate_organization_url(endpoint, organization, ruleset_id, "version")
        raw_version, link, request_id = fetcher(endpoint, token, timeout)
        if link is not None or not isinstance(raw_version, dict):
            raise CollectorError("GitHub organization ruleset version response is malformed")
        history_entry = next(entry for entry in history if entry["version_id"] == version_id)
        actor = raw_version.get("actor")
        if (
            raw_version.get("version_id") != version_id
            or not isinstance(actor, dict)
            or actor.get("id") != history_entry["actor_id"]
            or actor.get("type") != "User"
            or raw_version.get("updated_at") != history_entry["updated_at"]
        ):
            raise CollectorError("GitHub organization ruleset version does not match history")
        state = ruleset_state(
            raw_version.get("state"), ruleset_id, organization, "Organization"
        )
        if state["updated_at"] != raw_version["updated_at"]:
            raise CollectorError("GitHub organization ruleset state timestamp is mismatched")
        versions.append(
            {
                "version_id": version_id,
                "actor_id": actor["id"],
                "updated_at": raw_version["updated_at"],
                "state": state,
            }
        )
        version_request_ids.append(request_id)
    if versions[1]["state"] != current:
        raise CollectorError(
            "GitHub current organization ruleset does not match the latest requested version"
        )
    if versions[0]["state"]["created_at"] != versions[1]["state"]["created_at"]:
        raise CollectorError(
            "GitHub organization ruleset generation changed across requested versions"
        )
    if versions[0]["state"]["target"] != versions[1]["state"]["target"]:
        raise CollectorError(
            "GitHub organization ruleset target changed across requested versions"
        )

    return {
        "schema": "psb-github-organization-ruleset-snapshot/v1",
        "organization": organization,
        "collected_at": timestamp(observed_at),
        "complete": True,
        "collection": {
            "api_version": API_VERSION,
            "organization_endpoint": org_endpoint,
            "ruleset_endpoint": current_endpoint,
            "history_endpoint": history_endpoint,
            "history_pages": len(seen),
            "history_complete": True,
            "organization_request_id": org_request_id,
            "ruleset_request_id": current_request_id,
            "history_request_ids": history_request_ids,
            "version_request_ids": version_request_ids,
        },
        "organization_identity": {
            "id": organization_id,
            "node_id": organization_node_id,
            "login": organization,
        },
        "ruleset": {
            "id": ruleset_id,
            "node_id": current["node_id"],
            "before_version_id": before_version_id,
            "after_version_id": after_version_id,
            "history": history,
            "versions": versions,
            "current": current,
        },
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
        raise CollectorError("cannot write GitHub ruleset snapshot") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization", required=True)
    parser.add_argument("--repository")
    parser.add_argument("--ruleset-id", type=int, required=True)
    parser.add_argument("--before-version-id", type=int, required=True)
    parser.add_argument("--after-version-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    try:
        common = (
            args.organization,
            args.ruleset_id,
            args.before_version_id,
            args.after_version_id,
            datetime.now(timezone.utc),
            os.environ.get(args.token_env, ""),
            args.timeout,
        )
        output = (
            collect(args.organization, args.repository, *common[1:])
            if args.repository is not None
            else collect_organization(*common)
        )
        write_output(args.output, output)
    except CollectorError as error:
        print(f"ERROR GitHub ruleset collection unavailable: {error}", file=sys.stderr)
        return 2
    print(
        f"COLLECTED GitHub ruleset {output['ruleset']['id']} "
        f"versions {output['ruleset']['before_version_id']}..{output['ruleset']['after_version_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
