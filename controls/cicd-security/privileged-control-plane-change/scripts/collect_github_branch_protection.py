#!/usr/bin/env python3
"""Collect exact GitHub legacy branch-protection settings read-only."""

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


SCHEMA = "psb-github-branch-protection-snapshot/v4"
API_VERSION = "2026-03-10"
API_HOST = "api.github.com"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


class CollectorError(ValueError):
    """GitHub branch-protection state could not be collected safely."""


Fetcher = Callable[[str, str, int], tuple[Any, str]]


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def valid_branch(value: str) -> bool:
    return bool(
        BRANCH_RE.fullmatch(value)
        and "*" not in value
        and ".." not in value
        and "//" not in value
        and "@{" not in value
        and not value.endswith(("/", ".", ".lock"))
    )


def repository_url(owner: str, repository: str) -> str:
    return f"https://{API_HOST}/repos/{owner}/{repository}"


def protection_url(owner: str, repository: str, branch: str) -> str:
    encoded = urllib.parse.quote(branch, safe="")
    return repository_url(owner, repository) + f"/branches/{encoded}/protection"


def validate_url(
    value: str, owner: str, repository: str, branch: str, endpoint: str
) -> None:
    try:
        parsed = urllib.parse.urlparse(value)
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise CollectorError("GitHub branch-protection URL is malformed") from error
    paths = {
        "repository": f"/repos/{owner}/{repository}",
        "protection": (
            f"/repos/{owner}/{repository}/branches/"
            f"{urllib.parse.quote(branch, safe='')}/protection"
        ),
    }
    if not all(
        (
            parsed.scheme == "https",
            parsed.hostname == API_HOST,
            port in (None, 443),
            parsed.username is None,
            parsed.password is None,
            parsed.path == paths.get(endpoint),
            parsed.query == "",
            parsed.fragment == "",
            parsed.params == "",
        )
    ):
        raise CollectorError("GitHub branch-protection request escaped the approved endpoint")


def fetch(url: str, token: str, timeout: int) -> tuple[Any, str]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "product-security-controls-branch-protection-collector",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            request_id = response.headers.get("x-github-request-id", "")
    except urllib.error.HTTPError as error:
        raise CollectorError(
            "GitHub branch-protection API denied or failed collection"
        ) from error
    except (OSError, urllib.error.URLError) as error:
        raise CollectorError("GitHub branch-protection API request failed") from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise CollectorError("GitHub branch-protection API response exceeds the size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectorError("GitHub branch-protection API response is malformed") from error
    if not request_id:
        raise CollectorError("GitHub branch-protection API response lacks a request identity")
    return value, request_id


def collect(
    organization: str,
    repository: str,
    branch: str,
    collected_at: datetime,
    token: str,
    timeout: int,
    fetcher: Fetcher = fetch,
) -> dict[str, Any]:
    if NAME_RE.fullmatch(organization) is None or NAME_RE.fullmatch(repository) is None:
        raise CollectorError("GitHub organization or repository is malformed")
    if not valid_branch(branch):
        raise CollectorError("GitHub branch name is malformed or unsupported")
    if not token or any(character.isspace() for character in token):
        raise CollectorError("GitHub branch-protection token is unavailable or malformed")
    if not 1 <= timeout <= 120:
        raise CollectorError("collector timeout is outside 1..120 seconds")
    if collected_at.tzinfo is None:
        raise CollectorError("collection time must be timezone-aware")

    repo_endpoint = repository_url(organization, repository)
    protection_endpoint = protection_url(organization, repository, branch)
    validate_url(repo_endpoint, organization, repository, branch, "repository")
    validate_url(protection_endpoint, organization, repository, branch, "protection")
    raw_repository, repository_request_id = fetcher(repo_endpoint, token, timeout)
    raw_protection, protection_request_id = fetcher(protection_endpoint, token, timeout)

    if not isinstance(raw_repository, dict) or not isinstance(raw_protection, dict):
        raise CollectorError("GitHub branch-protection response must be an object")
    repository_id = raw_repository.get("id")
    repository_node_id = raw_repository.get("node_id")
    full_name = raw_repository.get("full_name")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
        or not isinstance(repository_node_id, str)
        or not repository_node_id
        or not isinstance(full_name, str)
        or full_name.lower() != f"{organization}/{repository}".lower()
    ):
        raise CollectorError("GitHub repository stable identity is mismatched")
    force_pushes = raw_protection.get("allow_force_pushes")
    deletions = raw_protection.get("allow_deletions")
    enforce_admins = raw_protection.get("enforce_admins")
    pull_request_reviews = raw_protection.get("required_pull_request_reviews")
    if not isinstance(force_pushes, dict) or not isinstance(
        force_pushes.get("enabled"), bool
    ):
        raise CollectorError(
            "GitHub branch protection lacks an exact force-push setting"
        )
    if not isinstance(deletions, dict) or not isinstance(
        deletions.get("enabled"), bool
    ):
        raise CollectorError(
            "GitHub branch protection lacks an exact deletion setting"
        )
    if not isinstance(enforce_admins, dict) or not isinstance(
        enforce_admins.get("enabled"), bool
    ):
        raise CollectorError(
            "GitHub branch protection lacks an exact admin-enforcement setting"
        )
    if not isinstance(pull_request_reviews, dict) or not isinstance(
        pull_request_reviews.get("require_code_owner_reviews"), bool
    ):
        raise CollectorError(
            "GitHub branch protection lacks an exact code-owner-review setting"
        )

    return {
        "schema": SCHEMA,
        "organization": organization,
        "collected_at": timestamp(collected_at),
        "complete": True,
        "collection": {
            "api_version": API_VERSION,
            "repository_endpoint": repo_endpoint,
            "protection_endpoint": protection_endpoint,
            "repository_request_id": repository_request_id,
            "protection_request_id": protection_request_id,
        },
        "repository": {
            "id": repository_id,
            "node_id": repository_node_id,
            "full_name": full_name,
        },
        "branch": {"name": branch},
        "protection": {
            "allow_force_pushes": force_pushes["enabled"],
            "allow_deletions": deletions["enabled"],
            "enforce_admins": enforce_admins["enabled"],
            "require_code_owner_reviews": pull_request_reviews[
                "require_code_owner_reviews"
            ],
        },
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
        raise CollectorError("cannot write GitHub branch-protection snapshot") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        output = collect(
            args.organization,
            args.repository,
            args.branch,
            datetime.now(timezone.utc),
            token,
            args.timeout,
        )
        write_output(args.output, output)
    except CollectorError as error:
        print(f"ERROR GitHub branch-protection collection unavailable: {error}", file=sys.stderr)
        return 2
    print("COLLECTED GitHub legacy branch-protection current state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
