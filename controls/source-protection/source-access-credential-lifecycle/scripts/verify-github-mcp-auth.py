#!/usr/bin/env python3
"""Verify GitHub MCP authentication and least-authority metadata without secrets."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-github-mcp-auth-policy/v1"
REMOTE_URL = "https://api.githubcopilot.com/mcp/"
SECRET_REFERENCE = "${input:github_token}"
MCP_COMMAND = "/opt/product-security/bin/github-mcp-server-reviewed"
TOOLSETS = ["context", "repos", "pull_requests"]
TOOLSETS_TEXT = ",".join(TOOLSETS)
PROHIBITED_PERSISTENCE = {
    "repository",
    "ide-json-literal",
    "shell-profile",
    "dotenv-file",
    "git-remote-url",
}
SENSITIVE_VALUE = re.compile(
    r"(?:Bearer\s+|github_pat_(?!REDACTED)|gh[pousr]_[A-Za-z0-9])",
    re.IGNORECASE,
)


class EvaluationError(Exception):
    """Evidence cannot be evaluated safely."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is missing") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return value


def nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def strings(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return []
    return value


def reject_sensitive(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            reject_sensitive(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_sensitive(item, f"{path}[{index}]")
    elif isinstance(value, str) and value != SECRET_REFERENCE and SENSITIVE_VALUE.search(value):
        raise EvaluationError(f"sensitive credential material is prohibited at {path}")


def exact_server(config: dict[str, Any]) -> dict[str, Any]:
    servers = config.get("servers")
    if not isinstance(servers, dict) or set(servers) != {"github"}:
        return {}
    server = servers.get("github")
    return server if isinstance(server, dict) else {}


def render(check_id: str, passed: bool, success: str, failure: str) -> None:
    status = "PASS" if passed else "FAIL"
    print(f"{status} PSB-SOURCE-004/{check_id} {success if passed else failure}")


def verify(policy_path: Path, oauth_path: Path, pat_path: Path) -> int:
    try:
        policy = load_json(policy_path, "GitHub MCP authentication policy")
        oauth_config = load_json(oauth_path, "GitHub MCP OAuth configuration")
        pat_config = load_json(pat_path, "GitHub MCP PAT fallback configuration")
        for value in (policy, oauth_config, pat_config):
            reject_sensitive(value)
    except EvaluationError as error:
        print(f"ERROR PSB-SOURCE-004/GITHUB-MCP-EVIDENCE {error}")
        return 2

    oauth_server = exact_server(oauth_config)
    pat_server = exact_server(pat_config)
    inputs = pat_config.get("inputs")
    pat_input = inputs[0] if isinstance(inputs, list) and len(inputs) == 1 else {}
    if not isinstance(pat_input, dict):
        pat_input = {}
    pat_env = pat_server.get("env")
    if not isinstance(pat_env, dict):
        pat_env = {}

    auth_ok = all(
        (
            policy.get("schema") == POLICY_SCHEMA,
            policy.get("authentication_order")
            == ["remote-oauth", "local-oauth-memory-only", "fine-grained-pat-fallback"],
            nested(policy, "oauth", "remote_url") == REMOTE_URL,
            nested(policy, "oauth", "organization_app_approval") == "required",
            nested(policy, "oauth", "sso") == "required",
            oauth_server == {"type": "http", "url": REMOTE_URL},
        )
    )

    pat_policy_ok = all(
        (
            nested(policy, "pat_fallback", "type") == "fine-grained",
            nested(policy, "pat_fallback", "purpose") == "github-mcp-only",
            nested(policy, "pat_fallback", "resource_owner_count") == 1,
            nested(policy, "pat_fallback", "repository_selection") == "explicit",
            nested(policy, "pat_fallback", "permissions") == "read-only-minimum",
            isinstance(nested(policy, "pat_fallback", "maximum_lifetime_days"), int)
            and not isinstance(nested(policy, "pat_fallback", "maximum_lifetime_days"), bool),
            1 <= nested(policy, "pat_fallback", "maximum_lifetime_days") <= 90,
            nested(policy, "pat_fallback", "organization_approval") == "required",
            nested(policy, "pat_fallback", "shared_with_git_or_automation") is False,
        )
    )

    secret_delivery_ok = all(
        (
            nested(policy, "secret_delivery", "at_rest")
            == "os-keychain-or-approved-secret-manager",
            nested(policy, "secret_delivery", "ide_secret_reference") == SECRET_REFERENCE,
            nested(policy, "secret_delivery", "target_environment")
            == "mcp-child-process-only",
            set(strings(nested(policy, "secret_delivery", "prohibited_persistence")))
            == PROHIBITED_PERSISTENCE,
            pat_input
            == {
                "type": "promptString",
                "id": "github_token",
                "description": "GitHub MCP dedicated fine-grained PAT",
                "password": True,
            },
            pat_env.get("GITHUB_PERSONAL_ACCESS_TOKEN") == SECRET_REFERENCE,
            SECRET_REFERENCE not in json.dumps(oauth_config, sort_keys=True),
        )
    )

    authority_ok = all(
        (
            nested(policy, "runtime_authority", "default_mode") == "read-only",
            strings(nested(policy, "runtime_authority", "toolsets")) == TOOLSETS,
            nested(policy, "runtime_authority", "all_toolset") is False,
            nested(policy, "runtime_authority", "write_profile")
            == "separate-human-approved",
            nested(policy, "runtime_authority", "unknown_tools") == "deny",
            pat_server.get("type") == "stdio",
            pat_server.get("command") == MCP_COMMAND,
            pat_server.get("args")
            == ["stdio", "--read-only", "--toolsets", TOOLSETS_TEXT],
            pat_env
            == {
                "GITHUB_PERSONAL_ACCESS_TOKEN": SECRET_REFERENCE,
                "GITHUB_READ_ONLY": "1",
                "GITHUB_TOOLSETS": TOOLSETS_TEXT,
            },
        )
    )

    lifecycle_ok = all(
        (
            nested(policy, "lifecycle_binding", "credential_control") == "PSB-SOURCE-004",
            nested(policy, "lifecycle_binding", "dependency_control") == "PSB-AI-002",
            nested(policy, "lifecycle_binding", "runtime_control") == "PSB-AI-004",
            nested(policy, "lifecycle_binding", "revocation_triggers")
            == "offboarding-role-change-device-loss-exposure-unused",
            nested(policy, "lifecycle_binding", "audit_events")
            == "creation-authorization-use-change-revocation",
            policy.get("live_adoption") == "NOT_CHECKED",
        )
    )

    results = [auth_ok, pat_policy_ok, secret_delivery_ok, authority_ok, lifecycle_ok]
    render(
        "SCL-013",
        auth_ok,
        "GitHub MCP defaults to exact remote OAuth without a configured PAT",
        "GitHub MCP does not default to exact organization-approved OAuth",
    )
    render(
        "SCL-014",
        pat_policy_ok,
        "PAT fallback is dedicated fine-grained repository-restricted and time-bound",
        "PAT fallback is broad shared classic unapproved or unbounded",
    )
    render(
        "SCL-015",
        secret_delivery_ok,
        "PAT stays in an approved secret store and is referenced only by the MCP child",
        "PAT is persisted or delivered beyond the exact MCP child process",
    )
    render(
        "SCL-016",
        authority_ok,
        "PAT fallback uses an exact managed command read-only mode and three toolsets",
        "MCP runtime command toolsets or write authority are not narrowly constrained",
    )
    render(
        "SCL-017",
        lifecycle_ok,
        "credential dependency runtime revocation and audit ownership stay explicit",
        "MCP authentication lacks exact lifecycle control ownership or overclaims adoption",
    )

    if all(results):
        print("ACCEPTED GitHub MCP authentication profile")
        return 0
    print(f"REJECTED GitHub MCP authentication profile: {sum(not item for item in results)} checks failed")
    return 1


def main() -> int:
    if len(sys.argv) != 4:
        print(
            f"usage: {Path(sys.argv[0]).name} POLICY.json OAUTH.json PAT-FALLBACK.json",
            file=sys.stderr,
        )
        return 2
    return verify(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))


if __name__ == "__main__":
    raise SystemExit(main())
