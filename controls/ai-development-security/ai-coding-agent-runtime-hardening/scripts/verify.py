#!/usr/bin/env python3
"""Verify PSB-AI-004 policy adapters without invoking an AI coding agent."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


POLICY_SCHEMA = "psb-ai-runtime-policy/v1"
PROFILE_SCHEMA = "psb-ai-runtime-profile/v1"
PROVIDERS = ("claude-code", "codex")


class EvaluationError(Exception):
    """A configuration could not be evaluated safely."""


@dataclass(frozen=True)
class CheckResult:
    provider: str
    check_id: str
    passed: bool
    pass_reason: str
    fail_reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        reason = self.pass_reason if self.passed else self.fail_reason
        return (
            f"{status} PSB-AI-004/{self.check_id} "
            f"provider={self.provider} {reason}"
        )


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


def load_toml(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is missing") from error
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be a TOML table")
    return value


def referenced_file(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise EvaluationError(f"{label} path is missing")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise EvaluationError(f"{label} path leaves the profile directory") from error
    if not candidate.is_file():
        raise EvaluationError(f"{label} is missing")
    return candidate


def nested(mapping: dict[str, Any], *keys: str) -> Any:
    value: Any = mapping
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return []
    return value


def only_strings(value: Any, allowed: set[str]) -> bool:
    values = string_list(value)
    return bool(values) and set(values).issubset(allowed)


def claude_repository_broadens(repository: dict[str, Any]) -> bool:
    permissions = nested(repository, "permissions")
    sandbox = nested(repository, "sandbox")
    filesystem = nested(repository, "sandbox", "filesystem")
    network = nested(repository, "sandbox", "network")
    return any(
        (
            bool(nested(repository, "permissions", "allow")),
            nested(repository, "permissions", "defaultMode") == "bypassPermissions",
            nested(repository, "sandbox", "enabled") is False,
            nested(repository, "sandbox", "allowUnsandboxedCommands") is True,
            nested(repository, "sandbox", "filesystem", "disabled") is True,
            bool(nested(repository, "sandbox", "filesystem", "allowWrite")),
            bool(nested(repository, "sandbox", "filesystem", "allowRead")),
            bool(nested(repository, "sandbox", "network", "allowedDomains")),
            nested(repository, "sandbox", "network", "allowAllUnixSockets") is True,
            nested(repository, "sandbox", "network", "allowLocalBinding") is True,
            not isinstance(permissions, (dict, type(None))),
            not isinstance(sandbox, (dict, type(None))),
            not isinstance(filesystem, (dict, type(None))),
            not isinstance(network, (dict, type(None))),
        )
    )


def evaluate_claude(
    policy: dict[str, Any],
    profile_root: Path,
    adapter: dict[str, Any],
) -> list[CheckResult]:
    managed = load_json(
        referenced_file(profile_root, adapter.get("managed_settings"), "Claude managed settings"),
        "Claude managed settings",
    )
    repository = load_json(
        referenced_file(
            profile_root,
            adapter.get("repository_settings"),
            "Claude repository settings",
        ),
        "Claude repository settings",
    )
    required = policy["required_outcomes"]
    credential = f"./{required['synthetic_credential_path']}"
    protected = {f"./{path}" for path in required["protected_write_paths"]}
    deny_write = set(string_list(nested(managed, "sandbox", "filesystem", "denyWrite")))
    deny_read = set(string_list(nested(managed, "sandbox", "filesystem", "denyRead")))
    permission_deny = set(string_list(nested(managed, "permissions", "deny")))
    permission_ask = set(string_list(nested(managed, "permissions", "ask")))
    permission_allow = set(string_list(nested(managed, "permissions", "allow")))
    managed_domains = string_list(
        nested(managed, "sandbox", "network", "allowedDomains")
    )
    repository_broadens = claude_repository_broadens(repository)

    sandbox_ok = all(
        (
            nested(managed, "sandbox", "enabled") is True,
            nested(managed, "sandbox", "failIfUnavailable") is True,
            nested(managed, "sandbox", "filesystem", "disabled") is False,
            nested(managed, "sandbox", "excludedCommands") == [],
        )
    )
    writes_ok = all(
        (
            nested(managed, "sandbox", "filesystem", "allowWrite") == [],
            protected.issubset(deny_write),
            not bool(nested(repository, "sandbox", "filesystem", "allowWrite")),
        )
    )
    credential_ok = all(
        (
            credential in deny_read,
            f"Read({credential}/**)" in permission_deny,
            not bool(nested(repository, "sandbox", "filesystem", "allowRead")),
            f"Read({credential}/**)"
            not in set(string_list(nested(repository, "permissions", "allow"))),
        )
    )
    network_ok = all(
        (
            managed_domains == [],
            nested(managed, "sandbox", "network", "strictAllowlist") is True,
            nested(managed, "sandbox", "network", "allowManagedDomainsOnly") is True,
            nested(managed, "sandbox", "network", "allowAllUnixSockets") is False,
            nested(managed, "sandbox", "network", "allowLocalBinding") is False,
            not bool(nested(repository, "sandbox", "network", "allowedDomains")),
        )
    )
    publication_ok = all(
        (
            "Bash(git push *)" in permission_ask,
            "Bash(git push *)" not in permission_allow,
            "Bash(git push *)"
            not in set(string_list(nested(repository, "permissions", "allow"))),
            "git *"
            not in set(string_list(nested(managed, "sandbox", "excludedCommands"))),
        )
    )
    bypass_ok = all(
        (
            nested(managed, "permissions", "disableBypassPermissionsMode")
            == "disable",
            nested(managed, "permissions", "defaultMode") != "bypassPermissions",
            nested(managed, "sandbox", "allowUnsandboxedCommands") is False,
            nested(repository, "permissions", "defaultMode")
            != "bypassPermissions",
            nested(repository, "sandbox", "allowUnsandboxedCommands") is not True,
        )
    )
    precedence_ok = all(
        (
            managed.get("allowManagedPermissionRulesOnly") is True,
            nested(managed, "sandbox", "network", "allowManagedDomainsOnly") is True,
            not repository_broadens,
        )
    )

    return [
        CheckResult(
            "claude-code",
            "AAR-001",
            sandbox_ok,
            "sandbox is enforced and fails closed",
            "sandbox is disabled, bypassable, or can fall back unsandboxed",
        ),
        CheckResult(
            "claude-code",
            "AAR-002",
            writes_ok,
            "writes stay in the workspace and policy paths are protected",
            "write scope is broad or policy paths are not protected",
        ),
        CheckResult(
            "claude-code",
            "AAR-003",
            credential_ok,
            "synthetic credential path is denied",
            "synthetic credential path can be read or re-allowed",
        ),
        CheckResult(
            "claude-code",
            "AAR-004",
            network_ok,
            "network is default-deny with local and socket escapes disabled",
            "network, local binding, or socket access is broader than policy",
        ),
        CheckResult(
            "claude-code",
            "AAR-005",
            publication_ok,
            "git push requires explicit human approval",
            "git push can run without an explicit approval rule",
        ),
        CheckResult(
            "claude-code",
            "AAR-006",
            bypass_ok,
            "dangerous permission and sandbox bypass modes are prohibited",
            "a dangerous permission or sandbox bypass mode remains available",
        ),
        CheckResult(
            "claude-code",
            "AAR-007",
            precedence_ok,
            "managed policy rejects repository broadening",
            "repository settings can attempt or obtain broader authority",
        ),
    ]


def codex_rules_require_push_prompt(requirements: dict[str, Any]) -> bool:
    rules = nested(requirements, "rules", "prefix_rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("pattern") == ["git", "push"] and rule.get("decision") == "prompt":
            return True
    return False


def evaluate_codex(
    policy: dict[str, Any],
    profile_root: Path,
    adapter: dict[str, Any],
) -> list[CheckResult]:
    requirements = load_toml(
        referenced_file(
            profile_root,
            adapter.get("managed_requirements"),
            "Codex managed requirements",
        ),
        "Codex managed requirements",
    )
    repository = load_toml(
        referenced_file(
            profile_root,
            adapter.get("repository_config"),
            "Codex repository config",
        ),
        "Codex repository config",
    )
    required = policy["required_outcomes"]
    credential = required["synthetic_credential_path"]
    protected = set(required["protected_write_paths"])
    managed_profile_name = requirements.get("default_permissions")
    managed_profiles = requirements.get("allowed_permission_profiles")
    profile = nested(requirements, "permissions", str(managed_profile_name))
    filesystem = nested(profile or {}, "filesystem", ":workspace_roots")
    network = nested(profile or {}, "network")
    allowed_approvals = string_list(requirements.get("allowed_approval_policies"))

    profile_allowlisted = (
        isinstance(managed_profiles, dict)
        and managed_profiles.get(managed_profile_name) is True
        and managed_profiles.get(":danger-full-access") is not True
    )
    sandbox_ok = all(
        (
            isinstance(profile, dict),
            nested(profile or {}, "extends") == ":workspace",
            profile_allowlisted,
            repository.get("default_permissions") == managed_profile_name,
        )
    )
    writes_ok = all(
        (
            isinstance(filesystem, dict),
            (filesystem or {}).get(".") == "write",
            all((filesystem or {}).get(path) == "read" for path in protected),
            all(
                value != "write"
                for path, value in (filesystem or {}).items()
                if path != "."
            ),
        )
    )
    credential_ok = (
        isinstance(filesystem, dict)
        and filesystem.get(credential) == "deny"
    )
    network_ok = all(
        (
            isinstance(network, dict),
            (network or {}).get("enabled") is False,
            (network or {}).get("allow_local_binding") is False,
            (network or {}).get("dangerously_allow_all_unix_sockets") is False,
            not bool((network or {}).get("domains")),
        )
    )
    publication_ok = all(
        (
            codex_rules_require_push_prompt(requirements),
            repository.get("approval_policy") in {"untrusted", "on-request"},
            "never" not in allowed_approvals,
        )
    )
    bypass_ok = all(
        (
            only_strings(
                requirements.get("allowed_approval_policies"),
                {"untrusted", "on-request"},
            ),
            profile_allowlisted,
            repository.get("approval_policy") != "never",
            repository.get("default_permissions") != ":danger-full-access",
            repository.get("allow_login_shell") is False,
        )
    )
    precedence_ok = all(
        (
            profile_allowlisted,
            repository.get("default_permissions") == managed_profile_name,
            repository.get("approval_policy") in allowed_approvals,
            "permissions" not in repository,
            "allowed_permission_profiles" not in repository,
        )
    )

    return [
        CheckResult(
            "codex",
            "AAR-001",
            sandbox_ok,
            "managed permission profile is enforced",
            "managed isolation profile is missing, disallowed, or bypassed",
        ),
        CheckResult(
            "codex",
            "AAR-002",
            writes_ok,
            "writes stay in the workspace and policy paths are read-only",
            "write scope is broad or policy paths are writable",
        ),
        CheckResult(
            "codex",
            "AAR-003",
            credential_ok,
            "synthetic credential path is denied",
            "synthetic credential path is not denied",
        ),
        CheckResult(
            "codex",
            "AAR-004",
            network_ok,
            "network is disabled with local and socket escapes disabled",
            "network, local binding, or socket access is broader than policy",
        ),
        CheckResult(
            "codex",
            "AAR-005",
            publication_ok,
            "git push requires explicit human approval",
            "git push can run without an explicit approval rule",
        ),
        CheckResult(
            "codex",
            "AAR-006",
            bypass_ok,
            "dangerous full-access and never-approve modes are prohibited",
            "dangerous full-access or never-approve mode remains available",
        ),
        CheckResult(
            "codex",
            "AAR-007",
            precedence_ok,
            "managed requirements reject repository broadening",
            "repository configuration conflicts with managed requirements",
        ),
    ]


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema_version") != POLICY_SCHEMA:
        raise EvaluationError("policy schema is unsupported")
    supported = policy.get("supported_adapters")
    required = policy.get("required_outcomes")
    if not isinstance(supported, dict) or not isinstance(required, dict):
        raise EvaluationError("policy is incomplete")
    expected_outcomes = {
        "sandbox",
        "write_scope",
        "protected_write_paths",
        "synthetic_credential_path",
        "network",
        "source_publication",
        "dangerous_bypass",
        "configuration_precedence",
    }
    if not expected_outcomes.issubset(required):
        raise EvaluationError("policy required outcomes are incomplete")


def validate_adapter_identity(
    policy: dict[str, Any],
    provider: str,
    adapter: dict[str, Any],
) -> None:
    expected = policy["supported_adapters"].get(provider)
    if not isinstance(expected, dict):
        raise EvaluationError(f"{provider} is not supported by the policy")
    for key in ("configuration_baseline", "minimum_product_version"):
        if adapter.get(key) != expected.get(key):
            raise EvaluationError(f"{provider} {key} is unsupported")


def evaluate(policy_path: Path, profile_root: Path) -> tuple[str, list[CheckResult]]:
    policy = load_json(policy_path, "runtime policy")
    validate_policy(policy)
    profile = load_json(profile_root / "profile.json", "runtime profile")
    if profile.get("profile_schema") != PROFILE_SCHEMA:
        raise EvaluationError("profile schema is unsupported")
    if profile.get("policy_schema") != POLICY_SCHEMA:
        raise EvaluationError("profile policy schema is unsupported")
    name = profile.get("name")
    if not isinstance(name, str) or not name:
        raise EvaluationError("profile name is missing")
    providers = profile.get("providers")
    if not isinstance(providers, dict):
        raise EvaluationError("profile providers are missing")
    if set(providers) != set(PROVIDERS):
        unknown_or_missing = sorted(set(providers).symmetric_difference(PROVIDERS))
        raise EvaluationError(
            "profile provider set is unsupported: " + ",".join(unknown_or_missing)
        )

    evaluators: dict[
        str,
        Callable[[dict[str, Any], Path, dict[str, Any]], list[CheckResult]],
    ] = {
        "claude-code": evaluate_claude,
        "codex": evaluate_codex,
    }
    results: list[CheckResult] = []
    for provider in PROVIDERS:
        adapter = providers.get(provider)
        if not isinstance(adapter, dict):
            raise EvaluationError(f"{provider} adapter is malformed")
        validate_adapter_identity(policy, provider, adapter)
        results.extend(evaluators[provider](policy, profile_root, adapter))
    return name, results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Claude Code and Codex adapters against PSB-AI-004."
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()

    try:
        name, results = evaluate(args.policy.resolve(), args.profile.resolve())
    except EvaluationError as error:
        print(f"ERROR PSB-AI-004 evaluation failed: {error}")
        return 2
    except Exception:
        print("ERROR PSB-AI-004 evaluation failed: unexpected evaluator failure")
        return 2

    failures = sum(not result.passed for result in results)
    for result in results:
        print(result.render())
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} profile={name} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
