#!/usr/bin/env python3
"""Verify extension adapters and low-frequency HITL decisions offline."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "psb-ai-extension-capabilities/v1"
PROFILE_SCHEMA = "psb-ai-runtime-profile/v1"
INVOCATION_SCHEMA = "psb-ai-extension-invocation/v1"
ENGINE_SCHEMA = "psb-ai-capability-engine-state/v1"
HOOK_MATCHER = "^mcp__.*$"
HOOK_SCRIPT = "/opt/psb-ai-004/hooks/pretool-gate.py"
HOOK_POLICY = "/opt/psb-ai-004/policy/runtime-policy.json"
HOOK_ENGINE = "/var/lib/psb-ai-004/capability-engine-state.json"
HOOK_ACTOR = "/var/lib/psb-ai-004/actor-state.json"
HOOK_APPROVAL_DIR = "/var/lib/psb-ai-004/approvals"
HOOK_APPROVAL_TRUST = "/opt/psb-ai-004/trust/approval-trust.json"
HOOK_APPROVAL_LEDGER = "/var/lib/psb-ai-004/approval-consumption.sqlite3"
HOOK_OPENSSL = "/usr/bin/openssl"
HOOK_AUDIT_POLICY = "/opt/psb-ai-004/policy/runtime-assessment-policy.json"
HOOK_AUDIT_LOG = "/var/log/psb-ai-004/pretool-audit.jsonl"


class EvaluationError(Exception):
    """Capability evidence could not be evaluated safely."""


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    pass_reason: str
    fail_reason: str
    provider: str | None = None

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        provider = f" provider={self.provider}" if self.provider else ""
        reason = self.pass_reason if self.passed else self.fail_reason
        return f"{status} PSB-AI-004/{self.check_id}{provider} {reason}"


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
    return value


def nested(mapping: dict[str, Any], *keys: str) -> Any:
    value: Any = mapping
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
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


def extension_policy(runtime_policy: dict[str, Any]) -> dict[str, Any]:
    policy = runtime_policy.get("extension_capabilities")
    if not isinstance(policy, dict):
        raise EvaluationError("runtime policy has no extension capability policy")
    if policy.get("schema_version") != POLICY_SCHEMA:
        raise EvaluationError("extension capability policy schema is unsupported")
    if policy.get("default_decision") != "deny":
        raise EvaluationError("extension capability default decision is not deny")
    extensions = policy.get("extensions")
    if not isinstance(extensions, dict) or not extensions:
        raise EvaluationError("extension capability inventory is missing")
    return policy


def expected_mcp(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for extension_id, extension in policy["extensions"].items():
        if not isinstance(extension, dict):
            raise EvaluationError("extension capability entry is malformed")
        if extension.get("kind") != "mcp":
            continue
        identity = extension.get("identity")
        tools = extension.get("tools")
        if (
            not isinstance(extension_id, str)
            or not isinstance(identity, dict)
            or identity.get("transport") != "streamable-http"
            or not isinstance(identity.get("url"), str)
            or not isinstance(tools, dict)
            or not tools
        ):
            raise EvaluationError("MCP extension capability entry is malformed")
        result[extension_id] = extension
    if not result:
        raise EvaluationError("MCP extension inventory is empty")
    return result


def tool_sets(extension: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    automatic: set[str] = set()
    approval: set[str] = set()
    denied: set[str] = set()
    tools = extension["tools"]
    for tool_name, tool in tools.items():
        if not isinstance(tool_name, str) or not isinstance(tool, dict):
            raise EvaluationError("extension tool policy is malformed")
        decision = tool.get("decision")
        hitl = tool.get("hitl")
        if decision == "allow" and hitl == "none":
            automatic.add(tool_name)
        elif decision == "require-bound-approval" and hitl == "one-bound-approval":
            approval.add(tool_name)
        elif decision == "deny" and hitl == "none":
            denied.add(tool_name)
        else:
            raise EvaluationError("extension tool decision is malformed")
    return automatic, approval, denied


def claude_managed_hook_matches(managed: dict[str, Any]) -> bool:
    groups = nested(managed, "hooks", "PreToolUse")
    if not isinstance(groups, list) or len(groups) != 1:
        return False
    group = groups[0]
    handlers = group.get("hooks") if isinstance(group, dict) else None
    if (
        not isinstance(group, dict)
        or group.get("matcher") != HOOK_MATCHER
        or not isinstance(handlers, list)
        or len(handlers) != 1
    ):
        return False
    handler = handlers[0]
    expected_args = [
        HOOK_SCRIPT,
        "--provider",
        "claude-code",
        "--policy",
        HOOK_POLICY,
        "--engine-state",
        HOOK_ENGINE,
        "--actor-state",
        HOOK_ACTOR,
        "--approval-dir",
        HOOK_APPROVAL_DIR,
        "--approval-trust",
        HOOK_APPROVAL_TRUST,
        "--approval-ledger",
        HOOK_APPROVAL_LEDGER,
        "--openssl",
        HOOK_OPENSSL,
        "--audit-policy",
        HOOK_AUDIT_POLICY,
        "--audit-log",
        HOOK_AUDIT_LOG,
    ]
    return bool(
        managed.get("allowManagedHooksOnly") is True
        and isinstance(handler, dict)
        and handler.get("type") == "command"
        and handler.get("command") == "/usr/bin/python3"
        and handler.get("args") == expected_args
        and isinstance(handler.get("timeout"), int)
        and 0 < handler["timeout"] <= 5
        and handler.get("async", False) is False
        and managed.get("disableAllHooks") is not True
    )


def codex_managed_hook_matches(requirements: dict[str, Any]) -> bool:
    groups = nested(requirements, "hooks", "PreToolUse")
    if not isinstance(groups, list) or len(groups) != 1:
        return False
    group = groups[0]
    handlers = group.get("hooks") if isinstance(group, dict) else None
    if (
        not isinstance(group, dict)
        or group.get("matcher") != HOOK_MATCHER
        or not isinstance(handlers, list)
        or len(handlers) != 1
    ):
        return False
    handler = handlers[0]
    expected_command = (
        f"/usr/bin/python3 {HOOK_SCRIPT} --provider codex "
        f"--policy {HOOK_POLICY} --engine-state {HOOK_ENGINE} "
        f"--actor-state {HOOK_ACTOR} --approval-dir {HOOK_APPROVAL_DIR} "
        f"--approval-trust {HOOK_APPROVAL_TRUST} "
        f"--approval-ledger {HOOK_APPROVAL_LEDGER} --openssl {HOOK_OPENSSL} "
        f"--audit-policy {HOOK_AUDIT_POLICY} --audit-log {HOOK_AUDIT_LOG}"
    )
    return bool(
        requirements.get("allow_managed_hooks_only") is True
        and nested(requirements, "features", "hooks") is True
        and nested(requirements, "hooks", "managed_dir")
        == "/opt/psb-ai-004/hooks"
        and isinstance(handler, dict)
        and handler.get("type") == "command"
        and handler.get("command") == expected_command
        and isinstance(handler.get("timeout"), int)
        and 0 < handler["timeout"] <= 5
        and handler.get("async", False) is False
    )


def evaluate_claude_adapters(
    policy: dict[str, Any],
    root: Path,
    adapter: dict[str, Any],
) -> list[CheckResult]:
    managed = load_json(
        referenced_file(root, adapter.get("managed_settings"), "Claude managed settings"),
        "Claude managed settings",
    )
    repository = load_json(
        referenced_file(
            root, adapter.get("repository_settings"), "Claude repository settings"
        ),
        "Claude repository settings",
    )
    mcp_config = load_json(
        referenced_file(root, adapter.get("mcp_config"), "Claude MCP config"),
        "Claude MCP config",
    )
    expected = expected_mcp(policy)
    expected_urls = {
        extension["identity"]["url"] for extension in expected.values()
    }
    allowed_entries = managed.get("allowedMcpServers")
    actual_urls = (
        {
            item.get("serverUrl")
            for item in allowed_entries
            if isinstance(item, dict) and isinstance(item.get("serverUrl"), str)
        }
        if isinstance(allowed_entries, list)
        else set()
    )
    configured = mcp_config.get("mcpServers")
    configured_urls = (
        {
            name: entry.get("url")
            for name, entry in configured.items()
            if isinstance(name, str) and isinstance(entry, dict)
        }
        if isinstance(configured, dict)
        else {}
    )
    identity_ok = all(
        (
            managed.get("allowManagedMcpServersOnly") is True,
            actual_urls == expected_urls,
            set(configured_urls) == set(expected),
            all(
                configured_urls.get(name) == extension["identity"]["url"]
                for name, extension in expected.items()
            ),
            managed.get("strictKnownMarketplaces") == [],
            not bool(repository.get("enabledPlugins")),
            not bool(repository.get("extraKnownMarketplaces")),
        )
    )

    permission_allow = set(nested(managed, "permissions", "allow") or [])
    permission_ask = set(nested(managed, "permissions", "ask") or [])
    permission_deny = set(nested(managed, "permissions", "deny") or [])
    automatic: set[str] = set()
    fallback_prompt: set[str] = set()
    signed_approval_fallback: set[str] = set()
    denied: set[str] = set()
    for extension_id, extension in expected.items():
        auto_tools, approval_tools, denied_tools = tool_sets(extension)
        for tool in auto_tools:
            canonical_name = f"mcp__{extension_id}__{tool}"
            if extension["tools"][tool].get("effect") == "read-only":
                automatic.add(canonical_name)
            else:
                fallback_prompt.add(canonical_name)
        signed_approval_fallback.update(
            f"mcp__{extension_id}__{tool}" for tool in approval_tools
        )
        denied.update(f"mcp__{extension_id}__{tool}" for tool in denied_tools)
    hitl_ok = all(
        (
            automatic.issubset(permission_allow),
            denied.issubset(permission_deny),
            automatic.isdisjoint(permission_ask),
            fallback_prompt.isdisjoint(permission_allow),
            fallback_prompt.isdisjoint(permission_ask),
            fallback_prompt.isdisjoint(permission_deny),
            signed_approval_fallback.isdisjoint(permission_allow),
            signed_approval_fallback.isdisjoint(permission_ask),
            signed_approval_fallback.isdisjoint(permission_deny),
            denied.isdisjoint(permission_ask),
        )
    )
    return [
        CheckResult(
            "AAR-012",
            identity_ok,
            "managed MCP identities and repository extension sources are exact",
            "MCP identity allowlist or repository extension source is broad",
            "claude-code",
        ),
        CheckResult(
            "AAR-014",
            hitl_ok,
            "routine tools avoid HITL and signed high-impact approval is not prompted twice",
            "tool approval rules are excessive missing or allow a prohibited tool",
            "claude-code",
        ),
        CheckResult(
            "AAR-015",
            claude_managed_hook_matches(managed),
            "managed-only PreToolUse gate covers every MCP tool",
            "managed PreToolUse gate is absent broad or replaceable",
            "claude-code",
        ),
    ]


def evaluate_codex_adapters(
    policy: dict[str, Any],
    root: Path,
    adapter: dict[str, Any],
) -> list[CheckResult]:
    requirements = load_toml(
        referenced_file(
            root, adapter.get("managed_requirements"), "Codex managed requirements"
        ),
        "Codex managed requirements",
    )
    config = load_toml(
        referenced_file(root, adapter.get("repository_config"), "Codex config"),
        "Codex config",
    )
    expected = expected_mcp(policy)
    required_servers = requirements.get("mcp_servers")
    configured_servers = config.get("mcp_servers")
    identity_ok = isinstance(required_servers, dict) and isinstance(
        configured_servers, dict
    )
    if identity_ok:
        identity_ok = set(required_servers) == set(expected) and set(
            configured_servers
        ) == set(expected)
    if identity_ok:
        for extension_id, extension in expected.items():
            expected_url = extension["identity"]["url"]
            if nested(required_servers, extension_id, "identity", "url") != expected_url:
                identity_ok = False
            if nested(configured_servers, extension_id, "url") != expected_url:
                identity_ok = False
    features = requirements.get("features")
    disabled_families_ok = isinstance(features, dict) and all(
        features.get(key) is False
        for key in (
            "browser_use",
            "browser_use_external",
            "browser_use_full_cdp_access",
            "computer_use",
            "plugins",
            "remote_plugin",
            "plugin_sharing",
        )
    )
    identity_ok = bool(identity_ok and disabled_families_ok)

    hitl_ok = True
    if not isinstance(configured_servers, dict):
        hitl_ok = False
    else:
        for extension_id, extension in expected.items():
            automatic, approval, denied = tool_sets(extension)
            server = configured_servers.get(extension_id)
            if not isinstance(server, dict):
                hitl_ok = False
                continue
            enabled = set(server.get("enabled_tools") or [])
            disabled = set(server.get("disabled_tools") or [])
            allowed_tools = automatic | approval
            if enabled != allowed_tools or not denied.issubset(disabled):
                hitl_ok = False
            if extension_id == "docs_reader":
                if server.get("default_tools_approval_mode") != "auto":
                    hitl_ok = False
            else:
                if server.get("default_tools_approval_mode") != "writes":
                    hitl_ok = False
                for tool in automatic:
                    tool_policy = extension["tools"][tool]
                    if (
                        tool_policy.get("effect") == "bounded-reversible-write"
                        and nested(server, "tools", tool, "approval_mode")
                        != "prompt"
                    ):
                        hitl_ok = False
                for tool in approval:
                    if nested(server, "tools", tool, "approval_mode") != "prompt":
                        hitl_ok = False
    return [
        CheckResult(
            "AAR-012",
            identity_ok,
            "managed MCP identities and disabled capability families are exact",
            "MCP identity or plugin browser and computer-use boundary is broad",
            "codex",
        ),
        CheckResult(
            "AAR-014",
            hitl_ok,
            "reads avoid HITL and native high-impact writes remain prompt-protected",
            "tool set or approval mode is excessive missing or broad",
            "codex",
        ),
        CheckResult(
            "AAR-015",
            codex_managed_hook_matches(requirements),
            "managed-only PreToolUse gate covers every MCP tool",
            "managed PreToolUse gate is absent broad or replaceable",
            "codex",
        ),
    ]


def evaluate_adapters(
    policy_path: Path, profile_root: Path
) -> tuple[str, list[CheckResult]]:
    runtime_policy = load_json(policy_path, "runtime policy")
    policy = extension_policy(runtime_policy)
    profile = load_json(profile_root / "profile.json", "runtime profile")
    if profile.get("profile_schema") != PROFILE_SCHEMA:
        raise EvaluationError("profile schema is unsupported")
    name = profile.get("name")
    providers = profile.get("providers")
    if not isinstance(name, str) or not isinstance(providers, dict):
        raise EvaluationError("runtime profile is incomplete")
    claude = providers.get("claude-code")
    codex = providers.get("codex")
    if not isinstance(claude, dict) or not isinstance(codex, dict):
        raise EvaluationError("runtime profile providers are incomplete")
    results = evaluate_claude_adapters(policy, profile_root, claude)
    results.extend(evaluate_codex_adapters(policy, profile_root, codex))
    return name, results


def evaluate_constraints(tool: dict[str, Any], invocation: dict[str, Any]) -> bool:
    if tool.get("effect") != "bounded-reversible-write":
        return True
    constraints = tool.get("constraints")
    if not isinstance(constraints, dict):
        raise EvaluationError("bounded-write constraints are missing")
    body_bytes = invocation.get("body_bytes")
    idempotency_key = invocation.get("idempotency_key")
    return all(
        (
            invocation.get("resource") == constraints.get("allowed_resource"),
            isinstance(body_bytes, int),
            0 <= body_bytes <= constraints.get("maximum_body_bytes", -1),
            isinstance(idempotency_key, str) and bool(idempotency_key),
            constraints.get("require_idempotency_key") is True,
        )
    )


def evaluate_invocation(
    policy_path: Path, invocation_path: Path, engine_path: Path
) -> tuple[str, str, str, int, list[CheckResult]]:
    runtime_policy = load_json(policy_path, "runtime policy")
    policy = extension_policy(runtime_policy)
    invocation = load_json(invocation_path, "extension invocation")
    engine = load_json(engine_path, "capability engine state")
    if invocation.get("schema_version") != INVOCATION_SCHEMA:
        raise EvaluationError("extension invocation schema is unsupported")
    if engine.get("schema_version") != ENGINE_SCHEMA:
        raise EvaluationError("capability engine state schema is unsupported")
    if engine.get("available") is not True:
        raise EvaluationError("capability policy engine is unavailable")

    invocation_id = invocation.get("invocation_id")
    extension_id = invocation.get("extension_id")
    tool_name = invocation.get("tool")
    declared_effect = invocation.get("declared_effect")
    confirmations = invocation.get("human_confirmations")
    if (
        not isinstance(invocation_id, str)
        or not isinstance(extension_id, str)
        or not isinstance(tool_name, str)
        or not isinstance(declared_effect, str)
        or not isinstance(confirmations, int)
        or confirmations < 0
    ):
        raise EvaluationError("extension invocation fields are malformed")

    extension = policy["extensions"].get(extension_id)
    known_extension = isinstance(extension, dict) and extension.get("kind") == "mcp"
    tool = nested(extension or {}, "tools", tool_name)
    known_tool = isinstance(tool, dict)
    known = bool(known_extension and known_tool)
    effect_ok = bool(
        known
        and tool.get("effect") == declared_effect
        and evaluate_constraints(tool, invocation)
    )
    decision = tool.get("decision") if known else policy["default_decision"]
    if not effect_ok:
        decision = "deny"

    if decision == "allow":
        expected_confirmations = 0
    elif decision == "require-bound-approval":
        expected_confirmations = 1
    else:
        expected_confirmations = 0
    hitl_ok = confirmations == expected_confirmations
    allowed_or_routed = decision in {"allow", "require-bound-approval"}

    results = [
        CheckResult(
            "AAR-012",
            known,
            "extension and tool are present in the reviewed capability inventory",
            "extension or tool is unknown and defaults to deny",
        ),
        CheckResult(
            "AAR-013",
            effect_ok and allowed_or_routed,
            "declared effect and machine-checkable constraints match policy",
            "effect constraints or policy decision deny the invocation",
        ),
        CheckResult(
            "AAR-014",
            hitl_ok,
            "HITL count matches the risk-based minimum",
            "HITL count is excessive or missing for the operation risk",
        ),
    ]
    return invocation_id, extension_id, tool_name, expected_confirmations, results


def render_results(
    label: str, details: str, results: list[CheckResult]
) -> int:
    failures = sum(not result.passed for result in results)
    for result in results:
        print(result.render())
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} {label}={details} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify PSB-AI-004 extension capability policy."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    adapters = subparsers.add_parser("adapters")
    adapters.add_argument("policy", type=Path)
    adapters.add_argument("profile", type=Path)
    invocation = subparsers.add_parser("invocation")
    invocation.add_argument("policy", type=Path)
    invocation.add_argument("invocation", type=Path)
    invocation.add_argument("engine_state", type=Path)
    args = parser.parse_args()

    try:
        if args.mode == "adapters":
            name, results = evaluate_adapters(
                args.policy.resolve(), args.profile.resolve()
            )
            return render_results("profile", name, results)
        invocation_id, extension_id, tool_name, expected_hitl, results = (
            evaluate_invocation(
                args.policy.resolve(),
                args.invocation.resolve(),
                args.engine_state.resolve(),
            )
        )
        details = (
            f"{invocation_id} extension={extension_id} tool={tool_name} "
            f"expected_hitl={expected_hitl}"
        )
        return render_results("invocation", details, results)
    except EvaluationError as error:
        print(f"ERROR PSB-AI-004 capability evaluation failed: {error}")
        return 2
    except Exception:
        print(
            "ERROR PSB-AI-004 capability evaluation failed: "
            "unexpected evaluator failure"
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
