#!/usr/bin/env python3
"""Verify destination-specific AI coding-agent network evidence offline."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


POLICY_SCHEMA = "psb-ai-network-boundary-policy/v1"
EVIDENCE_SCHEMA = "psb-ai-network-boundary-evidence/v1"
CASE_FIELDS = {
    "scenario_id",
    "network_profile",
    "destination_url",
    "proxy_url",
    "socks_enabled",
    "local_bind_address",
    "unix_socket",
    "resolver",
    "connected_address",
    "transport_address_bound",
}
RESOLVER_FIELDS = {"status", "hostname", "captured_at", "addresses"}


class EvaluationError(Exception):
    """Network evidence could not be evaluated safely."""


@dataclass(frozen=True)
class Result:
    check_id: str
    scenario_id: str
    passed: bool
    pass_reason: str
    fail_reason: str

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        reason = self.pass_reason if self.passed else self.fail_reason
        return (
            f"{status} PSB-AI-004/{self.check_id} "
            f"scenario={self.scenario_id} {reason}"
        )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise EvaluationError(f"{label} is unavailable") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"{label} is malformed or unreadable") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"{label} must be an object")
    return value


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvaluationError(f"{label} is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise EvaluationError(f"{label} has no timezone")
    return parsed.astimezone(timezone.utc)


def require_policy(policy: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    dns = policy.get("dns")
    destinations = policy.get("allowed_destinations")
    if (
        policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("default_network") != "deny"
        or policy.get("enforcement_point") != "managed-egress-gateway"
        or policy.get("require_managed_policy") is not True
        or policy.get("allowed_schemes") != ["https"]
        or policy.get("allow_wildcard_hosts") is not False
        or policy.get("allow_ip_literal_urls") is not False
        or policy.get("allow_local_binding") is not False
        or policy.get("allow_upstream_proxy") is not False
        or policy.get("allow_socks") is not False
        or policy.get("allow_unix_sockets") != []
        or not isinstance(destinations, list)
        or not destinations
        or not isinstance(dns, dict)
        or dns.get("required_status") != "complete"
        or dns.get("require_all_addresses_global") is not True
        or dns.get("require_connected_address_in_resolution") is not True
        or dns.get("require_transport_address_binding") is not True
    ):
        raise EvaluationError("network boundary policy is unsafe or malformed")
    maximum_age = dns.get("maximum_age_seconds")
    if not isinstance(maximum_age, int) or maximum_age < 1:
        raise EvaluationError("network DNS freshness policy is malformed")
    seen: set[tuple[str, int, str]] = set()
    for destination in destinations:
        if not isinstance(destination, dict) or set(destination) != {
            "destination_id",
            "host",
            "port",
            "path_prefix",
        }:
            raise EvaluationError("network destination policy is malformed")
        host = destination.get("host")
        path = destination.get("path_prefix")
        port = destination.get("port")
        if (
            not isinstance(destination.get("destination_id"), str)
            or not isinstance(host, str)
            or not host
            or "*" in host
            or host != host.lower()
            or not isinstance(port, int)
            or port != 443
            or not isinstance(path, str)
            or not path.startswith("/")
            or "?" in path
            or "#" in path
        ):
            raise EvaluationError("network destination policy is unsafe")
        identity = (host, port, path)
        if identity in seen:
            raise EvaluationError("network destination policy is ambiguous")
        seen.add(identity)
    for field in ("metadata_hostnames", "metadata_addresses"):
        values = policy.get(field)
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise EvaluationError("metadata destination policy is malformed")
    try:
        for address in policy["metadata_addresses"]:
            ipaddress.ip_address(address)
    except ValueError as error:
        raise EvaluationError("metadata address policy is malformed") from error
    return destinations, dns


def parsed_url(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        raise EvaluationError("destination URL is malformed")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise EvaluationError("destination URL is malformed") from error
    if parsed.hostname is None:
        raise EvaluationError("destination URL has no hostname")
    return parsed


def route_is_allowed(
    case: dict[str, Any],
    destinations: list[dict[str, Any]],
    metadata_hosts: set[str],
) -> tuple[bool, str]:
    parsed = parsed_url(case.get("destination_url"))
    hostname = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ipaddress.ip_address(hostname)
        ip_literal = True
    except ValueError:
        ip_literal = False
    destination_match = any(
        hostname == destination["host"]
        and port == destination["port"]
        and (
            parsed.path == destination["path_prefix"]
            or parsed.path.startswith(destination["path_prefix"] + "/")
        )
        for destination in destinations
    )
    path_segments = parsed.path.split("/")
    path_is_canonical = (
        "%" not in parsed.path
        and "\\" not in parsed.path
        and "." not in path_segments
        and ".." not in path_segments
        and "//" not in parsed.path
    )
    allowed = all(
        (
            case.get("network_profile") == "destination-specific",
            parsed.scheme == "https",
            parsed.username is None,
            parsed.password is None,
            not parsed.query,
            not parsed.fragment,
            path_is_canonical,
            not ip_literal,
            hostname not in metadata_hosts,
            destination_match,
            case.get("proxy_url") is None,
            case.get("socks_enabled") is False,
            case.get("local_bind_address") is None,
            case.get("unix_socket") is None,
        )
    )
    reason = (
        "exact managed HTTPS destination has no proxy local listener or socket escape"
        if allowed
        else "destination transport or local escape surface is outside managed policy"
    )
    return allowed, reason


def address_is_allowed(
    case: dict[str, Any],
    dns_policy: dict[str, Any],
    metadata_addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
    now: datetime,
) -> tuple[bool, str]:
    resolver = case.get("resolver")
    if not isinstance(resolver, dict) or set(resolver) != RESOLVER_FIELDS:
        raise EvaluationError("resolver evidence is malformed")
    if resolver.get("status") != dns_policy["required_status"]:
        raise EvaluationError("resolver evidence is unavailable")
    addresses = resolver.get("addresses")
    if not isinstance(addresses, list) or not addresses or not all(
        isinstance(value, str) for value in addresses
    ):
        raise EvaluationError("resolver address evidence is malformed")
    try:
        parsed_addresses = {ipaddress.ip_address(value) for value in addresses}
        connected = ipaddress.ip_address(case.get("connected_address"))
    except (ValueError, TypeError) as error:
        raise EvaluationError("network address evidence is malformed") from error
    parsed = parsed_url(case.get("destination_url"))
    captured = parse_time(resolver.get("captured_at"), "resolver captured_at")
    age = (now - captured).total_seconds()
    resolver_host = resolver.get("hostname")
    if not isinstance(resolver_host, str):
        raise EvaluationError("resolver hostname evidence is malformed")
    def public_unicast(
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        return all(
            (
                address.is_global,
                not address.is_loopback,
                not address.is_private,
                not address.is_link_local,
                not address.is_multicast,
                not address.is_reserved,
                not address.is_unspecified,
            )
        )

    allowed = all(
        (
            resolver_host.lower() == parsed.hostname.lower(),
            0 <= age <= dns_policy["maximum_age_seconds"],
            all(public_unicast(address) for address in parsed_addresses),
            not bool(parsed_addresses & metadata_addresses),
            public_unicast(connected),
            connected not in metadata_addresses,
            connected in parsed_addresses,
            case.get("transport_address_bound") is True,
        )
    )
    reason = (
        "recent complete DNS evidence stays public and binds the connected address"
        if allowed
        else "DNS classification freshness or connected-address binding is unsafe"
    )
    return allowed, reason


def evaluate(
    policy: dict[str, Any], evidence: dict[str, Any], now: datetime
) -> list[Result]:
    destinations, dns_policy = require_policy(policy)
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvaluationError("network evidence schema is unsupported")
    if evidence.get("managed_gateway_available") is not True:
        raise EvaluationError("managed egress gateway is unavailable")
    cases = evidence.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationError("network evidence cases are missing")
    metadata_hosts = {value.lower() for value in policy["metadata_hostnames"]}
    metadata_addresses = {
        ipaddress.ip_address(value) for value in policy["metadata_addresses"]
    }
    results: list[Result] = []
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != CASE_FIELDS:
            raise EvaluationError("network evidence case is malformed")
        scenario_id = case.get("scenario_id")
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or scenario_id in seen
        ):
            raise EvaluationError("network scenario identity is malformed")
        seen.add(scenario_id)
        route_allowed, route_reason = route_is_allowed(
            case, destinations, metadata_hosts
        )
        address_allowed, address_reason = address_is_allowed(
            case, dns_policy, metadata_addresses, now
        )
        results.extend(
            (
                Result(
                    "AAR-020",
                    scenario_id,
                    route_allowed,
                    route_reason,
                    route_reason,
                ),
                Result(
                    "AAR-021",
                    scenario_id,
                    address_allowed,
                    address_reason,
                    address_reason,
                ),
            )
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--now", default="2026-07-29T12:02:00Z")
    args = parser.parse_args()
    profile = "unknown"
    try:
        policy = load_json(args.policy, "network boundary policy")
        evidence = load_json(args.evidence, "network boundary evidence")
        if isinstance(evidence.get("profile"), str):
            profile = evidence["profile"]
        results = evaluate(policy, evidence, parse_time(args.now, "evaluation time"))
    except EvaluationError as error:
        print(
            "ERROR PSB-AI-004/AAR-020 "
            f"profile={profile} network boundary evaluation failed: {error}"
        )
        print(f"RESULT ERROR profile={profile} checks=0 failures=1")
        return 2
    for result in results:
        print(result.render())
    failures = sum(not result.passed for result in results)
    status = "PASS" if failures == 0 else "FAIL"
    print(
        f"RESULT {status} profile={profile} "
        f"checks={len(results)} failures={failures}"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
