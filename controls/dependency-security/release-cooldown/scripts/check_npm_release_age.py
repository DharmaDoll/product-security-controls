#!/usr/bin/env python3
"""Check one exact npm version before dependency-controlled code can run."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


REFERENCE_MINIMUM_DAYS = 7
OFFICIAL_REGISTRY = "https://registry.npmjs.org"
MAX_METADATA_BYTES = 32 * 1024 * 1024
NETWORK_TIMEOUT_SECONDS = 10
PACKAGE_RE = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$"
)
EXACT_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class InputError(ValueError):
    """Raised when no trustworthy cooldown decision can be made."""


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent an approved registry request from following another origin."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InputError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InputError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise InputError(f"{label} must use UTC")
    return parsed


def validate_package(value: str) -> str:
    if len(value) > 214 or PACKAGE_RE.fullmatch(value) is None:
        raise InputError("--package must be one exact npm package name")
    return value


def validate_version(value: str) -> str:
    if EXACT_VERSION_RE.fullmatch(value) is None:
        raise InputError("--version must be one exact semantic version")
    return value


def validate_registry(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise InputError(
            "npm registry must be an HTTPS origin without credentials, path, query, or fragment"
        )
    return value.rstrip("/")


def load_npmrc(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InputError("cannot read the repository npm configuration") from error

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            raise InputError(f"npm configuration line {line_number} must use key=value")
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip().lower()
        value = raw_value.strip()
        if not key or not value:
            raise InputError(f"npm configuration line {line_number} is incomplete")
        if key in values:
            raise InputError(f"npm configuration duplicates key {key}")
        values[key] = value
    return values


def assess_npmrc(values: dict[str, str]) -> tuple[int, list[str]]:
    findings: list[str] = []
    raw_registry = values.get("registry")
    if raw_registry is None:
        raise InputError("npm configuration must declare registry")
    registry = validate_registry(raw_registry)
    if registry != OFFICIAL_REGISTRY:
        findings.append("npm registry is not the approved official public registry")

    raw_minimum = values.get("min-release-age")
    if raw_minimum is None or not raw_minimum.isdigit():
        raise InputError("npm min-release-age must be one integer day value")
    minimum_days = int(raw_minimum)
    if minimum_days < REFERENCE_MINIMUM_DAYS:
        findings.append(
            f"npm min-release-age is {minimum_days} days; reference minimum is "
            f"{REFERENCE_MINIMUM_DAYS}"
        )

    if any(key.startswith("min-release-age-exclude") for key in values):
        findings.append("npm configuration contains a persistent age-gate exclusion")
    if "before" in values:
        findings.append("npm before can override the repository age gate")
    if values.get("save-exact") != "true":
        findings.append("npm save-exact must be true")
    if values.get("package-lock") != "true":
        findings.append("npm package-lock must be true")

    credential_keys = {
        "_auth",
        "_authtoken",
        "_password",
        "username",
    }
    if any(
        key in credential_keys
        or key.startswith("//")
        or "authtoken" in key
        for key in values
    ):
        findings.append("public registry metadata configuration must not contain credentials")
    return minimum_days * 24, findings


def decode_metadata(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InputError("registry metadata is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise InputError("registry metadata must be a JSON object")
    return value


def load_fixture_metadata(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_METADATA_BYTES:
            raise InputError("registry metadata exceeds the size limit")
        raw = path.read_bytes()
    except OSError as error:
        raise InputError("cannot read registry metadata fixture") from error
    return decode_metadata(raw)


def fetch_live_metadata(package: str) -> dict[str, Any]:
    encoded_package = quote(package, safe="@")
    url = f"{OFFICIAL_REGISTRY}/{encoded_package}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "psb-release-cooldown/1.0",
        },
        method="GET",
    )
    opener = build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise InputError(f"registry returned HTTP {response.status}")
            if response.geturl() != url:
                raise InputError("registry response changed the approved request origin")
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise InputError("registry response is not application/json")
            raw = response.read(MAX_METADATA_BYTES + 1)
    except HTTPError as error:
        raise InputError(f"registry returned HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise InputError("registry metadata request failed") from error
    if len(raw) > MAX_METADATA_BYTES:
        raise InputError("registry metadata exceeds the size limit")
    return decode_metadata(raw)


def release_timestamp(metadata: dict[str, Any], package: str, version: str) -> datetime:
    if metadata.get("name") != package:
        raise InputError("registry metadata package identity does not match the request")
    versions = metadata.get("versions")
    if not isinstance(versions, dict) or not isinstance(versions.get(version), dict):
        raise InputError("registry metadata does not contain the requested exact version")
    version_record = versions[version]
    if version_record.get("name") != package or version_record.get("version") != version:
        raise InputError("registry version record identity does not match the request")
    times = metadata.get("time")
    if not isinstance(times, dict) or version not in times:
        raise InputError("registry metadata lacks the requested version publish timestamp")
    return parse_timestamp(times[version], "version publish timestamp")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check one exact npm version against the repository release-age gate."
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--metadata-file", type=Path)
    mode.add_argument("--live", action="store_true")
    parser.add_argument(
        "--as-of",
        help="fixed RFC 3339 UTC time; permitted only with --metadata-file",
    )
    args = parser.parse_args()

    try:
        package = validate_package(args.package)
        version = validate_version(args.version)
        minimum_hours, findings = assess_npmrc(load_npmrc(args.config))
        for finding in findings:
            print(f"FAIL {finding}")
        if findings:
            print(f"REJECTED {len(findings)} npm cooldown configuration finding(s)")
            return 1

        if args.live:
            if args.as_of is not None:
                raise InputError("--as-of cannot override the clock in --live mode")
            metadata = fetch_live_metadata(package)
            as_of = datetime.now(timezone.utc)
            source = "live-registry"
        else:
            if args.as_of is None:
                raise InputError("--as-of is required with --metadata-file")
            metadata = load_fixture_metadata(args.metadata_file)
            as_of = parse_timestamp(args.as_of, "--as-of")
            source = "fixture"

        published_at = release_timestamp(metadata, package, version)
        if published_at > as_of:
            raise InputError("version publish timestamp is in the future")
        age_seconds = int((as_of - published_at).total_seconds())
        minimum_seconds = minimum_hours * 3600
        age_hours = age_seconds // 3600
        if age_seconds < minimum_seconds:
            remaining_hours = math.ceil((minimum_seconds - age_seconds) / 3600)
            print(
                f"COOLDOWN_WAIT {package}@{version} age_hours={age_hours} "
                f"minimum_hours={minimum_hours} remaining_hours={remaining_hours} "
                f"source={source}"
            )
            return 1
        print(
            f"ACCEPTED {package}@{version} age_hours={age_hours} "
            f"minimum_hours={minimum_hours} source={source}"
        )
        return 0
    except InputError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
