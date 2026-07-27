#!/usr/bin/env python3
"""Generate clickable GitHub.com Code Search URLs for owned indicators."""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path
from urllib.parse import urlencode


CONTROL_DIRECTORY = Path(__file__).resolve().parent.parent
INDICATOR_SCANNER = CONTROL_DIRECTORY / "scripts" / "scan-organization-exposure.py"
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


def load_indicator_module():
    specification = importlib.util.spec_from_file_location(
        "psb_organization_indicator_scanner", INDICATOR_SCANNER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("organization indicator parser cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def regex_domain(domain: str) -> str:
    escaped = re.escape(domain).replace("/", r"\/")
    return rf"/https?:\/\/[A-Za-z0-9._-]*{escaped}/"


def with_scope(query: str, owner: str | None) -> str:
    return f"{query} org:{owner}" if owner else query


def github_url(query: str) -> str:
    return "https://github.com/search?" + urlencode([("q", query), ("type", "code")])


def query_catalog(module, configuration, owner: str | None):
    queries: list[tuple[str, str, str]] = []
    config_paths = (
        "path:*.env OR path:*.yml OR path:*.yaml OR path:*.json "
        "OR path:*.properties OR path:*.tf"
    )
    credential_context = (
        "password OR token OR secret OR api_key OR client_secret OR credential"
    )
    source_languages = (
        "language:Python OR language:Java OR language:JavaScript "
        "OR language:TypeScript OR language:Go OR language:C# OR language:C++"
    )

    for indicator_id, domain in module.indicator_entries(
        configuration, "domains", True
    ):
        exact = f"content:{quoted(domain)}"
        queries.extend(
            [
                (
                    f"{indicator_id}-EXACT",
                    "Exact domain in file content",
                    with_scope(exact, owner),
                ),
                (
                    f"{indicator_id}-CREDENTIAL-CONTEXT",
                    "Domain near credential-related terms",
                    with_scope(
                        f"{exact} AND ({credential_context})",
                        owner,
                    ),
                ),
                (
                    f"{indicator_id}-CONFIG-PATHS",
                    "Domain in configuration-like paths",
                    with_scope(f"{exact} AND ({config_paths})", owner),
                ),
                (
                    f"{indicator_id}-URL-REGEX",
                    "HTTP or HTTPS endpoint below the domain",
                    with_scope(regex_domain(domain), owner),
                ),
            ]
        )

    for indicator_id, domain in module.indicator_entries(
        configuration, "email_domains", True
    ):
        email = f"content:{quoted('@' + domain)}"
        queries.extend(
            [
                (
                    f"{indicator_id}-EXACT",
                    "Email address using the organization domain",
                    with_scope(email, owner),
                ),
                (
                    f"{indicator_id}-CONFIG-PATHS",
                    "Organization email in configuration-like paths",
                    with_scope(f"{email} AND ({config_paths})", owner),
                ),
            ]
        )

    for indicator_id, marker in module.indicator_entries(
        configuration, "confidentiality_markers", False
    ):
        exact = f"content:{quoted(marker)}"
        queries.extend(
            [
                (
                    f"{indicator_id}-EXACT",
                    "Exact confidentiality marker",
                    with_scope(exact, owner),
                ),
                (
                    f"{indicator_id}-SOURCE",
                    "Confidentiality marker in common source languages",
                    with_scope(f"{exact} AND ({source_languages})", owner),
                ),
                (
                    f"{indicator_id}-HIGH-SIGNAL",
                    "Marker excluding generated and vendored results",
                    with_scope(
                        f"{exact} AND NOT is:generated AND NOT is:vendored",
                        owner,
                    ),
                ),
            ]
        )
    return queries


def render(queries: list[tuple[str, str, str]], owner: str | None) -> str:
    scope = f"GitHub organization `{owner}`" if owner else "all GitHub code visible to the signed-in account"
    lines = [
        "# GitHub public exposure dorks",
        "",
        f"Scope: {scope}.",
        "",
        "This file contains organization indicators. Keep it access-controlled and do not attach it to public issues.",
        "",
    ]
    for query_id, title, query in queries:
        lines.extend(
            [
                f"## {query_id}",
                "",
                title,
                "",
                f"- [Open in GitHub Code Search]({github_url(query)})",
                f"- Query: `{query}`",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indicators", type=Path, required=True)
    parser.add_argument(
        "--owner",
        help="Optionally restrict every query to one GitHub organization.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write Markdown to this access-controlled path instead of stdout.",
    )
    args = parser.parse_args()
    try:
        if args.owner and OWNER_RE.fullmatch(args.owner) is None:
            raise ValueError("owner is not a valid GitHub organization name")
        module = load_indicator_module()
        configuration = module.load_configuration(args.indicators)
        module.compile_rules(configuration)
        queries = query_catalog(module, configuration, args.owner)
        if not queries:
            raise ValueError("no GitHub dorks were generated")
        document = render(queries, args.owner)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(document + "\n", encoding="utf-8")
            print(f"WROTE {args.output}")
        else:
            print(document)
    except (OSError, RuntimeError, UnicodeError, ValueError) as error:
        print(f"ERROR GitHub web dork generation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
