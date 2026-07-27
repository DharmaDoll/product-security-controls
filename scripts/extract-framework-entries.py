#!/usr/bin/env python3
"""Extract minimal mapping entries from pinned upstream framework artifacts."""

from __future__ import annotations

import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


def attack_entries(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = []
    for item in data["objects"]:
        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        references = item.get("external_references", [])
        reference = next(
            (
                candidate
                for candidate in references
                if candidate.get("source_name") == "mitre-attack"
                and candidate.get("external_id")
            ),
            None,
        )
        if reference is None:
            continue
        entry_id = reference["external_id"]
        if not re.fullmatch(r"(?:TA|T|M|G|S|DS)\d+(?:\.\d+)?", entry_id):
            continue
        entries.append(
            {
                "id": entry_id,
                "title": item["name"],
                "type": item["type"],
                "source_url": reference.get(
                    "url", f"https://attack.mitre.org/techniques/{entry_id}/"
                ),
            }
        )
    return sorted(entries, key=lambda entry: entry["id"])


def atlas_entries(path: Path) -> list[dict[str, Any]]:
    section_types = {
        "tactics": "tactic",
        "techniques": "technique",
        "mitigations": "mitigation",
        "case-studies": "case-study",
    }
    url_segments = {
        "tactic": "tactics",
        "technique": "techniques",
        "mitigation": "mitigations",
        "case-study": "case-studies",
    }
    section = None
    current: dict[str, Any] | None = None
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line in {f"{name}:" for name in section_types}:
            if current:
                entries.append(current)
            section = line[:-1]
            current = None
            continue
        if line and not line.startswith(" "):
            if current:
                entries.append(current)
            section = None
            current = None
            continue
        if section is None:
            continue
        match = re.fullmatch(r"  (AML\.(?:TA|T|M|CS)\d+(?:\.\d+)?):", line)
        if match:
            if current:
                entries.append(current)
            entry_id = match.group(1)
            entry_type = section_types[section]
            current = {
                "id": entry_id,
                "title": "",
                "type": entry_type,
                "source_url": (
                    f"https://atlas.mitre.org/{url_segments[entry_type]}/{entry_id}/"
                ),
            }
            continue
        if current and line.startswith("    name: "):
            current["title"] = line.removeprefix("    name: ").strip("'\"")
    if current:
        entries.append(current)
    return sorted(entries, key=lambda entry: entry["id"])


def asvs_entries(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data["Version"]
    entries = []
    for chapter in data["Requirements"]:
        for section in chapter["Items"]:
            for requirement in section["Items"]:
                short_id = requirement["Shortcode"].removeprefix("V")
                entry_id = f"v{version}-{short_id}"
                entries.append(
                    {
                        "id": entry_id,
                        "title": f"{chapter['Name']} / {section['Name']}",
                        "type": "verification-requirement",
                        "level": int(requirement["L"]),
                        "source_url": (
                            "https://github.com/OWASP/ASVS/tree/"
                            f"v{version}_release/5.0/en"
                        ),
                    }
                )
    return sorted(entries, key=lambda entry: entry["id"])


class OSPSParser(HTMLParser):
    def __init__(self, source_url: str) -> None:
        super().__init__()
        self.source_url = source_url
        self.heading: str | None = None
        self.buffer: list[str] = []
        self.control_title = ""
        self.entries: list[dict[str, Any]] = []
        self.last_entry: dict[str, Any] | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag in {"h3", "h4"}:
            self.heading = tag
            self.buffer = []

    def handle_data(self, data: str) -> None:
        if self.heading:
            self.buffer.append(data)
        elif self.last_entry is not None and "Retired in " in data:
            self.last_entry["status"] = "retired"

    def handle_endtag(self, tag: str) -> None:
        if tag != self.heading:
            return
        text = " ".join("".join(self.buffer).split())
        if tag == "h3" and re.match(r"^OSPS-[A-Z]{2}-\d{2}\b", text):
            self.control_title = text
        elif tag == "h4" and re.fullmatch(r"OSPS-[A-Z]{2}-\d{2}\.\d{2}", text):
            title = re.sub(r"^OSPS-[A-Z]{2}-\d{2}\s*-\s*", "", self.control_title)
            self.last_entry = {
                "id": text,
                "title": title,
                "type": "assessment-requirement",
                "source_url": f"{self.source_url}#{text.lower().replace('.', '')}",
            }
            self.entries.append(self.last_entry)
        self.heading = None
        self.buffer = []


def osps_entries(path: Path) -> list[dict[str, Any]]:
    source_url = "https://baseline.openssf.org/versions/2026-02-19"
    parser = OSPSParser(source_url)
    parser.feed(path.read_text(encoding="utf-8"))
    deduplicated = {entry["id"]: entry for entry in parser.entries}
    return [deduplicated[key] for key in sorted(deduplicated)]


EXTRACTORS = {
    "attack": attack_entries,
    "atlas": atlas_entries,
    "asvs": asvs_entries,
    "osps": osps_entries,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=sorted(EXTRACTORS))
    parser.add_argument("source", type=Path)
    parser.add_argument("registry", type=Path)
    args = parser.parse_args()

    with args.registry.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)
    registry["entries"] = EXTRACTORS[args.kind](args.source)
    with args.registry.open("w", encoding="utf-8") as handle:
        json.dump(registry, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"wrote {len(registry['entries'])} entries to {args.registry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
