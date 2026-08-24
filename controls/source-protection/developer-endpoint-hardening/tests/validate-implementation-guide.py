#!/usr/bin/env python3
"""Check that every control check has one implementation-guide entry."""

from __future__ import annotations

import re
import sys
from pathlib import Path


CONTROL_ID_PATTERN = re.compile(r"^  - id: ([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)$", re.MULTILINE)
GUIDE_HEADING_PATTERN = re.compile(r"^## ((?:DEH|END)-[0-9]{3})：", re.MULTILINE)


def main() -> int:
    control_dir = Path(__file__).resolve().parent.parent
    control_text = (control_dir / "control.yaml").read_text(encoding="utf-8")
    guide_text = (control_dir / "docs/check-implementation-guide.md").read_text(
        encoding="utf-8"
    )

    try:
        checks_text = control_text.split("checks:\n", 1)[1].split("\nmappings:", 1)[0]
    except IndexError:
        print("FAIL control.yaml does not contain an isolated checks section")
        return 1
    check_ids = CONTROL_ID_PATTERN.findall(checks_text)
    guide_ids = GUIDE_HEADING_PATTERN.findall(guide_text)
    if len(check_ids) != 29 or len(set(check_ids)) != 29:
        print(f"FAIL expected 29 unique control checks, found {len(check_ids)}")
        return 1
    if set(guide_ids) != set(check_ids):
        missing = sorted(set(check_ids) - set(guide_ids))
        unexpected = sorted(set(guide_ids) - set(check_ids))
        print(f"FAIL implementation guide coverage missing={missing} unexpected={unexpected}")
        return 1
    duplicates = sorted(check_id for check_id in set(guide_ids) if guide_ids.count(check_id) != 1)
    if duplicates:
        print(f"FAIL implementation guide has duplicate entries: {duplicates}")
        return 1

    required_phrases = (
        "## 読み方",
        "## 導入の進め方",
        "**最小構成**",
        "**組織管理**",
        "**確認の例**",
        "**限界**",
    )
    missing_phrases = [phrase for phrase in required_phrases if phrase not in guide_text]
    if missing_phrases:
        print(f"FAIL implementation guide missing required sections: {missing_phrases}")
        return 1

    print("PASS implementation guide covers all 29 checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
