#!/usr/bin/env python3
"""Validate every discovered control package."""

from __future__ import annotations

from control_metadata import discover_controls, validate_controls
from framework_registry import discover_registries, validate_registries


def main() -> int:
    try:
        controls = discover_controls()
        errors = validate_controls(controls)
        registries = discover_registries()
        errors.extend(validate_registries(registries, controls))
    except (OSError, ValueError) as error:
        print(f"control validation error: {error}")
        return 2

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1

    print(
        f"validated {len(controls)} control package(s) and "
        f"{len(registries)} framework registries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
