#!/usr/bin/env bash
# INSECURE EXAMPLE: --frozen uses uv.lock without checking pyproject.toml freshness.
set -euo pipefail

cd "${1:-.}"
uv sync --frozen
