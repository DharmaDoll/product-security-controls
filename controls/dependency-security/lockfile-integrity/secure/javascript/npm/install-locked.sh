#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo "ERROR usage: install-locked.sh [project-directory]" >&2
  exit 2
fi

project_directory="${1:-.}"
script_directory="${BASH_SOURCE[0]%/*}"

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR node runtime is unavailable" >&2
  exit 2
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "ERROR npm runtime is unavailable" >&2
  exit 2
fi
if [[ ! -f "$project_directory/package.json" ]]; then
  echo "ERROR package.json is missing" >&2
  exit 2
fi
if [[ ! -f "$project_directory/package-lock.json" ]]; then
  echo "ERROR package-lock.json is missing" >&2
  exit 2
fi

node "$script_directory/verify-package-lock.mjs" \
  "$project_directory/package-lock.json"

(
  cd "$project_directory"
  npm ci \
    --package-lock=true \
    --ignore-scripts \
    --no-audit \
    --no-fund
)

echo "PASS npm immutable install completed without changing the lockfile"
