#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo "ERROR usage: install-locked.sh [project-directory]" >&2
  exit 2
fi

project_directory="${1:-.}"
script_directory="${BASH_SOURCE[0]%/*}"
pnpm_runtime="${PSB_PNPM:-pnpm}"

if ! command -v "$pnpm_runtime" >/dev/null 2>&1; then
  echo "ERROR pnpm runtime is unavailable" >&2
  exit 2
fi
if [[ ! -f "$project_directory/package.json" ]]; then
  echo "ERROR package.json is missing" >&2
  exit 2
fi
if [[ ! -f "$project_directory/pnpm-lock.yaml" ]]; then
  echo "ERROR pnpm-lock.yaml is missing" >&2
  exit 2
fi

required_version="$(<"$script_directory/PNPM_VERSION")"
actual_version="$("$pnpm_runtime" --version 2>/dev/null)" || {
  echo "ERROR pnpm version cannot be determined" >&2
  exit 2
}
if [[ "$actual_version" != "$required_version" ]]; then
  echo "ERROR expected pnpm $required_version but found $actual_version" >&2
  exit 2
fi

pnpm_arguments=(
  --dir "$project_directory"
  install
  --frozen-lockfile
  --ignore-scripts
)
if [[ -n "${PSB_PNPM_STORE_DIR:-}" ]]; then
  pnpm_arguments+=(--store-dir "$PSB_PNPM_STORE_DIR")
fi
if [[ "${PSB_PNPM_OFFLINE:-0}" == "1" ]]; then
  pnpm_arguments+=(--offline)
fi

"$pnpm_runtime" "${pnpm_arguments[@]}"

echo "PASS pnpm immutable install completed without changing the lockfile"
