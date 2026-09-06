#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo "ERROR usage: install-locked-wheel-only.sh [project-directory]" >&2
  exit 2
fi

project_directory="${1:-.}"
script_directory="${BASH_SOURCE[0]%/*}"
uv_runtime="${PSB_UV:-uv}"

if ! command -v "$uv_runtime" >/dev/null 2>&1; then
  echo "ERROR uv runtime is unavailable" >&2
  exit 2
fi
if [[ ! -f "$project_directory/pyproject.toml" || ! -f "$project_directory/uv.lock" ]]; then
  echo "ERROR pyproject.toml and uv.lock are required" >&2
  exit 2
fi

required_version="$(<"$script_directory/UV_VERSION")"
actual_version="$("$uv_runtime" --version 2>/dev/null)" || {
  echo "ERROR uv version cannot be determined" >&2
  exit 2
}
case "$actual_version" in
  "uv $required_version"|"uv $required_version "*) ;;
  *)
    echo "ERROR expected uv $required_version but found $actual_version" >&2
    exit 2
    ;;
esac

"$uv_runtime" sync \
  --directory "$project_directory" \
  --locked \
  --no-build \
  --no-python-downloads \
  --no-progress

echo "PASS uv synchronized an up-to-date wheel-only project lock"
