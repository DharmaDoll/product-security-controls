#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo "ERROR usage: sync-hashed-requirements.sh [project-directory]" >&2
  exit 2
fi

project_directory="${1:-.}"
script_directory="${BASH_SOURCE[0]%/*}"
uv_runtime="${PSB_UV:-uv}"
python_runtime="${PSB_PYTHON:-python3}"
requirements_lock="$project_directory/requirements.lock"

if ! command -v "$uv_runtime" >/dev/null 2>&1; then
  echo "ERROR uv runtime is unavailable" >&2
  exit 2
fi
if ! command -v "$python_runtime" >/dev/null 2>&1; then
  echo "ERROR Python runtime is unavailable" >&2
  exit 2
fi
if [[ ! -f "$requirements_lock" ]]; then
  echo "ERROR requirements.lock is missing" >&2
  exit 2
fi
if ! "$python_runtime" -c 'import sys; raise SystemExit(0 if sys.prefix != sys.base_prefix else 1)'; then
  echo "ERROR a dedicated Python virtual environment is required" >&2
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

"$uv_runtime" pip sync \
  --python "$python_runtime" \
  --require-hashes \
  --only-binary :all: \
  --strict \
  --no-python-downloads \
  --no-progress \
  "$requirements_lock"

echo "PASS uv pip synchronized the complete hash-locked requirements graph"
