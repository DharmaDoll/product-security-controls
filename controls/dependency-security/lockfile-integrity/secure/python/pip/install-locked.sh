#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo "ERROR usage: install-locked.sh [project-directory]" >&2
  exit 2
fi

project_directory="${1:-.}"
python_runtime="${PSB_PYTHON:-python3}"
requirements_lock="$project_directory/requirements.lock"

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

"$python_runtime" -m pip install \
  --disable-pip-version-check \
  --no-input \
  --require-hashes \
  --only-binary=:all: \
  -r "$requirements_lock"
"$python_runtime" -m pip check

echo "PASS pip installed the complete hash-locked dependency graph"
