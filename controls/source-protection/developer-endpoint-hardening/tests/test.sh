#!/usr/bin/env bash
set -u

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.sh"

"${BASH:-bash}" "$verify" secure
insecure_output="$(mktemp "${TMPDIR:-/tmp}/psb-source-001.XXXXXX")"
trap 'rm -f "$insecure_output"' EXIT
if "${BASH:-bash}" "$verify" insecure >"$insecure_output" 2>&1; then
  echo "FAIL insecure fixture was accepted"
  cat "$insecure_output"
  exit 1
fi

echo "PASS insecure fixture was rejected"
