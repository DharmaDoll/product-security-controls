#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.sh"
secure_output="$(mktemp "${TMPDIR:-/tmp}/psb-source-001-secure.XXXXXX")"
insecure_output="$(mktemp "${TMPDIR:-/tmp}/psb-source-001-insecure.XXXXXX")"
trap 'rm -f "$secure_output" "$insecure_output"' EXIT

"${BASH:-bash}" "$verify" secure >"$secure_output"
diff -u "$control_dir/expected-results/secure.txt" "$secure_output"

if "${BASH:-bash}" "$verify" insecure >"$insecure_output" 2>&1; then
  echo "FAIL insecure fixture was accepted"
  cat "$insecure_output"
  exit 1
fi

diff -u "$control_dir/expected-results/insecure.txt" "$insecure_output"
echo "PASS secure fixture matched expected evidence"
echo "PASS insecure fixture was rejected"
