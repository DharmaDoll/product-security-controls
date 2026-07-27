#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-source-004.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

python3 "$verify" "$control_dir/secure/credential-policy.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" \
  "$temporary_directory/secure.txt"

insecure_exit=0
python3 "$verify" "$control_dir/insecure/credential-policy.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
if [[ "$insecure_exit" -ne 1 ]]; then
  echo "FAIL insecure policy exit: expected=1 actual=$insecure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/insecure.txt" \
  "$temporary_directory/insecure.txt"

malformed_exit=0
python3 "$verify" "$control_dir/README.md" \
  >"$temporary_directory/error.txt" || malformed_exit=$?
if [[ "$malformed_exit" -ne 2 ]]; then
  echo "FAIL malformed policy exit: expected=2 actual=$malformed_exit"
  exit 1
fi
grep -F "ERROR cannot load policy metadata:" "$temporary_directory/error.txt" \
  >/dev/null

echo "PASS secure credential lifecycle policy matched expected evidence"
echo "PASS insecure credential lifecycle policy was rejected"
echo "PASS malformed input remained distinct from a clean result"
