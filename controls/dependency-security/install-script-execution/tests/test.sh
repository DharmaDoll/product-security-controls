#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/install-script-execution"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --profile-dir "$control/secure" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --profile-dir "$control/insecure" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure fixture exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

cp -R "$control/secure" "$temporary_directory/malformed"
printf '%s\n' '[install' >"$temporary_directory/malformed/bun/bunfig.toml"
set +e
python3 "$control/scripts/verify.py" \
  --profile-dir "$temporary_directory/malformed" \
  >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2 || {
  echo "expected malformed config exit 2, got $malformed_status" >&2
  exit 1
}
grep -F "ERROR verification unavailable" "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$control/scripts/verify.py" \
  --profile-dir "$temporary_directory/missing" \
  >"$temporary_directory/missing.txt" 2>&1
missing_status=$?
set -e
test "$missing_status" -eq 2 || {
  echo "expected missing config exit 2, got $missing_status" >&2
  exit 1
}
grep -F "ERROR verification unavailable" "$temporary_directory/missing.txt" >/dev/null

echo "PASS secure native install-execution profiles accepted"
echo "PASS dangerous overrides broad approval and source fallback rejected"
echo "PASS missing and malformed configuration fail closed"
