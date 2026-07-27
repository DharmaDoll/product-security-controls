#!/usr/bin/env bash
set -euo pipefail

control="controls/build-security/build-containment"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --plan "$control/secure/build-plan.json" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --plan "$control/insecure/build-plan.json" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

printf '%s\n' '{"jobs":' >"$temporary_directory/malformed.json"
set +e
python3 "$control/scripts/verify.py" \
  --plan "$temporary_directory/malformed.json" >"$temporary_directory/error.txt" 2>&1
error_status=$?
set -e
test "$error_status" -eq 2

echo "PASS isolated credential-free build and protected deploy accepted"
echo "PASS mixed privilege broad egress root socket and missing telemetry rejected"
echo "PASS malformed build plan fails closed"
