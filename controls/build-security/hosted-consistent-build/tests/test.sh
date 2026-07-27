#!/usr/bin/env bash
set -euo pipefail

control="controls/build-security/hosted-consistent-build"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/build-policy.json" \
  --record "$control/secure/build-record.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/build-policy.json" \
  --record "$control/insecure/build-record.json" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/build-policy.json" \
  --record "$control/insecure/build-record.json" \
  >"$temporary_directory/drift.txt"
drift_status=$?
set -e
test "$drift_status" -eq 1
grep -q '^FAIL release build must run in a hosted execution environment$' \
  "$temporary_directory/drift.txt"
grep -q '^FAIL build definition revision must equal the source revision$' \
  "$temporary_directory/drift.txt"
grep -q '^FAIL release trigger manual is not allowed by producer policy$' \
  "$temporary_directory/drift.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/build-policy.json" \
  --record "$control/secure/build-record.json" \
  >"$temporary_directory/weak-policy.txt"
weak_policy_status=$?
set -e
test "$weak_policy_status" -eq 1
grep -q '^FAIL approved builder .* must be hosted$' \
  "$temporary_directory/weak-policy.txt"
grep -q '^FAIL build definition must be bound to the source revision$' \
  "$temporary_directory/weak-policy.txt"
grep -q '^FAIL release policy must require hosted builds$' \
  "$temporary_directory/weak-policy.txt"

printf '%s\n' '{"schema_version": 1, "target_slsa_build_level":' \
  >"$temporary_directory/malformed.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/malformed.json" \
  --record "$control/secure/build-record.json" \
  >"$temporary_directory/error.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2
grep -q '^ERROR verification unavailable:' "$temporary_directory/error.txt"

printf '%s\n' '{"schema_version": 1}' >"$temporary_directory/incomplete.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/incomplete.json" \
  --record "$control/secure/build-record.json" \
  >"$temporary_directory/incomplete-error.txt" 2>&1
incomplete_status=$?
set -e
test "$incomplete_status" -eq 2
grep -q '^ERROR verification unavailable:' "$temporary_directory/incomplete-error.txt"

echo "PASS approved hosted builder and consistent versioned process accepted"
echo "PASS local drifting build and insufficient platform evidence rejected"
echo "PASS secure policy rejects drift and secure record cannot rescue weak policy"
echo "PASS malformed and incomplete evidence fail closed"
