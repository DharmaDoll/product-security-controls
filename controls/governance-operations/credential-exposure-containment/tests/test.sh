#!/usr/bin/env bash
set -euo pipefail

control="controls/governance-operations/credential-exposure-containment"
verify="$control/scripts/verify.py"
mutate="$control/tests/mutate_fixture.py"
evaluation_time="2026-08-10T12:00:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --bundle "$control/secure/response-bundle.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/insecure/policy.json" \
  --bundle "$control/insecure/response-bundle.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

expect_error() {
  local scenario="$1"
  local expected="$2"
  local fixture="$temporary_directory/$scenario.json"
  local output="$temporary_directory/$scenario.txt"
  python3 "$mutate" \
    --source "$control/secure/response-bundle.json" \
    --output "$fixture" \
    --scenario "$scenario"
  set +e
  python3 "$verify" \
    --policy "$control/secure/policy.json" \
    --bundle "$fixture" \
    --evaluation-time "$evaluation_time" \
    >"$output" 2>&1
  local status=$?
  set -e
  test "$status" -eq 2 || {
    echo "expected $scenario exit 2, got $status" >&2
    exit 1
  }
  grep -F "$expected" "$output" >/dev/null
}

expect_error "missing-consumer" "is missing a known consumer disposition"
expect_error "stale-inventory" "credential inventory is stale"
expect_error "partial-revocation" "provider receipts are partial"
expect_error "replacement-only" "old-authority denial test was skipped unsupported or failed"
expect_error "out-of-order" "state transitions are missing or out of order"
expect_error "adapter-error" "provider adapter is unavailable or unhealthy"
expect_error "secret-bearing" "contains forbidden sensitive field credential_value"
if grep -F "SYNTHETIC_FORBIDDEN_FIXTURE_VALUE" \
  "$temporary_directory/secret-bearing.txt" >/dev/null; then
  echo "secret-bearing fixture value leaked to verifier output" >&2
  exit 1
fi

python3 "$mutate" \
  --source "$control/secure/response-bundle.json" \
  --output "$temporary_directory/old-authority-still-valid.json" \
  --scenario "old-authority-still-valid"
set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --bundle "$temporary_directory/old-authority-still-valid.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/old-authority-still-valid.txt"
old_authority_status=$?
set -e
test "$old_authority_status" -eq 1
grep -F "old authority is still valid" \
  "$temporary_directory/old-authority-still-valid.txt" >/dev/null

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --bundle "$control/tests/fixtures/malformed-bundle.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2
grep -F "cannot load credential response bundle" \
  "$temporary_directory/malformed.txt" >/dev/null

echo "PASS reusable bearer signer and short-lived credential response paths verified"
echo "PASS containment migration denial impact review and closure ordering verified"
echo "PASS unsafe replacement unresolved consumer live mutation and old authority rejected"
echo "PASS missing stale partial malformed secret-bearing and adapter-error evidence fails closed"
echo "PASS live provider mutation remains NOT_CHECKED in the provider-neutral dry-run slice"
