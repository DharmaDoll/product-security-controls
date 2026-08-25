#!/usr/bin/env bash
set -euo pipefail

control="controls/source-protection/github-organization-governance"
verify="$control/scripts/verify.py"
mutate="$control/tests/mutate_fixture.py"
evaluation_time="2026-08-26T12:00:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --snapshot "$control/secure/organization-snapshot.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --snapshot "$control/insecure/organization-snapshot.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

python3 "$mutate" \
  --source "$control/secure/policy.json" \
  --output "$temporary_directory/weak-policy.json" \
  --scenario weak-policy
set +e
python3 "$verify" \
  --policy "$temporary_directory/weak-policy.json" \
  --snapshot "$control/secure/organization-snapshot.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/weak-policy.txt"
weak_policy_status=$?
set -e
test "$weak_policy_status" -eq 1
grep -F "FAIL GHO-010 policy can weaken the governance baseline" \
  "$temporary_directory/weak-policy.txt" >/dev/null

expect_error() {
  local scenario="$1"
  local expected="$2"
  local fixture="$temporary_directory/$scenario.json"
  local output="$temporary_directory/$scenario.txt"
  python3 "$mutate" \
    --source "$control/secure/organization-snapshot.json" \
    --output "$fixture" \
    --scenario "$scenario"
  set +e
  python3 "$verify" \
    --policy "$control/secure/policy.json" \
    --snapshot "$fixture" \
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

expect_error stale "organization snapshot is stale"
expect_error partial "collector pagination is incomplete"
expect_error count-mismatch "access inventory count mismatch"
expect_error adapter-error "collector sources are unavailable or unhealthy"
expect_error secret-bearing "contains forbidden sensitive field token"
if grep -F "SYNTHETIC_FORBIDDEN_VALUE" \
  "$temporary_directory/secret-bearing.txt" >/dev/null; then
  echo "secret-bearing fixture value leaked to verifier output" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --snapshot "$control/tests/fixtures/malformed.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2
grep -F "cannot parse organization snapshot" "$temporary_directory/malformed.txt" >/dev/null

echo "PASS GitHub Organization identity access defaults Actions applications and repository posture verified"
echo "PASS audit drift alert and policy-bound evidence verified"
echo "PASS unsafe hosted settings and ungoverned local exceptions rejected"
echo "PASS stale partial malformed secret-bearing and adapter-error evidence fails closed"
echo "PASS live provider enforcement remains NOT_CHECKED in the provider-neutral fixture slice"
