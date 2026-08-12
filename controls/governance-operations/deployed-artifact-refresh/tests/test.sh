#!/usr/bin/env bash
set -euo pipefail

control="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verify="$control/scripts/verify.py"
policy="$control/secure/policy.json"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$verify" --policy "$policy" --case "$control/secure/case-remediated.json" >"$temporary_directory/remediated.txt"
cmp "$control/expected-results/remediated.txt" "$temporary_directory/remediated.txt"

python3 "$verify" --policy "$policy" --case "$control/secure/case-not-affected.json" >"$temporary_directory/not-affected.txt"
cmp "$control/expected-results/not-affected.txt" "$temporary_directory/not-affected.txt"

set +e
python3 "$verify" --policy "$policy" --case "$control/secure/case-in-progress.json" >"$temporary_directory/in-progress.txt"
in_progress_status=$?
set -e
test "$in_progress_status" -eq 1
cmp "$control/expected-results/in-progress.txt" "$temporary_directory/in-progress.txt"

set +e
python3 "$verify" --policy "$control/insecure/policy.json" --case "$control/insecure/case.json" >"$temporary_directory/insecure-policy.txt"
insecure_policy_status=$?
set -e
test "$insecure_policy_status" -eq 2
rg -F "policy_id has invalid immutable identity" "$temporary_directory/insecure-policy.txt" >/dev/null

set +e
python3 "$verify" --policy "$policy" --case "$control/insecure/case.json" >"$temporary_directory/insecure-case.txt"
insecure_case_status=$?
set -e
test "$insecure_case_status" -eq 1
rg -F "FINDING decision deadline does not match policy" "$temporary_directory/insecure-case.txt" >/dev/null

for scenario in stale partial sensitive; do
  python3 "$control/tests/mutate_fixture.py" --source "$control/secure/case-remediated.json" --output "$temporary_directory/$scenario.json" --scenario "$scenario"
  set +e
  python3 "$verify" --policy "$policy" --case "$temporary_directory/$scenario.json" >"$temporary_directory/$scenario.txt"
  status=$?
  set -e
  test "$status" -eq 2
done
rg -F "deployment inventory is stale" "$temporary_directory/stale.txt" >/dev/null
rg -F "risk evidence source set is incomplete" "$temporary_directory/partial.txt" >/dev/null
rg -F "case contains forbidden sensitive field token" "$temporary_directory/sensitive.txt" >/dev/null
if rg -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive value leaked to output" >&2
  exit 1
fi

python3 "$control/tests/mutate_fixture.py" --source "$control/secure/case-remediated.json" --output "$temporary_directory/mismatch.json" --scenario mismatch
set +e
python3 "$verify" --policy "$policy" --case "$temporary_directory/mismatch.json" >"$temporary_directory/mismatch.txt"
mismatch_status=$?
set -e
test "$mismatch_status" -eq 2
rg -F "replacement release signature_subject is mismatched" "$temporary_directory/mismatch.txt" >/dev/null

python3 "$control/tests/mutate_fixture.py" --source "$control/secure/case-remediated.json" --output "$temporary_directory/old-active.json" --scenario old-active
set +e
python3 "$verify" --policy "$policy" --case "$temporary_directory/old-active.json" >"$temporary_directory/old-active.txt"
old_active_status=$?
set -e
test "$old_active_status" -eq 1
rg -F "FINDING post-deployment target does not run the replacement digest" "$temporary_directory/old-active.txt" >/dev/null

python3 "$control/tests/mutate_fixture.py" --source "$control/secure/case-remediated.json" --output "$temporary_directory/same-digest.json" --scenario same-digest
set +e
python3 "$verify" --policy "$policy" --case "$temporary_directory/same-digest.json" >"$temporary_directory/same-digest.txt"
same_digest_status=$?
set -e
test "$same_digest_status" -eq 1
rg -F "FINDING replacement reuses the affected artifact digest" "$temporary_directory/same-digest.txt" >/dev/null

sed 's/"critical": 24/"critical": 48/' "$policy" >"$temporary_directory/weakened-policy.json"
set +e
python3 "$verify" --policy "$temporary_directory/weakened-policy.json" --case "$control/secure/case-remediated.json" >"$temporary_directory/weakened-policy.txt"
weakened_policy_status=$?
set -e
test "$weakened_policy_status" -eq 1
rg -F "FINDING policy deadlines are weakened or incomplete" "$temporary_directory/weakened-policy.txt" >/dev/null

python3 "$control/tests/mutate_fixture.py" --source "$control/secure/case-remediated.json" --output "$temporary_directory/overdue.json" --scenario overdue
set +e
python3 "$verify" --policy "$policy" --case "$temporary_directory/overdue.json" >"$temporary_directory/overdue.txt"
overdue_status=$?
set -e
test "$overdue_status" -eq 1
rg -F "OVERDUE case=REFRESH-2026-0004" "$temporary_directory/overdue.txt" >/dev/null

printf '{' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" --policy "$policy" --case "$temporary_directory/malformed.json" >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "case cannot be loaded or parsed" "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$verify" --policy "$policy" --case "$temporary_directory/missing.json" >"$temporary_directory/missing.txt"
missing_status=$?
set -e
test "$missing_status" -eq 2
rg -F "case cannot be loaded or parsed" "$temporary_directory/missing.txt" >/dev/null

echo "PASS complete exact inventory and current risk evidence verified"
echo "PASS rebuild decision replacement admission and old-digest removal verified"
echo "PASS not-affected in-progress overdue remediated FINDING and ERROR states remain distinct"
echo "PASS stale partial mismatched malformed unsafe and sensitive evidence fails closed"
