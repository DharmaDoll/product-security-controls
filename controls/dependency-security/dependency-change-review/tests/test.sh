#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/dependency-change-review"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --policy "$control/secure/policy.json"
  --base-lock "$control/secure/base-lock.json"
  --as-of "2026-07-31T12:30:00Z"
)

python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/secure/proposed-lock.json" \
  --advisories "$control/secure/advisories.json" \
  --review "$control/secure/review.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/insecure/proposed-lock.json" \
  --advisories "$control/insecure/advisories.json" \
  --review "$control/insecure/review.json" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/secure/proposed-lock.json" \
  --advisories "$control/tests/fixtures/incomplete-advisories.json" \
  --review "$control/secure/review.json" \
  >"$temporary_directory/incomplete.txt"
incomplete_status=$?
set -e
test "$incomplete_status" -eq 2
rg -F "ERROR DCR-004 dependency review unavailable: advisory snapshot is incomplete" \
  "$temporary_directory/incomplete.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/secure/proposed-lock.json" \
  --advisories "$control/secure/advisories.json" \
  --review "$control/secure/review.json" \
  --as-of "2026-08-02T12:30:00Z" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "ERROR DCR-004 dependency review unavailable: advisory snapshot is stale or from the future" \
  "$temporary_directory/stale.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/secure/proposed-lock.json" \
  --advisories "$control/secure/advisories.json" \
  --review "$control/tests/fixtures/mismatched-advisory-review.json" \
  >"$temporary_directory/advisory-mismatch.txt"
advisory_mismatch_status=$?
set -e
test "$advisory_mismatch_status" -eq 2
rg -F "ERROR DCR-004 dependency review unavailable: review is not bound to exact advisory snapshot" \
  "$temporary_directory/advisory-mismatch.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/secure/proposed-lock.json" \
  --advisories "$control/secure/advisories.json" \
  --review "$control/tests/fixtures/duplicate-change-review.json" \
  >"$temporary_directory/duplicate-change.txt"
duplicate_change_status=$?
set -e
test "$duplicate_change_status" -eq 2
rg -F "ERROR DCR-007 dependency review unavailable: reviewed dependency delta is incomplete" \
  "$temporary_directory/duplicate-change.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --proposed-lock "$control/tests/fixtures/malformed-lock.json" \
  --advisories "$control/secure/advisories.json" \
  --review "$control/secure/review.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "ERROR DCR-009 dependency review unavailable: cannot load proposed lock" \
  "$temporary_directory/malformed.txt" >/dev/null

echo "PASS exact direct and transitive dependency delta reviewed"
echo "PASS source vulnerability license provenance approval and exception findings blocked"
echo "PASS mismatched duplicate incomplete stale and malformed evidence remained ERROR"
