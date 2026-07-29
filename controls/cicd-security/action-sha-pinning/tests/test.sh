#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/action-sha-pinning"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" "$control/secure/workflow.yml" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" "$control/insecure/workflow.yml" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure fixture exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

python3 "$control/scripts/verify.py" .github/workflows \
  >"$temporary_directory/repository-workflows.txt"

python3 "$control/scripts/verify-advisories.py" \
  --inventory "$control/secure/action-inventory.json" \
  --snapshot "$control/secure/advisories.json" \
  --as-of "2026-07-30T12:00:00Z" \
  >"$temporary_directory/secure-advisories.txt"
diff -u \
  "$control/expected-results/secure-advisories.txt" \
  "$temporary_directory/secure-advisories.txt"

set +e
python3 "$control/scripts/verify-advisories.py" \
  --inventory "$control/insecure/action-inventory.json" \
  --snapshot "$control/insecure/advisories.json" \
  --as-of "2026-07-30T12:00:00Z" \
  >"$temporary_directory/insecure-advisories.txt"
advisory_status=$?
set -e
test "$advisory_status" -eq 1
diff -u \
  "$control/expected-results/insecure-advisories.txt" \
  "$temporary_directory/insecure-advisories.txt"

set +e
python3 "$control/scripts/verify-advisories.py" \
  --inventory "$control/secure/action-inventory.json" \
  --snapshot "$control/secure/advisories.json" \
  --as-of "2026-08-08T00:00:01Z" \
  >"$temporary_directory/stale-advisories.txt" 2>&1
stale_status=$?
set -e
test "$stale_status" -eq 2

set +e
python3 "$control/scripts/collect-advisories.py" \
  --output "$temporary_directory/should-not-exist.json" \
  --timeout 0 \
  >"$temporary_directory/collector-error.txt" 2>&1
collector_status=$?
set -e
test "$collector_status" -eq 2
test ! -e "$temporary_directory/should-not-exist.json"

set +e
python3 "$control/scripts/verify.py" "$temporary_directory/missing.yml" \
  >"$temporary_directory/error.txt" 2>&1
error_status=$?
set -e
test "$error_status" -eq 2 || {
  echo "expected verifier error exit 2, got $error_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Unsupported flow syntax" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  "      - { uses: example-org/action@v1 }" \
  >"$temporary_directory/unsupported.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/unsupported.yml" \
  >"$temporary_directory/unsupported.txt" 2>&1
unsupported_status=$?
set -e
test "$unsupported_status" -eq 2 || {
  echo "expected unsupported syntax exit 2, got $unsupported_status" >&2
  exit 1
}

echo "PASS secure immutable references accepted"
echo "PASS insecure mutable references rejected"
echo "PASS repository workflows use immutable references"
echo "PASS reviewed Action advisory snapshot accepted"
echo "PASS vulnerable Action release rejected"
echo "PASS stale or unavailable advisory evidence fails closed"
echo "PASS advisory collector argument failure cannot create a clean snapshot"
echo "PASS verifier execution error distinguished from policy violation"
echo "PASS unsupported uses syntax fails closed"
