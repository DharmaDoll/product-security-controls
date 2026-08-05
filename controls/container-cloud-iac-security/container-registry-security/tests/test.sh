#!/usr/bin/env bash
set -euo pipefail

control="controls/container-cloud-iac-security/container-registry-security"
verify="$control/scripts/verify.py"
evaluation_time="2026-08-04T12:05:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

secure=(
  --policy "$control/secure/policy.json"
  --identity "$control/secure/identity.json"
  --operations "$control/secure/operations.json"
  --audit "$control/secure/audit.json"
  --inventory "$control/secure/inventory.json"
  --evidence-health "$control/secure/evidence-health.json"
  --evaluation-time "$evaluation_time"
)

python3 "$verify" "${secure[@]}" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/insecure/policy.json" \
  --identity "$control/insecure/identity.json" \
  --operations "$control/insecure/operations.json" \
  --audit "$control/insecure/audit.json" \
  --inventory "$control/insecure/inventory.json" \
  --evidence-health "$control/secure/evidence-health.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$verify" "${secure[@]}" \
  --evidence-health "$control/tests/fixtures/evidence-unavailable.json" \
  >"$temporary_directory/unavailable.txt"
unavailable_status=$?
set -e
test "$unavailable_status" -eq 2
diff -u "$control/expected-results/unavailable.txt" "$temporary_directory/unavailable.txt"

set +e
python3 "$verify" "${secure[@]}" \
  --evidence-health "$control/tests/fixtures/stale-evidence-health.json" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "ERROR PSB-CONTAINER-002 registry evaluation unavailable: evidence health manifest is stale" \
  "$temporary_directory/stale.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --inventory "$control/tests/fixtures/scanner-error-inventory.json" \
  >"$temporary_directory/scanner-error.txt"
scanner_status=$?
set -e
test "$scanner_status" -eq 2
diff -u \
  "$control/expected-results/scanner-error.txt" \
  "$temporary_directory/scanner-error.txt"

printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${secure[@]}" \
  --audit "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "ERROR PSB-CONTAINER-002 registry evaluation unavailable: invalid audit JSON:" \
  "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --audit "$control/tests/fixtures/secret-bearing-audit.json" \
  >"$temporary_directory/secret-bearing.txt"
secret_bearing_status=$?
set -e
test "$secret_bearing_status" -eq 2
rg -F "audit contains forbidden credential field token" \
  "$temporary_directory/secret-bearing.txt" >/dev/null
if rg -F "SYNTHETIC_TEST_VALUE" "$temporary_directory/secret-bearing.txt" >/dev/null; then
  echo "secret-bearing evidence value leaked to verifier output" >&2
  exit 1
fi

echo "PASS TLS-only exact registry trust and default-deny authorization accepted"
echo "PASS anonymous wildcard cross-repository and broad identity paths rejected"
echo "PASS protected release overwrite and deletion paths rejected"
echo "PASS sensitive reads writes and administration require attributable audit"
echo "PASS stale images enter bounded non-deployable lifecycle states"
echo "PASS unavailable stale malformed and scanner-error evidence remains ERROR"
echo "PASS credential-bearing evidence is rejected without echoing its value"
