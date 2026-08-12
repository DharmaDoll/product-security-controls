#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/runner-hardening"
verify="$control/scripts/verify.py"
evaluation_time="2026-08-11T03:10:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

secure=(
  --policy "$control/secure/runner-policy.json"
  --fleet-snapshot "$control/secure/fleet-snapshot.json"
  --image-evidence "$control/secure/image-evidence.json"
  --teardown-receipts "$control/secure/teardown-receipts.json"
  --evidence-health "$control/secure/evidence-health.json"
  --evaluation-time "$evaluation_time"
)

python3 "$verify" "${secure[@]}" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/insecure/runner-policy.json" \
  --fleet-snapshot "$control/insecure/fleet-snapshot.json" \
  --image-evidence "$control/insecure/image-evidence.json" \
  --teardown-receipts "$control/insecure/teardown-receipts.json" \
  --evidence-health "$control/insecure/evidence-health.json" \
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
rg -F "ERROR PSB-CICD-007 runner evaluation unavailable: runner evidence collector is unavailable" \
  "$temporary_directory/unavailable.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --evaluation-time "2026-08-11T04:00:00Z" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "fleet snapshot is stale" "$temporary_directory/stale.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${secure[@]}" \
  --fleet-snapshot "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "invalid fleet snapshot JSON" "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --fleet-snapshot "$control/tests/fixtures/secret-bearing-fleet.json" \
  >"$temporary_directory/secret.txt"
secret_status=$?
set -e
test "$secret_status" -eq 2
rg -F "fleet snapshot contains forbidden credential field token" \
  "$temporary_directory/secret.txt" >/dev/null
if rg -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" "$temporary_directory/secret.txt" >/dev/null; then
  echo "secret-bearing evidence leaked to verifier output" >&2
  exit 1
fi

sed 's/release-jit-20260811-731/release-jit-wrong-generation/' \
  "$control/secure/teardown-receipts.json" \
  >"$temporary_directory/mismatched-teardown.json"
set +e
python3 "$verify" "${secure[@]}" \
  --teardown-receipts "$temporary_directory/mismatched-teardown.json" \
  >"$temporary_directory/mismatched.txt"
mismatched_status=$?
set -e
test "$mismatched_status" -eq 1
rg -F "FAIL RNR-007 job job-release-731 teardown generation does not match dispatch" \
  "$temporary_directory/mismatched.txt" >/dev/null

echo "PASS hosted and self-hosted lifecycle evidence remain distinct"
echo "PASS untrusted routing persistent runners mutable images and residual state rejected"
echo "PASS metadata management socket registration teardown and log failures rejected"
echo "PASS stale malformed unavailable and credential-bearing evidence fail closed"
