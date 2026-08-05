#!/usr/bin/env bash
set -euo pipefail

control="controls/container-cloud-iac-security/container-host-daemon-hardening"
verify="$control/scripts/verify.py"
evaluation_time="2026-08-04T12:05:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

secure=(
  --policy "$control/secure/policy.json"
  --host-evidence "$control/secure/host-evidence.json"
  --exceptions "$control/secure/exceptions.json"
  --evidence-health "$control/secure/evidence-health.json"
  --evaluation-time "$evaluation_time"
)

python3 "$verify" "${secure[@]}" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/insecure/policy.json" \
  --host-evidence "$control/insecure/host-evidence.json" \
  --exceptions "$control/insecure/exceptions.json" \
  --evidence-health "$control/secure/evidence-health.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$verify" "${secure[@]}" \
  --host-evidence "$control/insecure/host-evidence.json" \
  >"$temporary_directory/secure-policy-insecure-host.txt"
secure_policy_insecure_host_status=$?
set -e
test "$secure_policy_insecure_host_status" -eq 1
rg -F "protected path /etc/systemd/system/containerd.service has wrong type" \
  "$temporary_directory/secure-policy-insecure-host.txt" >/dev/null
rg -F "protected file /usr/bin/containerd digest does not match" \
  "$temporary_directory/secure-policy-insecure-host.txt" >/dev/null

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
  --evaluation-time "2026-08-04T14:05:00Z" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "ERROR PSB-CONTAINER-003 host evaluation unavailable: evidence health manifest is stale" \
  "$temporary_directory/stale.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --host-evidence "$control/tests/fixtures/unsupported-host.json" \
  --evidence-health "$control/tests/fixtures/unsupported-health.json" \
  >"$temporary_directory/unsupported.txt"
unsupported_status=$?
set -e
test "$unsupported_status" -eq 3
diff -u "$control/expected-results/unsupported.txt" "$temporary_directory/unsupported.txt"

sed 's/"user_namespace_enabled": true/"user_namespace_enabled": false/' \
  "$control/secure/host-evidence.json" \
  >"$temporary_directory/isolation-limited-host.json"
set +e
python3 "$verify" "${secure[@]}" \
  --host-evidence "$temporary_directory/isolation-limited-host.json" \
  --exceptions "$control/tests/fixtures/valid-isolation-exception.json" \
  >"$temporary_directory/valid-exception.txt"
valid_exception_status=$?
set -e
test "$valid_exception_status" -eq 3
diff -u \
  "$control/expected-results/valid-exception.txt" \
  "$temporary_directory/valid-exception.txt"

set +e
python3 "$verify" "${secure[@]}" \
  --host-evidence "$temporary_directory/isolation-limited-host.json" \
  --exceptions "$control/tests/fixtures/expired-isolation-exception.json" \
  >"$temporary_directory/expired-exception.txt"
expired_exception_status=$?
set -e
test "$expired_exception_status" -eq 1
rg -F "FAIL HST-004 isolation exception is not current" \
  "$temporary_directory/expired-exception.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${secure[@]}" \
  --host-evidence "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "ERROR PSB-CONTAINER-003 host evaluation unavailable: invalid host evidence JSON:" \
  "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --host-evidence "$control/tests/fixtures/secret-bearing-host.json" \
  >"$temporary_directory/secret-bearing.txt"
secret_bearing_status=$?
set -e
test "$secret_bearing_status" -eq 2
rg -F "host evidence contains forbidden credential field token" \
  "$temporary_directory/secret-bearing.txt" >/dev/null
if rg -F "SYNTHETIC_TEST_VALUE" "$temporary_directory/secret-bearing.txt" >/dev/null; then
  echo "credential-bearing host evidence leaked to verifier output" >&2
  exit 1
fi

echo "PASS dedicated minimal patched Linux host baseline accepted"
echo "PASS public daemon socket mount weak isolation and tampered paths rejected"
echo "PASS secure policy cannot be rescued by insecure observed host state"
echo "PASS operator network audit and hardware trust failures rejected"
echo "PASS valid exception and unsupported platform remain NOT_CHECKED not PASS"
echo "PASS expired exception unavailable malformed and secret-bearing evidence fail closed"
echo "PASS stale host evidence remains ERROR"
