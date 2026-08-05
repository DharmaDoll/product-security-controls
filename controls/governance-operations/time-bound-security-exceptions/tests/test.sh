#!/usr/bin/env bash
set -euo pipefail

control="controls/governance-operations/time-bound-security-exceptions"
verify="$control/scripts/verify.py"
evaluation_time="2026-08-05T10:10:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --policy "$control/secure/policy.yaml"
  --evaluation-time "$evaluation_time"
)

python3 "$verify" "${common[@]}" \
  --register "$control/secure/register.json" \
  --exceptions-dir "$control/secure/exceptions" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --register "$control/insecure/register.json" \
  --exceptions-dir "$control/insecure/exceptions" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --register "$control/tests/fixtures/wrong-check-register.json" \
  --exceptions-dir "$control/tests/fixtures/wrong-check" \
  >"$temporary_directory/wrong-check.txt"
wrong_check_status=$?
set -e
test "$wrong_check_status" -eq 1
rg -F "INVALID EXC-2026-8002: check_id does not belong to control_id" \
  "$temporary_directory/wrong-check.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --register "$control/tests/fixtures/unavailable-register.json" \
  --exceptions-dir "$control/secure/exceptions" \
  >"$temporary_directory/unavailable.txt"
unavailable_status=$?
set -e
test "$unavailable_status" -eq 2
diff -u "$control/expected-results/unavailable.txt" "$temporary_directory/unavailable.txt"

cp -R "$control/secure/exceptions" "$temporary_directory/tampered"
printf '# unauthorized edit\n' >>"$temporary_directory/tampered/active-dependency.yaml"
set +e
python3 "$verify" "${common[@]}" \
  --register "$control/secure/register.json" \
  --exceptions-dir "$temporary_directory/tampered" \
  >"$temporary_directory/tampered.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 2
rg -F "registered exception digest mismatch: active-dependency.yaml" \
  "$temporary_directory/tampered.txt" >/dev/null

cp -R "$control/secure/exceptions" "$temporary_directory/incomplete"
cp "$control/tests/fixtures/wrong-check/wrong-check.yaml" \
  "$temporary_directory/incomplete/undeclared.yaml"
set +e
python3 "$verify" "${common[@]}" \
  --register "$control/secure/register.json" \
  --exceptions-dir "$temporary_directory/incomplete" \
  >"$temporary_directory/incomplete.txt"
incomplete_status=$?
set -e
test "$incomplete_status" -eq 2
rg -F "exception file is absent from complete register: undeclared.yaml" \
  "$temporary_directory/incomplete.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --register "$control/tests/fixtures/secret-register.json" \
  --exceptions-dir "$control/tests/fixtures/secret" \
  >"$temporary_directory/secret.txt"
secret_status=$?
set -e
test "$secret_status" -eq 2
rg -F "contains forbidden sensitive field token" "$temporary_directory/secret.txt" >/dev/null
if rg -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" "$temporary_directory/secret.txt" >/dev/null; then
  echo "credential-like exception value leaked to verifier output" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.yaml" \
  --register "$control/secure/register.json" \
  --exceptions-dir "$control/secure/exceptions" \
  --evaluation-time "2026-08-05T11:01:00Z" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "exception register evidence is stale" "$temporary_directory/stale.txt" >/dev/null

echo "PASS exact control check target and environment scope accepted"
echo "PASS broad self-approved overlong and mismatched exceptions rejected"
echo "PASS active expiring expired and invalid states are derived at evaluation time"
echo "PASS incomplete stale unavailable tampered and secret-bearing evidence fails closed"
