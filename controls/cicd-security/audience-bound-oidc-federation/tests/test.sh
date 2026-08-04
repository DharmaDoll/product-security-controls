#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/audience-bound-oidc-federation"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --policy "$control/secure/policy.json"
  --workflow "$control/secure/workflow.yml"
  --secret-inventory "$control/secure/secret-inventory.json"
  --replay-state "$control/secure/replay-state.json"
  --receipt "$control/secure/credential-receipt.json"
  --now 1785823200
)

python3 "$control/scripts/verify.py" \
  "${common[@]}" \
  --token "$control/secure/token.jwt" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/policy.json" \
  --workflow "$control/insecure/workflow.yml" \
  --token "$control/insecure/token.jwt" \
  --secret-inventory "$control/insecure/secret-inventory.json" \
  --replay-state "$control/insecure/replay-state.json" \
  --receipt "$control/insecure/credential-receipt.json" \
  --now 1785823200 \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

run_signed_negative() {
  local name="$1"
  local token="$2"
  local expected="$3"
  set +e
  python3 "$control/scripts/verify.py" \
    "${common[@]}" \
    --token "$token" \
    >"$temporary_directory/$name.txt"
  local status=$?
  set -e
  test "$status" -eq 1
  grep -F "PASS PSB-CICD-006/OIDC-001" "$temporary_directory/$name.txt" >/dev/null
  grep -F "$expected" "$temporary_directory/$name.txt" >/dev/null
}

run_signed_negative \
  "wrong-audience" "$control/insecure/token.jwt" \
  "aud claim does not match exact trust policy"
run_signed_negative \
  "fork-pr" "$control/tests/fixtures/fork-pr.jwt" \
  "event_name claim does not match exact trust policy"
run_signed_negative \
  "wrong-repository" "$control/tests/fixtures/wrong-repository.jwt" \
  "repository claim does not match exact trust policy"
run_signed_negative \
  "mutable-workflow" "$control/tests/fixtures/mutable-workflow.jwt" \
  "job_workflow_ref uses a mutable or unsupported ref"
run_signed_negative \
  "expired" "$control/tests/fixtures/expired.jwt" \
  "token is expired"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/policy.json" \
  --workflow "$control/secure/workflow.yml" \
  --token "$control/secure/token.jwt" \
  --secret-inventory "$control/secure/secret-inventory.json" \
  --replay-state "$control/insecure/replay-state.json" \
  --receipt "$control/secure/credential-receipt.json" \
  --now 1785823200 \
  >"$temporary_directory/replay.txt"
replay_status=$?
set -e
test "$replay_status" -eq 1
grep -F "token jti was already consumed" "$temporary_directory/replay.txt" >/dev/null

sed 's/.$/A/' "$control/secure/token.jwt" >"$temporary_directory/tampered.jwt"
set +e
python3 "$control/scripts/verify.py" \
  "${common[@]}" \
  --token "$temporary_directory/tampered.jwt" \
  >"$temporary_directory/tampered.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 1
grep -F "JWT signature verification failed" "$temporary_directory/tampered.txt" >/dev/null

sed 's/"status": "issued"/"status": "denied"/' \
  "$control/secure/credential-receipt.json" \
  >"$temporary_directory/denied-receipt.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/policy.json" \
  --workflow "$control/secure/workflow.yml" \
  --token "$control/secure/token.jwt" \
  --secret-inventory "$control/secure/secret-inventory.json" \
  --replay-state "$control/secure/replay-state.json" \
  --receipt "$temporary_directory/denied-receipt.json" \
  --now 1785823200 \
  >"$temporary_directory/denied.txt"
denied_status=$?
set -e
test "$denied_status" -eq 1
grep -F "cloud credential exchange did not issue a credential" \
  "$temporary_directory/denied.txt" >/dev/null

set +e
python3 "$control/scripts/verify.py" \
  "${common[@]}" \
  --token "$control/secure/token.jwt" \
  --openssl "$temporary_directory/missing-openssl" \
  >"$temporary_directory/openssl-error.txt"
openssl_status=$?
set -e
test "$openssl_status" -eq 2
grep -F "ERROR PSB-CICD-006" "$temporary_directory/openssl-error.txt" >/dev/null

sed 's/"status": "complete"/"status": "unavailable"/' \
  "$control/secure/secret-inventory.json" \
  >"$temporary_directory/unavailable-inventory.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/policy.json" \
  --workflow "$control/secure/workflow.yml" \
  --token "$control/secure/token.jwt" \
  --secret-inventory "$temporary_directory/unavailable-inventory.json" \
  --replay-state "$control/secure/replay-state.json" \
  --receipt "$control/secure/credential-receipt.json" \
  --now 1785823200 \
  >"$temporary_directory/inventory-error.txt"
inventory_status=$?
set -e
test "$inventory_status" -eq 2

echo "PASS signed exact OIDC claims and bounded credential receipt accepted"
echo "PASS fork PR wrong audience repository mutable workflow expired and replay cases rejected"
echo "PASS static credentials broad trust and overbroad downstream authority rejected"
echo "PASS invalid signature denied exchange and unavailable verification fail closed"
