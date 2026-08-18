#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/cache-provenance-isolation"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --policy "$control/secure/policy.json"
  --record "$control/secure/cache-record.json"
  --signature "$control/secure/cache-record.sig"
  --content "$control/secure/cache-content.json"
  --as-of 2026-08-17T12:00:00Z
)

python3 "$verify" "${common[@]}" \
  --request "$control/secure/restore-request.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --request "$control/insecure/restore-request.json" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

sed 's/cache-run-9001-attempt-1/cache-run-9001-attempt-2/' \
  "$control/secure/cache-record.json" >"$temporary_directory/tampered-record.json"
set +e
python3 "$verify" "${common[@]}" \
  --record "$temporary_directory/tampered-record.json" \
  --request "$control/secure/restore-request.json" \
  >"$temporary_directory/tampered-record.txt"
tampered_record_status=$?
set -e
test "$tampered_record_status" -eq 1
grep -F "FAIL CAC-001 cache record signature is invalid" \
  "$temporary_directory/tampered-record.txt" >/dev/null

sed 's/example-wheel/changed-wheel/' \
  "$control/secure/cache-content.json" >"$temporary_directory/tampered-content.json"
set +e
python3 "$verify" "${common[@]}" \
  --content "$temporary_directory/tampered-content.json" \
  --request "$control/secure/restore-request.json" \
  >"$temporary_directory/tampered-content.txt"
tampered_content_status=$?
set -e
test "$tampered_content_status" -eq 1
grep -F "FAIL CAC-004 cache content digest does not match producer record" \
  "$temporary_directory/tampered-content.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --request "$control/secure/restore-request.json" \
  --as-of 2026-08-18T00:00:00Z \
  >"$temporary_directory/expired.txt"
expired_status=$?
set -e
test "$expired_status" -eq 1
grep -F "FAIL CAC-005 cache record is not current at evaluation time" \
  "$temporary_directory/expired.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --policy "$control/tests/fixtures/invalid-policy.json" \
  --request "$control/secure/restore-request.json" \
  >"$temporary_directory/invalid-policy.txt" 2>&1
invalid_policy_status=$?
set -e
test "$invalid_policy_status" -eq 2
grep -F "ERROR policy fields are incomplete or unknown" \
  "$temporary_directory/invalid-policy.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --request "$control/secure/restore-request.json" \
  --openssl "$temporary_directory/missing-openssl" \
  >"$temporary_directory/missing-openssl.txt" 2>&1
missing_openssl_status=$?
set -e
test "$missing_openssl_status" -eq 2
grep -F "ERROR cannot execute OpenSSL" "$temporary_directory/missing-openssl.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed-request.json"
set +e
python3 "$verify" "${common[@]}" \
  --request "$temporary_directory/malformed-request.json" \
  >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2
grep -F "ERROR restore request is not valid UTF-8 JSON" \
  "$temporary_directory/malformed.txt" >/dev/null

ln -s "$(pwd)/$control/secure/restore-request.json" "$temporary_directory/request-link.json"
set +e
python3 "$verify" "${common[@]}" \
  --request "$temporary_directory/request-link.json" \
  >"$temporary_directory/symlink.txt" 2>&1
symlink_status=$?
set -e
test "$symlink_status" -eq 2
grep -F "ERROR restore request is unavailable or symbolic" \
  "$temporary_directory/symlink.txt" >/dev/null

if grep -R -F "example-wheel" "$temporary_directory" >/dev/null; then
  echo "cache content leaked to verifier output" >&2
  exit 1
fi

echo "PASS signed exact cache provenance and same-class restore accepted"
echo "PASS cross-boundary prefix tampered and expired cache restores rejected"
echo "PASS malformed symbolic and unavailable cryptographic evaluation fail closed"
