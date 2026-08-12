#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
generate="$control_dir/scripts/generate_fixture_bundle.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-rel-005.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_profile() {
  local profile="$1"
  shift
  python3 "$verify" \
    --policy "$control_dir/$profile/signing-policy.json" \
    --artifact "$control_dir/$profile/artifact/release.bin" \
    --request "$control_dir/$profile/signing-request.json" \
    --authorization "$control_dir/$profile/authorization.json" \
    --signer-evidence "$control_dir/$profile/signer-evidence.json" \
    --statement "$control_dir/$profile/signature-statement.json" \
    --signature "$control_dir/$profile/signature.b64" \
    --receipt "$control_dir/$profile/signing-receipt.json" \
    --as-of "2026-08-10T03:02:00Z" \
    "$@"
}

run_profile secure >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
run_profile insecure >"$temporary_directory/insecure.txt" || insecure_exit=$?
test "$insecure_exit" -eq 1
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

cp "$control_dir/secure/artifact/release.bin" "$temporary_directory/tampered.bin"
printf 'tampered\n' >>"$temporary_directory/tampered.bin"
tampered_exit=0
python3 "$verify" \
  --policy "$control_dir/secure/signing-policy.json" \
  --artifact "$temporary_directory/tampered.bin" \
  --request "$control_dir/secure/signing-request.json" \
  --authorization "$control_dir/secure/authorization.json" \
  --signer-evidence "$control_dir/secure/signer-evidence.json" \
  --statement "$control_dir/secure/signature-statement.json" \
  --signature "$control_dir/secure/signature.b64" \
  --receipt "$control_dir/secure/signing-receipt.json" \
  --as-of "2026-08-10T03:02:00Z" \
  >"$temporary_directory/tampered.txt" || tampered_exit=$?
test "$tampered_exit" -eq 1
grep -F "FAIL PSB-REL-005/ASG-001" "$temporary_directory/tampered.txt" >/dev/null
grep -F "FAIL PSB-REL-005/ASG-004" "$temporary_directory/tampered.txt" >/dev/null

printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' \
  >"$temporary_directory/invalid-signature.b64"
signature_exit=0
python3 "$verify" \
  --policy "$control_dir/secure/signing-policy.json" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --request "$control_dir/secure/signing-request.json" \
  --authorization "$control_dir/secure/authorization.json" \
  --signer-evidence "$control_dir/secure/signer-evidence.json" \
  --statement "$control_dir/secure/signature-statement.json" \
  --signature "$temporary_directory/invalid-signature.b64" \
  --receipt "$control_dir/secure/signing-receipt.json" \
  --as-of "2026-08-10T03:02:00Z" \
  >"$temporary_directory/invalid-signature.txt" || signature_exit=$?
test "$signature_exit" -eq 1
grep -F "FAIL PSB-REL-005/ASG-005 artifact signature verification failed" \
  "$temporary_directory/invalid-signature.txt" >/dev/null

openssl_exit=0
run_profile secure --openssl "$temporary_directory/missing-openssl" \
  >"$temporary_directory/openssl-error.txt" || openssl_exit=$?
test "$openssl_exit" -eq 2
grep -F "ERROR PSB-REL-005/ASG-008 verification unavailable: cannot execute OpenSSL" \
  "$temporary_directory/openssl-error.txt" >/dev/null

printf '{"schema":' >"$temporary_directory/malformed.json"
malformed_exit=0
python3 "$verify" \
  --policy "$control_dir/secure/signing-policy.json" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --request "$temporary_directory/malformed.json" \
  --authorization "$control_dir/secure/authorization.json" \
  --signer-evidence "$control_dir/secure/signer-evidence.json" \
  --statement "$control_dir/secure/signature-statement.json" \
  --signature "$control_dir/secure/signature.b64" \
  --receipt "$control_dir/secure/signing-receipt.json" \
  --as-of "2026-08-10T03:02:00Z" \
  >"$temporary_directory/malformed.txt" || malformed_exit=$?
test "$malformed_exit" -eq 2

fixture_input="$temporary_directory/fixture-input"
mkdir -m 700 "$fixture_input"
openssl genpkey -algorithm ED25519 -out "$fixture_input/private.pem"
chmod 600 "$fixture_input/private.pem"
openssl pkey -in "$fixture_input/private.pem" -pubout \
  -out "$fixture_input/signer-public-key.pem"
public_digest="$(sha256sum "$fixture_input/signer-public-key.pem" | cut -d ' ' -f 1)"
sed "s/1b2e83758fa94ed96086e47d9663d88c03201ec76482096e22528f69d1a82e77/$public_digest/g" \
  "$control_dir/secure/signing-policy.json" >"$fixture_input/signing-policy.json"
sed "s/1b2e83758fa94ed96086e47d9663d88c03201ec76482096e22528f69d1a82e77/$public_digest/g" \
  "$control_dir/secure/signer-evidence.json" >"$fixture_input/signer-evidence.json"

python3 "$generate" \
  --policy "$fixture_input/signing-policy.json" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --request "$control_dir/secure/signing-request.json" \
  --authorization "$control_dir/secure/authorization.json" \
  --signer-evidence "$fixture_input/signer-evidence.json" \
  --fixture-private-key "$fixture_input/private.pem" \
  --output "$temporary_directory/generated" \
  --signed-at "2026-08-10T03:02:00Z" \
  --fixture-transparency-log-id "synthetic-test-log" \
  >"$temporary_directory/generate.txt"
grep -F "PASS PSB-REL-005 fixture bundle generated" "$temporary_directory/generate.txt" >/dev/null
if rg -n --no-messages "BEGIN .*PRIVATE KEY|fixture-private-key" \
  "$temporary_directory/generated"; then
  echo "FAIL generated signing bundle retained sensitive material"
  exit 1
fi
python3 "$verify" \
  --policy "$fixture_input/signing-policy.json" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --request "$control_dir/secure/signing-request.json" \
  --authorization "$control_dir/secure/authorization.json" \
  --signer-evidence "$fixture_input/signer-evidence.json" \
  --statement "$temporary_directory/generated/signature-statement.json" \
  --signature "$temporary_directory/generated/signature.b64" \
  --receipt "$temporary_directory/generated/signing-receipt.json" \
  --as-of "2026-08-10T03:02:00Z" \
  >"$temporary_directory/generated-verify.txt"
grep -F "RESULT PASS profile=secure checks=8 failures=0" \
  "$temporary_directory/generated-verify.txt" >/dev/null

chmod 644 "$fixture_input/private.pem"
unsafe_key_exit=0
python3 "$generate" \
  --policy "$fixture_input/signing-policy.json" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --request "$control_dir/secure/signing-request.json" \
  --authorization "$control_dir/secure/authorization.json" \
  --signer-evidence "$fixture_input/signer-evidence.json" \
  --fixture-private-key "$fixture_input/private.pem" \
  --output "$temporary_directory/unsafe-key-output" \
  --signed-at "2026-08-10T03:02:00Z" \
  --fixture-transparency-log-id "synthetic-test-log" \
  >"$temporary_directory/unsafe-key.txt" || unsafe_key_exit=$?
test "$unsafe_key_exit" -eq 2
grep -F "fixture private key permissions must be 0600" "$temporary_directory/unsafe-key.txt" >/dev/null

echo "PASS exact artifact authorization signer statement signature and receipt accepted"
echo "PASS mutable broad exportable fail-open and sensitive-evidence fixture rejected"
echo "PASS tampering invalid signature malformed input and missing crypto fail closed"
echo "PASS ephemeral fixture generation retains no private key and rejects unsafe key permissions"
