#!/usr/bin/env bash
set -euo pipefail

control="controls/release-integrity/signature-provenance-verification"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/verification-policy.json" \
  --artifact "$control/secure/artifact/release.bin" \
  --provenance "$control/secure/provenance.json" \
  --signature "$control/secure/signature.b64" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/verification-policy.json" \
  --artifact "$control/insecure/artifact/release.bin" \
  --provenance "$control/insecure/provenance.json" \
  --signature "$control/insecure/signature.b64" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

cp -R "$control/secure" "$temporary_directory/tampered"
printf '%s\n' "tampered" >>"$temporary_directory/tampered/artifact/release.bin"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/tampered/verification-policy.json" \
  --artifact "$temporary_directory/tampered/artifact/release.bin" \
  --provenance "$temporary_directory/tampered/provenance.json" \
  --signature "$temporary_directory/tampered/signature.b64" \
  >"$temporary_directory/tampered.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 1
grep -F "artifact SHA-256 does not match provenance subject" \
  "$temporary_directory/tampered.txt" >/dev/null

printf '%s\n' '{"subject":' >"$temporary_directory/malformed.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/verification-policy.json" \
  --artifact "$control/secure/artifact/release.bin" \
  --provenance "$temporary_directory/malformed.json" \
  --signature "$control/secure/signature.b64" >"$temporary_directory/error.txt" 2>&1
error_status=$?
set -e
test "$error_status" -eq 2

echo "PASS signed provenance and consumer expectations accepted"
echo "PASS trust downgrade invalid signature builder source and parameters rejected"
echo "PASS tampered artifact rejected"
echo "PASS malformed provenance fails closed"
