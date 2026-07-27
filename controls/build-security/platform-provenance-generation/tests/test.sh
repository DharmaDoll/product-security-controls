#!/usr/bin/env bash
set -euo pipefail

control="controls/build-security/platform-provenance-generation"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/platform-policy.json" \
  --artifact "$control/secure/artifact/release.bin" \
  --provenance "$control/secure/provenance.json" \
  --signature "$control/secure/signature.b64" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/platform-policy.json" \
  --artifact "$control/insecure/artifact/release.bin" \
  --provenance "$control/insecure/provenance.json" \
  --signature "$control/insecure/signature.b64" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/platform-policy.json" \
  --artifact "$control/insecure/artifact/release.bin" \
  --provenance "$control/insecure/provenance.json" \
  --signature "$control/insecure/signature.b64" \
  >"$temporary_directory/tenant-provenance.txt"
tenant_status=$?
set -e
test "$tenant_status" -eq 1
grep -q '^FAIL platform provenance signature verification failed$' \
  "$temporary_directory/tenant-provenance.txt"
grep -q '^FAIL provenance builder identity does not match platform policy$' \
  "$temporary_directory/tenant-provenance.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/platform-policy.json" \
  --artifact "$control/secure/artifact/release.bin" \
  --provenance "$control/secure/provenance.json" \
  --signature "$control/secure/signature.b64" \
  >"$temporary_directory/unsafe-platform.txt"
unsafe_platform_status=$?
set -e
test "$unsafe_platform_status" -eq 1
grep -q '^FAIL provenance generator must run in the control plane$' \
  "$temporary_directory/unsafe-platform.txt"
grep -q '^FAIL tenant must not have platform provenance signing capability$' \
  "$temporary_directory/unsafe-platform.txt"

printf '%s\n' '{"predicate":' >"$temporary_directory/malformed.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/platform-policy.json" \
  --artifact "$control/secure/artifact/release.bin" \
  --provenance "$temporary_directory/malformed.json" \
  --signature "$control/secure/signature.b64" \
  >"$temporary_directory/malformed-error.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2
grep -q '^ERROR verification unavailable:' "$temporary_directory/malformed-error.txt"

python_path="$(command -v python3)"
set +e
PATH="$temporary_directory" "$python_path" "$control/scripts/verify.py" \
  --policy "$control/secure/platform-policy.json" \
  --artifact "$control/secure/artifact/release.bin" \
  --provenance "$control/secure/provenance.json" \
  --signature "$control/secure/signature.b64" \
  >"$temporary_directory/tool-error.txt" 2>&1
tool_status=$?
set -e
test "$tool_status" -eq 2
grep -q '^ERROR verification unavailable: cannot execute OpenSSL:' \
  "$temporary_directory/tool-error.txt"

echo "PASS automatic platform provenance and valid signature accepted"
echo "PASS tenant-generated provenance and unsafe platform policy rejected"
echo "PASS malformed evidence and unavailable crypto verifier fail closed"
