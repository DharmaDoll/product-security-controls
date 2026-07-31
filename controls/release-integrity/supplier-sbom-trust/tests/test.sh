#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-rel-004.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_secure() {
  python3 "$verify" \
    --policy "$control_dir/secure/intake-policy.json" \
    --artifact "$control_dir/secure/artifact/release.bin" \
    --sbom "${1:-$control_dir/secure/bom.cdx.json}" \
    --envelope "${2:-$control_dir/secure/supplier-envelope.json}" \
    --signature "${3:-$control_dir/secure/signature.b64}" \
    --revocation-snapshot "${4:-$control_dir/secure/revocation-snapshot.json}" \
    --as-of "2026-07-31T12:00:00Z" \
    "${@:5}"
}

run_secure >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
python3 "$verify" \
  --policy "$control_dir/insecure/intake-policy.json" \
  --artifact "$control_dir/insecure/artifact/release.bin" \
  --sbom "$control_dir/insecure/bom.cdx.json" \
  --envelope "$control_dir/insecure/supplier-envelope.json" \
  --signature "$control_dir/insecure/signature.b64" \
  --revocation-snapshot "$control_dir/insecure/revocation-snapshot.json" \
  --as-of "2026-07-31T12:00:00Z" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
test "$insecure_exit" -eq 1
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

wrong_product_exit=0
run_secure \
  "$control_dir/secure/bom.cdx.json" \
  "$control_dir/insecure/supplier-envelope.json" \
  "$control_dir/insecure/signature.b64" \
  >"$temporary_directory/wrong-product.txt" || wrong_product_exit=$?
test "$wrong_product_exit" -eq 1
grep -F "QUARANTINE SUP-002 signed supplier and product identity" \
  "$temporary_directory/wrong-product.txt" >/dev/null
if grep -F "signature verification failed" "$temporary_directory/wrong-product.txt" >/dev/null; then
  echo "FAIL wrong-product fixture must retain a valid signature"
  exit 1
fi

cp "$control_dir/secure/bom.cdx.json" "$temporary_directory/tampered-sbom.json"
printf ' ' >>"$temporary_directory/tampered-sbom.json"
tampered_exit=0
run_secure "$temporary_directory/tampered-sbom.json" \
  >"$temporary_directory/tampered.txt" || tampered_exit=$?
test "$tampered_exit" -eq 1
grep -F "QUARANTINE SUP-002 signed envelope does not bind the exact artifact and SBOM bytes" \
  "$temporary_directory/tampered.txt" >/dev/null

for fixture in \
  "$control_dir/insecure/revocation-snapshot.json" \
  "$control_dir/tests/fixtures/unknown-signer-snapshot.json" \
  "$control_dir/tests/fixtures/expired-signer-snapshot.json"; do
  lifecycle_exit=0
  run_secure \
    "$control_dir/secure/bom.cdx.json" \
    "$control_dir/secure/supplier-envelope.json" \
    "$control_dir/secure/signature.b64" \
    "$fixture" \
    >"$temporary_directory/lifecycle.txt" || lifecycle_exit=$?
  test "$lifecycle_exit" -eq 1
  grep -F "QUARANTINE SUP-004" "$temporary_directory/lifecycle.txt" >/dev/null
done

for fixture in \
  "$control_dir/tests/fixtures/stale-snapshot.json" \
  "$control_dir/tests/fixtures/unavailable-snapshot.json"; do
  status_exit=0
  run_secure \
    "$control_dir/secure/bom.cdx.json" \
    "$control_dir/secure/supplier-envelope.json" \
    "$control_dir/secure/signature.b64" \
    "$fixture" \
    >"$temporary_directory/status-error.txt" || status_exit=$?
  test "$status_exit" -eq 2
  grep -F "ERROR SUP-008 verification unavailable" \
    "$temporary_directory/status-error.txt" >/dev/null
done

for fixture in malformed-sbom unsupported-sbom; do
  content_exit=0
  run_secure "$control_dir/tests/fixtures/$fixture.json" \
    >"$temporary_directory/$fixture.txt" || content_exit=$?
  test "$content_exit" -eq 1
  grep -F "RESULT QUARANTINE" "$temporary_directory/$fixture.txt" >/dev/null
done

missing_signature_exit=0
run_secure \
  "$control_dir/secure/bom.cdx.json" \
  "$control_dir/secure/supplier-envelope.json" \
  "$temporary_directory/missing-signature.b64" \
  >"$temporary_directory/missing-signature.txt" || missing_signature_exit=$?
test "$missing_signature_exit" -eq 1
grep -F "RESULT QUARANTINE" "$temporary_directory/missing-signature.txt" >/dev/null

openssl_error_exit=0
run_secure \
  "$control_dir/secure/bom.cdx.json" \
  "$control_dir/secure/supplier-envelope.json" \
  "$control_dir/secure/signature.b64" \
  "$control_dir/secure/revocation-snapshot.json" \
  --openssl "$temporary_directory/missing-openssl" \
  >"$temporary_directory/openssl-error.txt" || openssl_error_exit=$?
test "$openssl_error_exit" -eq 2
grep -F "ERROR SUP-008 verification unavailable: cannot execute OpenSSL" \
  "$temporary_directory/openssl-error.txt" >/dev/null

echo "PASS signed supplier SBOM accepted only for the expected product artifact"
echo "PASS wrong product tampering unsigned malformed and unsupported input quarantined"
echo "PASS unknown expired and revoked signers quarantined"
echo "PASS stale unavailable status and crypto execution failures remain ERROR"
