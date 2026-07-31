#!/usr/bin/env bash
set -euo pipefail

control="controls/container-cloud-iac-security/container-admission-baseline"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --policy "$control/secure/policy.json"
  --platform-evidence "$control/secure/platform-evidence.json"
  --admission-review "$control/secure/admission-review.json"
  --network-policy "$control/secure/network-policy.json"
  --oci-manifest "$control/secure/oci-manifest.json"
  --provenance-policy "$control/secure/provenance-policy.json"
  --provenance "$control/secure/provenance.json"
  --signature "$control/secure/signature.b64"
)

python3 "$verify" "${common[@]}" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/insecure/policy.json" \
  --platform-evidence "$control/insecure/platform-evidence.json" \
  --admission-review "$control/insecure/admission-review.json" \
  --network-policy "$control/insecure/network-policy.json" \
  --oci-manifest "$control/secure/oci-manifest.json" \
  --provenance-policy "$control/secure/provenance-policy.json" \
  --provenance "$control/insecure/provenance.json" \
  --signature "$control/secure/signature.b64" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --admission-review "$control/insecure/admission-review.json" \
  --network-policy "$control/insecure/network-policy.json" \
  >"$temporary_directory/unsafe-workload.txt"
unsafe_workload_status=$?
set -e
test "$unsafe_workload_status" -eq 1
diff -u \
  "$control/expected-results/unsafe-workload.txt" \
  "$temporary_directory/unsafe-workload.txt"

set +e
python3 "$verify" "${common[@]}" \
  --provenance "$control/insecure/provenance.json" \
  >"$temporary_directory/provenance-mismatch.txt"
provenance_status=$?
set -e
test "$provenance_status" -eq 1
diff -u \
  "$control/expected-results/provenance-mismatch.txt" \
  "$temporary_directory/provenance-mismatch.txt"

set +e
python3 "$verify" "${common[@]}" \
  --platform-evidence "$control/insecure/platform-error.json" \
  >"$temporary_directory/platform-error.txt"
platform_error_status=$?
set -e
test "$platform_error_status" -eq 2
diff -u \
  "$control/expected-results/platform-error.txt" \
  "$temporary_directory/platform-error.txt"

cp "$control/secure/oci-manifest.json" "$temporary_directory/tampered-manifest.json"
printf '\n' >>"$temporary_directory/tampered-manifest.json"
set +e
python3 "$verify" "${common[@]}" \
  --oci-manifest "$temporary_directory/tampered-manifest.json" \
  >"$temporary_directory/tampered-manifest.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 1
rg -F "admitted image digest does not match OCI manifest bytes" \
  "$temporary_directory/tampered-manifest.txt" >/dev/null
rg -F "PSB-REL-001 rejected image provenance" \
  "$temporary_directory/tampered-manifest.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provenance-verifier "$temporary_directory/missing-verifier.py" \
  >"$temporary_directory/missing-verifier.txt"
missing_verifier_status=$?
set -e
test "$missing_verifier_status" -eq 2
rg -F "ERROR admission evaluation unavailable: PSB-REL-001 verifier is unavailable:" \
  "$temporary_directory/missing-verifier.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${common[@]}" \
  --admission-review "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "ERROR admission evaluation unavailable: invalid admission review JSON:" \
  "$temporary_directory/malformed.txt" >/dev/null

echo "PASS secure workload and fail-closed admission policy accepted"
echo "PASS mutable root privileged host-mounted and unbounded workload rejected"
echo "PASS exact OCI digest is bound to authenticated PSB-REL-001 provenance"
echo "PASS provenance mismatch and artifact substitution rejected"
echo "PASS default-deny network and bounded runtime resources verified"
echo "PASS platform verifier and malformed-input failures remain ERROR"
