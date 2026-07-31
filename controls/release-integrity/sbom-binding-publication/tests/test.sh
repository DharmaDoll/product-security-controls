#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-rel-003.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

python3 "$verify" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --sbom "$control_dir/secure/bom.cdx.json" \
  --manifest "$control_dir/secure/release-manifest.json" \
  --lifecycle-policy "$control_dir/secure/sbom-lifecycle-policy.json" \
  --dependency-track-policy "$control_dir/secure/dependency-track-policy.json" \
  --dependency-track-receipt "$control_dir/secure/dependency-track-receipt.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
python3 "$verify" \
  --artifact "$control_dir/insecure/artifact/release.bin" \
  --sbom "$control_dir/insecure/bom.cdx.json" \
  --manifest "$control_dir/insecure/release-manifest.json" \
  --lifecycle-policy "$control_dir/insecure/sbom-lifecycle-policy.json" \
  --dependency-track-policy "$control_dir/insecure/dependency-track-policy.json" \
  --dependency-track-receipt "$control_dir/insecure/dependency-track-receipt.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
if [[ "$insecure_exit" -ne 1 ]]; then
  echo "FAIL insecure SBOM release exit: expected=1 actual=$insecure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

for fixture in processing-failed validation-failed stale-analyzer malformed-receipt; do
  error_exit=0
  python3 "$verify" \
    --artifact "$control_dir/secure/artifact/release.bin" \
    --sbom "$control_dir/secure/bom.cdx.json" \
    --manifest "$control_dir/secure/release-manifest.json" \
    --lifecycle-policy "$control_dir/secure/sbom-lifecycle-policy.json" \
    --dependency-track-policy "$control_dir/secure/dependency-track-policy.json" \
    --dependency-track-receipt "$control_dir/tests/fixtures/$fixture.json" \
    >"$temporary_directory/$fixture.txt" || error_exit=$?
  if [[ "$error_exit" -ne 2 ]]; then
    echo "FAIL $fixture exit: expected=2 actual=$error_exit"
    exit 1
  fi
  grep -F "ERROR " "$temporary_directory/$fixture.txt" >/dev/null
done

malformed_lifecycle_exit=0
python3 "$verify" \
  --artifact "$control_dir/secure/artifact/release.bin" \
  --sbom "$control_dir/secure/bom.cdx.json" \
  --manifest "$control_dir/secure/release-manifest.json" \
  --lifecycle-policy "$control_dir/tests/fixtures/malformed-lifecycle-policy.json" \
  --dependency-track-policy "$control_dir/secure/dependency-track-policy.json" \
  --dependency-track-receipt "$control_dir/secure/dependency-track-receipt.json" \
  >"$temporary_directory/malformed-lifecycle.txt" || malformed_lifecycle_exit=$?
if [[ "$malformed_lifecycle_exit" -ne 2 ]]; then
  echo "FAIL malformed lifecycle policy exit: expected=2 actual=$malformed_lifecycle_exit"
  exit 1
fi
grep -F "ERROR " "$temporary_directory/malformed-lifecycle.txt" >/dev/null

echo "PASS exact artifact SBOM and component graph binding verified"
echo "PASS Dependency-Track project permission and processed receipt verified"
echo "PASS processing validation freshness and parser failures remain ERROR"
echo "PASS source build and deployment observations remain distinct and linked"
