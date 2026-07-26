#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/lockfile-integrity"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/policy.json" \
  --manifest "$control/secure/manifest.json" \
  --lockfile "$control/secure/lockfile.json" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/policy.json" \
  --manifest "$control/insecure/manifest.json" \
  --lockfile "$control/insecure/lockfile.json" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

cp -R "$control/secure" "$temporary_directory/tampered"
printf '%s\n' "tampered" >>"$temporary_directory/tampered/artifacts/stable-lib-1.4.0.pkg"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/tampered/policy.json" \
  --manifest "$temporary_directory/tampered/manifest.json" \
  --lockfile "$temporary_directory/tampered/lockfile.json" \
  >"$temporary_directory/tampered.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 1
grep -F "artifact SHA-256 does not match lockfile" \
  "$temporary_directory/tampered.txt" >/dev/null

printf '%s\n' '{"dependencies":' >"$temporary_directory/malformed.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/policy.json" \
  --manifest "$temporary_directory/malformed.json" \
  --lockfile "$control/secure/lockfile.json" >"$temporary_directory/error.txt" 2>&1
error_status=$?
set -e
test "$error_status" -eq 2

echo "PASS frozen exact dependency graph and artifact accepted"
echo "PASS mutable graph range weak registry and missing integrity rejected"
echo "PASS tampered artifact rejected"
echo "PASS malformed input fails closed"
