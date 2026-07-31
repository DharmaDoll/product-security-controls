#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/release-cooldown"
as_of="2026-07-27T00:00:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/cooldown-policy.json" \
  --proxy-policy "$control/secure/registry-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$control/secure/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/cooldown-policy.json" \
  --proxy-policy "$control/insecure/registry-proxy-policy.json" \
  --lockfile "$control/insecure/lockfile.json" \
  --metadata "$control/insecure/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure fixture exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/tests/fixtures/expired-policy.json" \
  --proxy-policy "$control/secure/registry-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$control/secure/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/expired.txt"
expired_status=$?
set -e
test "$expired_status" -eq 1 || {
  echo "expected expired exception exit 1, got $expired_status" >&2
  exit 1
}
grep -F "urgent-security-fix@2.0.1 age is 24 hours" \
  "$temporary_directory/expired.txt" >/dev/null
grep -F "exception urgent-security-fix@2.0.1 is unused" \
  "$temporary_directory/expired.txt" >/dev/null

cp -R "$control/secure" "$temporary_directory/tampered"
printf '%s\n' "tampered bytes" \
  >>"$temporary_directory/tampered/artifacts/stable-lib-1.4.0.artifact"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/tampered/cooldown-policy.json" \
  --proxy-policy "$temporary_directory/tampered/registry-proxy-policy.json" \
  --lockfile "$temporary_directory/tampered/lockfile.json" \
  --metadata "$temporary_directory/tampered/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/tampered.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 1 || {
  echo "expected tampered artifact exit 1, got $tampered_status" >&2
  exit 1
}
grep -F "stable-lib@1.4.0 artifact sha256 does not match lockfile" \
  "$temporary_directory/tampered.txt" >/dev/null

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/cooldown-policy.json" \
  --proxy-policy "$control/secure/registry-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$temporary_directory/missing-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/missing.txt" 2>&1
missing_status=$?
set -e
test "$missing_status" -eq 2 || {
  echo "expected missing metadata exit 2, got $missing_status" >&2
  exit 1
}

printf '%s\n' '{"packages":' >"$temporary_directory/malformed-metadata.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/cooldown-policy.json" \
  --proxy-policy "$control/secure/registry-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$temporary_directory/malformed-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2 || {
  echo "expected malformed metadata exit 2, got $malformed_status" >&2
  exit 1
}

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/cooldown-policy.json" \
  --proxy-policy "$control/tests/fixtures/malformed-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$control/secure/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/malformed-proxy.txt" 2>&1
malformed_proxy_status=$?
set -e
test "$malformed_proxy_status" -eq 2 || {
  echo "expected malformed proxy policy exit 2, got $malformed_proxy_status" >&2
  exit 1
}

echo "PASS stable and exact-exception dependencies accepted"
echo "PASS zero cooldown fresh version unapproved registry and missing integrity rejected"
echo "PASS expired cooldown exception rejected"
echo "PASS tampered artifact rejected"
echo "PASS missing and malformed metadata fail closed"
echo "PASS managed registry proxy enforced and malformed proxy policy fails closed"
