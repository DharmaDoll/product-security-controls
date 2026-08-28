#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/release-cooldown"
as_of="2026-07-27T00:00:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/cooldown-policy.json" \
  --native-policy "$control/secure/native-cooldown-policy.json" \
  --proxy-policy "$control/secure/registry-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$control/secure/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/cooldown-policy.json" \
  --native-policy "$control/insecure/native-cooldown-policy.json" \
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
  --native-policy "$control/secure/native-cooldown-policy.json" \
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
  --native-policy "$temporary_directory/tampered/native-cooldown-policy.json" \
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
  --native-policy "$control/secure/native-cooldown-policy.json" \
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
  --native-policy "$control/secure/native-cooldown-policy.json" \
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
  --native-policy "$control/secure/native-cooldown-policy.json" \
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

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/cooldown-policy.json" \
  --native-policy "$control/tests/fixtures/malformed-native-policy.json" \
  --proxy-policy "$control/secure/registry-proxy-policy.json" \
  --lockfile "$control/secure/lockfile.json" \
  --metadata "$control/secure/registry-metadata.json" \
  --as-of "$as_of" >"$temporary_directory/malformed-native.txt" 2>&1
malformed_native_status=$?
set -e
test "$malformed_native_status" -eq 2 || {
  echo "expected malformed native cooldown policy exit 2, got $malformed_native_status" >&2
  exit 1
}

npm_checker="$control/scripts/check_npm_release_age.py"
npm_config="$control/secure/direct-public-registry/.npmrc"
npm_metadata="$control/tests/fixtures/npm-packument.json"

python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 1.0.0 \
  --metadata-file "$npm_metadata" \
  --as-of "$as_of" >"$temporary_directory/npm-accepted.txt"
diff -u "$control/expected-results/npm-release-age-accepted.txt" \
  "$temporary_directory/npm-accepted.txt"

python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 1.1.0 \
  --metadata-file "$npm_metadata" \
  --as-of "$as_of" >"$temporary_directory/npm-boundary.txt"
grep -F "age_hours=168 minimum_hours=168" \
  "$temporary_directory/npm-boundary.txt" >/dev/null

set +e
python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 1.1.1 \
  --metadata-file "$npm_metadata" \
  --as-of "$as_of" >"$temporary_directory/npm-before-boundary.txt"
npm_before_boundary_status=$?
set -e
test "$npm_before_boundary_status" -eq 1 || {
  echo "expected npm release just inside cooldown to exit 1, got $npm_before_boundary_status" >&2
  exit 1
}
grep -F "remaining_hours=1" "$temporary_directory/npm-before-boundary.txt" >/dev/null

set +e
python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 2.0.0 \
  --metadata-file "$npm_metadata" \
  --as-of "$as_of" >"$temporary_directory/npm-wait.txt"
npm_wait_status=$?
set -e
test "$npm_wait_status" -eq 1 || {
  echo "expected fresh npm release exit 1, got $npm_wait_status" >&2
  exit 1
}
diff -u "$control/expected-results/npm-release-age-wait.txt" \
  "$temporary_directory/npm-wait.txt"

set +e
python3 "$npm_checker" \
  --config "$control/insecure/direct-public-registry/.npmrc" \
  --package example-cooldown-package \
  --version 2.0.0 \
  --metadata-file "$npm_metadata" \
  --as-of "$as_of" >"$temporary_directory/npm-insecure-config.txt"
npm_insecure_config_status=$?
set -e
test "$npm_insecure_config_status" -eq 1 || {
  echo "expected insecure npm config exit 1, got $npm_insecure_config_status" >&2
  exit 1
}
diff -u "$control/expected-results/npm-release-age-insecure-config.txt" \
  "$temporary_directory/npm-insecure-config.txt"

set +e
python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 1.0.0 \
  --metadata-file "$temporary_directory/missing-packument.json" \
  --as-of "$as_of" >"$temporary_directory/npm-missing.txt" 2>&1
npm_missing_status=$?
set -e
test "$npm_missing_status" -eq 2 || {
  echo "expected missing npm metadata exit 2, got $npm_missing_status" >&2
  exit 1
}
grep -F "ERROR cannot read registry metadata fixture" \
  "$temporary_directory/npm-missing.txt" >/dev/null

printf '%s\n' '{"name":' >"$temporary_directory/malformed-packument.json"
set +e
python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 1.0.0 \
  --metadata-file "$temporary_directory/malformed-packument.json" \
  --as-of "$as_of" >"$temporary_directory/npm-malformed.txt" 2>&1
npm_malformed_status=$?
set -e
test "$npm_malformed_status" -eq 2 || {
  echo "expected malformed npm metadata exit 2, got $npm_malformed_status" >&2
  exit 1
}

printf '%s\n' \
  'registry=https://example-token:example-secret@registry.npmjs.org/' \
  'min-release-age=7' \
  'save-exact=true' \
  'package-lock=true' >"$temporary_directory/credential-npmrc"
set +e
python3 "$npm_checker" \
  --config "$temporary_directory/credential-npmrc" \
  --package example-cooldown-package \
  --version 1.0.0 \
  --metadata-file "$npm_metadata" \
  --as-of "$as_of" >"$temporary_directory/npm-credential.txt" 2>&1
npm_credential_status=$?
set -e
test "$npm_credential_status" -eq 2 || {
  echo "expected credential-bearing npm config exit 2, got $npm_credential_status" >&2
  exit 1
}
if grep -F "example-secret" "$temporary_directory/npm-credential.txt" >/dev/null; then
  echo "npm checker leaked a credential value" >&2
  exit 1
fi

set +e
python3 "$npm_checker" \
  --config "$npm_config" \
  --package example-cooldown-package \
  --version 1.0.0 \
  --live \
  --as-of "$as_of" >"$temporary_directory/npm-live-clock.txt" 2>&1
npm_live_clock_status=$?
set -e
test "$npm_live_clock_status" -eq 2 || {
  echo "expected live clock override exit 2, got $npm_live_clock_status" >&2
  exit 1
}
grep -F "ERROR --as-of cannot override the clock in --live mode" \
  "$temporary_directory/npm-live-clock.txt" >/dev/null

echo "PASS stable and exact-exception dependencies accepted"
echo "PASS zero cooldown fresh version unapproved registry and missing integrity rejected"
echo "PASS expired cooldown exception rejected"
echo "PASS tampered artifact rejected"
echo "PASS missing and malformed metadata fail closed"
echo "PASS managed registry proxy enforced and malformed proxy policy fails closed"
echo "PASS native cooldown clients preserve the baseline and reject persistent bypasses"
echo "PASS direct-public npm age check accepts the boundary and waits before it"
echo "PASS direct-public npm config weakening metadata failure and clock override fail closed"
echo "PASS direct-public npm checker redacts credential-bearing configuration"
