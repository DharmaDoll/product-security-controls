#!/usr/bin/env bash
set -euo pipefail

control="controls/detection-verification/integrity-verified-scanner"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" release \
  "$control/secure/policy.json" \
  "$control/secure/release-receipt.json" \
  >"$temporary_directory/secure-release.txt"
diff -u \
  "$control/expected-results/secure-release.txt" \
  "$temporary_directory/secure-release.txt"

set +e
python3 "$control/scripts/verify.py" release \
  "$control/secure/policy.json" \
  "$control/insecure/release-receipt.json" \
  >"$temporary_directory/insecure-release.txt"
insecure_release_status=$?
set -e
test "$insecure_release_status" -eq 1
diff -u \
  "$control/expected-results/insecure-release.txt" \
  "$temporary_directory/insecure-release.txt"

printf 'PSB synthetic artifact\n' >"$temporary_directory/artifact"
python3 "$control/scripts/verify.py" artifact \
  "$temporary_directory/artifact" \
  832d0f3255181a3235746bb850d9327dc4183a795ca2fa294891ee3ddf7a46e3 \
  >"$temporary_directory/artifact.txt"
printf 'tampered\n' >"$temporary_directory/artifact"
set +e
python3 "$control/scripts/verify.py" artifact \
  "$temporary_directory/artifact" \
  832d0f3255181a3235746bb850d9327dc4183a795ca2fa294891ee3ddf7a46e3 \
  >>"$temporary_directory/artifact.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 1
diff -u \
  "$control/expected-results/artifact.txt" \
  "$temporary_directory/artifact.txt"

python3 "$control/scripts/verify.py" result \
  "$control/secure/policy.json" \
  "$control/secure/database-metadata.json" \
  "$control/secure/results/clean.json" \
  >"$temporary_directory/clean.txt"
diff -u \
  "$control/expected-results/clean.txt" \
  "$temporary_directory/clean.txt"

: >"$temporary_directory/findings.txt"
for result in \
  vulnerability \
  container-misconfiguration \
  iac-misconfiguration \
  secret \
  sbom-vulnerability
do
  set +e
  python3 "$control/scripts/verify.py" result \
    "$control/secure/policy.json" \
    "$control/secure/database-metadata.json" \
    "$control/secure/results/${result}.json" \
    >>"$temporary_directory/findings.txt"
  finding_status=$?
  set -e
  test "$finding_status" -eq 1
done
diff -u \
  "$control/expected-results/findings.txt" \
  "$temporary_directory/findings.txt"

: >"$temporary_directory/errors.txt"
for result in scanner-error database-mismatch secret-leak
do
  set +e
  python3 "$control/scripts/verify.py" result \
    "$control/secure/policy.json" \
    "$control/secure/database-metadata.json" \
    "$control/insecure/results/${result}.json" \
    >>"$temporary_directory/errors.txt"
  error_status=$?
  set -e
  test "$error_status" -eq 2
done
printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$control/scripts/verify.py" result \
  "$control/secure/policy.json" \
  "$control/secure/database-metadata.json" \
  "$temporary_directory/malformed.json" \
  >>"$temporary_directory/errors.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
diff -u \
  "$control/expected-results/errors.txt" \
  "$temporary_directory/errors.txt"

: >"$temporary_directory/exceptions.txt"
python3 "$control/scripts/verify.py" exception \
  "$control/secure/policy.json" \
  "$control/secure/exception.json" \
  --at 2026-07-30T00:00:00Z \
  >>"$temporary_directory/exceptions.txt"
set +e
python3 "$control/scripts/verify.py" exception \
  "$control/secure/policy.json" \
  "$control/insecure/exception.json" \
  --at 2026-07-30T00:00:00Z \
  >>"$temporary_directory/exceptions.txt"
broad_exception_status=$?
python3 "$control/scripts/verify.py" exception \
  "$control/secure/policy.json" \
  "$control/secure/exception.json" \
  --at 2026-08-16T00:00:00Z \
  >>"$temporary_directory/exceptions.txt"
expired_exception_status=$?
set -e
test "$broad_exception_status" -eq 1
test "$expired_exception_status" -eq 1
diff -u \
  "$control/expected-results/exceptions.txt" \
  "$temporary_directory/exceptions.txt"

python3 "$control/scripts/verify.py" comparison \
  "$control/secure/checkov-comparison.json" \
  >"$temporary_directory/comparison.txt"
diff -u \
  "$control/expected-results/comparison.txt" \
  "$temporary_directory/comparison.txt"

python3 "$control/scripts/verify.py" docksec-profile \
  "$control/secure/docksec-profile.json" \
  >"$temporary_directory/docksec-profile-secure.txt"
diff -u \
  "$control/expected-results/docksec-profile-secure.txt" \
  "$temporary_directory/docksec-profile-secure.txt"

set +e
python3 "$control/scripts/verify.py" docksec-profile \
  "$control/insecure/docksec-profile.json" \
  >"$temporary_directory/docksec-profile-insecure.txt"
docksec_profile_status=$?
set -e
test "$docksec_profile_status" -eq 1
diff -u \
  "$control/expected-results/docksec-profile-insecure.txt" \
  "$temporary_directory/docksec-profile-insecure.txt"

OPENAI_API_KEY="synthetic-not-a-real-key" \
ANTHROPIC_API_KEY="synthetic-not-a-real-key" \
GOOGLE_API_KEY="synthetic-not-a-real-key" \
python3 "$control/scripts/run-docksec-scan-only.py" \
  --docksec "$control/tests/fixtures/fake-docksec.py" \
  --profile "$control/secure/docksec-profile.json" \
  --target "$control/tests/fixtures/fixture-clean.Dockerfile" \
  --output "$temporary_directory/docksec-clean.json" \
  >"$temporary_directory/docksec-clean.txt"
grep -Fx "CLEAN DockSec completed with 0 blocking findings" \
  "$temporary_directory/docksec-clean.txt" >/dev/null
diff -u \
  "$control/expected-results/docksec-clean.json" \
  "$temporary_directory/docksec-clean.json"

set +e
python3 "$control/scripts/run-docksec-scan-only.py" \
  --docksec "$control/tests/fixtures/fake-docksec.py" \
  --profile "$control/secure/docksec-profile.json" \
  --target "$control/tests/fixtures/fixture-finding.Dockerfile" \
  --output "$temporary_directory/docksec-finding.json" \
  >"$temporary_directory/docksec-finding.txt"
docksec_finding_status=$?
set -e
test "$docksec_finding_status" -eq 1
grep -Fx "FINDING DockSec completed with 1 blocking finding(s)" \
  "$temporary_directory/docksec-finding.txt" >/dev/null
diff -u \
  "$control/expected-results/docksec-finding.json" \
  "$temporary_directory/docksec-finding.json"

: >"$temporary_directory/docksec-errors.txt"
for target in usage-error runtime-error malformed ai-output
do
  set +e
  python3 "$control/scripts/run-docksec-scan-only.py" \
    --docksec "$control/tests/fixtures/fake-docksec.py" \
    --profile "$control/secure/docksec-profile.json" \
    --target "$control/tests/fixtures/fixture-${target}.Dockerfile" \
    --output "$temporary_directory/docksec-${target}.json" \
    >>"$temporary_directory/docksec-errors.txt"
  docksec_error_status=$?
  set -e
  test "$docksec_error_status" -eq 2
  test ! -e "$temporary_directory/docksec-${target}.json"
done
diff -u \
  "$control/expected-results/docksec-errors.txt" \
  "$temporary_directory/docksec-errors.txt"

python3 "$control/scripts/normalize-trivy.py" \
  "$control/tests/fixtures/raw-trivy-secret.json" \
  "$control/secure/database-metadata.json" \
  filesystem \
  "$temporary_directory/normalized-secret.json" \
  --target fixtures/secrets \
  --categories secret \
  >/dev/null
if rg -q '"(Match|match|secret|value|content|code|line|snippet)"[[:space:]]*:' \
  "$temporary_directory/normalized-secret.json"
then
  echo "normalized evidence retained a prohibited secret field" >&2
  exit 1
fi
set +e
python3 "$control/scripts/verify.py" result \
  "$control/secure/policy.json" \
  "$control/secure/database-metadata.json" \
  "$temporary_directory/normalized-secret.json" \
  >/dev/null
normalized_finding_status=$?
set -e
test "$normalized_finding_status" -eq 1

python3 "$control/scripts/normalize-trivy.py" \
  "$control/tests/fixtures/raw-trivy-clean.json" \
  "$control/secure/database-metadata.json" \
  filesystem \
  "$temporary_directory/normalized-clean.json" \
  --target fixtures/clean \
  --categories vulnerability,iac-misconfiguration,secret \
  >/dev/null
python3 "$control/scripts/verify.py" result \
  "$control/secure/policy.json" \
  "$control/secure/database-metadata.json" \
  "$temporary_directory/normalized-clean.json" \
  >/dev/null

set +e
bash "$control/scripts/run-trivy-offline.sh" \
  --trivy "$temporary_directory/missing-trivy" \
  --cache-directory "$temporary_directory/missing-cache" \
  --target "$control/tests/fixtures/raw-trivy-clean.json" \
  --output "$temporary_directory/raw.json" \
  >/dev/null 2>&1
missing_scanner_status=$?
set -e
test "$missing_scanner_status" -eq 2

for required in \
  bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea \
  0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e \
  ebe9d19a774b950e240b1017a038e9b5a002ea068e02023369ff6d241c10c580 \
  fccbe7d4877af44f27e205528626dfeb3ff6efac57c22061f1fccb59e8a80007 \
  --offline-scan \
  --skip-db-update \
  --skip-check-update \
  --skip-vex-repo-update
do
  rg -F -- "$required" "$control/scripts/" >/dev/null
done
rg -F 'api.github.com/repos/aquasecurity/trivy/releases/tags/' \
  "$control/scripts/fetch-trivy.sh" >/dev/null

echo "PASS pinned Trivy release integrity and affected-version rejection verified"
echo "PASS clean findings and scanner errors use distinct exit states"
echo "PASS vulnerability container IaC secret and SBOM fixtures block"
echo "PASS evidence normalization removes matched secret values"
echo "PASS unavailable scanner database mismatch and malformed result fail closed"
echo "PASS exceptions are exact independently approved and time-bound"
echo "PASS Checkov remains evaluation-only without a documented coverage gap"
echo "PASS DockSec optional remediation adapter has a unique non-authoritative role"
echo "PASS DockSec scan-only clean finding usage and runtime errors fail closed"
echo "PASS DockSec gate strips AI credentials and rejects AI output"
echo "PASS explicit offline runner and explicit network fetch boundary verified"
