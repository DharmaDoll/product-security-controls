#!/usr/bin/env bash
set -euo pipefail

control="controls/governance-operations/supply-chain-incident-readiness"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

set +e
python3 "$control/scripts/respond.py" \
  --package compromised-lib \
  --version 4.2.0 \
  --inventory-dir "$control/secure/inventory" \
  --records "$control/secure/build-records.json" \
  --runbook "$control/secure/runbook.json" \
  --dry-run >"$temporary_directory/detected.txt"
detected_status=$?
set -e
test "$detected_status" -eq 1
diff -u "$control/expected-results/detected.txt" "$temporary_directory/detected.txt"

set +e
python3 "$control/scripts/respond.py" \
  --package compromised-lib \
  --version 4.2.0 \
  --inventory-dir "$control/secure/inventory" \
  --records "$control/secure/build-records.json" \
  --runbook "$control/secure/runbook.json" \
  --dependency-track-policy "$control/secure/dependency-track-policy.json" \
  --dependency-track-response "$control/secure/dependency-track-response.json" \
  --vulnerability-id CVE-2026-4242 \
  --dry-run >"$temporary_directory/dependency-track-detected.txt"
dependency_track_status=$?
set -e
test "$dependency_track_status" -eq 1
diff -u \
  "$control/expected-results/dependency-track-detected.txt" \
  "$temporary_directory/dependency-track-detected.txt"

python3 "$control/scripts/respond.py" \
  --package absent-lib \
  --version 1.0.0 \
  --inventory-dir "$control/secure/inventory" \
  --records "$control/secure/build-records.json" \
  --runbook "$control/secure/runbook.json" \
  --dry-run >"$temporary_directory/clean.txt"
diff -u "$control/expected-results/clean.txt" "$temporary_directory/clean.txt"

set +e
python3 "$control/scripts/respond.py" \
  --package compromised-lib \
  --version 4.2.0 \
  --inventory-dir "$control/insecure/inventory" \
  --records "$control/insecure/build-records.json" \
  --runbook "$control/insecure/runbook.json" \
  --dry-run >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

printf '%s\n' '{"bomFormat":' >"$temporary_directory/broken.cdx.json"
set +e
python3 "$control/scripts/respond.py" \
  --package compromised-lib \
  --version 4.2.0 \
  --inventory-dir "$temporary_directory" \
  --records "$control/secure/build-records.json" \
  --runbook "$control/secure/runbook.json" \
  --dry-run >"$temporary_directory/error.txt" 2>&1
error_status=$?
set -e
test "$error_status" -eq 2

for response in \
  "$control/insecure/dependency-track-response.json" \
  "$control/tests/fixtures/dependency-track-unavailable.json"; do
  dependency_track_error_status=0
  python3 "$control/scripts/respond.py" \
    --package compromised-lib \
    --version 4.2.0 \
    --inventory-dir "$control/secure/inventory" \
    --records "$control/secure/build-records.json" \
    --runbook "$control/secure/runbook.json" \
    --dependency-track-policy "$control/secure/dependency-track-policy.json" \
    --dependency-track-response "$response" \
    --vulnerability-id CVE-2026-4242 \
    --dry-run >"$temporary_directory/dependency-track-error.txt" \
    || dependency_track_error_status=$?
  test "$dependency_track_error_status" -eq 2
  grep -F "ERROR verification unavailable:" \
    "$temporary_directory/dependency-track-error.txt" >/dev/null
done

echo "PASS impacted products and evidence identified"
echo "PASS clean inventory distinguished from detection"
echo "PASS incomplete inventory and unsafe runbook rejected"
echo "PASS malformed SBOM fails closed"
echo "PASS Dependency-Track exact CVE PURL portfolio impact is evidence-linked"
echo "PASS Dependency-Track incomplete pagination and outage remain ERROR"
