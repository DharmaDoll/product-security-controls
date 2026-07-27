#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/actions-static-analysis"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" workflow "$control/secure/workflow.yml" \
  >"$temporary_directory/secure-workflow.txt"
diff -u \
  "$control/expected-results/secure-workflow.txt" \
  "$temporary_directory/secure-workflow.txt"

set +e
python3 "$control/scripts/verify.py" workflow "$control/insecure/workflow.yml" \
  >"$temporary_directory/insecure-workflow.txt"
insecure_workflow_status=$?
set -e
test "$insecure_workflow_status" -eq 1 || {
  echo "expected insecure workflow exit 1, got $insecure_workflow_status" >&2
  exit 1
}
diff -u \
  "$control/expected-results/insecure-workflow.txt" \
  "$temporary_directory/insecure-workflow.txt"

python3 "$control/scripts/verify.py" sarif "$control/secure/clean.sarif" \
  >"$temporary_directory/clean-sarif.txt"
diff -u \
  "$control/expected-results/clean-sarif.txt" \
  "$temporary_directory/clean-sarif.txt"

set +e
python3 "$control/scripts/verify.py" sarif "$control/insecure/finding.sarif" \
  >"$temporary_directory/finding-sarif.txt"
finding_status=$?
set -e
test "$finding_status" -eq 1 || {
  echo "expected finding SARIF exit 1, got $finding_status" >&2
  exit 1
}
diff -u \
  "$control/expected-results/finding-sarif.txt" \
  "$temporary_directory/finding-sarif.txt"

set +e
python3 "$control/scripts/verify.py" sarif "$control/insecure/scanner-error.sarif" \
  >"$temporary_directory/scanner-error.txt" 2>&1
scanner_error_status=$?
set -e
test "$scanner_error_status" -eq 2 || {
  echo "expected scanner failure exit 2, got $scanner_error_status" >&2
  exit 1
}
diff -u \
  "$control/expected-results/scanner-error.txt" \
  "$temporary_directory/scanner-error.txt"

printf '{not-json}\n' >"$temporary_directory/malformed.sarif"
set +e
python3 "$control/scripts/verify.py" sarif "$temporary_directory/malformed.sarif" \
  >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2 || {
  echo "expected malformed SARIF exit 2, got $malformed_status" >&2
  exit 1
}

cmp "$control/secure/workflow.yml" .github/workflows/actions-security.yml

echo "PASS secure scanner workflow policy accepted"
echo "PASS mutable and over-privileged scanner workflow rejected"
echo "PASS clean and finding SARIF states distinguished"
echo "PASS scanner execution failure distinguished from a clean result"
echo "PASS malformed SARIF fails closed"
echo "PASS adopted workflow matches the reviewed secure example"
