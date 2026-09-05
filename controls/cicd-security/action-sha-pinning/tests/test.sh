#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/action-sha-pinning"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" "$control/secure/workflow.yml" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

python3 "$control/scripts/verify.py" "$control/secure/verify-action-pinning.yml" \
  >"$temporary_directory/adoption-workflow.txt"

set +e
python3 "$control/scripts/verify.py" "$control/insecure/workflow.yml" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure fixture exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

python3 "$control/scripts/verify.py" .github/workflows \
  >"$temporary_directory/repository-workflows.txt"

set +e
python3 "$control/scripts/verify.py" "$temporary_directory/missing.yml" \
  >"$temporary_directory/error.txt" 2>&1
error_status=$?
set -e
test "$error_status" -eq 2 || {
  echo "expected missing input exit 2, got $error_status" >&2
  exit 1
}

echo "PASS secure immutable references accepted"
echo "PASS copyable adoption workflow accepted"
echo "PASS insecure mutable references rejected"
echo "PASS repository workflows use immutable references"
echo "PASS unavailable input fails closed"
