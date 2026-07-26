#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/actions-command-injection"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" "$control/secure/workflow.yml" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

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
  echo "expected verifier error exit 2, got $error_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Unsupported run alias" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  "      - run: *shared-command" \
  >"$temporary_directory/unsupported.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/unsupported.yml" \
  >"$temporary_directory/unsupported.txt" 2>&1
unsupported_status=$?
set -e
test "$unsupported_status" -eq 2 || {
  echo "expected unsupported syntax exit 2, got $unsupported_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Unsupported multiline quoted run" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  '      - run: "printf %s' \
  '          ${{ github.event.issue.title }}"' \
  >"$temporary_directory/multiline-quoted.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/multiline-quoted.yml" \
  >"$temporary_directory/multiline-quoted.txt" 2>&1
multiline_quoted_status=$?
set -e
test "$multiline_quoted_status" -eq 2 || {
  echo "expected multiline quoted syntax exit 2, got $multiline_quoted_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Split expression" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  "      - run: >" \
  '          printf "%s\\n" "${{' \
  '          github.event.issue.title }}"' \
  >"$temporary_directory/split-expression.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/split-expression.yml" \
  >"$temporary_directory/split-expression.txt"
split_status=$?
set -e
test "$split_status" -eq 1 || {
  echo "expected split expression exit 1, got $split_status" >&2
  exit 1
}

echo "PASS secure env boundary accepted"
echo "PASS insecure direct expressions rejected"
echo "PASS repository workflows contain no direct run expressions"
echo "PASS verifier execution error distinguished from policy violation"
echo "PASS unsupported run syntax fails closed"
echo "PASS multiline quoted run syntax fails closed"
echo "PASS multiline expressions are rejected"
