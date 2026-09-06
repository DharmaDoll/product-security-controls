#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/actions-command-injection"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

bash "$control/scripts/self-test.sh" >"$temporary_directory/self-test.txt"
diff -u "$control/expected-results/self-test.txt" \
  "$temporary_directory/self-test.txt"

adopter="$temporary_directory/adopter"
mkdir -p "$adopter/.security/actions-command-injection"
mkdir -p "$adopter/.github/workflows"
cp "$control/scripts/verify.py" \
  "$adopter/.security/actions-command-injection/verify.py"
cp "$control/scripts/self-test.sh" \
  "$adopter/.security/actions-command-injection/self-test.sh"
cp "$control/secure/local-gate.yml" \
  "$adopter/.github/workflows/actions-command-injection.yml"
bash "$adopter/.security/actions-command-injection/self-test.sh" \
  >"$temporary_directory/copied-self-test.txt"
diff -u "$control/expected-results/self-test.txt" \
  "$temporary_directory/copied-self-test.txt"
(
  cd "$adopter"
  python3 .security/actions-command-injection/verify.py .github/workflows
) >"$temporary_directory/copied-local-gate.txt"
diff -u "$control/expected-results/local-gate.txt" \
  "$temporary_directory/copied-local-gate.txt"

python3 "$control/scripts/verify.py" "$control/secure/workflow.yml" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

python3 "$control/scripts/verify.py" "$control/secure/local-gate.yml" \
  >"$temporary_directory/local-gate.txt"
diff -u "$control/expected-results/local-gate.txt" \
  "$temporary_directory/local-gate.txt"

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

printf '%s\n' \
  "name: No run steps" \
  "jobs:" \
  "  metadata:" \
  "    uses: example.invalid/reusable.yml" \
  >"$temporary_directory/no-run.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/no-run.yml" \
  >"$temporary_directory/no-run.txt" 2>&1
no_run_status=$?
set -e
test "$no_run_status" -eq 2 || {
  echo "expected no run steps exit 2, got $no_run_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Flow-style run" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  '    steps: [{run: "printf safe"}]' \
  >"$temporary_directory/flow-style.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/flow-style.yml" \
  >"$temporary_directory/flow-style.txt" 2>&1
flow_style_status=$?
set -e
test "$flow_style_status" -eq 2 || {
  echo "expected flow-style run exit 2, got $flow_style_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Unterminated expression" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  '      - run: printf "%s\n" "${{ github.event.issue.title"' \
  >"$temporary_directory/unterminated-expression.yml"
set +e
python3 "$control/scripts/verify.py" \
  "$temporary_directory/unterminated-expression.yml" \
  >"$temporary_directory/unterminated-expression.txt" 2>&1
unterminated_expression_status=$?
set -e
test "$unterminated_expression_status" -eq 2 || {
  echo "expected unterminated expression exit 2, got $unterminated_expression_status" >&2
  exit 1
}

printf '%s\n' \
  "name: Tab-indented run block" \
  "jobs:" \
  "  verify:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  "      - run: |" \
  $'\tprintf safe' \
  >"$temporary_directory/tab-indented.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/tab-indented.yml" \
  >"$temporary_directory/tab-indented.txt" 2>&1
tab_indented_status=$?
set -e
test "$tab_indented_status" -eq 2 || {
  echo "expected tab indentation exit 2, got $tab_indented_status" >&2
  exit 1
}

printf '\377' >"$temporary_directory/invalid-utf8.yml"
set +e
python3 "$control/scripts/verify.py" "$temporary_directory/invalid-utf8.yml" \
  >"$temporary_directory/invalid-utf8.txt" 2>&1
invalid_utf8_status=$?
set -e
test "$invalid_utf8_status" -eq 2 || {
  echo "expected invalid UTF-8 exit 2, got $invalid_utf8_status" >&2
  exit 1
}

set +e
bash "$control/scripts/self-test.sh" "$temporary_directory/missing-verifier.py" \
  >"$temporary_directory/missing-verifier.txt" 2>&1
missing_verifier_status=$?
set -e
test "$missing_verifier_status" -eq 2 || {
  echo "expected missing verifier exit 2, got $missing_verifier_status" >&2
  exit 1
}

bash_path="$(command -v bash)"
set +e
PATH=/nonexistent "$bash_path" "$control/scripts/self-test.sh" \
  >"$temporary_directory/missing-python.txt" 2>&1
missing_python_status=$?
set -e
test "$missing_python_status" -eq 2 || {
  echo "expected missing python3 exit 2, got $missing_python_status" >&2
  exit 1
}

echo "PASS secure env boundary accepted"
echo "PASS insecure direct expressions rejected"
echo "PASS copyable local gate accepted"
echo "PASS documented three-file adoption path works in a temporary repository"
echo "PASS repository workflows contain no direct run expressions"
echo "PASS inert shell metacharacters remain data"
echo "PASS verifier execution error distinguished from policy violation"
echo "PASS unsupported run syntax fails closed"
echo "PASS multiline quoted run syntax fails closed"
echo "PASS multiline expressions are rejected"
echo "PASS missing run steps fail closed"
echo "PASS flow-style run syntax fails closed"
echo "PASS malformed expressions fail closed"
echo "PASS tab indentation and invalid UTF-8 fail closed"
echo "PASS missing verifier and Python runtime fail closed"
