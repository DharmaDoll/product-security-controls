#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
repository_root="$(cd "$control_dir/../../.." && pwd)"
verify="$control_dir/scripts/verify.py"
policy="$control_dir/secure/policy.json"
secure_delegation="$control_dir/secure/delegation-envelope.json"
secure_response="$control_dir/secure/response-envelope.json"
secure_evidence="$control_dir/secure/execution-evidence.json"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-ai-008.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local delegation="$3"
  local response="$4"
  local evidence="$5"
  local expected_result="$6"
  local openssl_path="${7:-/usr/bin/openssl}"
  local actual_exit=0

  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --delegation "$delegation" \
    --response "$response" \
    --evidence "$evidence" \
    --openssl "$openssl_path" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_error_case() {
  local case_name="$1"
  local delegation="$2"
  local evidence="$3"
  local openssl_path="${4:-/usr/bin/openssl}"
  local actual_exit=0

  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --delegation "$delegation" \
    --response "$secure_response" \
    --evidence "$evidence" \
    --openssl "$openssl_path" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne 2 ]]; then
    echo "FAIL $case_name exit: expected=2 actual=$actual_exit"
    exit 1
  fi
  grep -F "ERROR PSB-AI-008/EVIDENCE" "$temporary_directory/$case_name.txt" >/dev/null
}

run_case secure 0 "$secure_delegation" "$secure_response" "$secure_evidence" secure.txt
run_case insecure 1 \
  "$control_dir/insecure/delegation-envelope.json" \
  "$secure_response" \
  "$control_dir/insecure/execution-evidence.json" \
  insecure.txt

run_error_case malformed "$control_dir/tests/fixtures/malformed.json" "$secure_evidence"
run_error_case evaluator-unavailable "$secure_delegation" "$control_dir/tests/fixtures/unavailable-evaluator.json"
run_error_case sensitive "$secure_delegation" "$control_dir/tests/fixtures/sensitive-evidence.json"
run_error_case crypto-unavailable "$secure_delegation" "$secure_evidence" "/nonexistent/openssl"

echo "PASS authenticated delegation capability data budget replay and response binding verified"
echo "PASS forged escalated cross-tenant replayed onward and ambient behavior rejected"
echo "PASS malformed unavailable evaluator crypto and sensitive evidence remained ERROR"
