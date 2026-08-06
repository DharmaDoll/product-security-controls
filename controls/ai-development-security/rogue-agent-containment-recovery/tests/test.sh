#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
repository_root="$(cd "$control_dir/../../.." && pwd)"
verify="$control_dir/scripts/verify.py"
policy="$control_dir/secure/policy.json"
trigger="$control_dir/secure/trigger-evidence.json"
secure_containment="$control_dir/secure/containment-command.json"
secure_recovery="$control_dir/secure/recovery-authorization.json"
secure_evidence="$control_dir/secure/incident-evidence.json"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-ai-009.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local containment="$3"
  local recovery="$4"
  local evidence="$5"
  local expected_result="$6"
  local actual_exit=0

  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --trigger "$trigger" \
    --containment-command "$containment" \
    --recovery-authorization "$recovery" \
    --evidence "$evidence" \
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
  local trigger_input="$2"
  local evidence="$3"
  local openssl_path="${4:-/usr/bin/openssl}"
  local actual_exit=0

  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --trigger "$trigger_input" \
    --containment-command "$secure_containment" \
    --recovery-authorization "$secure_recovery" \
    --evidence "$evidence" \
    --openssl "$openssl_path" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne 2 ]]; then
    echo "FAIL $case_name exit: expected=2 actual=$actual_exit"
    exit 1
  fi
  grep -F "ERROR PSB-AI-009/EVIDENCE" "$temporary_directory/$case_name.txt" >/dev/null
}

run_case secure 0 \
  "$secure_containment" \
  "$secure_recovery" \
  "$secure_evidence" \
  secure.txt
run_case insecure 1 \
  "$control_dir/insecure/containment-command.json" \
  "$control_dir/insecure/recovery-authorization.json" \
  "$control_dir/insecure/incident-evidence.json" \
  insecure.txt

run_error_case malformed "$trigger" "$control_dir/tests/fixtures/malformed.json"
run_error_case unavailable-trigger "$control_dir/tests/fixtures/unavailable-trigger.json" "$secure_evidence"
run_error_case sensitive "$trigger" "$control_dir/tests/fixtures/sensitive-evidence.json"
run_error_case crypto-unavailable "$trigger" "$secure_evidence" "/nonexistent/openssl"

echo "PASS independent signed containment and bounded recovery verified"
echo "PASS continued authority unsafe fallback premature restore and overclaim rejected"
echo "PASS malformed unavailable crypto and sensitive evidence remained ERROR"
