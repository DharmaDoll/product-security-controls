#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
repository_root="$(cd "$control_dir/../../.." && pwd)"
verify="$control_dir/scripts/verify.py"
policy="$control_dir/secure/policy.json"
session="$control_dir/secure/workload-session.json"
corpus="$control_dir/secure/scenario-corpus.json"
secure_evidence="$control_dir/secure/gateway-evidence.json"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-ai-010.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local session_input="$3"
  local evidence="$4"
  local expected_result="$5"
  local actual_exit=0

  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --workload-session "$session_input" \
    --corpus "$corpus" \
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
  local evidence="$2"
  local openssl_path="${3:-/usr/bin/openssl}"
  local actual_exit=0

  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --workload-session "$session" \
    --corpus "$corpus" \
    --evidence "$evidence" \
    --openssl "$openssl_path" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne 2 ]]; then
    echo "FAIL $case_name exit: expected=2 actual=$actual_exit"
    exit 1
  fi
  grep -F "ERROR PSB-AI-010/EVIDENCE" "$temporary_directory/$case_name.txt" >/dev/null
}

run_case secure 0 "$session" "$secure_evidence" secure.txt
run_case insecure 1 "$session" "$control_dir/insecure/gateway-evidence.json" insecure.txt

forged_exit=0
python3 "$verify" \
  --repository-root "$repository_root" \
  --policy "$policy" \
  --workload-session "$control_dir/insecure/workload-session.json" \
  --corpus "$corpus" \
  --evidence "$secure_evidence" \
  >"$temporary_directory/forged-session.txt" || forged_exit=$?
if [[ "$forged_exit" -ne 1 ]]; then
  echo "FAIL forged-session exit: expected=1 actual=$forged_exit"
  exit 1
fi
grep -F "FAIL PSB-AI-010/AIG-002" "$temporary_directory/forged-session.txt" >/dev/null

run_error_case malformed "$control_dir/tests/fixtures/malformed.json"
run_error_case unavailable "$control_dir/tests/fixtures/unavailable-evidence.json"
run_error_case sensitive "$control_dir/tests/fixtures/sensitive-evidence.json"
run_error_case crypto-unavailable "$secure_evidence" "/nonexistent/openssl"

echo "PASS authenticated approved application gateway route and data policy verified"
echo "PASS bypass unapproved target sensitive oversized forged and overclaim cases rejected"
echo "PASS malformed unavailable crypto and sensitive evidence remained ERROR"
