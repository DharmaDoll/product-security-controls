#!/usr/bin/env bash
set -euo pipefail

control="controls/release-integrity/provenance-publication-distribution"
verifier="$control/scripts/verify.py"
secure_policy="$control/secure/publication-policy.json"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-rel-002.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local policy="$3"
  local manifest="$4"
  local expected_result="$5"
  local actual_exit=0

  python3 "$verifier" \
    --policy "$policy" \
    --manifest "$manifest" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_case \
  "secure" 0 \
  "$secure_policy" \
  "$control/secure/release-manifest.json" \
  "secure.txt"
run_case \
  "insecure" 1 \
  "$control/insecure/publication-policy.json" \
  "$control/insecure/release-manifest.json" \
  "insecure.txt"
run_case \
  "secure-policy-rejects-insecure-release" 1 \
  "$secure_policy" \
  "$control/insecure/release-manifest.json" \
  "insecure.txt"
run_case \
  "unavailable" 2 \
  "$secure_policy" \
  "$control/tests/fixtures/unavailable.json" \
  "unavailable.txt"
run_case \
  "malformed" 2 \
  "$secure_policy" \
  "$control/tests/fixtures/malformed.json" \
  "malformed.txt"

if rg -n -i 'credential|password|private[_-]?url|token=' \
  "$temporary_directory"; then
  echo "FAIL generated publication evidence contains sensitive content"
  exit 1
fi

echo "PASS one-to-one provenance publication and immutable discovery accepted"
echo "PASS missing mismatched mutable inaccessible late and short-lived evidence rejected"
echo "PASS protected artifact family cannot silently downgrade provenance"
echo "PASS unavailable and malformed publication evidence remain ERROR"
