#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.sh"
assess="$control_dir/assessment/assess.py"
validate_assessment="$control_dir/tests/validate-assessment.py"
validate_guide="$control_dir/tests/validate-implementation-guide.py"
secure_output="$(mktemp "${TMPDIR:-/tmp}/psb-source-001-secure.XXXXXX")"
insecure_output="$(mktemp "${TMPDIR:-/tmp}/psb-source-001-insecure.XXXXXX")"
assessment_tmp="$(mktemp -d "${TMPDIR:-/tmp}/psb-source-001-assessment.XXXXXX")"
trap 'rm -f "$secure_output" "$insecure_output"; rm -rf -- "$assessment_tmp"' EXIT

python3 "$validate_guide"

"${BASH:-bash}" "$verify" secure >"$secure_output"
diff -u "$control_dir/expected-results/secure.txt" "$secure_output"

if "${BASH:-bash}" "$verify" insecure >"$insecure_output" 2>&1; then
  echo "FAIL insecure fixture was accepted"
  cat "$insecure_output"
  exit 1
fi

diff -u "$control_dir/expected-results/insecure.txt" "$insecure_output"
echo "PASS secure fixture matched expected evidence"
echo "PASS insecure fixture was rejected"

run_assessment_fixture() {
  local name="$1" expected_exit="$2" actual_exit=0
  python3 "$assess" \
    --workspace "$control_dir" \
    --fixture "$control_dir/tests/fixtures/linux-$name.json" \
    --json-output "$assessment_tmp/$name.json" \
    --csv-output "$assessment_tmp/$name.csv" \
    >"$assessment_tmp/$name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $name assessment exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u \
    "$control_dir/expected-results/assessment-$name.txt" \
    "$assessment_tmp/$name.txt"
  python3 "$validate_assessment" \
    "$assessment_tmp/$name.json" \
    "$assessment_tmp/$name.csv" \
    --source test-fixture \
    --expected-exit "$expected_exit"
}

run_assessment_fixture secure 3
run_assessment_fixture insecure 1
run_assessment_fixture error 2

live_exit=0
python3 "$assess" \
  --workspace "$control_dir" \
  --json-output "$assessment_tmp/live.json" \
  --csv-output "$assessment_tmp/live.csv" \
  >"$assessment_tmp/live.txt" || live_exit=$?
case "$live_exit" in
  0|1|2|3) ;;
  *)
    echo "FAIL live assessment returned unsupported exit $live_exit"
    exit 1
    ;;
esac
python3 "$validate_assessment" \
  "$assessment_tmp/live.json" \
  "$assessment_tmp/live.csv" \
  --source live \
  --expected-exit "$live_exit"

malformed_exit=0
python3 "$assess" \
  --workspace "$control_dir" \
  --fixture "$control_dir/expected-results/secure.txt" \
  --json-output "$assessment_tmp/malformed.json" \
  --csv-output "$assessment_tmp/malformed.csv" \
  >"$assessment_tmp/malformed.txt" 2>&1 || malformed_exit=$?
if [[ "$malformed_exit" -ne 2 ]]; then
  echo "FAIL malformed assessment fixture was not an error"
  exit 1
fi

echo "PASS assessment PASS FAIL NOT_CHECKED and ERROR states distinguished"
echo "PASS live read-only assessment produced sanitized JSON and CSV"
