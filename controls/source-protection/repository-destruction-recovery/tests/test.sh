#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
assess="$control_dir/assessment/assess.py"
mutate="$control_dir/tests/mutate_fixture.py"
validate_assessment="$control_dir/tests/validate_assessment.py"
policy_id="$control_dir/scripts/policy_id.py"
policy="$control_dir/secure/policy.json"
as_of="2026-08-25T14:00:00Z"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-source-005.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

for check_id in RDR-001 RDR-002 RDR-003 RDR-006; do
  test "$(grep -c "^## $check_id" "$control_dir/docs/check-implementation-guide.md")" -eq 1
done
for label in 目的 最小構成 組織実装 必要証跡 'Harmless self-test' NOT_CHECKED 限界; do
  grep -F "**$label**" "$control_dir/docs/check-implementation-guide.md" >/dev/null
done
python3 "$policy_id" --check "$policy" >"$temporary_directory/policy-id.txt"
grep -Fx "repository-recovery-policy@sha256:a944b38f6e639fdb738f686180fa7f7cd152a8a66498616e440af33fcf747f50" \
  "$temporary_directory/policy-id.txt" >/dev/null

python3 "$verify" \
  --policy "$policy" \
  --evidence "$control_dir/secure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_status=0
python3 "$verify" \
  --policy "$policy" \
  --evidence "$control_dir/insecure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/insecure.txt" || insecure_status=$?
test "$insecure_status" -eq 1
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

run_assessment_fixture() {
  local name="$1" evidence="$2" expected_exit="$3" expected_output="$4"
  local actual_exit=0
  python3 "$assess" \
    --workspace "$control_dir" \
    --policy "$policy" \
    --fixture "$evidence" \
    --as-of "$as_of" \
    --json-output "$temporary_directory/$name.json" \
    --csv-output "$temporary_directory/$name.csv" \
    >"$temporary_directory/$name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $name assessment exit: expected=$expected_exit actual=$actual_exit" >&2
    exit 1
  fi
  if [[ "$expected_output" == "without-source" ]]; then
    diff -u \
      "$control_dir/expected-results/$name.txt" \
      <(tail -n +2 "$temporary_directory/$name.txt")
  else
    diff -u "$control_dir/expected-results/$expected_output" "$temporary_directory/$name.txt"
  fi
  python3 "$validate_assessment" \
    "$temporary_directory/$name.json" \
    "$temporary_directory/$name.csv" \
    --source test-fixture \
    --expected-exit "$expected_exit"
}

run_assessment_fixture \
  secure "$control_dir/secure/evidence.json" 0 without-source
run_assessment_fixture \
  insecure "$control_dir/insecure/evidence.json" 1 without-source
run_assessment_fixture \
  assessment-not-checked "$control_dir/tests/fixtures/not-checked.json" 3 assessment-not-checked.txt
run_assessment_fixture \
  assessment-error "$control_dir/tests/fixtures/error.json" 2 assessment-error.txt

no_evidence_status=0
python3 "$assess" \
  --workspace "$control_dir" \
  --policy "$policy" \
  --as-of "$as_of" \
  --json-output "$temporary_directory/no-evidence.json" \
  --csv-output "$temporary_directory/no-evidence.csv" \
  >"$temporary_directory/no-evidence.txt" || no_evidence_status=$?
test "$no_evidence_status" -eq 3
grep -F "SOURCE no-organization-evidence" "$temporary_directory/no-evidence.txt" >/dev/null
grep -F "INCOMPLETE 4 check(s) require organization evidence" \
  "$temporary_directory/no-evidence.txt" >/dev/null
python3 "$validate_assessment" \
  "$temporary_directory/no-evidence.json" \
  "$temporary_directory/no-evidence.csv" \
  --source no-organization-evidence \
  --expected-exit 3

for scenario in stale partial; do
  python3 "$mutate" \
    --source "$control_dir/secure/evidence.json" \
    --output "$temporary_directory/$scenario.json" \
    --scenario "$scenario"
  scenario_status=0
  python3 "$verify" \
    --policy "$policy" \
    --evidence "$temporary_directory/$scenario.json" \
    --as-of "$as_of" \
    >"$temporary_directory/$scenario.txt" 2>&1 || scenario_status=$?
  test "$scenario_status" -eq 2
done
grep -F "ERROR RDR-001 inventory evidence is stale or from the future" \
  "$temporary_directory/stale.txt" >/dev/null
grep -F "ERROR RDR-001 inventory pagination is incomplete" \
  "$temporary_directory/partial.txt" >/dev/null

python3 "$mutate" \
  --source "$control_dir/secure/evidence.json" \
  --output "$temporary_directory/missing-repository.json" \
  --scenario missing-repository
missing_status=0
python3 "$verify" \
  --policy "$policy" \
  --evidence "$temporary_directory/missing-repository.json" \
  --as-of "$as_of" \
  >"$temporary_directory/missing-repository.txt" || missing_status=$?
test "$missing_status" -eq 1
grep -F "FAIL RDR-001 inventory does not exactly cover required stable repository IDs" \
  "$temporary_directory/missing-repository.txt" >/dev/null

python3 "$mutate" \
  --source "$control_dir/secure/evidence.json" \
  --output "$temporary_directory/mismatch.json" \
  --scenario mismatch
mismatch_status=0
python3 "$verify" \
  --policy "$policy" \
  --evidence "$temporary_directory/mismatch.json" \
  --as-of "$as_of" \
  >"$temporary_directory/mismatch.txt" || mismatch_status=$?
test "$mismatch_status" -eq 1
grep -F "FAIL RDR-006 repository 1001 restored content_digest does not match the recovery copy" \
  "$temporary_directory/mismatch.txt" >/dev/null

python3 "$mutate" \
  --source "$policy" \
  --output "$temporary_directory/weakened-policy.json" \
  --scenario weakened-policy
python3 "$mutate" \
  --source "$control_dir/secure/evidence.json" \
  --policy "$temporary_directory/weakened-policy.json" \
  --output "$temporary_directory/weakened-policy-evidence.json" \
  --scenario bind-policy
weakened_status=0
python3 "$verify" \
  --policy "$temporary_directory/weakened-policy.json" \
  --evidence "$temporary_directory/weakened-policy-evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/weakened-policy.txt" || weakened_status=$?
test "$weakened_status" -eq 1
grep -F "FAIL RDR-002 policy permits more than one repository target per destructive request" \
  "$temporary_directory/weakened-policy.txt" >/dev/null

sed 's/a944b38f/00000000/' "$policy" >"$temporary_directory/tampered-policy.json"
tampered_status=0
python3 "$verify" \
  --policy "$temporary_directory/tampered-policy.json" \
  --evidence "$control_dir/secure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/tampered-policy.txt" 2>&1 || tampered_status=$?
test "$tampered_status" -eq 2
grep -F "policy_id does not match canonical policy content" \
  "$temporary_directory/tampered-policy.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed.json"
malformed_status=0
python3 "$assess" \
  --workspace "$control_dir" \
  --policy "$policy" \
  --fixture "$temporary_directory/malformed.json" \
  --as-of "$as_of" \
  --json-output "$temporary_directory/malformed-result.json" \
  --csv-output "$temporary_directory/malformed-result.csv" \
  >"$temporary_directory/malformed.txt" 2>&1 || malformed_status=$?
test "$malformed_status" -eq 2
grep -F "evidence is not valid UTF-8 JSON" "$temporary_directory/malformed.txt" >/dev/null
python3 "$validate_assessment" \
  "$temporary_directory/malformed-result.json" \
  "$temporary_directory/malformed-result.csv" \
  --source test-fixture \
  --expected-exit 2

ln -s "$control_dir/secure/evidence.json" "$temporary_directory/evidence-link.json"
symlink_status=0
python3 "$verify" \
  --policy "$policy" \
  --evidence "$temporary_directory/evidence-link.json" \
  --as-of "$as_of" \
  >"$temporary_directory/symlink.txt" 2>&1 || symlink_status=$?
test "$symlink_status" -eq 2
grep -F "evidence is unavailable or symbolic" "$temporary_directory/symlink.txt" >/dev/null

python3 "$mutate" \
  --source "$control_dir/secure/evidence.json" \
  --output "$temporary_directory/sensitive.json" \
  --scenario sensitive
sensitive_status=0
python3 "$assess" \
  --workspace "$control_dir" \
  --policy "$policy" \
  --fixture "$temporary_directory/sensitive.json" \
  --as-of "$as_of" \
  --json-output "$temporary_directory/sensitive-result.json" \
  --csv-output "$temporary_directory/sensitive-result.csv" \
  >"$temporary_directory/sensitive.txt" 2>&1 || sensitive_status=$?
test "$sensitive_status" -eq 2
grep -F "evidence contains forbidden sensitive field evidence.token" \
  "$temporary_directory/sensitive.txt" >/dev/null
if grep -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" \
  "$temporary_directory/sensitive.txt" \
  "$temporary_directory/sensitive-result.json" \
  "$temporary_directory/sensitive-result.csv" >/dev/null; then
  echo "sensitive repository recovery evidence leaked to output" >&2
  exit 1
fi

echo "PASS exact critical repository scope and destructive-action limit verified"
echo "PASS attacker-separated recovery copies and isolated restore drill verified"
echo "PASS implementation guide covers every core check and adoption boundary"
echo "PASS PASS FAIL NOT_CHECKED and ERROR assessment states distinguished"
echo "PASS stale partial malformed symbolic sensitive and weakened evidence fails closed"
