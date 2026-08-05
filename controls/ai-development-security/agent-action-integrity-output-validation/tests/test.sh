#!/usr/bin/env bash
set -euo pipefail

control="controls/ai-development-security/agent-action-integrity-output-validation"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --repository-root .
  --policy "$control/secure/policy.json"
  --proposals "$control/secure/proposals.json"
)

python3 "$verify" "${common[@]}" --evidence "$control/secure/execution-evidence.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" --evidence "$control/insecure/execution-evidence.json" \
  >"$temporary_directory/insecure.txt"
exit_code=$?
set -e
test "$exit_code" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

: >"$temporary_directory/errors.txt"
sed 's/memory lifecycle/memory lifecycle changed/' "$control/secure/proposals.json" \
  >"$temporary_directory/tampered-proposals.json"
set +e
python3 "$verify" --repository-root . --policy "$control/secure/policy.json" \
  --proposals "$temporary_directory/tampered-proposals.json" \
  --evidence "$control/secure/execution-evidence.json" >"$temporary_directory/tampered.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR proposal set binding digest mismatch" "$temporary_directory/tampered.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/d60a8aab5021e58d1ffff464854afb5bc951d02a7e431b7f47ee0b804659e59c/0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/policy.json" >"$temporary_directory/wrong-binding.json"
set +e
python3 "$verify" --repository-root . --policy "$temporary_directory/wrong-binding.json" \
  --proposals "$control/secure/proposals.json" \
  --evidence "$control/secure/execution-evidence.json" >"$temporary_directory/wrong-binding.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR PSB-AI-004 binding digest mismatch" "$temporary_directory/wrong-binding.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"collection_status": "complete"/"collection_status": "failed"/' \
  "$control/secure/execution-evidence.json" >"$temporary_directory/incomplete.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/incomplete.json" \
  >"$temporary_directory/incomplete.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR agent action evidence collection is incomplete" "$temporary_directory/incomplete.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"evaluator_status": "completed"/"evaluator_status": "failed"/' \
  "$control/secure/execution-evidence.json" >"$temporary_directory/evaluator-failed.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/evaluator-failed.json" \
  >"$temporary_directory/evaluator-failed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR agent action evaluator is unavailable" "$temporary_directory/evaluator-failed.txt" \
  >>"$temporary_directory/errors.txt"

sed '2i\  "raw_prompt": "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT",' \
  "$control/secure/execution-evidence.json" >"$temporary_directory/sensitive.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/sensitive.json" \
  >"$temporary_directory/sensitive.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/sensitive.txt" >>"$temporary_directory/errors.txt"
if rg -F "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive agent output leaked to verifier output" >&2
  exit 1
fi

printf '{' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR execution evidence is unavailable or malformed: JSONDecodeError" \
  "$temporary_directory/malformed.txt" >>"$temporary_directory/errors.txt"

sort -o "$temporary_directory/errors.txt" "$temporary_directory/errors.txt"
diff -u "$control/expected-results/errors.txt" "$temporary_directory/errors.txt"

echo "PASS structured proposals authorization execution and result identity verified"
echo "PASS replay TOCTOU malformed output and uncertain-outcome behavior rejected"
echo "PASS tampered incomplete evaluator-failed malformed and sensitive evidence remained ERROR"
