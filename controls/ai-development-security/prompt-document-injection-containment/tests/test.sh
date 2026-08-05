#!/usr/bin/env bash
set -euo pipefail

control="controls/ai-development-security/prompt-document-injection-containment"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --repository-root .
  --control-root "$control"
  --policy "$control/secure/policy.json"
  --corpus "$control/secure/scenario-corpus.json"
)

python3 "$verify" "${common[@]}" --results "$control/secure/run-results.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" --results "$control/insecure/run-results.json" \
  >"$temporary_directory/insecure.txt"
exit_code=$?
set -e
test "$exit_code" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

: >"$temporary_directory/errors.txt"
sed '0,/04795a2e20274c776fb7ea15fdbd7138cb5a60c857625eef7cda4d59a18ec1ef/s//0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/scenario-corpus.json" >"$temporary_directory/tampered-corpus.json"
set +e
python3 "$verify" --repository-root . --control-root "$control" \
  --policy "$control/secure/policy.json" --corpus "$temporary_directory/tampered-corpus.json" \
  --results "$control/secure/run-results.json" >"$temporary_directory/tampered.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR AII-T001 source digest mismatch" "$temporary_directory/tampered.txt" \
  >>"$temporary_directory/errors.txt"

sed '0,/d60a8aab5021e58d1ffff464854afb5bc951d02a7e431b7f47ee0b804659e59c/s//0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/policy.json" >"$temporary_directory/wrong-binding.json"
set +e
python3 "$verify" --repository-root . --control-root "$control" \
  --policy "$temporary_directory/wrong-binding.json" --corpus "$control/secure/scenario-corpus.json" \
  --results "$control/secure/run-results.json" >"$temporary_directory/wrong-binding.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR PSB-AI-004 binding digest mismatch" "$temporary_directory/wrong-binding.txt" \
  >>"$temporary_directory/errors.txt"

set +e
python3 "$verify" "${common[@]}" --results "$control/tests/fixtures/unavailable-results.json" \
  >"$temporary_directory/unavailable.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR result collection is incomplete" "$temporary_directory/unavailable.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"evaluator_status": "completed"/"evaluator_status": "failed"/' \
  "$control/secure/run-results.json" >"$temporary_directory/evaluator-failed.json"
set +e
python3 "$verify" "${common[@]}" --results "$temporary_directory/evaluator-failed.json" \
  >"$temporary_directory/evaluator-failed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR result evaluator is unavailable" "$temporary_directory/evaluator-failed.txt" \
  >>"$temporary_directory/errors.txt"

sed '2i\  "raw_prompt": "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT",' \
  "$control/secure/run-results.json" >"$temporary_directory/sensitive.json"
set +e
python3 "$verify" "${common[@]}" --results "$temporary_directory/sensitive.json" \
  >"$temporary_directory/sensitive.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/sensitive.txt" >>"$temporary_directory/errors.txt"
if rg -F "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive evidence value leaked to verifier output" >&2
  exit 1
fi

sort -o "$temporary_directory/errors.txt" "$temporary_directory/errors.txt"
diff -u "$control/expected-results/errors.txt" "$temporary_directory/errors.txt"

echo "PASS six direct and indirect injection surfaces exercised"
echo "PASS unsafe actions remained blocked while legitimate work completed"
echo "PASS tampered unavailable evaluator-failed and sensitive evidence remained ERROR"
