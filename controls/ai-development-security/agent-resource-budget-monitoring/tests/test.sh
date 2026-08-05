#!/usr/bin/env bash
set -euo pipefail

control="controls/ai-development-security/agent-resource-budget-monitoring"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --repository-root .
  --control-root "$control"
  --policy "$control/secure/policy.json"
)

python3 "$verify" "${common[@]}" --evidence "$control/secure/session-evidence.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" --evidence "$control/insecure/session-evidence.json" \
  >"$temporary_directory/insecure.txt"
exit_code=$?
set -e
test "$exit_code" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

: >"$temporary_directory/errors.txt"
sed 's/ff559da3bfd52eb8ce65f3ae9b22211b44f185316987ffeaf011b1274de42090/0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/policy.json" >"$temporary_directory/wrong-binding.json"
set +e
python3 "$verify" --repository-root . --control-root "$control" \
  --policy "$temporary_directory/wrong-binding.json" \
  --evidence "$control/secure/session-evidence.json" >"$temporary_directory/wrong-binding.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR PSB-AI-004 telemetry policy binding digest mismatch" \
  "$temporary_directory/wrong-binding.txt" >>"$temporary_directory/errors.txt"

sed 's/2018dcba964455a7c5f63bc5d45f30b9e624484d41c646665528b11aa8c063b1/0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/insecure/session-evidence.json" >"$temporary_directory/wrong-base.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/wrong-base.json" \
  >"$temporary_directory/wrong-base.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR insecure base evidence digest mismatch" "$temporary_directory/wrong-base.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"collection_status": "complete"/"collection_status": "failed"/' \
  "$control/secure/session-evidence.json" >"$temporary_directory/incomplete.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/incomplete.json" \
  >"$temporary_directory/incomplete.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR resource evidence collection is incomplete" "$temporary_directory/incomplete.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"evaluator_status": "completed"/"evaluator_status": "failed"/' \
  "$control/secure/session-evidence.json" >"$temporary_directory/evaluator-failed.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/evaluator-failed.json" \
  >"$temporary_directory/evaluator-failed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR resource budget evaluator is unavailable" "$temporary_directory/evaluator-failed.txt" \
  >>"$temporary_directory/errors.txt"

sed '0,/"sequence_gap": false/s//"sequence_gap": true/' \
  "$control/secure/session-evidence.json" >"$temporary_directory/sequence-gap.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/sequence-gap.json" \
  >"$temporary_directory/sequence-gap.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR resource telemetry collection is unavailable or incomplete" \
  "$temporary_directory/sequence-gap.txt" >>"$temporary_directory/errors.txt"

sed '2i\  "raw_prompt": "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT",' \
  "$control/secure/session-evidence.json" >"$temporary_directory/sensitive.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/sensitive.json" \
  >"$temporary_directory/sensitive.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/sensitive.txt" >>"$temporary_directory/errors.txt"
if rg -F "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive resource evidence leaked to verifier output" >&2
  exit 1
fi

printf '{' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR resource evidence is unavailable or malformed: JSONDecodeError" \
  "$temporary_directory/malformed.txt" >>"$temporary_directory/errors.txt"

sort -o "$temporary_directory/errors.txt" "$temporary_directory/errors.txt"
diff -u "$control/expected-results/errors.txt" "$temporary_directory/errors.txt"

echo "PASS token cost duration tool retry recursion and anomaly budgets verified"
echo "PASS warning restriction block circuit breaker and alert delivery verified"
echo "PASS tampered incomplete unavailable malformed and sensitive evidence remained ERROR"
