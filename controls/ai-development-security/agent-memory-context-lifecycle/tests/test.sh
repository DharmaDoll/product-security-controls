#!/usr/bin/env bash
set -euo pipefail

control="controls/ai-development-security/agent-memory-context-lifecycle"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --repository-root .
  --control-root "$control"
  --policy "$control/secure/policy.json"
  --candidates "$control/secure/candidate-writes.json"
)

python3 "$verify" "${common[@]}" --evidence "$control/secure/lifecycle-evidence.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" --evidence "$control/insecure/lifecycle-evidence.json" \
  >"$temporary_directory/insecure.txt"
exit_code=$?
set -e
test "$exit_code" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

: >"$temporary_directory/errors.txt"
sed '0,/f9985d8c420e04912fde02ec2af0300b0047e608675770840a5ee296589cebe4/s//0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/candidate-writes.json" >"$temporary_directory/tampered-candidate.json"
set +e
python3 "$verify" --repository-root . --control-root "$control" \
  --policy "$control/secure/policy.json" --candidates "$temporary_directory/tampered-candidate.json" \
  --evidence "$control/secure/lifecycle-evidence.json" >"$temporary_directory/tampered.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR MEM-CAND-001 payload digest mismatch" "$temporary_directory/tampered.txt" \
  >>"$temporary_directory/errors.txt"

sed '0,/d95ad1b1fd0c1988e8366f9896475eb0d2cc5d71bdb230413add2d5ae0d4e271/s//0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/policy.json" >"$temporary_directory/wrong-binding.json"
set +e
python3 "$verify" --repository-root . --control-root "$control" \
  --policy "$temporary_directory/wrong-binding.json" --candidates "$control/secure/candidate-writes.json" \
  --evidence "$control/secure/lifecycle-evidence.json" >"$temporary_directory/wrong-binding.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR PSB-AI-003 corpus binding digest mismatch" "$temporary_directory/wrong-binding.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"collection_status": "complete"/"collection_status": "failed"/' \
  "$control/secure/lifecycle-evidence.json" >"$temporary_directory/incomplete.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/incomplete.json" \
  >"$temporary_directory/incomplete.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR memory lifecycle collection is incomplete" "$temporary_directory/incomplete.txt" \
  >>"$temporary_directory/errors.txt"

sed 's/"evaluator_status": "completed"/"evaluator_status": "failed"/' \
  "$control/secure/lifecycle-evidence.json" >"$temporary_directory/evaluator-failed.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/evaluator-failed.json" \
  >"$temporary_directory/evaluator-failed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR memory lifecycle evaluator is unavailable" "$temporary_directory/evaluator-failed.txt" \
  >>"$temporary_directory/errors.txt"

sed '2i\  "raw_prompt": "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT",' \
  "$control/secure/lifecycle-evidence.json" >"$temporary_directory/sensitive.json"
set +e
python3 "$verify" "${common[@]}" --evidence "$temporary_directory/sensitive.json" \
  >"$temporary_directory/sensitive.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/sensitive.txt" >>"$temporary_directory/errors.txt"
if rg -F "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive lifecycle value leaked to verifier output" >&2
  exit 1
fi

sort -o "$temporary_directory/errors.txt" "$temporary_directory/errors.txt"
diff -u "$control/expected-results/errors.txt" "$temporary_directory/errors.txt"

echo "PASS memory write store retrieval expiry and deletion lifecycle verified"
echo "PASS poisoned sensitive oversized and cross-scope behavior rejected"
echo "PASS tampered incomplete evaluator-failed and sensitive evidence remained ERROR"
