#!/usr/bin/env bash
set -euo pipefail

control="controls/ai-development-security/agent-extension-dependency-governance"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(--control-root "$control" --policy "$control/secure/policy.json")

python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/dependency-manifest.json" \
  --revocations "$control/secure/revocations.json" \
  --benchmark "$control/secure/benchmark-results.json" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/insecure/dependency-manifest.json" \
  --revocations "$control/insecure/revocations.json" \
  --benchmark "$control/insecure/benchmark-results.json" >"$temporary_directory/insecure.txt"
exit_code=$?
set -e
test "$exit_code" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

: >"$temporary_directory/errors.txt"
sed '0,/b828e647195ca72df808cb28e1862ff9b3121f3b8ad543b5245e4d58f2c7b284/s//0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/dependency-manifest.json" >"$temporary_directory/tampered.json"
set +e
python3 "$verify" "${common[@]}" --manifest "$temporary_directory/tampered.json" \
  --revocations "$control/secure/revocations.json" --benchmark "$control/secure/benchmark-results.json" \
  >"$temporary_directory/tampered.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/tampered.txt" >>"$temporary_directory/errors.txt"

sed 's/"collection_status": "complete"/"collection_status": "failed"/' \
  "$control/secure/revocations.json" >"$temporary_directory/incomplete-revocations.json"
set +e
python3 "$verify" "${common[@]}" --manifest "$control/secure/dependency-manifest.json" \
  --revocations "$temporary_directory/incomplete-revocations.json" --benchmark "$control/secure/benchmark-results.json" \
  >"$temporary_directory/incomplete.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/incomplete.txt" >>"$temporary_directory/errors.txt"

sed 's/"evaluator_status": "completed"/"evaluator_status": "failed"/' \
  "$control/secure/benchmark-results.json" >"$temporary_directory/failed-benchmark.json"
set +e
python3 "$verify" "${common[@]}" --manifest "$control/secure/dependency-manifest.json" \
  --revocations "$control/secure/revocations.json" --benchmark "$temporary_directory/failed-benchmark.json" \
  >"$temporary_directory/failed.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
rg -Fx "ERROR benchmark evaluator or evidence is unavailable" "$temporary_directory/failed.txt" >>"$temporary_directory/errors.txt"

sed '2i\  "raw_prompt": "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT",' \
  "$control/secure/benchmark-results.json" >"$temporary_directory/sensitive.json"
set +e
python3 "$verify" "${common[@]}" --manifest "$control/secure/dependency-manifest.json" \
  --revocations "$control/secure/revocations.json" --benchmark "$temporary_directory/sensitive.json" \
  >"$temporary_directory/sensitive.txt"
exit_code=$?
set -e
test "$exit_code" -eq 2
head -n 1 "$temporary_directory/sensitive.txt" >>"$temporary_directory/errors.txt"
if rg -F "SYNTHETIC_SENSITIVE_VALUE_DO_NOT_PRINT" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive benchmark value leaked to verifier output" >&2
  exit 1
fi

sort -o "$temporary_directory/errors.txt" "$temporary_directory/errors.txt"
diff -u "$control/expected-results/errors.txt" "$temporary_directory/errors.txt"

sed '0,/"status":"active"/s//"status":"revoked"/' \
  "$control/secure/revocations.json" >"$temporary_directory/revoked.json"
set +e
python3 "$verify" "${common[@]}" --manifest "$control/secure/dependency-manifest.json" \
  --revocations "$temporary_directory/revoked.json" --benchmark "$control/secure/benchmark-results.json" \
  >"$temporary_directory/revoked.txt"
exit_code=$?
set -e
test "$exit_code" -eq 1
rg -Fx "FAIL EXT-FIXTURE-DOCS-001 is revoked" "$temporary_directory/revoked.txt" >/dev/null

echo "PASS reviewed dependency manifest and runtime handoff verified"
echo "PASS mutable over-privileged unreviewed and expired dependency rejected"
echo "PASS tamper revocation and benchmark evidence failures remain ERROR"
echo "PASS known revocation remains a security finding"
