#!/usr/bin/env bash
set -euo pipefail

control="controls/ai-development-security/repository-owned-ai-security-guidance"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --repository-root .
  --semantic-review "$control/secure/semantic-review.json"
)
benchmark=(
  --criteria "$control/secure/benchmark/criteria.json"
  --corpus "$control/secure/benchmark/tasks.json"
  --baseline "$control/secure/benchmark/baseline-results.json"
  --guided "$control/secure/benchmark/guided-results.json"
)
: >"$temporary_directory/errors.txt"

python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  "${benchmark[@]}" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/insecure/guidance-manifest.json" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

sed '0,/a737b0a6be8c4488cd3f91db290fbb018452160180b89eeb51bf9932ee8c2643/s//0000000000000000000000000000000000000000000000000000000000000000/' \
  "$control/secure/guidance-manifest.json" >"$temporary_directory/tampered-manifest.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$temporary_directory/tampered-manifest.json" \
  >"$temporary_directory/tampered.txt"
tampered_status=$?
set -e
test "$tampered_status" -eq 2
rg -F "ERROR pinned repository-agents digest mismatch" "$temporary_directory/tampered.txt" >/dev/null
tail -n 1 "$temporary_directory/tampered.txt" >>"$temporary_directory/errors.txt"

sed '0,/"corpus_sha256": "[0-9a-f]*"/s//"corpus_sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' \
  "$control/secure/benchmark/guided-results.json" >"$temporary_directory/wrong-corpus.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  --criteria "$control/secure/benchmark/criteria.json" \
  --corpus "$control/secure/benchmark/tasks.json" \
  --baseline "$control/secure/benchmark/baseline-results.json" \
  --guided "$temporary_directory/wrong-corpus.json" \
  >"$temporary_directory/wrong-corpus.txt"
wrong_corpus_status=$?
set -e
test "$wrong_corpus_status" -eq 2
rg -Fx "ERROR guided result corpus digest mismatch" "$temporary_directory/wrong-corpus.txt" >/dev/null
tail -n 1 "$temporary_directory/wrong-corpus.txt" >>"$temporary_directory/errors.txt"

sed '0,/"repetition":2/s//"repetition":3/' \
  "$control/secure/benchmark/guided-results.json" >"$temporary_directory/missing-pair.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  --criteria "$control/secure/benchmark/criteria.json" \
  --corpus "$control/secure/benchmark/tasks.json" \
  --baseline "$control/secure/benchmark/baseline-results.json" \
  --guided "$temporary_directory/missing-pair.json" \
  >"$temporary_directory/missing-pair.txt"
missing_pair_status=$?
set -e
test "$missing_pair_status" -eq 2
rg -Fx "ERROR guided task AIG-T001 repetition is outside the frozen range" \
  "$temporary_directory/missing-pair.txt" >/dev/null
tail -n 1 "$temporary_directory/missing-pair.txt" >>"$temporary_directory/errors.txt"

sed 's/"evidence_status": "available"/"evidence_status": "unavailable"/' \
  "$control/secure/benchmark/guided-results.json" >"$temporary_directory/unavailable.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  --criteria "$control/secure/benchmark/criteria.json" \
  --corpus "$control/secure/benchmark/tasks.json" \
  --baseline "$control/secure/benchmark/baseline-results.json" \
  --guided "$temporary_directory/unavailable.json" \
  >"$temporary_directory/unavailable.txt"
unavailable_status=$?
set -e
test "$unavailable_status" -eq 2
rg -Fx "ERROR guided evidence is unavailable" "$temporary_directory/unavailable.txt" >/dev/null
tail -n 1 "$temporary_directory/unavailable.txt" >>"$temporary_directory/errors.txt"

sed '2i\  "raw_output": "SYNTHETIC_TEST_VALUE_DO_NOT_USE",' \
  "$control/secure/benchmark/guided-results.json" >"$temporary_directory/sensitive.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  --criteria "$control/secure/benchmark/criteria.json" \
  --corpus "$control/secure/benchmark/tasks.json" \
  --baseline "$control/secure/benchmark/baseline-results.json" \
  --guided "$temporary_directory/sensitive.json" \
  >"$temporary_directory/sensitive.txt"
sensitive_status=$?
set -e
test "$sensitive_status" -eq 2
rg -Fx "ERROR guided result contains forbidden evidence field $.raw_output" \
  "$temporary_directory/sensitive.txt" >/dev/null
tail -n 1 "$temporary_directory/sensitive.txt" >>"$temporary_directory/errors.txt"
if rg -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive benchmark value leaked to verifier output" >&2
  exit 1
fi

sed 's/"recommendation": "pilot"/"recommendation": "adopt"/' \
  "$control/secure/benchmark/guided-results.json" >"$temporary_directory/overclaim.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  --criteria "$control/secure/benchmark/criteria.json" \
  --corpus "$control/secure/benchmark/tasks.json" \
  --baseline "$control/secure/benchmark/baseline-results.json" \
  --guided "$temporary_directory/overclaim.json" \
  >"$temporary_directory/overclaim.txt"
overclaim_status=$?
set -e
test "$overclaim_status" -eq 2
rg -Fx "ERROR guided recommendation exceeds the allowed evidence claim" \
  "$temporary_directory/overclaim.txt" >/dev/null
tail -n 1 "$temporary_directory/overclaim.txt" >>"$temporary_directory/errors.txt"
diff -u "$control/expected-results/errors.txt" "$temporary_directory/errors.txt"

sed '0,/"security_invariants_preserved":2/s//"security_invariants_preserved":0/' \
  "$control/secure/benchmark/guided-results.json" >"$temporary_directory/regression.json"
set +e
python3 "$verify" "${common[@]}" \
  --manifest "$control/secure/guidance-manifest.json" \
  --criteria "$control/secure/benchmark/criteria.json" \
  --corpus "$control/secure/benchmark/tasks.json" \
  --baseline "$control/secure/benchmark/baseline-results.json" \
  --guided "$temporary_directory/regression.json" \
  >"$temporary_directory/regression.txt"
regression_status=$?
set -e
test "$regression_status" -eq 1
rg -F "FAIL guided invariant preservation does not improve enough over baseline" \
  "$temporary_directory/regression.txt" >/dev/null

echo "PASS canonical AGENTS CodeGuard procedure and review identities verified"
echo "PASS unsafe mutable self-approved guidance rejected"
echo "PASS paired benchmark security quality and false-block metrics verified"
echo "PASS tampered incomplete unavailable and sensitive evidence fails closed"
echo "PASS synthetic evidence remains bounded to PILOT with live NOT_CHECKED"
