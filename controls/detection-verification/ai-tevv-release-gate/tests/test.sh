#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
repository_root="$(cd "$control_dir/../../.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-detect-002.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_eval() {
  local policy="${1:-$control_dir/secure/policy.json}"
  local sut="${2:-$control_dir/secure/system-under-test.json}"
  local suite="${3:-$control_dir/secure/test-suite.json}"
  local subject="${4:-$control_dir/secure/known-safe-subject.json}"
  local calibration="${5:-$control_dir/insecure/known-vulnerable-subject.json}"
  local evidence="${6:-$control_dir/secure/evaluation-evidence.json}"
  local decision="${7:-$control_dir/secure/release-decision.json}"
  local tool="${8:-$control_dir/secure/tool/synthetic-evaluator.bin.b64}"
  python3 "$verify" \
    --repository-root "$repository_root" \
    --policy "$policy" \
    --sut "$sut" \
    --suite "$suite" \
    --subject "$subject" \
    --calibration-subject "$calibration" \
    --evidence "$evidence" \
    --decision "$decision" \
    --tool-artifact "$tool" \
    --as-of "2026-08-06T12:00:00Z"
}

run_eval >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
run_eval "" "" "" \
  "$control_dir/insecure/known-vulnerable-subject.json" \
  "" \
  "$control_dir/insecure/evaluation-evidence.json" \
  "$control_dir/insecure/release-decision.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
test "$insecure_exit" -eq 1
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

cp "$control_dir/secure/known-safe-subject.json" "$temporary_directory/incomplete-subject.json"
cp "$control_dir/secure/evaluation-evidence.json" "$temporary_directory/incomplete-evidence.json"
cp "$control_dir/secure/release-decision.json" "$temporary_directory/incomplete-decision.json"
python3 - "$temporary_directory/incomplete-subject.json" "$temporary_directory/incomplete-evidence.json" "$temporary_directory/incomplete-decision.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

subject_path, evidence_path, decision_path = map(Path, sys.argv[1:])
subject = json.loads(subject_path.read_text())
subject["behaviors"]["TEVV-S005"] = subject["behaviors"]["TEVV-S005"][:3]
subject_path.write_text(json.dumps(subject, indent=2) + "\n")
subject_digest = hashlib.sha256(subject_path.read_bytes()).hexdigest()

evidence = json.loads(evidence_path.read_text())
evidence["identity"]["candidate_subject_sha256"] = subject_digest
evidence["candidate_state"] = "INCOMPLETE"
row = next(item for item in evidence["scenario_results"] if item["scenario_id"] == "TEVV-S005")
row.update({"completed_repetitions": 3, "passed_repetitions": 3, "state": "INCOMPLETE"})
evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
evidence_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

decision = json.loads(decision_path.read_text())
decision["identity"]["candidate_subject_sha256"] = subject_digest
decision["identity"]["evaluation_evidence_sha256"] = evidence_digest
decision["evaluation_state"] = "INCOMPLETE"
decision["decision"] = "BLOCKED"
decision_path.write_text(json.dumps(decision, indent=2) + "\n")
PY
incomplete_exit=0
run_eval "" "" "" \
  "$temporary_directory/incomplete-subject.json" \
  "" \
  "$temporary_directory/incomplete-evidence.json" \
  "$temporary_directory/incomplete-decision.json" \
  >"$temporary_directory/incomplete.txt" || incomplete_exit=$?
test "$incomplete_exit" -eq 1
grep -F "INCOMPLETE TEV-005 scenario TEVV-S005 completed 3/5 repetitions" \
  "$temporary_directory/incomplete.txt" >/dev/null
grep -F "RESULT INCOMPLETE" "$temporary_directory/incomplete.txt" >/dev/null

unavailable_exit=0
run_eval "" "" "" "" "" "$control_dir/tests/fixtures/unavailable-evidence.json" \
  >"$temporary_directory/unavailable.txt" || unavailable_exit=$?
test "$unavailable_exit" -eq 2
grep -F "ERROR TEV-009 verification unavailable: AI TEVV evidence is unavailable or incomplete" \
  "$temporary_directory/unavailable.txt" >/dev/null

malformed_exit=0
run_eval "" "" "" "" "" "$control_dir/tests/fixtures/malformed.json" \
  >"$temporary_directory/malformed.txt" || malformed_exit=$?
test "$malformed_exit" -eq 2
grep -F "ERROR TEV-009 verification unavailable: cannot parse AI TEVV evidence" \
  "$temporary_directory/malformed.txt" >/dev/null

cp "$control_dir/secure/evaluation-evidence.json" "$temporary_directory/evaluator-error.json"
python3 - "$temporary_directory/evaluator-error.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["evaluator_status"] = "ERROR"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
evaluator_exit=0
run_eval "" "" "" "" "" "$temporary_directory/evaluator-error.json" \
  >"$temporary_directory/evaluator-error.txt" || evaluator_exit=$?
test "$evaluator_exit" -eq 2
grep -F "ERROR TEV-009 verification unavailable: AI TEVV evaluator did not complete successfully" \
  "$temporary_directory/evaluator-error.txt" >/dev/null

cp "$control_dir/secure/evaluation-evidence.json" "$temporary_directory/sensitive-evidence.json"
python3 - "$temporary_directory/sensitive-evidence.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["prompt"] = "synthetic content that must never be retained or echoed"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
sensitive_exit=0
run_eval "" "" "" "" "" "$temporary_directory/sensitive-evidence.json" \
  >"$temporary_directory/sensitive.txt" || sensitive_exit=$?
test "$sensitive_exit" -eq 2
grep -F "ERROR TEV-009 verification unavailable: sensitive field evidence.prompt is prohibited" \
  "$temporary_directory/sensitive.txt" >/dev/null
if grep -F "synthetic content that must never be retained" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "FAIL sensitive evaluation content must not be echoed"
  exit 1
fi

cp "$control_dir/secure/policy.json" "$temporary_directory/overclaim-policy.json"
python3 - "$temporary_directory/overclaim-policy.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["live_claims"]["production_release_gate"] = "PASS"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
overclaim_exit=0
run_eval "$temporary_directory/overclaim-policy.json" \
  >"$temporary_directory/overclaim.txt" || overclaim_exit=$?
test "$overclaim_exit" -eq 1
grep -F "BLOCK TEV-010 fixture policy overclaims live AI TEVV enforcement" \
  "$temporary_directory/overclaim.txt" >/dev/null

echo "PASS immutable SUT evaluator suite scenario and threshold identities verified"
echo "PASS known-safe and known-vulnerable deterministic and probabilistic behavior distinguished"
echo "PASS fail incomplete unavailable evaluator-error and sensitive evidence states verified"
echo "PASS credential-free network-free execution and fixture claim boundary verified"
