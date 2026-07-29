#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
verify_approval="$control_dir/scripts/verify-approval.py"
authorize_signed="$control_dir/scripts/authorize-signed-approval.py"
verify_capabilities="$control_dir/scripts/verify-capabilities.py"
verify_runtime_state="$control_dir/scripts/verify-runtime-state.py"
verify_network_boundary="$control_dir/scripts/verify-network-boundary.py"
verify_hook_failure_boundary="$control_dir/scripts/verify-hook-failure-boundary.py"
verify_side_effect_reconciliation="$control_dir/scripts/verify-side-effect-reconciliation.py"
verify_command_broker="$control_dir/scripts/verify-command-broker.py"
verify_fleet_telemetry="$control_dir/scripts/verify-fleet-telemetry.py"
verify_fleet_evidence="$control_dir/scripts/verify-fleet-evidence.py"
pretool_gate="$control_dir/scripts/pretool-gate.py"
policy="$control_dir/policy/runtime-policy.json"
runtime_assessment_policy="$control_dir/policy/runtime-assessment-policy.json"
network_boundary_policy="$control_dir/policy/network-boundary-policy.json"
hook_failure_boundary_policy="$control_dir/policy/hook-failure-boundary-policy.json"
side_effect_reconciliation_policy="$control_dir/policy/side-effect-reconciliation-policy.json"
command_broker_policy="$control_dir/policy/command-broker-policy.json"
fleet_telemetry_policy="$control_dir/policy/fleet-telemetry-policy.json"
fleet_evidence_trust_policy="$control_dir/policy/fleet-evidence-trust-policy.json"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-ai-004.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_approval_case() {
  local case_name="$1"
  local expected_exit="$2"
  local request="$3"
  local approval="$4"
  local replay_state="$5"
  local validation_state="$6"
  local expected_result="$7"
  local actual_exit=0

  python3 "$verify_approval" "$policy" "$request" "$approval" \
    "$replay_state" "$validation_state" \
    --now "2026-07-29T12:02:00Z" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_capability_adapter_case() {
  local case_name="$1"
  local expected_exit="$2"
  local profile="$3"
  local expected_result="$4"
  local actual_exit=0

  python3 "$verify_capabilities" adapters "$policy" "$profile" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_capability_invocation_case() {
  local case_name="$1"
  local expected_exit="$2"
  local invocation="$3"
  local engine_state="$4"
  local expected_result="$5"
  local actual_exit=0

  python3 "$verify_capabilities" invocation "$policy" "$invocation" \
    "$engine_state" >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_hook_case() {
  local case_name="$1"
  local provider="$2"
  local expected_exit="$3"
  local input="$4"
  local engine_state="$5"
  local expected_result="$6"
  local policy_path="${7:-$policy}"
  local actor_state="${8:-$hook_actor_state}"
  local approval_inbox="${9:-$empty_approval_inbox}"
  local approval_ledger="${10:-$temporary_directory/$case_name.sqlite3}"
  local openssl_path="${11:-/usr/bin/openssl}"
  local now_text="${12:-2026-07-29T12:02:00Z}"
  local audit_policy="${13:-$hook_audit_policy}"
  local audit_log="${14:-$hook_audit_log}"
  local actual_exit=0

  python3 "$pretool_gate" \
    --provider "$provider" \
    --policy "$policy_path" \
    --engine-state "$engine_state" \
    --actor-state "$actor_state" \
    --approval-dir "$approval_inbox" \
    --approval-trust "$hook_approval_trust" \
    --approval-ledger "$approval_ledger" \
    --openssl "$openssl_path" \
    --audit-policy "$audit_policy" \
    --audit-log "$audit_log" \
    --now "$now_text" \
    <"$input" >"$temporary_directory/$case_name.txt" 2>&1 || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_runtime_state_case() {
  local case_name="$1"
  local expected_exit="$2"
  local profile="$3"
  local claude_inventory="$4"
  local codex_inventory="$5"
  local audit_state="$6"
  local audit_events="$7"
  local expected_result="$8"
  local actual_exit=0

  python3 "$verify_runtime_state" \
    "$runtime_assessment_policy" \
    "$policy" \
    "$claude_inventory" \
    "$codex_inventory" \
    "$audit_state" \
    "$audit_events" \
    --profile "$profile" \
    --now "2026-07-29T12:02:00Z" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_signed_approval_case() {
  local case_name="$1"
  local expected_exit="$2"
  local request="$3"
  local envelope="$4"
  local ledger="$5"
  local expected_result="$6"
  local now_text="${7:-2026-07-29T12:02:00Z}"
  local openssl_path="${8:-/usr/bin/openssl}"
  local actual_exit=0

  python3 "$authorize_signed" \
    "$policy" \
    "$request" \
    "$envelope" \
    "$hook_approval_trust" \
    "$ledger" \
    --openssl "$openssl_path" \
    --now "$now_text" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_network_boundary_case() {
  local case_name="$1"
  local expected_exit="$2"
  local evidence="$3"
  local expected_result="$4"
  local actual_exit=0

  python3 "$verify_network_boundary" \
    "$network_boundary_policy" \
    "$evidence" \
    --now "2026-07-29T12:02:00Z" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_hook_failure_boundary_case() {
  local case_name="$1"
  local expected_exit="$2"
  local evidence="$3"
  local expected_result="$4"
  local actual_exit=0

  python3 "$verify_hook_failure_boundary" \
    "$hook_failure_boundary_policy" \
    "$evidence" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_side_effect_reconciliation_case() {
  local case_name="$1"
  local expected_exit="$2"
  local evidence="$3"
  local expected_result="$4"
  local actual_exit=0

  python3 "$verify_side_effect_reconciliation" \
    "$side_effect_reconciliation_policy" \
    "$evidence" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_command_broker_case() {
  local case_name="$1"
  local expected_exit="$2"
  local evidence="$3"
  local expected_result="$4"
  local actual_exit=0

  python3 "$verify_command_broker" \
    "$command_broker_policy" \
    "$evidence" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_fleet_telemetry_case() {
  local case_name="$1"
  local expected_exit="$2"
  local evidence="$3"
  local expected_result="$4"
  local actual_exit=0

  python3 "$verify_fleet_telemetry" \
    "$fleet_telemetry_policy" \
    "$evidence" \
    --now "2026-07-29T12:02:00Z" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

run_fleet_evidence_case() {
  local case_name="$1"
  local expected_exit="$2"
  local envelope="$3"
  local evidence="$4"
  local checkpoint="$5"
  local expected_result="$6"
  local openssl_path="${7:-/usr/bin/openssl}"
  local actual_exit=0

  python3 "$verify_fleet_evidence" \
    "$fleet_evidence_trust_policy" \
    "$control_dir/secure/fleet-evidence/collector-trust.json" \
    "$envelope" \
    "$evidence" \
    "$checkpoint" \
    --openssl "$openssl_path" \
    --now "2026-07-29T12:02:00Z" \
    >"$temporary_directory/$case_name.txt" || actual_exit=$?
  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "FAIL $case_name exit: expected=$expected_exit actual=$actual_exit"
    exit 1
  fi
  diff -u "$control_dir/expected-results/$expected_result" \
    "$temporary_directory/$case_name.txt"
}

python3 "$verify" "$policy" "$control_dir/secure" \
  >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" \
  "$temporary_directory/secure.txt"

insecure_exit=0
python3 "$verify" "$policy" "$control_dir/insecure" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
if [[ "$insecure_exit" -ne 1 ]]; then
  echo "FAIL insecure profile exit: expected=1 actual=$insecure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/insecure.txt" \
  "$temporary_directory/insecure.txt"

downgrade_exit=0
python3 "$verify" "$policy" \
  "$control_dir/tests/fixtures/repository-downgrade" \
  >"$temporary_directory/downgrade.txt" || downgrade_exit=$?
if [[ "$downgrade_exit" -ne 1 ]]; then
  echo "FAIL repository downgrade exit: expected=1 actual=$downgrade_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/repository-downgrade.txt" \
  "$temporary_directory/downgrade.txt"

malformed_exit=0
python3 "$verify" "$policy" "$control_dir/tests/fixtures/malformed" \
  >"$temporary_directory/malformed.txt" || malformed_exit=$?
if [[ "$malformed_exit" -ne 2 ]]; then
  echo "FAIL malformed profile exit: expected=2 actual=$malformed_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/malformed.txt" \
  "$temporary_directory/malformed.txt"

unsupported_exit=0
python3 "$verify" "$policy" "$control_dir/tests/fixtures/unsupported" \
  >"$temporary_directory/unsupported.txt" || unsupported_exit=$?
if [[ "$unsupported_exit" -ne 2 ]]; then
  echo "FAIL unsupported profile exit: expected=2 actual=$unsupported_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/unsupported.txt" \
  "$temporary_directory/unsupported.txt"

evaluator_failure_exit=0
PSB_TEST_POLICY="$policy" PSB_TEST_PROFILE="$control_dir/secure" \
  python3 -c '
import os
import runpy
import sys

module = runpy.run_path(sys.argv[1], run_name="psb_verify")
module["evaluate_codex"] = lambda *_: (_ for _ in ()).throw(RuntimeError("synthetic"))
module["evaluate"].__globals__["evaluate_codex"] = module["evaluate_codex"]
sys.argv = [sys.argv[1], os.environ["PSB_TEST_POLICY"], os.environ["PSB_TEST_PROFILE"]]
raise SystemExit(module["main"]())
' "$verify" >"$temporary_directory/evaluator-error.txt" || evaluator_failure_exit=$?
if [[ "$evaluator_failure_exit" -ne 2 ]]; then
  echo "FAIL evaluator failure exit: expected=2 actual=$evaluator_failure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/evaluator-error.txt" \
  "$temporary_directory/evaluator-error.txt"

approval_dir="$control_dir/secure/approval"
approval_fixtures="$control_dir/tests/fixtures/approval"
run_approval_case \
  "approval-secure" 0 \
  "$approval_dir/request.json" \
  "$approval_dir/approval.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-secure.txt"
run_approval_case \
  "approval-insecure" 1 \
  "$approval_dir/request.json" \
  "$control_dir/insecure/approval/approval.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-insecure.txt"
run_approval_case \
  "approval-expired" 1 \
  "$approval_dir/request.json" \
  "$approval_fixtures/expired.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-expired.txt"
run_approval_case \
  "approval-replay" 1 \
  "$approval_dir/request.json" \
  "$approval_dir/approval.json" \
  "$approval_fixtures/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-replay.txt"
run_approval_case \
  "approval-target-tamper" 1 \
  "$approval_fixtures/target-tamper-request.json" \
  "$approval_dir/approval.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-target-tamper.txt"
run_approval_case \
  "approval-parameter-tamper" 1 \
  "$approval_fixtures/parameter-tamper-request.json" \
  "$approval_dir/approval.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-parameter-tamper.txt"
run_approval_case \
  "approval-unclassified" 1 \
  "$approval_fixtures/unclassified-request.json" \
  "$approval_fixtures/unclassified-approval.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-unclassified.txt"
run_approval_case \
  "approval-validator-unavailable" 2 \
  "$approval_dir/request.json" \
  "$approval_dir/approval.json" \
  "$approval_dir/replay-state.json" \
  "$approval_fixtures/unavailable-validation-state.json" \
  "approval-validator-unavailable.txt"
run_approval_case \
  "approval-malformed" 2 \
  "$approval_dir/request.json" \
  "$approval_fixtures/malformed.json" \
  "$approval_dir/replay-state.json" \
  "$approval_dir/validation-state.json" \
  "approval-malformed.txt"

capability_dir="$control_dir/secure/capabilities"
capability_fixtures="$control_dir/tests/fixtures/capabilities"
capability_engine="$capability_dir/engine-state.json"
run_capability_adapter_case \
  "capability-adapters-secure" 0 "$control_dir/secure" \
  "capability-adapters-secure.txt"
run_capability_adapter_case \
  "capability-adapters-insecure" 1 "$control_dir/insecure" \
  "capability-adapters-insecure.txt"
run_capability_invocation_case \
  "capability-read" 0 \
  "$capability_dir/read-invocation.json" "$capability_engine" \
  "capability-read.txt"
run_capability_invocation_case \
  "capability-bounded-write" 0 \
  "$capability_dir/bounded-write-invocation.json" "$capability_engine" \
  "capability-bounded-write.txt"
run_capability_invocation_case \
  "capability-high-impact" 0 \
  "$capability_dir/high-impact-invocation.json" "$capability_engine" \
  "capability-high-impact.txt"
run_capability_invocation_case \
  "capability-destructive" 1 \
  "$capability_fixtures/destructive-invocation.json" "$capability_engine" \
  "capability-destructive.txt"
run_capability_invocation_case \
  "capability-unknown" 1 \
  "$capability_fixtures/unknown-tool-invocation.json" "$capability_engine" \
  "capability-unknown.txt"
run_capability_invocation_case \
  "capability-effect-mismatch" 1 \
  "$capability_fixtures/effect-mismatch-invocation.json" "$capability_engine" \
  "capability-effect-mismatch.txt"
run_capability_invocation_case \
  "capability-target-broadening" 1 \
  "$capability_fixtures/target-broadening-invocation.json" "$capability_engine" \
  "capability-target-broadening.txt"
run_capability_invocation_case \
  "capability-excessive-hitl" 1 \
  "$capability_fixtures/excessive-hitl-invocation.json" "$capability_engine" \
  "capability-excessive-hitl.txt"
run_capability_invocation_case \
  "capability-missing-hitl" 1 \
  "$capability_fixtures/missing-hitl-invocation.json" "$capability_engine" \
  "capability-missing-hitl.txt"
run_capability_invocation_case \
  "capability-malformed" 2 \
  "$capability_fixtures/malformed-invocation.json" "$capability_engine" \
  "capability-malformed.txt"
run_capability_invocation_case \
  "capability-engine-unavailable" 2 \
  "$capability_dir/read-invocation.json" \
  "$capability_fixtures/unavailable-engine-state.json" \
  "capability-engine-unavailable.txt"

approval_runtime="$control_dir/secure/approval-runtime"
approval_runtime_fixtures="$control_dir/tests/fixtures/approval-runtime"
forged_approval="$control_dir/insecure/approval-runtime/forged-envelope.json"
hook_actor_state="$approval_runtime/actor-state.json"
hook_approval_trust="$approval_runtime/approval-trust.json"
empty_approval_inbox="$temporary_directory/empty-approval-inbox"
mkdir -p "$empty_approval_inbox"
hook_audit_policy="$runtime_assessment_policy"
hook_audit_directory="$temporary_directory/hook-audit"
mkdir -m 700 "$hook_audit_directory"
hook_audit_log="$hook_audit_directory/pretool-audit.jsonl"

secure_runtime_state="$control_dir/secure/runtime-assessment"
insecure_runtime_state="$control_dir/insecure/runtime-assessment"
runtime_state_fixtures="$control_dir/tests/fixtures/runtime-assessment"
run_runtime_state_case \
  "runtime-state-secure" 0 "secure" \
  "$secure_runtime_state/claude-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$secure_runtime_state/audit-state.json" \
  "$secure_runtime_state/audit-events.jsonl" \
  "runtime-state-secure.txt"
run_runtime_state_case \
  "runtime-state-insecure" 1 "insecure" \
  "$insecure_runtime_state/claude-inventory.json" \
  "$insecure_runtime_state/codex-inventory.json" \
  "$insecure_runtime_state/audit-state.json" \
  "$insecure_runtime_state/audit-events.jsonl" \
  "runtime-state-insecure.txt"
run_runtime_state_case \
  "runtime-state-stale" 1 "stale" \
  "$runtime_state_fixtures/stale-claude-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$secure_runtime_state/audit-state.json" \
  "$secure_runtime_state/audit-events.jsonl" \
  "runtime-state-stale.txt"
run_runtime_state_case \
  "runtime-state-inventory-unavailable" 2 "unavailable" \
  "$runtime_state_fixtures/unavailable-claude-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$secure_runtime_state/audit-state.json" \
  "$secure_runtime_state/audit-events.jsonl" \
  "runtime-state-inventory-unavailable.txt"
run_runtime_state_case \
  "runtime-state-malformed" 2 "malformed" \
  "$runtime_state_fixtures/malformed-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$secure_runtime_state/audit-state.json" \
  "$secure_runtime_state/audit-events.jsonl" \
  "runtime-state-malformed.txt"
run_runtime_state_case \
  "runtime-state-audit-unavailable" 2 "audit-unavailable" \
  "$secure_runtime_state/claude-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$runtime_state_fixtures/unavailable-audit-state.json" \
  "$secure_runtime_state/audit-events.jsonl" \
  "runtime-state-audit-unavailable.txt"
run_runtime_state_case \
  "runtime-state-audit-malformed" 2 "audit-malformed" \
  "$secure_runtime_state/claude-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$secure_runtime_state/audit-state.json" \
  "$runtime_state_fixtures/malformed-audit-events.jsonl" \
  "runtime-state-audit-malformed.txt"

signed_ledger="$temporary_directory/signed-approval.sqlite3"
run_signed_approval_case \
  "signed-approval-secure" 0 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$signed_ledger" "signed-approval-secure.txt"
run_signed_approval_case \
  "signed-approval-replay" 1 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$signed_ledger" "signed-approval-replay.txt"
run_signed_approval_case \
  "signed-approval-tampered-signature" 1 \
  "$approval_runtime/claude-request.json" \
  "$forged_approval" \
  "$temporary_directory/tampered-signature.sqlite3" \
  "signed-approval-tampered-signature.txt"
run_signed_approval_case \
  "signed-approval-untrusted-key" 2 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime_fixtures/untrusted-key-envelope.json" \
  "$temporary_directory/untrusted-key.sqlite3" \
  "signed-approval-untrusted-key.txt"
run_signed_approval_case \
  "signed-approval-malformed-envelope" 2 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime_fixtures/malformed-envelope.json" \
  "$temporary_directory/malformed-envelope.sqlite3" \
  "signed-approval-malformed-envelope.txt"
run_signed_approval_case \
  "signed-approval-expired" 1 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$temporary_directory/expired.sqlite3" \
  "signed-approval-expired.txt" "2026-07-29T12:06:00Z"
run_signed_approval_case \
  "signed-approval-target-tamper" 1 \
  "$approval_runtime_fixtures/target-tamper-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$temporary_directory/target-tamper.sqlite3" \
  "signed-approval-target-tamper.txt"
run_signed_approval_case \
  "signed-approval-verifier-unavailable" 2 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$temporary_directory/verifier-unavailable.sqlite3" \
  "signed-approval-verifier-unavailable.txt" \
  "2026-07-29T12:02:00Z" "$temporary_directory/missing-openssl"
cp "$approval_runtime_fixtures/corrupt-ledger.txt" \
  "$temporary_directory/corrupt-ledger.sqlite3"
chmod 600 "$temporary_directory/corrupt-ledger.sqlite3"
run_signed_approval_case \
  "signed-approval-ledger-error" 2 \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$temporary_directory/corrupt-ledger.sqlite3" \
  "signed-approval-ledger-error.txt"

concurrent_ledger="$temporary_directory/concurrent.sqlite3"
concurrent_exit_one=0
concurrent_exit_two=0
python3 "$authorize_signed" \
  "$policy" \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$hook_approval_trust" \
  "$concurrent_ledger" \
  --now "2026-07-29T12:02:00Z" \
  >"$temporary_directory/concurrent-one.txt" &
concurrent_pid_one=$!
python3 "$authorize_signed" \
  "$policy" \
  "$approval_runtime/claude-request.json" \
  "$approval_runtime/claude-envelope.json" \
  "$hook_approval_trust" \
  "$concurrent_ledger" \
  --now "2026-07-29T12:02:00Z" \
  >"$temporary_directory/concurrent-two.txt" &
concurrent_pid_two=$!
wait "$concurrent_pid_one" || concurrent_exit_one=$?
wait "$concurrent_pid_two" || concurrent_exit_two=$?
if ! {
  [[ "$concurrent_exit_one" -eq 0 && "$concurrent_exit_two" -eq 1 ]] ||
    [[ "$concurrent_exit_one" -eq 1 && "$concurrent_exit_two" -eq 0 ]]
}; then
  echo "FAIL concurrent approval consumption did not produce one allow and one replay"
  exit 1
fi
if [[ "$(rg -l '^RESULT PASS ' "$temporary_directory"/concurrent-*.txt | wc -l)" -ne 1 ]] ||
  [[ "$(rg -l '^RESULT FAIL ' "$temporary_directory"/concurrent-*.txt | wc -l)" -ne 1 ]]; then
  echo "FAIL concurrent approval evidence is inconsistent"
  exit 1
fi

hook_fixtures="$control_dir/tests/fixtures/hooks"
for provider in claude-code codex; do
  run_hook_case \
    "hook-$provider-bounded-write" "$provider" 0 \
    "$hook_fixtures/bounded-write.json" "$capability_engine" \
    "hook-allow.txt"
  run_hook_case \
    "hook-$provider-wrong-resource" "$provider" 0 \
    "$hook_fixtures/wrong-resource.json" "$capability_engine" \
    "hook-deny-constraints.txt"
  run_hook_case \
    "hook-$provider-oversized-body" "$provider" 0 \
    "$hook_fixtures/oversized-body.json" "$capability_engine" \
    "hook-deny-constraints.txt"
  run_hook_case \
    "hook-$provider-missing-idempotency" "$provider" 0 \
    "$hook_fixtures/missing-idempotency.json" "$capability_engine" \
    "hook-deny-constraints.txt"
  run_hook_case \
    "hook-$provider-destructive" "$provider" 0 \
    "$hook_fixtures/destructive.json" "$capability_engine" \
    "hook-deny-policy.txt"
  run_hook_case \
    "hook-$provider-unknown" "$provider" 0 \
    "$hook_fixtures/unknown-tool.json" "$capability_engine" \
    "hook-deny-unknown.txt"
  run_hook_case \
    "hook-$provider-unknown-reviewed-server-tool" "$provider" 0 \
    "$hook_fixtures/unknown-reviewed-server-tool.json" "$capability_engine" \
    "hook-deny-unknown-tool.txt"
  run_hook_case \
    "hook-$provider-malformed" "$provider" 2 \
    "$hook_fixtures/malformed.json" "$capability_engine" \
    "hook-error.txt"
  run_hook_case \
    "hook-$provider-engine-unavailable" "$provider" 2 \
    "$hook_fixtures/claude-read.json" \
    "$capability_fixtures/unavailable-engine-state.json" \
    "hook-error.txt"
  run_hook_case \
    "hook-$provider-policy-unavailable" "$provider" 2 \
    "$hook_fixtures/claude-read.json" "$capability_engine" \
    "hook-error.txt" "$hook_fixtures/missing-policy.json"
done

run_hook_case \
  "hook-claude-read" "claude-code" 0 \
  "$hook_fixtures/claude-read.json" "$capability_engine" \
  "hook-allow.txt"
run_hook_case \
  "hook-codex-read" "codex" 0 \
  "$hook_fixtures/codex-read.json" "$capability_engine" \
  "hook-allow.txt"
run_hook_case \
  "hook-claude-high-impact" "claude-code" 0 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-high-impact-missing.txt"
run_hook_case \
  "hook-codex-high-impact" "codex" 0 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-high-impact-missing.txt"
for provider in claude-code codex; do
  run_hook_case \
    "hook-$provider-high-impact-unknown-argument" "$provider" 2 \
    "$hook_fixtures/high-impact-unknown-argument.json" "$capability_engine" \
    "hook-error.txt"
done

claude_approval_inbox="$temporary_directory/claude-approval-inbox"
codex_approval_inbox="$temporary_directory/codex-approval-inbox"
tampered_approval_inbox="$temporary_directory/tampered-approval-inbox"
mkdir -p \
  "$claude_approval_inbox" \
  "$codex_approval_inbox" \
  "$tampered_approval_inbox"
cp "$approval_runtime/claude-envelope.json" \
  "$claude_approval_inbox/50dfe3528a5c5d626f1672216f13e3ac1c72ad9c335f8d55ba3c03165c261b0d.json"
cp "$approval_runtime/codex-envelope.json" \
  "$codex_approval_inbox/9fe0413e15d51da9f987d56b79767acdc983937f6c3a3867c185e02b80af247f.json"
cp "$forged_approval" \
  "$tampered_approval_inbox/50dfe3528a5c5d626f1672216f13e3ac1c72ad9c335f8d55ba3c03165c261b0d.json"

claude_hook_ledger="$temporary_directory/claude-hook.sqlite3"
codex_hook_ledger="$temporary_directory/codex-hook.sqlite3"
run_hook_case \
  "hook-claude-high-impact-approved" "claude-code" 0 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-high-impact-allow.txt" "$policy" "$hook_actor_state" \
  "$claude_approval_inbox" "$claude_hook_ledger"
run_hook_case \
  "hook-codex-high-impact-approved" "codex" 0 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-high-impact-allow.txt" "$policy" "$hook_actor_state" \
  "$codex_approval_inbox" "$codex_hook_ledger"
run_hook_case \
  "hook-claude-high-impact-replay" "claude-code" 0 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-high-impact-invalid.txt" "$policy" "$hook_actor_state" \
  "$claude_approval_inbox" "$claude_hook_ledger"
run_hook_case \
  "hook-claude-high-impact-tampered" "claude-code" 0 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-high-impact-invalid.txt" "$policy" "$hook_actor_state" \
  "$tampered_approval_inbox"
run_hook_case \
  "hook-claude-high-impact-actor-unavailable" "claude-code" 2 \
  "$hook_fixtures/high-impact.json" "$capability_engine" \
  "hook-error.txt" "$policy" \
  "$approval_runtime_fixtures/unavailable-actor-state.json" \
  "$claude_approval_inbox"
run_hook_case \
  "hook-audit-sink-unavailable" "claude-code" 2 \
  "$hook_fixtures/claude-read.json" "$capability_engine" \
  "hook-error.txt" "$policy" "$hook_actor_state" \
  "$empty_approval_inbox" "$temporary_directory/audit-failure-ledger.sqlite3" \
  "/usr/bin/openssl" "2026-07-29T12:02:00Z" \
  "$hook_audit_policy" \
  "$temporary_directory/missing-audit-directory/audit.jsonl"
audit_symlink_target="$hook_audit_directory/symlink-target.jsonl"
audit_symlink_path="$hook_audit_directory/symlink-audit.jsonl"
touch "$audit_symlink_target"
chmod 600 "$audit_symlink_target"
ln -s "$audit_symlink_target" "$audit_symlink_path"
run_hook_case \
  "hook-audit-sink-symlink" "codex" 2 \
  "$hook_fixtures/codex-read.json" "$capability_engine" \
  "hook-error.txt" "$policy" "$hook_actor_state" \
  "$empty_approval_inbox" "$temporary_directory/audit-symlink-ledger.sqlite3" \
  "/usr/bin/openssl" "2026-07-29T12:02:00Z" \
  "$hook_audit_policy" "$audit_symlink_path"

run_runtime_state_case \
  "runtime-state-generated-audit" 0 "secure" \
  "$secure_runtime_state/claude-inventory.json" \
  "$secure_runtime_state/codex-inventory.json" \
  "$secure_runtime_state/audit-state.json" \
  "$hook_audit_log" \
  "runtime-state-secure.txt"

network_boundary_fixtures="$control_dir/tests/fixtures/network-boundary"
run_network_boundary_case \
  "network-boundary-secure" 0 \
  "$control_dir/secure/network-boundary/evidence.json" \
  "network-boundary-secure.txt"
run_network_boundary_case \
  "network-boundary-insecure" 1 \
  "$control_dir/insecure/network-boundary/evidence.json" \
  "network-boundary-insecure.txt"
run_network_boundary_case \
  "network-boundary-resolver-unavailable" 2 \
  "$network_boundary_fixtures/unavailable-resolver.json" \
  "network-boundary-resolver-unavailable.txt"
run_network_boundary_case \
  "network-boundary-gateway-unavailable" 2 \
  "$network_boundary_fixtures/unavailable-gateway.json" \
  "network-boundary-gateway-unavailable.txt"
run_network_boundary_case \
  "network-boundary-malformed" 2 \
  "$network_boundary_fixtures/malformed.json" \
  "network-boundary-malformed.txt"

hook_failure_boundary_fixtures="$control_dir/tests/fixtures/hook-failure-boundary"
run_hook_failure_boundary_case \
  "hook-failure-boundary-secure" 0 \
  "$control_dir/secure/hook-failure-boundary/evidence.json" \
  "hook-failure-boundary-secure.txt"
run_hook_failure_boundary_case \
  "hook-failure-boundary-insecure" 1 \
  "$control_dir/insecure/hook-failure-boundary/evidence.json" \
  "hook-failure-boundary-insecure.txt"
run_hook_failure_boundary_case \
  "hook-failure-boundary-gateway-unavailable" 2 \
  "$hook_failure_boundary_fixtures/gateway-unavailable.json" \
  "hook-failure-boundary-gateway-unavailable.txt"
run_hook_failure_boundary_case \
  "hook-failure-boundary-malformed" 2 \
  "$hook_failure_boundary_fixtures/malformed.json" \
  "hook-failure-boundary-malformed.txt"

side_effect_reconciliation_fixtures="$control_dir/tests/fixtures/side-effect-reconciliation"
run_side_effect_reconciliation_case \
  "side-effect-reconciliation-secure" 0 \
  "$control_dir/secure/side-effect-reconciliation/evidence.json" \
  "side-effect-reconciliation-secure.txt"
run_side_effect_reconciliation_case \
  "side-effect-reconciliation-insecure" 1 \
  "$control_dir/insecure/side-effect-reconciliation/evidence.json" \
  "side-effect-reconciliation-insecure.txt"
run_side_effect_reconciliation_case \
  "side-effect-reconciliation-unavailable" 2 \
  "$side_effect_reconciliation_fixtures/unavailable.json" \
  "side-effect-reconciliation-unavailable.txt"
run_side_effect_reconciliation_case \
  "side-effect-reconciliation-malformed" 2 \
  "$side_effect_reconciliation_fixtures/malformed.json" \
  "side-effect-reconciliation-malformed.txt"

command_broker_fixtures="$control_dir/tests/fixtures/command-broker"
run_command_broker_case \
  "command-broker-secure" 0 \
  "$control_dir/secure/command-broker/evidence.json" \
  "command-broker-secure.txt"
run_command_broker_case \
  "command-broker-insecure" 1 \
  "$control_dir/insecure/command-broker/evidence.json" \
  "command-broker-insecure.txt"
run_command_broker_case \
  "command-broker-unavailable" 2 \
  "$command_broker_fixtures/unavailable.json" \
  "command-broker-unavailable.txt"
run_command_broker_case \
  "command-broker-malformed" 2 \
  "$command_broker_fixtures/malformed.json" \
  "command-broker-malformed.txt"

fleet_telemetry_fixtures="$control_dir/tests/fixtures/fleet-telemetry"
run_fleet_telemetry_case \
  "fleet-telemetry-secure" 0 \
  "$control_dir/secure/fleet-telemetry/evidence.json" \
  "fleet-telemetry-secure.txt"
run_fleet_telemetry_case \
  "fleet-telemetry-insecure" 1 \
  "$control_dir/insecure/fleet-telemetry/evidence.json" \
  "fleet-telemetry-insecure.txt"
run_fleet_telemetry_case \
  "fleet-telemetry-unavailable" 2 \
  "$fleet_telemetry_fixtures/unavailable.json" \
  "fleet-telemetry-unavailable.txt"
run_fleet_telemetry_case \
  "fleet-telemetry-malformed" 2 \
  "$fleet_telemetry_fixtures/malformed.json" \
  "fleet-telemetry-malformed.txt"

fleet_evidence="$control_dir/secure/fleet-evidence"
fleet_evidence_fixtures="$control_dir/tests/fixtures/fleet-evidence"
fleet_snapshot="$control_dir/secure/fleet-telemetry/evidence.json"
run_fleet_evidence_case \
  "fleet-evidence-secure" 0 \
  "$fleet_evidence/envelope.json" \
  "$fleet_snapshot" \
  "$fleet_evidence/checkpoint.json" \
  "fleet-evidence-secure.txt"
run_fleet_evidence_case \
  "fleet-evidence-payload-tampered" 1 \
  "$fleet_evidence/envelope.json" \
  "$control_dir/insecure/fleet-telemetry/evidence.json" \
  "$fleet_evidence/checkpoint.json" \
  "fleet-evidence-payload-tampered.txt"
run_fleet_evidence_case \
  "fleet-evidence-signature-tampered" 1 \
  "$fleet_evidence_fixtures/tampered-signature-envelope.json" \
  "$fleet_snapshot" \
  "$fleet_evidence/checkpoint.json" \
  "fleet-evidence-signature-tampered.txt"
run_fleet_evidence_case \
  "fleet-evidence-replay" 1 \
  "$fleet_evidence/envelope.json" \
  "$fleet_snapshot" \
  "$fleet_evidence_fixtures/replay-checkpoint.json" \
  "fleet-evidence-replay.txt"
run_fleet_evidence_case \
  "fleet-evidence-untrusted-key" 2 \
  "$fleet_evidence_fixtures/untrusted-key-envelope.json" \
  "$fleet_snapshot" \
  "$fleet_evidence/checkpoint.json" \
  "fleet-evidence-untrusted-key.txt"
run_fleet_evidence_case \
  "fleet-evidence-malformed" 2 \
  "$fleet_evidence_fixtures/malformed-envelope.json" \
  "$fleet_snapshot" \
  "$fleet_evidence/checkpoint.json" \
  "fleet-evidence-malformed.txt"
run_fleet_evidence_case \
  "fleet-evidence-verifier-unavailable" 2 \
  "$fleet_evidence/envelope.json" \
  "$fleet_snapshot" \
  "$fleet_evidence/checkpoint.json" \
  "fleet-evidence-verifier-unavailable.txt" \
  "$temporary_directory/missing-openssl"

if rg -n -i 'token=|api[_-]?key|password|secret-value|private-url' \
  "$temporary_directory"; then
  echo "FAIL generated evidence contains a forbidden sensitive marker"
  exit 1
fi

echo "PASS secure Claude Code and Codex adapters matched the canonical outcomes"
echo "PASS insecure adapters and repository downgrade were rejected"
echo "PASS malformed unsupported and evaluator failures remained ERROR"
echo "PASS high-impact approvals were classified bound time-limited and single-use"
echo "PASS expired replayed tampered unclassified and unavailable cases failed closed"
echo "PASS exact MCP adapters and risk-based low-frequency HITL policy were enforced"
echo "PASS unknown destructive broadened and malformed capability calls failed closed"
echo "PASS managed PreToolUse gates normalized both providers and blocked evaluation errors"
echo "PASS signed approvals were authenticated and atomically limited to one consumer"
echo "PASS both managed hooks allowed one exact approval and denied missing invalid and replayed evidence"
echo "PASS installed runtime inventories matched approved dependencies and rejected drift"
echo "PASS managed audit covered allow deny and error without request content"
echo "PASS unavailable inventory and audit sinks failed closed"
echo "PASS exact egress allowed only reviewed HTTPS destinations and path prefixes"
echo "PASS proxy local private metadata socket and DNS rebinding paths failed closed"
echo "PASS downstream permits contained hook startup timeout exit and output failures"
echo "PASS uncertain side effects reconciled without approval replay or duplicate mutation"
echo "PASS typed command broker denied shell script task-runner and alias indirection"
echo "PASS adopted fleet telemetry verified both providers ingestion and alert delivery"
echo "PASS collector-signed fleet evidence rejected tampering replay and unknown trust"
echo "PASS evidence stayed deterministic and sanitized"
