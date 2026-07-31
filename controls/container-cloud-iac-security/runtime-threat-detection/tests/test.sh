#!/usr/bin/env bash
set -euo pipefail

control="controls/container-cloud-iac-security/runtime-threat-detection"
verify="$control/scripts/verify.py"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

common=(
  --policy "$control/secure/runtime-policy.json"
  --workload-identity "$control/secure/workload-identity.json"
  --alert-delivery "$control/secure/alert-delivery.json"
  --response-policy "$control/secure/response-policy.json"
  --as-of "2026-07-31T12:04:00Z"
)

python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/secure/falco-events.jsonl" \
  --health "$control/secure/falco-health.json" \
  >"$temporary_directory/secure-falco.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure-falco.txt"

python3 "$verify" "${common[@]}" \
  --provider sysdig \
  --events "$control/secure/sysdig-events.json" \
  --health "$control/secure/sysdig-health.json" \
  >"$temporary_directory/secure-sysdig.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure-sysdig.txt"

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/insecure/falco-events.jsonl" \
  --health "$control/insecure/falco-detection-health.json" \
  --response-policy "$control/insecure/response-policy.json" \
  >"$temporary_directory/insecure-falco.txt"
falco_detection_status=$?
set -e
test "$falco_detection_status" -eq 1
diff -u "$control/expected-results/insecure-falco.txt" "$temporary_directory/insecure-falco.txt"

set +e
python3 "$verify" "${common[@]}" \
  --provider sysdig \
  --events "$control/insecure/sysdig-events.json" \
  --health "$control/insecure/sysdig-detection-health.json" \
  >"$temporary_directory/insecure-sysdig.txt"
sysdig_detection_status=$?
set -e
test "$sysdig_detection_status" -eq 1
diff -u "$control/expected-results/insecure-sysdig.txt" "$temporary_directory/insecure-sysdig.txt"

for output in "$temporary_directory/insecure-falco.txt" "$temporary_directory/insecure-sysdig.txt"; do
  if rg -F "SYNTHETIC-SENSITIVE-COMMAND" "$output" >/dev/null; then
    echo "raw provider content leaked into evidence" >&2
    exit 1
  fi
done

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/secure/falco-events.jsonl" \
  --health "$control/tests/fixtures/falco-dropped-health.json" \
  >"$temporary_directory/falco-drop.txt"
falco_drop_status=$?
set -e
test "$falco_drop_status" -eq 2
rg -F "ERROR RTD-009 runtime evaluation unavailable: runtime telemetry reports dropped events or alerts" \
  "$temporary_directory/falco-drop.txt" >/dev/null
rg -F "RESULT ERROR; absence of events is not clean" "$temporary_directory/falco-drop.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider sysdig \
  --events "$control/secure/sysdig-events.json" \
  --health "$control/tests/fixtures/sysdig-disconnected-health.json" \
  >"$temporary_directory/sysdig-disconnected.txt"
sysdig_disconnected_status=$?
set -e
test "$sysdig_disconnected_status" -eq 2
rg -F "ERROR RTD-009 runtime evaluation unavailable: runtime sensor is not healthy connected and licensed" \
  "$temporary_directory/sysdig-disconnected.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/tests/fixtures/malformed-falco-events.jsonl" \
  --health "$control/secure/falco-health.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "ERROR RTD-009 runtime evaluation unavailable: Falco event line 1 is malformed" \
  "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/secure/falco-events.jsonl" \
  --health "$control/secure/falco-health.json" \
  --alert-delivery "$control/insecure/alert-delivery.json" \
  >"$temporary_directory/delivery-error.txt"
delivery_status=$?
set -e
test "$delivery_status" -eq 2
rg -F "ERROR RTD-010 runtime evaluation unavailable: runtime alert receiver delivery is not verified" \
  "$temporary_directory/delivery-error.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/secure/falco-events.jsonl" \
  --health "$control/secure/falco-health.json" \
  --as-of "2026-07-31T12:10:00Z" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "ERROR RTD-009 runtime evaluation unavailable: health.observed_at is stale or from the future" \
  "$temporary_directory/stale.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/secure/falco-events.jsonl" \
  --health "$control/tests/fixtures/falco-missing-rule-health.json" \
  >"$temporary_directory/missing-rule.txt"
missing_rule_status=$?
set -e
test "$missing_rule_status" -eq 2
rg -F "ERROR RTD-009 runtime evaluation unavailable: runtime sensor required rule inventory is incomplete" \
  "$temporary_directory/missing-rule.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --events "$control/secure/falco-events.jsonl" \
  --health "$control/insecure/falco-detection-health.json" \
  >"$temporary_directory/sequence-error.txt"
sequence_status=$?
set -e
test "$sequence_status" -eq 2
rg -F "ERROR RTD-009 runtime evaluation unavailable: sensor event count does not match normalized batch" \
  "$temporary_directory/sequence-error.txt" >/dev/null

set +e
python3 "$verify" "${common[@]}" \
  --provider falco \
  --workload-identity "$control/tests/fixtures/wrong-workload-identity.json" \
  --events "$control/insecure/falco-events.jsonl" \
  --health "$control/insecure/falco-detection-health.json" \
  >"$temporary_directory/identity-error.txt"
identity_status=$?
set -e
test "$identity_status" -eq 2
rg -F "ERROR RTD-002 runtime evaluation unavailable: runtime event is not bound to the expected workload and image digest" \
  "$temporary_directory/identity-error.txt" >/dev/null

echo "PASS Falco and Sysdig clean event batches evaluated"
echo "PASS six runtime behavior categories detected through both adapters"
echo "PASS raw provider command content excluded from evidence"
echo "PASS exact workload and immutable image identity binding enforced"
echo "PASS sensor drops disconnection stale signals missing rules sequence errors malformed events and delivery failure remain ERROR"
