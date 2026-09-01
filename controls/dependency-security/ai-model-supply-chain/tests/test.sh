#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-deps-005.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_eval() {
  local policy="${1:-$control_dir/secure/policy.json}"
  local acquisition="${2:-$control_dir/secure/acquisition.json}"
  local artifact="${3:-$control_dir/secure/artifacts/tiny-model.safetensors.b64}"
  local dataset="${4:-$control_dir/secure/artifacts/synthetic-training.jsonl}"
  local mlbom="${5:-$control_dir/secure/model.mlbom.cdx.json}"
  local attestation="${6:-$control_dir/secure/intake-attestation.json}"
  local signature="${7:-$control_dir/secure/intake-attestation.sig.b64}"
  local signer_status="${8:-$control_dir/secure/signer-status.json}"
  local handoff="${9:-$control_dir/secure/deployment-handoff.json}"
  local openssl="${10:-openssl}"
  python3 "$verify" \
    --policy "$policy" \
    --acquisition "$acquisition" \
    --artifact "$artifact" \
    --dataset "$dataset" \
    --mlbom "$mlbom" \
    --attestation "$attestation" \
    --signature "$signature" \
    --signer-status "$signer_status" \
    --handoff "$handoff" \
    --as-of "2026-08-06T12:00:00Z" \
    --openssl "$openssl"
}

run_eval >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
run_eval \
  "$control_dir/secure/policy.json" \
  "$control_dir/insecure/acquisition.json" \
  "$control_dir/insecure/artifacts/inert-unsafe-model.pkl.b64" \
  "$control_dir/insecure/artifacts/synthetic-training.jsonl" \
  "$control_dir/insecure/model.mlbom.cdx.json" \
  "$control_dir/insecure/intake-attestation.json" \
  "$control_dir/insecure/intake-attestation.sig.b64" \
  "$control_dir/secure/signer-status.json" \
  "$control_dir/insecure/deployment-handoff.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
test "$insecure_exit" -eq 1
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"
if grep -F "signature verification failed" "$temporary_directory/insecure.txt" >/dev/null; then
  echo "FAIL insecure fixture must retain a valid signature"
  exit 1
fi

python3 - "$control_dir/secure/artifacts/tiny-model.safetensors.b64" \
  "$temporary_directory/tampered-model.b64" <<'PY'
import base64
import sys
from pathlib import Path

value = bytearray(base64.b64decode(Path(sys.argv[1]).read_bytes()))
value[-1] ^= 1
Path(sys.argv[2]).write_bytes(base64.b64encode(value) + b"\n")
PY
tampered_model_exit=0
run_eval "" "" "$temporary_directory/tampered-model.b64" \
  >"$temporary_directory/tampered-model.txt" || tampered_model_exit=$?
test "$tampered_model_exit" -eq 1
grep -F "QUARANTINE AMS-001" "$temporary_directory/tampered-model.txt" >/dev/null
grep -F "QUARANTINE AMS-005" "$temporary_directory/tampered-model.txt" >/dev/null

cp "$control_dir/secure/intake-attestation.json" "$temporary_directory/tampered-attestation.json"
printf ' ' >>"$temporary_directory/tampered-attestation.json"
tampered_attestation_exit=0
run_eval "" "" "" "" "" "$temporary_directory/tampered-attestation.json" \
  >"$temporary_directory/tampered-attestation.txt" || tampered_attestation_exit=$?
test "$tampered_attestation_exit" -eq 1
grep -F "QUARANTINE AMS-005 intake attestation signature verification failed" \
  "$temporary_directory/tampered-attestation.txt" >/dev/null

malformed_exit=0
run_eval "" "" "" "" "$control_dir/tests/fixtures/malformed.json" \
  >"$temporary_directory/malformed.txt" || malformed_exit=$?
test "$malformed_exit" -eq 1
grep -F "QUARANTINE AMS-002 ML-BOM is malformed" \
  "$temporary_directory/malformed.txt" >/dev/null

for status_fixture in unavailable-signer-status stale-signer-status; do
  status_exit=0
  run_eval "" "" "" "" "" "" "" \
    "$control_dir/tests/fixtures/$status_fixture.json" \
    >"$temporary_directory/$status_fixture.txt" || status_exit=$?
  test "$status_exit" -eq 2
  grep -F "ERROR AMS-008 verification unavailable" \
    "$temporary_directory/$status_fixture.txt" >/dev/null
  grep -F "RESULT ERROR" "$temporary_directory/$status_fixture.txt" >/dev/null
done

openssl_exit=0
run_eval "" "" "" "" "" "" "" "" "" \
  "$temporary_directory/missing-openssl" \
  >"$temporary_directory/openssl.txt" || openssl_exit=$?
test "$openssl_exit" -eq 2
grep -F "ERROR AMS-008 verification unavailable: cannot execute OpenSSL" \
  "$temporary_directory/openssl.txt" >/dev/null

mkdir "$temporary_directory/policy-copy"
cp "$control_dir/secure/policy.json" "$temporary_directory/policy-copy/policy.json"
cp -R "$control_dir/secure/trust" "$temporary_directory/policy-copy/trust"
python3 - "$temporary_directory/policy-copy/policy.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["evidence"]["include_model_bytes"] = True
path.write_text(json.dumps(value, indent=2) + "\n")
PY
sensitive_exit=0
run_eval "$temporary_directory/policy-copy/policy.json" \
  >"$temporary_directory/sensitive.txt" || sensitive_exit=$?
test "$sensitive_exit" -eq 1
grep -F "QUARANTINE AMS-009 evidence policy permits sensitive model data or trust material" \
  "$temporary_directory/sensitive.txt" >/dev/null

malformed_policy_exit=0
run_eval "$control_dir/tests/fixtures/malformed.json" \
  >"$temporary_directory/malformed-policy.txt" || malformed_policy_exit=$?
test "$malformed_policy_exit" -eq 2
grep -F "RESULT ERROR" "$temporary_directory/malformed-policy.txt" >/dev/null

if rg -n "BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY" "$control_dir" >/dev/null; then
  echo "FAIL private key material must not be committed"
  exit 1
fi

bash "$control_dir/tests/test-central-intake.sh"

echo "PASS safe model bundle accepted without executing model code"
echo "PASS mutable pickle remote-code dataset and signed finding bundle quarantined"
echo "PASS tampering malformed input and sensitive evidence fail closed"
echo "PASS unavailable stale and crypto infrastructure failures remain ERROR"
