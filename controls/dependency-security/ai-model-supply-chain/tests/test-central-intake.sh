#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
worker="$control_dir/scripts/intake_worker.py"
artifact_sha256="df0c00870b43005f873ec026757af59db1956218773b4ee401df32a9536c1aed"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-deps-005-central.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

prepare_case() {
  local case_dir="$1"
  mkdir -p "$case_dir/state" "$case_dir/quarantine" "$case_dir/trusted"
}

run_intake() {
  local case_dir="$1"
  local request="$2"
  local bundle="$3"
  local openssl="${4:-openssl}"
  python3 -B "$worker" \
    --service-policy "$control_dir/secure/service-policy.json" \
    --request "$request" \
    --bundle-dir "$bundle" \
    --state-dir "$case_dir/state" \
    --quarantine-dir "$case_dir/quarantine" \
    --trusted-dir "$case_dir/trusted" \
    --as-of "2026-08-06T12:00:00Z" \
    --openssl "$openssl"
}

assert_no_trusted_files() {
  local trusted_dir="$1"
  if find "$trusted_dir" -type f -print -quit | grep -q .; then
    echo "FAIL rejected or unevaluable intake wrote to trusted storage"
    exit 1
  fi
}

safe_case="$temporary_directory/safe"
prepare_case "$safe_case"
run_intake \
  "$safe_case" \
  "$control_dir/secure/intake-request.json" \
  "$control_dir/secure" \
  >"$temporary_directory/central-secure.txt"
diff -u \
  "$control_dir/expected-results/central-secure.txt" \
  "$temporary_directory/central-secure.txt"

python3 - \
  "$safe_case" \
  "$artifact_sha256" \
  "intake-tiny-classifier-001" \
  "$control_dir/secure" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

case_dir = Path(sys.argv[1])
artifact_digest = sys.argv[2]
request_id = sys.argv[3]
source = Path(sys.argv[4])
quarantine = case_dir / "quarantine" / "sha256" / artifact_digest / "model.bin"
trusted = case_dir / "trusted" / "sha256" / artifact_digest / "model.safetensors"
state = case_dir / "state" / f"{request_id}.json"
receipt = trusted.parent / "promotions" / f"{request_id}.json"

for path in (quarantine, trusted, state, receipt):
    if not path.is_file():
        raise SystemExit(f"missing expected central-intake output: {path.name}")
for path in (quarantine, trusted):
    if hashlib.sha256(path.read_bytes()).hexdigest() != artifact_digest:
        raise SystemExit(f"digest readback failed: {path.name}")

records = [json.loads(state.read_text()), json.loads(receipt.read_text())]
if records[0].get("state") != "PROMOTED" or records[1].get("state") != "PROMOTED":
    raise SystemExit("promotion state was not persisted")
request_digest = records[0].get("request_sha256")
snapshot = (
    case_dir
    / "quarantine"
    / "requests"
    / request_id
    / "sha256"
    / request_digest
)
if (snapshot / "request.json").read_bytes() != (source / "intake-request.json").read_bytes():
    raise SystemExit("intake request was not snapshotted exactly")
for relative in (
    "acquisition.json",
    "artifacts/tiny-model.safetensors.b64",
    "artifacts/synthetic-training.jsonl",
    "model.mlbom.cdx.json",
    "intake-attestation.json",
    "intake-attestation.sig.b64",
    "deployment-handoff.json",
):
    if (snapshot / "bundle" / relative).read_bytes() != (source / relative).read_bytes():
        raise SystemExit(f"bundle material was not snapshotted exactly: {relative}")
for record in records:
    serialized = json.dumps(record, sort_keys=True).lower()
    forbidden = (
        "source_url",
        "signature",
        "public_key",
        "private_key",
        "credential",
        "dataset_rows",
        "model_bytes",
    )
    if any(item in serialized for item in forbidden):
        raise SystemExit("promotion evidence contains protected material")
PY

run_intake \
  "$safe_case" \
  "$control_dir/secure/intake-request.json" \
  "$control_dir/secure" \
  >"$temporary_directory/central-idempotent.txt"
diff -u \
  "$control_dir/expected-results/central-idempotent.txt" \
  "$temporary_directory/central-idempotent.txt"

changed_request="$temporary_directory/changed-request.json"
cp "$control_dir/secure/intake-request.json" "$changed_request"
printf '\n' >>"$changed_request"
reuse_exit=0
run_intake "$safe_case" "$changed_request" "$control_dir/secure" \
  >"$temporary_directory/reused-request.txt" || reuse_exit=$?
test "$reuse_exit" -eq 2
grep -F "request ID was reused with different bytes" \
  "$temporary_directory/reused-request.txt" >/dev/null
grep -F "RESULT ERROR" "$temporary_directory/reused-request.txt" >/dev/null

insecure_case="$temporary_directory/insecure"
prepare_case "$insecure_case"
insecure_exit=0
run_intake \
  "$insecure_case" \
  "$control_dir/insecure/intake-request.json" \
  "$control_dir/insecure" \
  >"$temporary_directory/central-insecure.txt" || insecure_exit=$?
test "$insecure_exit" -eq 1
diff -u \
  "$control_dir/expected-results/central-insecure.txt" \
  "$temporary_directory/central-insecure.txt"
assert_no_trusted_files "$insecure_case/trusted"

error_case="$temporary_directory/error"
prepare_case "$error_case"
error_exit=0
run_intake \
  "$error_case" \
  "$control_dir/secure/intake-request.json" \
  "$control_dir/secure" \
  "$temporary_directory/missing-openssl" \
  >"$temporary_directory/central-error.txt" || error_exit=$?
test "$error_exit" -eq 2
diff -u \
  "$control_dir/expected-results/central-error.txt" \
  "$temporary_directory/central-error.txt"
assert_no_trusted_files "$error_case/trusted"
grep -F '"state": "ERROR"' \
  "$error_case/state/intake-tiny-classifier-001.json" >/dev/null

escape_case="$temporary_directory/path-escape"
prepare_case "$escape_case"
cp -R "$control_dir/secure" "$escape_case/bundle"
python3 - "$escape_case/bundle/acquisition.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["dataset"]["fixture_path"] = "../../outside-dataset.json"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
escape_exit=0
run_intake \
  "$escape_case" \
  "$control_dir/secure/intake-request.json" \
  "$escape_case/bundle" \
  >"$temporary_directory/path-escape.txt" || escape_exit=$?
test "$escape_exit" -eq 1
grep -F "QUARANTINE AMS-006 dataset artifact path escapes the intake bundle" \
  "$temporary_directory/path-escape.txt" >/dev/null
assert_no_trusted_files "$escape_case/trusted"

same_root_case="$temporary_directory/same-root"
mkdir -p "$same_root_case/state" "$same_root_case/quarantine"
same_root_exit=0
python3 -B "$worker" \
  --service-policy "$control_dir/secure/service-policy.json" \
  --request "$control_dir/secure/intake-request.json" \
  --bundle-dir "$control_dir/secure" \
  --state-dir "$same_root_case/state" \
  --quarantine-dir "$same_root_case/quarantine" \
  --trusted-dir "$same_root_case/quarantine" \
  --as-of "2026-08-06T12:00:00Z" \
  >"$temporary_directory/same-root.txt" || same_root_exit=$?
test "$same_root_exit" -eq 2
grep -F "storage roots must be distinct" "$temporary_directory/same-root.txt" >/dev/null
grep -F "RESULT ERROR" "$temporary_directory/same-root.txt" >/dev/null

echo "PASS central intake snapshots the exact bundle before verification and promotes accepted bytes"
echo "PASS central intake is idempotent and rejects request identity reuse"
echo "PASS quarantine findings and verifier failures never write trusted artifacts"
echo "PASS bundle paths are confined and promotion evidence remains metadata-only"
