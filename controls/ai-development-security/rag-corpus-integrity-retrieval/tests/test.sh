#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-ai-011.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

run_eval() {
  local policy="${1:-$control_dir/secure/policy.json}"
  local registry="${2:-$control_dir/secure/source-registry.json}"
  local ingestion="${3:-$control_dir/secure/ingestion-evidence.json}"
  local snapshot="${4:-$control_dir/secure/corpus-snapshot.json}"
  local retrieval="${5:-$control_dir/secure/retrieval-evidence.json}"
  local deletion="${6:-$control_dir/secure/deletion-evidence.json}"
  python3 "$verify" \
    --policy "$policy" \
    --source-registry "$registry" \
    --ingestion "$ingestion" \
    --snapshot "$snapshot" \
    --retrieval "$retrieval" \
    --deletion "$deletion" \
    --as-of "2026-08-06T12:00:00Z"
}

run_eval >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
run_eval \
  "" \
  "" \
  "$control_dir/insecure/ingestion-evidence.json" \
  "$control_dir/insecure/corpus-snapshot.json" \
  "$control_dir/insecure/retrieval-evidence.json" \
  "$control_dir/insecure/deletion-evidence.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
test "$insecure_exit" -eq 1
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"
if grep -F "UNTRUSTED_INSTRUCTION_FIXTURE" "$temporary_directory/insecure.txt" >/dev/null; then
  echo "FAIL evidence must not echo corpus content"
  exit 1
fi

cp -R "$control_dir/secure" "$temporary_directory/tampered-bundle"
printf 'tamper\n' >>"$temporary_directory/tampered-bundle/documents/engineering-handbook.txt"
tampered_exit=0
run_eval \
  "$temporary_directory/tampered-bundle/policy.json" \
  "$temporary_directory/tampered-bundle/source-registry.json" \
  "$temporary_directory/tampered-bundle/ingestion-evidence.json" \
  "$temporary_directory/tampered-bundle/corpus-snapshot.json" \
  "$temporary_directory/tampered-bundle/retrieval-evidence.json" \
  "$temporary_directory/tampered-bundle/deletion-evidence.json" \
  >"$temporary_directory/tampered.txt" || tampered_exit=$?
test "$tampered_exit" -eq 1
grep -F "QUARANTINE RAG-002 SRC-001 source content size or digest mismatch" \
  "$temporary_directory/tampered.txt" >/dev/null

unavailable_exit=0
run_eval "" "" "$control_dir/tests/fixtures/unavailable-ingestion.json" \
  >"$temporary_directory/unavailable.txt" || unavailable_exit=$?
test "$unavailable_exit" -eq 2
grep -F "ERROR RAG-009 verification unavailable: RAG ingestion evidence is unavailable or incomplete" \
  "$temporary_directory/unavailable.txt" >/dev/null

malformed_exit=0
run_eval "" "" "" "" "$control_dir/tests/fixtures/malformed.json" \
  >"$temporary_directory/malformed.txt" || malformed_exit=$?
test "$malformed_exit" -eq 2
grep -F "ERROR RAG-009 verification unavailable: cannot parse RAG retrieval evidence" \
  "$temporary_directory/malformed.txt" >/dev/null

cp "$control_dir/secure/retrieval-evidence.json" "$temporary_directory/sensitive-retrieval.json"
python3 - "$temporary_directory/sensitive-retrieval.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["query_text"] = "synthetic secret query that must not be retained"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
sensitive_exit=0
run_eval "" "" "" "" "$temporary_directory/sensitive-retrieval.json" \
  >"$temporary_directory/sensitive.txt" || sensitive_exit=$?
test "$sensitive_exit" -eq 2
grep -F "ERROR RAG-009 verification unavailable: sensitive field retrieval.query_text is prohibited" \
  "$temporary_directory/sensitive.txt" >/dev/null
if grep -F "synthetic secret query" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "FAIL sensitive value must not be echoed"
  exit 1
fi

cp "$control_dir/secure/policy.json" "$temporary_directory/overclaim-policy.json"
python3 - "$temporary_directory/overclaim-policy.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["live_claims"]["vector_database"] = "PASS"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
overclaim_exit=0
run_eval "$temporary_directory/overclaim-policy.json" \
  >"$temporary_directory/overclaim.txt" || overclaim_exit=$?
test "$overclaim_exit" -eq 1
grep -F "QUARANTINE RAG-010 fixture policy overclaims live RAG enforcement" \
  "$temporary_directory/overclaim.txt" >/dev/null

echo "PASS authorized corpus admission and exact retrieval provenance verified"
echo "PASS poisoned unauthorized cross-tenant over-classified and stale content quarantined"
echo "PASS revoked source deletion and retrieval denial verified"
echo "PASS malformed unavailable and sensitive evidence remains ERROR"
