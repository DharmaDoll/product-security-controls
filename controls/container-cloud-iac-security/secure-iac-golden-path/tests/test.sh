#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-iac-001.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

python3 "$verify" \
  --policy "$control_dir/secure/golden-path-policy.json" \
  --plan "$control_dir/secure/tfplan.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" "$temporary_directory/secure.txt"

insecure_exit=0
python3 "$verify" \
  --policy "$control_dir/insecure/golden-path-policy.json" \
  --plan "$control_dir/insecure/tfplan.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
if [[ "$insecure_exit" -ne 1 ]]; then
  echo "FAIL insecure golden path exit: expected=1 actual=$insecure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

error_exit=0
python3 "$verify" \
  --policy "$control_dir/README.md" \
  --plan "$control_dir/secure/tfplan.json" \
  >"$temporary_directory/error.txt" || error_exit=$?
if [[ "$error_exit" -ne 2 ]]; then
  echo "FAIL malformed policy exit: expected=2 actual=$error_exit"
  exit 1
fi
grep -F "ERROR cannot load policy:" "$temporary_directory/error.txt" >/dev/null

echo "PASS secure IaC golden path matched expected evidence"
echo "PASS insecure defaults plan and enforcement were rejected"
echo "PASS policy evaluation error remained distinct from clean"
