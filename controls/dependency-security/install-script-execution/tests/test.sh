#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/install-script-execution"
as_of="2026-07-27T00:00:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/install-execution-policy.json" \
  --profile-dir "$control/secure" \
  --as-of "$as_of" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/install-execution-policy.json" \
  --profile-dir "$control/insecure" \
  --as-of "$as_of" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure fixture exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

cp -R "$control/secure" "$temporary_directory/expired"
sed -i 's/2026-07-31T00:00:00Z/2026-07-26T00:00:00Z/' \
  "$temporary_directory/expired/install-execution-policy.json"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/expired/install-execution-policy.json" \
  --profile-dir "$temporary_directory/expired" \
  --as-of "$as_of" >"$temporary_directory/expired.txt"
expired_status=$?
set -e
test "$expired_status" -eq 1 || {
  echo "expected expired approval exit 1, got $expired_status" >&2
  exit 1
}
grep -F "approval is not active" "$temporary_directory/expired.txt" >/dev/null

cp -R "$control/secure" "$temporary_directory/broad"
sed -i 's/native-fixture@1.2.3/native-fixture@*/' \
  "$temporary_directory/broad/pnpm/pnpm-workspace.yaml"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/broad/install-execution-policy.json" \
  --profile-dir "$temporary_directory/broad" \
  --as-of "$as_of" >"$temporary_directory/broad.txt"
broad_status=$?
set -e
test "$broad_status" -eq 1 || {
  echo "expected broad allowlist exit 1, got $broad_status" >&2
  exit 1
}
grep -F "allowBuilds entry must pin exact version" \
  "$temporary_directory/broad.txt" >/dev/null

cp -R "$control/secure" "$temporary_directory/malformed"
printf '%s\n' '[install' >"$temporary_directory/malformed/bun/bunfig.toml"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/malformed/install-execution-policy.json" \
  --profile-dir "$temporary_directory/malformed" \
  --as-of "$as_of" >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2 || {
  echo "expected malformed config exit 2, got $malformed_status" >&2
  exit 1
}

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/secure/install-execution-policy.json" \
  --profile-dir "$temporary_directory/missing" \
  --as-of "$as_of" >"$temporary_directory/missing.txt" 2>&1
missing_status=$?
set -e
test "$missing_status" -eq 2 || {
  echo "expected missing config exit 2, got $missing_status" >&2
  exit 1
}

echo "PASS secure npm pnpm Bun and pip profiles accepted"
echo "PASS fail-open broad approval sdist fallback and missing hashes rejected"
echo "PASS expired approval and broad pnpm selector rejected"
echo "PASS missing and malformed configuration fail closed"
