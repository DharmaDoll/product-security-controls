#!/usr/bin/env bash
set -euo pipefail

control="controls/secure-coding/unicode-source-deception"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

policy="$control/secure/unicode-policy.json"

python3 "$control/scripts/verify.py" --policy "$policy" "$control/secure" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

python3 "$control/scripts/materialize_fixture.py" \
  --fixture "$control/insecure/unicode-source.json" \
  --output-directory "$temporary_directory/insecure" \
  >"$temporary_directory/materialized.txt"
grep -F 'MATERIALIZED example.py sha256=7892ba96230297a5775dd48fcb2827bd61b58d40ba99f0b9dc13dc502252f5be' \
  "$temporary_directory/materialized.txt" >/dev/null

set +e
python3 "$control/scripts/materialize_fixture.py" \
  --fixture "$control/insecure/unicode-source.json" \
  --output-directory "$temporary_directory/insecure" \
  >"$temporary_directory/existing-output.txt" 2>&1
existing_output_status=$?
set -e
test "$existing_output_status" -eq 2 || {
  echo "expected existing fixture output exit 2, got $existing_output_status" >&2
  exit 1
}
grep -F 'ERROR fixture output already exists' \
  "$temporary_directory/existing-output.txt" >/dev/null

set +e
python3 "$control/scripts/verify.py" --policy "$policy" \
  "$temporary_directory/insecure" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure source exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"
if grep -F -e 'hidden text' -e 'safevalue' \
  "$temporary_directory/insecure.txt" >/dev/null; then
  echo "verifier output exposed source content" >&2
  exit 1
fi

set +e
python3 "$control/scripts/materialize_fixture.py" \
  --fixture "$control/tests/fixtures/tampered-manifest.json" \
  --output-directory "$temporary_directory/tampered" \
  >"$temporary_directory/tampered.txt" 2>&1
tampered_status=$?
set -e
test "$tampered_status" -eq 2 || {
  echo "expected tampered fixture exit 2, got $tampered_status" >&2
  exit 1
}
grep -F 'ERROR fixture materialized SHA-256 mismatch' \
  "$temporary_directory/tampered.txt" >/dev/null

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/tests/fixtures/invalid-policy.json" \
  "$control/secure" >"$temporary_directory/invalid-policy.txt" 2>&1
invalid_policy_status=$?
set -e
test "$invalid_policy_status" -eq 2 || {
  echo "expected invalid policy exit 2, got $invalid_policy_status" >&2
  exit 1
}
grep -F 'ERROR policy fields are incomplete or unknown' \
  "$temporary_directory/invalid-policy.txt" >/dev/null

mkdir "$temporary_directory/invalid-utf8"
printf '\377' >"$temporary_directory/invalid-utf8/example.py"
set +e
python3 "$control/scripts/verify.py" --policy "$policy" \
  "$temporary_directory/invalid-utf8" >"$temporary_directory/invalid-utf8.txt" 2>&1
invalid_utf8_status=$?
set -e
test "$invalid_utf8_status" -eq 2 || {
  echo "expected invalid UTF-8 exit 2, got $invalid_utf8_status" >&2
  exit 1
}
grep -F 'ERROR cannot decode example.py as UTF-8' \
  "$temporary_directory/invalid-utf8.txt" >/dev/null

mkdir "$temporary_directory/malformed"
printf '%s\n' 'def broken(:' >"$temporary_directory/malformed/example.py"
set +e
python3 "$control/scripts/verify.py" --policy "$policy" \
  "$temporary_directory/malformed" >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2 || {
  echo "expected malformed Python exit 2, got $malformed_status" >&2
  exit 1
}
grep -F 'ERROR cannot parse example.py as Python source' \
  "$temporary_directory/malformed.txt" >/dev/null

mkdir "$temporary_directory/empty"
set +e
python3 "$control/scripts/verify.py" --policy "$policy" \
  "$temporary_directory/empty" >"$temporary_directory/empty.txt" 2>&1
empty_status=$?
set -e
test "$empty_status" -eq 2 || {
  echo "expected empty source set exit 2, got $empty_status" >&2
  exit 1
}
grep -F 'ERROR no supported Python source files found' \
  "$temporary_directory/empty.txt" >/dev/null

mkdir "$temporary_directory/symlink-source"
ln -s "$control/secure/example.py" "$temporary_directory/symlink-source/example.py"
set +e
python3 "$control/scripts/verify.py" --policy "$policy" \
  "$temporary_directory/symlink-source" >"$temporary_directory/symlink-source.txt" 2>&1
symlink_status=$?
set -e
test "$symlink_status" -eq 2 || {
  echo "expected symbolic-link source exit 2, got $symlink_status" >&2
  exit 1
}
grep -F 'ERROR symbolic-link source is unsupported:' \
  "$temporary_directory/symlink-source.txt" >/dev/null

echo "PASS secure Unicode data and ASCII identifiers accepted"
echo "PASS bidi invisible confusable and normalization findings rejected"
echo "PASS finding evidence contains locations and code points but no source content"
echo "PASS fixture integrity overwrite scope policy UTF-8 syntax and empty-input errors fail closed"
