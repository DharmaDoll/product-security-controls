#!/usr/bin/env bash
set -euo pipefail

control="controls/source-protection/repository-destruction-recovery"
verify="$control/scripts/verify.py"
mutate="$control/tests/mutate_fixture.py"
as_of="2026-08-18T14:00:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --evidence "$control/secure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --evidence "$control/insecure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

for scenario in stale partial unavailable-audit sensitive; do
  python3 "$mutate" \
    --source "$control/secure/evidence.json" \
    --output "$temporary_directory/$scenario.json" \
    --scenario "$scenario"
  set +e
  python3 "$verify" \
    --policy "$control/secure/policy.json" \
    --evidence "$temporary_directory/$scenario.json" \
    --as-of "$as_of" \
    >"$temporary_directory/$scenario.txt" 2>&1
  status=$?
  set -e
  test "$status" -eq 2
done
grep -F "repository collector evidence is stale or from the future" \
  "$temporary_directory/stale.txt" >/dev/null
grep -F "repository collector coverage is incomplete" \
  "$temporary_directory/partial.txt" >/dev/null
grep -F "repository deletion audit is incomplete or unavailable" \
  "$temporary_directory/unavailable-audit.txt" >/dev/null
grep -F "evidence contains forbidden sensitive field evidence.token" \
  "$temporary_directory/sensitive.txt" >/dev/null
if grep -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" "$temporary_directory/sensitive.txt" >/dev/null; then
  echo "sensitive repository recovery evidence leaked to output" >&2
  exit 1
fi

python3 "$mutate" \
  --source "$control/secure/evidence.json" \
  --output "$temporary_directory/mismatch.json" \
  --scenario mismatch
set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --evidence "$temporary_directory/mismatch.json" \
  --as-of "$as_of" \
  >"$temporary_directory/mismatch.txt"
mismatch_status=$?
set -e
test "$mismatch_status" -eq 1
grep -F "FAIL RDR-006 repository 1001 restored content_digest does not match backup" \
  "$temporary_directory/mismatch.txt" >/dev/null

python3 "$mutate" \
  --source "$control/secure/policy.json" \
  --output "$temporary_directory/weakened-policy.json" \
  --scenario weakened-policy
set +e
python3 "$verify" \
  --policy "$temporary_directory/weakened-policy.json" \
  --evidence "$control/secure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/weakened-policy.txt"
weakened_policy_status=$?
set -e
test "$weakened_policy_status" -eq 1
grep -F "FAIL RDR-002 policy permits more than one repository deletion per request" \
  "$temporary_directory/weakened-policy.txt" >/dev/null
grep -F "FAIL RDR-007 evidence policy identity does not match the reviewed policy" \
  "$temporary_directory/weakened-policy.txt" >/dev/null

sed 's/e352b6dc/00000000/' \
  "$control/secure/policy.json" >"$temporary_directory/tampered-policy.json"
set +e
python3 "$verify" \
  --policy "$temporary_directory/tampered-policy.json" \
  --evidence "$control/secure/evidence.json" \
  --as-of "$as_of" \
  >"$temporary_directory/tampered-policy.txt" 2>&1
tampered_policy_status=$?
set -e
test "$tampered_policy_status" -eq 2
grep -F "policy_id does not match canonical policy content" \
  "$temporary_directory/tampered-policy.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --evidence "$temporary_directory/malformed.json" \
  --as-of "$as_of" \
  >"$temporary_directory/malformed.txt" 2>&1
malformed_status=$?
set -e
test "$malformed_status" -eq 2
grep -F "evidence is not valid UTF-8 JSON" "$temporary_directory/malformed.txt" >/dev/null

ln -s "$(pwd)/$control/secure/evidence.json" "$temporary_directory/evidence-link.json"
set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --evidence "$temporary_directory/evidence-link.json" \
  --as-of "$as_of" \
  >"$temporary_directory/symlink.txt" 2>&1
symlink_status=$?
set -e
test "$symlink_status" -eq 2
grep -F "evidence is unavailable or symbolic" "$temporary_directory/symlink.txt" >/dev/null

echo "PASS exact critical repository inventory and bulk-deletion denial verified"
echo "PASS attacker-separated immutable backup audit alert and containment verified"
echo "PASS complete isolated digest-bound restore drill verified"
echo "PASS stale partial malformed symbolic sensitive and weakened evidence fails closed"
