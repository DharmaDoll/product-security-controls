#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/untrusted-pr-boundary"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/policy.json" \
  --root "$control/secure" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$control/insecure/policy.json" \
  --root "$control/insecure" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

python3 "$control/scripts/verify.py" \
  --policy "$control/secure/repository-policy.json" \
  --root . \
  >"$temporary_directory/repository.txt"

set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/missing-policy.json" \
  --root "$control/secure" \
  >"$temporary_directory/missing.txt" 2>&1
missing_status=$?
set -e
test "$missing_status" -eq 2

cp "$control/secure/policy.json" "$temporary_directory/policy.json"
printf '%s\n' \
  "name: Unsupported event syntax" \
  "on: [pull_request, push]" \
  "permissions: {}" \
  "jobs:" \
  "  validate:" \
  "    runs-on: ubuntu-latest" \
  "    permissions: {}" \
  >"$temporary_directory/workflow.yml"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/policy.json" \
  --root "$temporary_directory" \
  >"$temporary_directory/unsupported.txt" 2>&1
unsupported_status=$?
set -e
test "$unsupported_status" -eq 2

cp "$control/secure/workflow.yml" "$temporary_directory/workflow.yml"
printf '%s\n' \
  "name: Unreviewed workflow" \
  "on:" \
  "  pull_request:" \
  "permissions: {}" \
  "jobs:" \
  "  validate:" \
  "    runs-on: ubuntu-latest" \
  "    permissions: {}" \
  >"$temporary_directory/unreviewed.yml"
set +e
python3 "$control/scripts/verify.py" \
  --policy "$temporary_directory/policy.json" \
  --root "$temporary_directory" \
  >"$temporary_directory/unreviewed.txt" 2>&1
unreviewed_status=$?
set -e
test "$unreviewed_status" -eq 2

echo "PASS fork pull-request validation stays unprivileged"
echo "PASS pull_request_target workflow_run head checkout cache and self-hosted runner paths rejected"
echo "PASS trusted jobs cannot elevate untrusted jobs in the original run"
echo "PASS repository workflows match the reviewed trust policy"
echo "PASS unsupported YAML missing policy and unreviewed workflows fail closed"
