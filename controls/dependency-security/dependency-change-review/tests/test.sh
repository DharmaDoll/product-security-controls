#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/dependency-change-review"
secure="$control/secure/github/dependency-review.yml"
insecure="$control/insecure/github/dependency-review.yml"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

check_reference_workflow() {
  local workflow="$1"
  if [[ ! -r "$workflow" ]]; then
    echo "ERROR workflow unavailable: $workflow"
    return 2
  fi

  local findings=0
  local expected
  for expected in \
    "  pull_request:" \
    "permissions: {}" \
    "      contents: read" \
    "          vulnerability-check: true" \
    "          license-check: false" \
    "          fail-on-severity: high" \
    "          fail-on-scopes: runtime, development, unknown" \
    "          warn-only: false" \
    "          show-openssf-scorecard: false"; do
    if ! rg -Fqx -- "$expected" "$workflow"; then
      echo "BLOCK missing required setting: $expected"
      findings=1
    fi
  done

  if rg -n \
    'pull_request_target:|permissions: write-all|warn-only: true|allow-ghsas:|exclude-packages:|exclude-groups:' \
    "$workflow"; then
    echo "BLOCK workflow contains a non-blocking or broad-bypass setting"
    findings=1
  fi
  return "$findings"
}

check_reference_workflow "$secure"
python3 controls/cicd-security/action-sha-pinning/scripts/verify.py "$secure" \
  >"$temporary_directory/action-pins.txt"
rg -Fx "ACCEPTED 1 immutable uses reference(s)" \
  "$temporary_directory/action-pins.txt" >/dev/null

set +e
check_reference_workflow "$insecure" >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
rg -F "BLOCK workflow contains a non-blocking or broad-bypass setting" \
  "$temporary_directory/insecure.txt" >/dev/null

set +e
check_reference_workflow "$temporary_directory/missing.yml" \
  >"$temporary_directory/missing.txt"
missing_status=$?
set -e
test "$missing_status" -eq 2
rg -F "ERROR workflow unavailable" "$temporary_directory/missing.txt" >/dev/null

echo "PASS pull-request dependency review is SHA-pinned and read-only"
echo "PASS high-severity changed dependencies use blocking mode across all scopes"
echo "PASS warn-only configuration is rejected and missing workflow remains ERROR"
echo "NOT_CHECKED live dependency diff and required-ruleset merge rejection"
