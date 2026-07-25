#!/usr/bin/env bash
set -euo pipefail

control="controls/source-protection/developer-endpoint-hardening"
for required in README.md control.yaml insecure/endpoint-policy.conf secure/endpoint-policy.conf tests/test.sh expected-results/secure.txt expected-results/insecure.txt; do
  test -f "$control/$required" || { echo "missing $control/$required" >&2; exit 1; }
done
echo "validated PSB-SOURCE-001 package structure"
