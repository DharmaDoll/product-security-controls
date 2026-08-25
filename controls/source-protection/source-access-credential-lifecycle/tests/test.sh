#!/usr/bin/env bash
set -euo pipefail

control_dir="$(cd "$(dirname "$0")/.." && pwd)"
verify="$control_dir/scripts/verify.py"
verify_github_mcp="$control_dir/scripts/verify-github-mcp-auth.py"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/psb-source-004.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

python3 "$verify" "$control_dir/secure/credential-policy.json" \
  >"$temporary_directory/secure.txt"
diff -u "$control_dir/expected-results/secure.txt" \
  "$temporary_directory/secure.txt"

insecure_exit=0
python3 "$verify" "$control_dir/insecure/credential-policy.json" \
  >"$temporary_directory/insecure.txt" || insecure_exit=$?
if [[ "$insecure_exit" -ne 1 ]]; then
  echo "FAIL insecure policy exit: expected=1 actual=$insecure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/insecure.txt" \
  "$temporary_directory/insecure.txt"

malformed_exit=0
python3 "$verify" "$control_dir/README.md" \
  >"$temporary_directory/error.txt" || malformed_exit=$?
if [[ "$malformed_exit" -ne 2 ]]; then
  echo "FAIL malformed policy exit: expected=2 actual=$malformed_exit"
  exit 1
fi
grep -F "ERROR cannot load policy metadata:" "$temporary_directory/error.txt" \
  >/dev/null

python3 "$verify_github_mcp" \
  "$control_dir/secure/github-mcp-auth-policy.json" \
  "$control_dir/secure/github-mcp-oauth.json" \
  "$control_dir/secure/github-mcp-pat-fallback.json" \
  >"$temporary_directory/github-mcp-secure.txt"
diff -u "$control_dir/expected-results/github-mcp-secure.txt" \
  "$temporary_directory/github-mcp-secure.txt"

github_mcp_insecure_exit=0
python3 "$verify_github_mcp" \
  "$control_dir/insecure/github-mcp-auth-policy.json" \
  "$control_dir/insecure/github-mcp-oauth.json" \
  "$control_dir/insecure/github-mcp-pat-fallback.json" \
  >"$temporary_directory/github-mcp-insecure.txt" || github_mcp_insecure_exit=$?
if [[ "$github_mcp_insecure_exit" -ne 1 ]]; then
  echo "FAIL insecure GitHub MCP profile exit: expected=1 actual=$github_mcp_insecure_exit"
  exit 1
fi
diff -u "$control_dir/expected-results/github-mcp-insecure.txt" \
  "$temporary_directory/github-mcp-insecure.txt"

for error_fixture in github-mcp-malformed.json github-mcp-sensitive.json; do
  github_mcp_error_exit=0
  python3 "$verify_github_mcp" \
    "$control_dir/secure/github-mcp-auth-policy.json" \
    "$control_dir/secure/github-mcp-oauth.json" \
    "$control_dir/tests/fixtures/$error_fixture" \
    >"$temporary_directory/$error_fixture.txt" || github_mcp_error_exit=$?
  if [[ "$github_mcp_error_exit" -ne 2 ]]; then
    echo "FAIL GitHub MCP evidence error exit: fixture=$error_fixture expected=2 actual=$github_mcp_error_exit"
    exit 1
  fi
  grep -F "ERROR PSB-SOURCE-004/GITHUB-MCP-EVIDENCE" \
    "$temporary_directory/$error_fixture.txt" >/dev/null
done

echo "PASS secure credential lifecycle reference matched expected output"
echo "PASS insecure credential lifecycle reference was rejected"
echo "PASS malformed input remained distinct from a clean result"
echo "PASS GitHub MCP OAuth-first and PAT-fallback reference profiles were distinguished"
echo "PASS GitHub MCP malformed and sensitive evidence remained ERROR"
