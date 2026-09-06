#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' "ERROR python3 is required" >&2
  exit 2
fi

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
verifier="${1:-$script_directory/verify.py}"
if [[ ! -f "$verifier" ]]; then
  printf 'ERROR verifier does not exist: %s\n' "$verifier" >&2
  exit 2
fi

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

printf '%s\n' \
  "name: Safe environment boundary" \
  "on: workflow_dispatch" \
  "concurrency:" \
  '  group: safe-${{ github.ref }}' \
  "jobs:" \
  "  inspect:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  "      - name: Treat metadata as data" \
  "        env:" \
  '          PR_TITLE: ${{ github.event.pull_request.title }}' \
  "          INERT_PRIVATE_VALUE: inert-private-value-for-redaction-test" \
  "        shell: bash" \
  "        run: |" \
  "          printf '%s\\n' \"\$PR_TITLE\"" \
  "      - name: Select a fixed operation" \
  "        env:" \
  '          REQUESTED_TARGET: ${{ inputs.target }}' \
  "        shell: bash" \
  "        run: |" \
  '          case "$REQUESTED_TARGET" in' \
  "            lint|test|verify) printf '%s\\n' \"\$REQUESTED_TARGET\" ;;" \
  "            *) exit 1 ;;" \
  "          esac" \
  >"$temporary_directory/safe.yml"

python3 "$verifier" "$temporary_directory/safe.yml" \
  >"$temporary_directory/safe-output.txt"
if grep -Fq "inert-private-value-for-redaction-test" \
  "$temporary_directory/safe-output.txt"; then
  printf '%s\n' "ERROR verifier output exposed an environment value" >&2
  exit 1
fi

printf '%s\n' \
  "name: Unsafe direct expression" \
  "on: pull_request" \
  "jobs:" \
  "  inspect:" \
  "    runs-on: ubuntu-latest" \
  "    steps:" \
  "      - name: Unsafe title" \
  '        run: printf '\''%s\n'\'' "${{ github.event.pull_request.title }}"' \
  >"$temporary_directory/unsafe.yml"

set +e
python3 "$verifier" "$temporary_directory/unsafe.yml" \
  >"$temporary_directory/unsafe-output.txt"
unsafe_status=$?
set -e
if [[ "$unsafe_status" -ne 1 ]]; then
  printf 'ERROR expected unsafe fixture exit 1, got %s\n' "$unsafe_status" >&2
  exit 1
fi

marker="$temporary_directory/unexpected-command"
payload="\"; touch \"$marker\"; #"
INERT_VALUE="$payload" bash -c \
  'printf '\''%s\n'\'' "$INERT_VALUE" >/dev/null'
if [[ -e "$marker" ]]; then
  printf '%s\n' "ERROR inert payload executed as shell source" >&2
  exit 1
fi

set +e
python3 "$verifier" "$temporary_directory/missing.yml" \
  >"$temporary_directory/error-output.txt" 2>&1
missing_status=$?
set -e
if [[ "$missing_status" -ne 2 ]]; then
  printf 'ERROR expected missing input exit 2, got %s\n' "$missing_status" >&2
  exit 1
fi

printf '%s\n' \
  "PASS safe environment boundary and allowlist accepted" \
  "PASS direct expression rejected" \
  "PASS inert shell metacharacters remained data" \
  "PASS verifier output omitted environment values" \
  "PASS missing input reported as verification error"
