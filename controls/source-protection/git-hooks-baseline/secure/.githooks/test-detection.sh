#!/usr/bin/env sh
set -eu

root="$(git rev-parse --show-toplevel)" || exit 2
scanner="$root/.githooks/scan-sensitive.py"
gitleaks="$root/.githooks/run-gitleaks.sh"
temporary_directory="$(mktemp -d)" || exit 2
trap 'rm -rf "$temporary_directory"' EXIT

safe_directory="$temporary_directory/safe"
finding_directory="$temporary_directory/finding"
mkdir "$safe_directory" "$finding_directory"
printf '%s\n' 'hello from PSB-SOURCE-002' >"$safe_directory/example.txt"

canary_value="hF9kLm2Np4Qr6St8Uv0Wx3Yz5Ab7Cd9E"
printf 'api_key = "%s"\n' "$canary_value" >"$finding_directory/example.txt"

python3 "$scanner" --file "$safe_directory/example.txt" --label safe \
  >"$temporary_directory/python-safe.txt"
echo "PASS Python scanner accepts safe content"

set +e
python3 "$scanner" --file "$finding_directory/example.txt" --label canary \
  >"$temporary_directory/python-finding.txt" 2>&1
python_status=$?
set -e
if grep -F "$canary_value" "$temporary_directory/python-finding.txt" >/dev/null; then
  echo "ERROR Python scanner exposed the canary value" >&2
  exit 2
fi
if test "$python_status" -ne 1; then
  echo "ERROR Python scanner returned $python_status; expected finding exit 1" >&2
  exit 2
fi
echo "PASS Python scanner blocks and redacts the inert canary"

test_repository="$temporary_directory/repository"
empty_hooks="$temporary_directory/empty-hooks"
mkdir "$empty_hooks"
git init -q "$test_repository"
git -C "$test_repository" config --local user.name "PSB self-test"
git -C "$test_repository" config --local user.email "self-test@example.invalid"
git -C "$test_repository" config --local core.hooksPath "$empty_hooks"
printf '%s\n' 'safe baseline' >"$test_repository/example.txt"
git -C "$test_repository" add example.txt
git -C "$test_repository" commit -q --no-verify -m "Safe baseline"

printf '%s\n' 'safe staged change' >"$test_repository/example.txt"
git -C "$test_repository" add example.txt
if ! (
  cd "$test_repository"
  sh "$gitleaks"
) \
  >"$temporary_directory/gitleaks-safe.txt" 2>&1; then
  echo "ERROR Gitleaks did not accept safe staged content" >&2
  cat "$temporary_directory/gitleaks-safe.txt" >&2
  exit 2
fi
echo "PASS Gitleaks accepts safe staged content"

printf 'api_key = "%s"\n' "$canary_value" >"$test_repository/example.txt"
git -C "$test_repository" add example.txt

set +e
(
  cd "$test_repository"
  sh "$gitleaks"
) \
  >"$temporary_directory/gitleaks-finding.txt" 2>&1
gitleaks_status=$?
set -e
if grep -F "$canary_value" "$temporary_directory/gitleaks-finding.txt" >/dev/null; then
  echo "ERROR Gitleaks exposed the canary value" >&2
  exit 2
fi
if test "$gitleaks_status" -ne 1; then
  echo "ERROR Gitleaks returned $gitleaks_status; expected finding exit 1" >&2
  cat "$temporary_directory/gitleaks-finding.txt" >&2
  exit 2
fi
echo "PASS Gitleaks blocks and redacts the staged inert canary"
echo "READY PSB-SOURCE-002 detection self-test passed"
