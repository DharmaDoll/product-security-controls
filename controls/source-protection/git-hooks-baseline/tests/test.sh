#!/usr/bin/env bash
set -euo pipefail

control="controls/source-protection/git-hooks-baseline"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

python3 "$control/tests/test_scan_sensitive.py" --quiet
bash "$control/tests/test_install.sh"

python3 "$control/scripts/verify.py" "$control/secure" \
  >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$control/scripts/verify.py" "$control/insecure" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1 || {
  echo "expected insecure fixture exit 1, got $insecure_status" >&2
  exit 1
}
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

repository="$temporary_directory/repository"
mkdir "$repository"
git -C "$repository" init -q
git -C "$repository" config --local user.name "Synthetic Test User"
git -C "$repository" config --local user.email "synthetic@example.invalid"
git -C "$repository" config --local core.hooksPath .githooks
cp -R "$control/secure/.githooks" "$repository/.githooks"

fake_bin="$temporary_directory/fake-bin"
mkdir "$fake_bin"
printf '%s\n' \
  '#!/usr/bin/env sh' \
  'printf "%s\n" "$*" >>"$FAKE_DOCKER_LOG"' \
  'exit "${FAKE_DOCKER_STATUS:-0}"' \
  >"$fake_bin/docker"
chmod +x "$fake_bin/docker"
export FAKE_DOCKER_LOG="$temporary_directory/docker-arguments.txt"
export PATH="$fake_bin:$PATH"

printf '%s\n' "safe content" >"$repository/safe.txt"
git -C "$repository" add safe.txt
git -C "$repository" commit -q -m "Add safe content" \
  >"$temporary_directory/safe-commit.txt" 2>&1
baseline_commit="$(git -C "$repository" rev-parse HEAD)"

printf '%s\n' "not a real secret" >"$repository/.env"
git -C "$repository" add .env
set +e
git -C "$repository" commit -q -m "Attempt sensitive filename" \
  >"$temporary_directory/sensitive-path.txt" 2>&1
sensitive_path_status=$?
set -e
test "$sensitive_path_status" -eq 1 || {
  echo "expected sensitive filename commit exit 1, got $sensitive_path_status" >&2
  exit 1
}
grep -F 'BLOCK sensitive-filename ".env"' \
  "$temporary_directory/sensitive-path.txt" >/dev/null
git -C "$repository" reset -q HEAD .env
rm -f "$repository/.env"

synthetic_token_prefix="ghp_"
synthetic_token="${synthetic_token_prefix}000000000000000000000000000000000000"
printf '%s\n' "$synthetic_token" >"$repository/leak.txt"
git -C "$repository" add leak.txt
set +e
(
  cd "$repository"
  .githooks/pre-commit
) \
  >"$temporary_directory/synthetic-token.txt" 2>&1
synthetic_token_status=$?
set -e
test "$synthetic_token_status" -eq 1 || {
  echo "expected synthetic token exit 1, got $synthetic_token_status" >&2
  exit 1
}
if grep -F "$synthetic_token" "$temporary_directory/synthetic-token.txt" >/dev/null; then
  echo "scanner output exposed the matched value" >&2
  exit 1
fi

printf '%s\n' "password=synthetic_value_only" \
  >"$temporary_directory/commit-message.txt"
set +e
(
  cd "$repository"
  .githooks/commit-msg "$temporary_directory/commit-message.txt"
) \
  >"$temporary_directory/commit-message-output.txt" 2>&1
commit_message_status=$?
set -e
test "$commit_message_status" -eq 1 || {
  echo "expected sensitive commit message exit 1, got $commit_message_status" >&2
  exit 1
}
if grep -F "synthetic_value_only" \
  "$temporary_directory/commit-message-output.txt" >/dev/null; then
  echo "commit-msg output exposed the matched value" >&2
  exit 1
fi

git -C "$repository" commit -q --no-verify -m "Synthetic bypass fixture"
git -C "$repository" rm -q leak.txt
git -C "$repository" commit -q -m "Remove synthetic fixture" \
  >"$temporary_directory/removal-commit.txt" 2>&1
head_commit="$(git -C "$repository" rev-parse HEAD)"

set +e
printf 'refs/heads/main %s refs/heads/main %s\n' \
  "$head_commit" "$baseline_commit" |
  (
    cd "$repository"
    .githooks/pre-push origin
  ) >"$temporary_directory/pre-push.txt" 2>&1
pre_push_status=$?
set -e
test "$pre_push_status" -eq 1 || {
  echo "expected historical secret pre-push exit 1, got $pre_push_status" >&2
  exit 1
}
grep -F "BLOCK github-token" "$temporary_directory/pre-push.txt" >/dev/null
if grep -F "$synthetic_token" "$temporary_directory/pre-push.txt" >/dev/null; then
  echo "pre-push output exposed the matched value" >&2
  exit 1
fi

forbidden_files=(
  sample.exe sample.dll sample.so sample.dylib sample.bin sample.msi
  sample.zip sample.tar sample.gz sample.7z sample.rar
  sample.sqlite sample.db sample.mdb sample.sqlite3
  sample.pyc sample.pyo sample.class sample.jar sample.war
  .DS_Store Thumbs.db
  sample.p12 sample.jks sample.keystore
  .env
)
for filename in "${forbidden_files[@]}"; do
  printf '%s\n' "synthetic fixture" >"$repository/$filename"
  git -C "$repository" add "$filename"
done
set +e
(
  cd "$repository"
  .githooks/pre-commit
) >"$temporary_directory/forbidden-files.txt" 2>&1
forbidden_files_status=$?
set -e
test "$forbidden_files_status" -eq 1 || {
  echo "expected forbidden files exit 1, got $forbidden_files_status" >&2
  exit 1
}
forbidden_count="$(
  grep -c '^BLOCK sensitive-filename ' "$temporary_directory/forbidden-files.txt"
)"
test "$forbidden_count" -eq "${#forbidden_files[@]}" || {
  echo "expected ${#forbidden_files[@]} forbidden files, got $forbidden_count" >&2
  exit 1
}
git -C "$repository" reset -q HEAD
for filename in "${forbidden_files[@]}"; do
  rm -f "$repository/$filename"
done

aws_access_key_prefix="AKIA"
aws_access_key="${aws_access_key_prefix}AAAAAAAAAAAAAAAA"
aws_secret_key="$(printf 'A%.0s' {1..40})"
google_key_prefix="AIza"
google_key="${google_key_prefix}00000000000000000000000000000000000"
jwt_header_prefix="eyJ"
jwt_value="${jwt_header_prefix}00000.000000.000000"
bearer_value="$(printf 'b%.0s' {1..20})"
slack_prefix="https://hooks.slack.com"
slack_value="${slack_prefix}/services/AAAAAAAA/BBBBBBBB/CCCCCCCCCCCCCCCC"
github_fine_grained_prefix="github_pat_"
github_fine_grained_value="${github_fine_grained_prefix}$(printf 'A%.0s' {1..82})"
npmrc_auth_value="0123456789abcdef0123"
npmrc_auth_line="//registry.npmjs.org/:_authToken=$npmrc_auth_value"
pypi_prefix="pypi-"
pypi_value="${pypi_prefix}$(printf 'P%.0s' {1..85})"
private_key_begin="-----BEGIN"
private_key_marker="${private_key_begin} PRIVATE KEY-----"
generic_value="$(printf 'g%.0s' {1..20})"
printf '%s\n' \
  "$aws_access_key" \
  "aws_secret_access_key=$aws_secret_key" \
  "$google_key" \
  "$jwt_value" \
  "Authorization: Bearer $bearer_value" \
  "$slack_value" \
  "$github_fine_grained_value" \
  "$npmrc_auth_line" \
  "$pypi_value" \
  "$private_key_marker" \
  "token=$generic_value" \
  >"$temporary_directory/secret-patterns.txt"
set +e
python3 "$repository/.githooks/scan-sensitive.py" \
  --file "$temporary_directory/secret-patterns.txt" --label secret-patterns \
  >"$temporary_directory/secret-pattern-output.txt"
secret_pattern_status=$?
set -e
test "$secret_pattern_status" -eq 1 || {
  echo "expected secret patterns exit 1, got $secret_pattern_status" >&2
  exit 1
}
for rule in \
  aws-access-key aws-secret-access-key google-api-key jwt bearer-token \
  slack-webhook github-fine-grained-pat npmrc-auth-token pypi-api-token \
  private-key credential-assignment; do
  grep -F "BLOCK $rule " "$temporary_directory/secret-pattern-output.txt" >/dev/null
done
for value in \
  "$aws_access_key" "$aws_secret_key" "$google_key" "$jwt_value" \
  "$bearer_value" "$slack_value" "$github_fine_grained_value" \
  "$npmrc_auth_value" "$pypi_value" "$private_key_marker" "$generic_value"; do
  if grep -F -- "$value" "$temporary_directory/secret-pattern-output.txt" >/dev/null; then
    echo "secret-pattern output exposed a matched value" >&2
    exit 1
  fi
done

oversized_file="$temporary_directory/over-5-mib.txt"
dd if=/dev/zero of="$oversized_file" bs=1 count=0 \
  seek="$((5 * 1024 * 1024 + 1))" 2>/dev/null
set +e
python3 "$repository/.githooks/scan-sensitive.py" \
  --file "$oversized_file" --label oversized \
  >"$temporary_directory/oversized-output.txt"
oversized_status=$?
set -e
test "$oversized_status" -eq 1 || {
  echo "expected oversized file exit 1, got $oversized_status" >&2
  exit 1
}
grep -F 'BLOCK file-too-large "oversized"' \
  "$temporary_directory/oversized-output.txt" >/dev/null

set +e
python3 "$repository/.githooks/scan-sensitive.py" \
  --file "$temporary_directory/missing.txt" --label missing \
  >"$temporary_directory/scanner-error.txt" 2>&1
scanner_error_status=$?
set -e
test "$scanner_error_status" -eq 2 || {
  echo "expected scanner execution error exit 2, got $scanner_error_status" >&2
  exit 1
}

set +e
(
  cd "$repository"
  FAKE_DOCKER_STATUS=2 sh .githooks/run-gitleaks.sh
) >"$temporary_directory/gitleaks-error.txt" 2>&1
gitleaks_error_status=$?
set -e
test "$gitleaks_error_status" -eq 2 || {
  echo "expected Gitleaks runtime error exit 2, got $gitleaks_error_status" >&2
  exit 1
}

set +e
(
  cd "$repository"
  PATH="$temporary_directory/no-docker" /bin/sh .githooks/run-gitleaks.sh
) >"$temporary_directory/docker-missing.txt" 2>&1
docker_missing_status=$?
set -e
test "$docker_missing_status" -eq 2 || {
  echo "expected missing Docker exit 2, got $docker_missing_status" >&2
  exit 1
}
grep -F "ERROR Docker is required" "$temporary_directory/docker-missing.txt" >/dev/null

grep -F -- "--pull never" "$FAKE_DOCKER_LOG" >/dev/null
grep -F -- "--network none" "$FAKE_DOCKER_LOG" >/dev/null
grep -F -- "readonly" "$FAKE_DOCKER_LOG" >/dev/null
grep -F -- "--redact" "$FAKE_DOCKER_LOG" >/dev/null
grep -F -- "sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9" \
  "$FAKE_DOCKER_LOG" >/dev/null

adoption_guide="$control/docs/adoption-guide.md"
for required_heading in \
  '## 一括install' \
  '## 1. `.githooks`をcopyする' \
  '## 2. Gitleaks imageを一度だけ取得する' \
  '## 4. 検出self-testを実行する' \
  '## CIとGitHubでも検査する' \
  '## よくある失敗' \
  '## 切り戻し'; do
  grep -Fx "$required_heading" "$adoption_guide" >/dev/null
done
grep -F "sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9" \
  "$adoption_guide" >/dev/null
grep -F ".githooks/test-detection.sh" "$adoption_guide" >/dev/null
grep -F "scripts/install.sh" "$adoption_guide" >/dev/null
grep -F -- "--enable-signing" "$adoption_guide" >/dev/null

echo "PASS secure Git configuration and hook bundle accepted"
echo "PASS dedicated scanner suite covers every filename suffix secret rule and mode"
echo "PASS one-command installer is repository-local conflict-safe and transactional"
echo "PASS insecure Git configuration rejected"
echo "PASS sensitive filename and synthetic token blocked"
echo "PASS sensitive commit message blocked without value disclosure"
echo "PASS pre-push found a deleted secret in introduced history"
echo "PASS all configured forbidden file types blocked"
echo "PASS AWS Google JWT bearer GitHub npmrc PyPI private-key Slack and generic patterns blocked"
echo "PASS files over 5 MiB blocked"
echo "PASS scanner execution error distinguished from clean result"
echo "PASS Gitleaks Docker wrapper is pinned isolated redacted and fail closed"
echo "PASS short adoption guide covers copy activation self-test CI and rollback"
