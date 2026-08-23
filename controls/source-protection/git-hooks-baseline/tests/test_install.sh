#!/usr/bin/env bash
set -euo pipefail

control="controls/source-protection/git-hooks-baseline"
installer="$control/scripts/install.sh"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

fake_bin="$temporary_directory/fake-bin"
fake_global_config="$temporary_directory/global.gitconfig"
mkdir "$fake_bin"
printf '%s\n' \
  '#!/usr/bin/env sh' \
  'set -eu' \
  'printf "%s\n" "$*" >>"$FAKE_DOCKER_LOG"' \
  'case "${1:-}" in' \
  '  version) exit "${FAKE_DOCKER_VERSION_STATUS:-0}" ;;' \
  '  pull) exit "${FAKE_DOCKER_PULL_STATUS:-0}" ;;' \
  '  image) exit "${FAKE_DOCKER_INSPECT_STATUS:-0}" ;;' \
  '  run)' \
  '    if test -n "${FAKE_DOCKER_RUN_STATUS:-}"; then' \
  '      exit "$FAKE_DOCKER_RUN_STATUS"' \
  '    fi' \
  '    count=0' \
  '    if test -f "$FAKE_DOCKER_STATE"; then count=$(cat "$FAKE_DOCKER_STATE"); fi' \
  '    count=$((count + 1))' \
  '    printf "%s\n" "$count" >"$FAKE_DOCKER_STATE"' \
  '    test "$count" -eq 1 && exit 0' \
  '    exit 1' \
  '    ;;' \
  'esac' \
  'exit 2' \
  >"$fake_bin/docker"
chmod +x "$fake_bin/docker"

new_repository() {
  repository_path=$1
  mkdir "$repository_path"
  git -C "$repository_path" init -q
}

run_installer() {
  repository_path=$1
  output_path=$2
  shift 2
  : >"$FAKE_DOCKER_LOG"
  rm -f "$FAKE_DOCKER_STATE"
  GIT_CONFIG_GLOBAL="$fake_global_config" GIT_CONFIG_NOSYSTEM=1 PATH="$fake_bin:$PATH" \
    "$installer" --target "$repository_path" "$@" >"$output_path" 2>&1
}

export FAKE_DOCKER_LOG="$temporary_directory/docker.log"
export FAKE_DOCKER_STATE="$temporary_directory/docker.state"

success_repository="$temporary_directory/success"
new_repository "$success_repository"
run_installer "$success_repository" "$temporary_directory/success.txt"
test "$(git -C "$success_repository" config --local --get core.hooksPath)" = .githooks
test "$(git -C "$success_repository" config --local --get push.default)" = simple
test "$(git -C "$success_repository" config --local --get user.useConfigOnly)" = true
if git -C "$success_repository" config --local --get commit.gpgSign >/dev/null; then
  echo "installer enabled commit signing without explicit authorization" >&2
  exit 1
fi
test -x "$success_repository/.githooks/pre-commit"
diff -r "$control/secure/.githooks" "$success_repository/.githooks"
grep -F "pull ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9" \
  "$FAKE_DOCKER_LOG" >/dev/null
grep -F "READY PSB-SOURCE-002 installed in" "$temporary_directory/success.txt" >/dev/null
test ! -e "$fake_global_config"

set +e
run_installer "$success_repository" "$temporary_directory/reinstall.txt"
reinstall_status=$?
set -e
test "$reinstall_status" -eq 2
grep -F "already exists; review and merge it manually" \
  "$temporary_directory/reinstall.txt" >/dev/null
test ! -s "$FAKE_DOCKER_LOG"

conflict_repository="$temporary_directory/conflict"
new_repository "$conflict_repository"
git -C "$conflict_repository" config --local core.hooksPath ../shared-hooks
set +e
run_installer "$conflict_repository" "$temporary_directory/conflict.txt"
conflict_status=$?
set -e
test "$conflict_status" -eq 2
test "$(git -C "$conflict_repository" config --local --get core.hooksPath)" = ../shared-hooks
test ! -e "$conflict_repository/.githooks"
test ! -s "$FAKE_DOCKER_LOG"

pull_failure_repository="$temporary_directory/pull-failure"
new_repository "$pull_failure_repository"
export FAKE_DOCKER_PULL_STATUS=2
set +e
run_installer "$pull_failure_repository" "$temporary_directory/pull-failure.txt"
pull_failure_status=$?
set -e
unset FAKE_DOCKER_PULL_STATUS
test "$pull_failure_status" -eq 2
test ! -e "$pull_failure_repository/.githooks"
if git -C "$pull_failure_repository" config --local --get core.hooksPath >/dev/null; then
  echo "pull failure left core.hooksPath configured" >&2
  exit 1
fi

self_test_failure_repository="$temporary_directory/self-test-failure"
new_repository "$self_test_failure_repository"
git -C "$self_test_failure_repository" config --local push.default simple
export FAKE_DOCKER_RUN_STATUS=2
set +e
run_installer \
  "$self_test_failure_repository" "$temporary_directory/self-test-failure.txt"
self_test_failure_status=$?
set -e
unset FAKE_DOCKER_RUN_STATUS
test "$self_test_failure_status" -eq 2
test ! -e "$self_test_failure_repository/.githooks"
test "$(git -C "$self_test_failure_repository" config --local --get push.default)" = simple
for setting_name in core.hooksPath user.useConfigOnly; do
  if git -C "$self_test_failure_repository" config --local --get "$setting_name" >/dev/null; then
    echo "self-test failure left $setting_name configured" >&2
    exit 1
  fi
done
grep -F "ROLLBACK removed installer-created hooks and local settings" \
  "$temporary_directory/self-test-failure.txt" >/dev/null

signing_repository="$temporary_directory/signing"
new_repository "$signing_repository"
run_installer \
  "$signing_repository" "$temporary_directory/signing.txt" --enable-signing
test "$(git -C "$signing_repository" config --local --get commit.gpgSign)" = true
test "$(git -C "$signing_repository" config --local --get tag.gpgSign)" = true

echo "PASS one-command installer activates only repository-local settings"
echo "PASS existing hooks and conflicting local configuration are preserved"
echo "PASS Docker pull and self-test failures do not leave a partial installation"
echo "PASS commit and tag signing require an explicit installer option"
