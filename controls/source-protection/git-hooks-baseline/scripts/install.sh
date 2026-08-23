#!/usr/bin/env sh
set -eu

GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"

usage() {
  cat <<'EOF'
Usage: scripts/install.sh --target /absolute/path/to/repository [--enable-signing]

Copies the reviewed .githooks bundle, pulls the digest-pinned Gitleaks image,
sets repository-local Git configuration, and runs the bundled self-test.

--enable-signing  Set local commit.gpgSign and tag.gpgSign to true. Use this
                  only after the repository's signing method and key are ready.
EOF
}

fail() {
  echo "ERROR $*" >&2
  exit 2
}

target=""
enable_signing=0
while test "$#" -gt 0; do
  case "$1" in
    --target)
      test "$#" -ge 2 || fail "--target requires an absolute repository path"
      target=$2
      shift 2
      ;;
    --enable-signing)
      enable_signing=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

test -n "$target" || {
  usage >&2
  fail "--target is required"
}
case "$target" in
  /*) ;;
  *) fail "--target must be an absolute path" ;;
esac

for command_name in git python3 docker mktemp; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name is required"
done

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' ||
  fail "Python 3.10 or newer is required"

script_directory=$(CDPATH= cd -P "$(dirname "$0")" && pwd -P) ||
  fail "cannot resolve the installer directory"
control_root=$(CDPATH= cd -P "$script_directory/.." && pwd -P) ||
  fail "cannot resolve the control directory"
source_hooks="$control_root/secure/.githooks"

test -f "$control_root/control.yaml" || fail "control.yaml is missing"
for hook_name in \
  pre-commit commit-msg pre-push run-gitleaks.sh scan-sensitive.py \
  test-detection.sh; do
  test -f "$source_hooks/$hook_name" ||
    fail "reviewed hook bundle is missing $hook_name"
done

target_root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) ||
  fail "target is not inside a Git worktree"
target_root=$(CDPATH= cd -P "$target_root" && pwd -P) ||
  fail "cannot resolve the target repository root"
target_hooks="$target_root/.githooks"

if test -e "$target_hooks" || test -L "$target_hooks"; then
  fail "$target_hooks already exists; review and merge it manually"
fi

check_local_setting() {
  setting_name=$1
  expected_value=$2
  if setting_value=$(git -C "$target_root" config --local --get-all "$setting_name"); then
    test "$setting_value" = "$expected_value" ||
      fail "local $setting_name already has a different value"
  else
    setting_status=$?
    test "$setting_status" -eq 1 ||
      fail "cannot inspect local $setting_name"
  fi
}

check_local_setting core.hooksPath .githooks
check_local_setting push.default simple
check_local_setting user.useConfigOnly true
if test "$enable_signing" -eq 1; then
  check_local_setting commit.gpgSign true
  check_local_setting tag.gpgSign true
fi

docker version >/dev/null 2>&1 ||
  fail "Docker daemon access is required and must already be approved"

echo "PULL $GITLEAKS_IMAGE"
docker pull "$GITLEAKS_IMAGE" || fail "cannot pull the pinned Gitleaks image"
docker image inspect "$GITLEAKS_IMAGE" >/dev/null 2>&1 ||
  fail "the pinned Gitleaks image is unavailable after pull"

staging_directory=""
hooks_copied=0
core_added=0
push_added=0
user_added=0
commit_signing_added=0
tag_signing_added=0
installation_complete=0

rollback() {
  exit_status=$?
  trap - EXIT HUP INT TERM
  if test "$installation_complete" -ne 1; then
    if test "$tag_signing_added" -eq 1; then
      git -C "$target_root" config --local --unset-all tag.gpgSign >/dev/null 2>&1 || true
    fi
    if test "$commit_signing_added" -eq 1; then
      git -C "$target_root" config --local --unset-all commit.gpgSign >/dev/null 2>&1 || true
    fi
    if test "$user_added" -eq 1; then
      git -C "$target_root" config --local --unset-all user.useConfigOnly >/dev/null 2>&1 || true
    fi
    if test "$push_added" -eq 1; then
      git -C "$target_root" config --local --unset-all push.default >/dev/null 2>&1 || true
    fi
    if test "$core_added" -eq 1; then
      git -C "$target_root" config --local --unset-all core.hooksPath >/dev/null 2>&1 || true
    fi
    if test "$hooks_copied" -eq 1; then
      rm -rf "$target_hooks"
    fi
    if test -n "$staging_directory" && test -d "$staging_directory"; then
      rm -rf "$staging_directory"
    fi
    echo "ROLLBACK removed installer-created hooks and local settings" >&2
  fi
  exit "$exit_status"
}
trap rollback EXIT
trap 'exit 2' HUP INT TERM

staging_directory=$(mktemp -d "$target_root/.psb-source-002-install.XXXXXX") ||
  fail "cannot create a staging directory in the target repository"
cp -R "$source_hooks" "$staging_directory/.githooks" ||
  fail "cannot copy the reviewed hook bundle"
chmod +x \
  "$staging_directory/.githooks/pre-commit" \
  "$staging_directory/.githooks/commit-msg" \
  "$staging_directory/.githooks/pre-push" \
  "$staging_directory/.githooks/run-gitleaks.sh" \
  "$staging_directory/.githooks/scan-sensitive.py" \
  "$staging_directory/.githooks/test-detection.sh" ||
  fail "cannot make the hook bundle executable"
mv "$staging_directory/.githooks" "$target_hooks" ||
  fail "cannot activate the reviewed hook bundle"
hooks_copied=1
rmdir "$staging_directory" || fail "cannot remove the empty staging directory"
staging_directory=""

add_local_setting() {
  setting_name=$1
  setting_value=$2
  added_flag=$3
  if git -C "$target_root" config --local --get-all "$setting_name" >/dev/null 2>&1; then
    return
  fi
  git -C "$target_root" config --local "$setting_name" "$setting_value" ||
    fail "cannot set local $setting_name"
  case "$added_flag" in
    core) core_added=1 ;;
    push) push_added=1 ;;
    user) user_added=1 ;;
    commit-signing) commit_signing_added=1 ;;
    tag-signing) tag_signing_added=1 ;;
  esac
}

add_local_setting core.hooksPath .githooks core
add_local_setting push.default simple push
add_local_setting user.useConfigOnly true user
if test "$enable_signing" -eq 1; then
  add_local_setting commit.gpgSign true commit-signing
  add_local_setting tag.gpgSign true tag-signing
fi

echo "SELF-TEST $target_hooks/test-detection.sh"
(
  cd "$target_root"
  .githooks/test-detection.sh
) || fail "the bundled detection self-test did not pass"

installation_complete=1
echo "READY PSB-SOURCE-002 installed in $target_root"
echo "NEXT review and commit .githooks through the normal pull-request process"
echo "REQUIRED keep independent CI scanning and source-platform secret protection enabled"
