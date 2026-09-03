#!/usr/bin/env bash
set -euo pipefail

control="controls/dependency-security/lockfile-integrity"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

test_number=0

show_failure_log() {
  local log_file="$1"
  sed "s|$temporary_directory|<tmp>|g" "$log_file" >&2
}

expect_success() {
  local label="$1"
  shift
  test_number=$((test_number + 1))
  local log_file="$temporary_directory/test-$test_number.log"
  if "$@" >"$log_file" 2>&1; then
    echo "PASS $label"
    return
  fi
  echo "ERROR expected success: $label" >&2
  show_failure_log "$log_file"
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  test_number=$((test_number + 1))
  local log_file="$temporary_directory/test-$test_number.log"
  if "$@" >"$log_file" 2>&1; then
    echo "ERROR expected rejection: $label" >&2
    show_failure_log "$log_file"
    exit 1
  fi
  echo "PASS $label"
}

expect_status() {
  local label="$1"
  local expected_status="$2"
  shift 2
  test_number=$((test_number + 1))
  local log_file="$temporary_directory/test-$test_number.log"
  set +e
  "$@" >"$log_file" 2>&1
  local actual_status=$?
  set -e
  if [[ "$actual_status" -eq "$expected_status" ]]; then
    echo "PASS $label"
    return
  fi
  echo "ERROR expected status $expected_status but got $actual_status: $label" >&2
  show_failure_log "$log_file"
  exit 1
}

file_sha256() {
  python3 -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

prepare_npm_lock() {
  local project_directory="$1"
  local cache_directory="$2"
  NPM_CONFIG_CACHE="$cache_directory" \
    NPM_CONFIG_OFFLINE=true \
    NPM_CONFIG_USERCONFIG=/dev/null \
    npm install \
      --prefix "$project_directory" \
      --package-lock-only \
      --ignore-scripts \
      --no-audit \
      --no-fund \
      --offline >/dev/null
}

create_venv() {
  python3 -m venv "$1"
}

for runtime in node npm python3 uv; do
  if ! command -v "$runtime" >/dev/null 2>&1; then
    echo "ERROR required test runtime is unavailable: $runtime" >&2
    exit 2
  fi
done

fixture_root="$control/tests/fixtures"
builder="$control/tests/helpers/build_fixture_artifacts.py"
npm_fixture="$temporary_directory/npm-fixture"
pnpm_fixture="$temporary_directory/pnpm-fixture"
pip_fixture="$temporary_directory/pip-fixture"
uv_fixture="$temporary_directory/uv-fixture"
tampered_fixture="$temporary_directory/tampered-fixture"

python3 "$builder" --output "$npm_fixture" --fixture-root "$fixture_root"
python3 "$builder" --output "$pnpm_fixture" --fixture-root "$fixture_root"
python3 "$builder" --output "$pip_fixture" --fixture-root "$fixture_root"
python3 "$builder" --output "$uv_fixture" --fixture-root "$fixture_root"
python3 "$builder" --output "$tampered_fixture" --fixture-root "$fixture_root" --tampered-leaf

npm_wrapper="$control/secure/javascript/npm/install-locked.sh"
npm_preflight="$control/secure/javascript/npm/verify-package-lock.mjs"
npm_insecure="$control/insecure/javascript/npm/install-mutable.sh"

basic_project="$npm_fixture/projects/javascript/basic"
prepare_npm_lock "$basic_project" "$temporary_directory/npm-basic-lock-cache"
expect_success \
  "npm installs a direct dependency from an immutable lock" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-basic-ci-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_wrapper" "$basic_project"

transitive_project="$npm_fixture/projects/javascript/transitive-change"
prepare_npm_lock "$transitive_project" "$temporary_directory/npm-transitive-lock-cache"
transitive_lock_before="$(file_sha256 "$transitive_project/package-lock.json")"
expect_success \
  "npm installs the locked direct and transitive graph" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-transitive-ci-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_wrapper" "$transitive_project"
transitive_lock_after="$(file_sha256 "$transitive_project/package-lock.json")"
if [[ "$transitive_lock_before" != "$transitive_lock_after" ]]; then
  echo "ERROR npm ci changed package-lock.json" >&2
  exit 1
fi
echo "PASS npm immutable install leaves package-lock.json unchanged"

npm_drift="$temporary_directory/npm-drift"
cp -R "$transitive_project" "$npm_drift"
cp "$npm_drift/package.drift.json" "$npm_drift/package.json"
expect_failure \
  "npm rejects manifest drift without rewriting the lock" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-drift-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_wrapper" "$npm_drift"

npm_mutable="$temporary_directory/npm-mutable"
cp -R "$transitive_project" "$npm_mutable"
cp "$npm_mutable/package.drift.json" "$npm_mutable/package.json"
npm_mutable_lock_before="$(file_sha256 "$npm_mutable/package-lock.json")"
expect_success \
  "insecure npm install silently repairs manifest drift" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-mutable-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_insecure" "$npm_mutable"
npm_mutable_lock_after="$(file_sha256 "$npm_mutable/package-lock.json")"
if [[ "$npm_mutable_lock_before" == "$npm_mutable_lock_after" ]]; then
  echo "ERROR insecure npm install did not demonstrate lockfile mutation" >&2
  exit 1
fi
echo "PASS insecure npm install demonstrates an unreviewed lockfile rewrite"

npm_missing_lock="$temporary_directory/npm-missing-lock"
cp -R "$transitive_project" "$npm_missing_lock"
rm -f "$npm_missing_lock/package-lock.json"
expect_status \
  "npm missing lockfile is an input error rather than a clean result" 2 \
  bash "$npm_wrapper" "$npm_missing_lock"

npm_missing_integrity="$temporary_directory/npm-missing-integrity"
cp -R "$transitive_project" "$npm_missing_integrity"
node -e '
  const fs = require("node:fs");
  const path = process.argv[1];
  const lock = JSON.parse(fs.readFileSync(path, "utf8"));
  delete lock.packages["node_modules/@psb/leaf"].integrity;
  fs.writeFileSync(path, JSON.stringify(lock, null, 2) + "\n");
' "$npm_missing_integrity/package-lock.json"
expect_status \
  "npm preflight rejects missing transitive artifact integrity" 1 \
  node "$npm_preflight" "$npm_missing_integrity/package-lock.json"

npm_weak_integrity="$temporary_directory/npm-weak-integrity"
cp -R "$transitive_project" "$npm_weak_integrity"
node -e '
  const fs = require("node:fs");
  const path = process.argv[1];
  const lock = JSON.parse(fs.readFileSync(path, "utf8"));
  lock.packages["node_modules/@psb/leaf"].integrity = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  fs.writeFileSync(path, JSON.stringify(lock, null, 2) + "\n");
' "$npm_weak_integrity/package-lock.json"
expect_status \
  "npm preflight rejects weak transitive artifact integrity" 1 \
  node "$npm_preflight" "$npm_weak_integrity/package-lock.json"

npm_malformed_lock="$temporary_directory/npm-malformed-lock.json"
printf '{\n' >"$npm_malformed_lock"
expect_status \
  "npm malformed lockfile is an input error" 2 \
  node "$npm_preflight" "$npm_malformed_lock"

workspace_project="$npm_fixture/projects/javascript/workspace"
prepare_npm_lock "$workspace_project" "$temporary_directory/npm-workspace-lock-cache"
expect_success \
  "npm accepts a declared workspace link without treating it as a registry artifact" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-workspace-ci-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_wrapper" "$workspace_project"
test -e "$workspace_project/node_modules/@psb/workspace-lib"

platform_project="$npm_fixture/projects/javascript/platform-optional"
prepare_npm_lock "$platform_project" "$temporary_directory/npm-platform-lock-cache"
expect_success \
  "npm preserves a platform-optional package in the lock graph" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-platform-ci-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_wrapper" "$platform_project"
node -e '
  const lock = require(process.argv[1]);
  if (!lock.packages["node_modules/@psb/linux-only"].optional) process.exit(1);
' "$platform_project/package-lock.json"
if [[ "$(uname -s)" == "Linux" ]]; then
  test -d "$platform_project/node_modules/@psb/linux-only"
fi
echo "PASS npm distinguishes the locked graph from the target platform install subset"

cp "$tampered_fixture/npm/psb-leaf-1.0.0.tgz" "$npm_fixture/npm/psb-leaf-1.0.0.tgz"
expect_failure \
  "npm rejects a valid but byte-different transitive tarball" \
  env NPM_CONFIG_CACHE="$temporary_directory/npm-tamper-cache" NPM_CONFIG_OFFLINE=true NPM_CONFIG_USERCONFIG=/dev/null \
  bash "$npm_wrapper" "$transitive_project"

mkdir -p "$temporary_directory/empty-path"
expect_status \
  "npm runtime unavailability is an error" 2 \
  env PATH="$temporary_directory/empty-path" "$BASH" "$npm_wrapper" "$transitive_project"

pnpm_wrapper="$control/secure/javascript/pnpm/install-locked.sh"
pnpm_runtime="${PSB_PNPM:-}"
if [[ -z "$pnpm_runtime" ]] && command -v pnpm >/dev/null 2>&1; then
  pnpm_runtime="$(command -v pnpm)"
fi
if [[ -z "$pnpm_runtime" ]]; then
  expect_status \
    "pnpm runtime unavailability is an error, not a clean profile result" 2 \
    env PSB_PNPM="$temporary_directory/missing-pnpm" bash "$pnpm_wrapper" "$pnpm_fixture/projects/javascript/transitive-change"
  echo "NOT_CHECKED pnpm native profile requires the digest-verified 11.25.0 runtime"
else
  pnpm_project="$pnpm_fixture/projects/javascript/transitive-change"
  node -e '
    const fs = require("node:fs");
    const path = process.argv[1];
    const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
    manifest.packageManager = "pnpm@11.25.0";
    fs.writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
  ' "$pnpm_project/package.json"
  "$pnpm_runtime" \
    --dir "$pnpm_project" \
    install \
    --lockfile-only \
    --ignore-scripts \
    --offline \
    --store-dir "$temporary_directory/pnpm-lock-store" >/dev/null
  pnpm_lock_before="$(file_sha256 "$pnpm_project/pnpm-lock.yaml")"
  expect_success \
    "pnpm installs the frozen direct and transitive graph" \
    env PSB_PNPM="$pnpm_runtime" PSB_PNPM_STORE_DIR="$temporary_directory/pnpm-positive-store" PSB_PNPM_OFFLINE=1 \
    bash "$pnpm_wrapper" "$pnpm_project"
  pnpm_lock_after="$(file_sha256 "$pnpm_project/pnpm-lock.yaml")"
  if [[ "$pnpm_lock_before" != "$pnpm_lock_after" ]]; then
    echo "ERROR pnpm frozen install changed pnpm-lock.yaml" >&2
    exit 1
  fi
  echo "PASS pnpm frozen install leaves pnpm-lock.yaml unchanged"

  pnpm_drift="$temporary_directory/pnpm-drift"
  cp -R "$pnpm_project" "$pnpm_drift"
  cp "$pnpm_drift/package.drift.json" "$pnpm_drift/package.json"
  node -e '
    const fs = require("node:fs");
    const path = process.argv[1];
    const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
    manifest.packageManager = "pnpm@11.25.0";
    fs.writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
  ' "$pnpm_drift/package.json"
  expect_failure \
    "pnpm rejects manifest drift without fixing the lock" \
    env PSB_PNPM="$pnpm_runtime" PSB_PNPM_STORE_DIR="$temporary_directory/pnpm-drift-store" PSB_PNPM_OFFLINE=1 \
    bash "$pnpm_wrapper" "$pnpm_drift"

  pnpm_missing_lock="$temporary_directory/pnpm-missing-lock"
  cp -R "$pnpm_project" "$pnpm_missing_lock"
  rm -f "$pnpm_missing_lock/pnpm-lock.yaml"
  expect_status \
    "pnpm missing lockfile is an input error" 2 \
    env PSB_PNPM="$pnpm_runtime" bash "$pnpm_wrapper" "$pnpm_missing_lock"

  pnpm_workspace="$pnpm_fixture/projects/javascript/workspace"
  node -e '
    const fs = require("node:fs");
    const path = process.argv[1];
    const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
    manifest.packageManager = "pnpm@11.25.0";
    manifest.dependencies["@psb/workspace-lib"] = "workspace:1.0.0";
    fs.writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
  ' "$pnpm_workspace/package.json"
  "$pnpm_runtime" \
    --dir "$pnpm_workspace" \
    install \
    --lockfile-only \
    --ignore-scripts \
    --offline \
    --store-dir "$temporary_directory/pnpm-workspace-lock-store" >/dev/null
  expect_success \
    "pnpm frozen workspace install preserves workspace resolution" \
    env PSB_PNPM="$pnpm_runtime" PSB_PNPM_STORE_DIR="$temporary_directory/pnpm-workspace-store" PSB_PNPM_OFFLINE=1 \
    bash "$pnpm_wrapper" "$pnpm_workspace"

  cp "$tampered_fixture/npm/psb-leaf-1.0.0.tgz" "$pnpm_fixture/npm/psb-leaf-1.0.0.tgz"
  expect_failure \
    "pnpm rejects a valid but byte-different transitive tarball" \
    env PSB_PNPM="$pnpm_runtime" PSB_PNPM_STORE_DIR="$temporary_directory/pnpm-tamper-store" PSB_PNPM_OFFLINE=1 \
    bash "$pnpm_wrapper" "$pnpm_project"
fi

pip_wrapper="$control/secure/python/pip/install-locked.sh"
pip_project="$pip_fixture/python"
pip_venv="$temporary_directory/pip-positive-venv"
create_venv "$pip_venv"
expect_success \
  "pip installs complete direct and transitive hashes" \
  env PIP_NO_INDEX=1 PIP_FIND_LINKS="$pip_project" PIP_CACHE_DIR="$temporary_directory/pip-positive-cache" PSB_PYTHON="$pip_venv/bin/python" \
  bash "$pip_wrapper" "$pip_project"

pip_missing_hash="$temporary_directory/pip-missing-hash"
cp -R "$pip_project" "$pip_missing_hash"
python3 -c '
from pathlib import Path
path = Path(__import__("sys").argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
lines[0] = lines[0].split(" --hash=", 1)[0]
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
' "$pip_missing_hash/requirements.lock"
create_venv "$temporary_directory/pip-missing-hash-venv"
expect_failure \
  "pip rejects a missing transitive hash" \
  env PIP_NO_INDEX=1 PIP_FIND_LINKS="$pip_missing_hash" PIP_CACHE_DIR="$temporary_directory/pip-missing-hash-cache" PSB_PYTHON="$temporary_directory/pip-missing-hash-venv/bin/python" \
  bash "$pip_wrapper" "$pip_missing_hash"

pip_range="$temporary_directory/pip-range"
cp -R "$pip_project" "$pip_range"
python3 -c '
from pathlib import Path
path = Path(__import__("sys").argv[1])
content = path.read_text(encoding="utf-8").replace("psb-parent==1.0.0", "psb-parent>=1.0.0")
path.write_text(content, encoding="utf-8")
' "$pip_range/requirements.lock"
create_venv "$temporary_directory/pip-range-venv"
expect_failure \
  "pip hash-checking mode rejects a non-exact requirement" \
  env PIP_NO_INDEX=1 PIP_FIND_LINKS="$pip_range" PIP_CACHE_DIR="$temporary_directory/pip-range-cache" PSB_PYTHON="$temporary_directory/pip-range-venv/bin/python" \
  bash "$pip_wrapper" "$pip_range"

cp "$tampered_fixture/python/psb_leaf-1.0.0-py3-none-any.whl" "$pip_project/psb_leaf-1.0.0-py3-none-any.whl"
create_venv "$temporary_directory/pip-tamper-venv"
expect_failure \
  "pip rejects a valid but byte-different transitive wheel" \
  env PIP_NO_INDEX=1 PIP_FIND_LINKS="$pip_project" PIP_CACHE_DIR="$temporary_directory/pip-tamper-cache" PSB_PYTHON="$temporary_directory/pip-tamper-venv/bin/python" \
  bash "$pip_wrapper" "$pip_project"

expect_status \
  "pip runtime unavailability is an error" 2 \
  env PSB_PYTHON="$temporary_directory/missing-python" bash "$pip_wrapper" "$pip_project"
expect_status \
  "pip refuses to mutate the system interpreter" 2 \
  env PSB_PYTHON=python3 bash "$pip_wrapper" "$pip_project"

uv_wrapper="$control/secure/python/uv/install-locked.sh"
uv_wheel_wrapper="$control/secure/python/uv/install-locked-wheel-only.sh"
uv_pip_wrapper="$control/secure/python/uv/sync-hashed-requirements.sh"
uv_project="$temporary_directory/uv-lock-source"
mkdir -p "$uv_project"
cp "$control/tests/fixtures/python/uv-project/pyproject.toml.template" "$uv_project/pyproject.toml"
uv_index_url="file://$uv_fixture/simple"
UV_CACHE_DIR="$temporary_directory/uv-lock-cache" \
  uv lock \
    --directory "$uv_project" \
    --default-index "$uv_index_url" \
    --no-build \
    --no-python-downloads \
    --no-progress >/dev/null

uv_pristine="$temporary_directory/uv-pristine"
mkdir -p "$uv_pristine"
cp "$uv_project/pyproject.toml" "$uv_pristine/pyproject.toml"
cp "$uv_project/uv.lock" "$uv_pristine/uv.lock"

uv_positive="$temporary_directory/uv-positive"
cp -R "$uv_pristine" "$uv_positive"
uv_lock_before="$(file_sha256 "$uv_positive/uv.lock")"
expect_success \
  "uv sync --locked installs an up-to-date project lock" \
  env UV_CACHE_DIR="$temporary_directory/uv-positive-cache" UV_PROJECT_ENVIRONMENT="$uv_positive/.venv" \
  bash "$uv_wrapper" "$uv_positive"
uv_lock_after="$(file_sha256 "$uv_positive/uv.lock")"
if [[ "$uv_lock_before" != "$uv_lock_after" ]]; then
  echo "ERROR uv sync --locked changed uv.lock" >&2
  exit 1
fi
echo "PASS uv immutable sync leaves uv.lock unchanged"

uv_wheel_only="$temporary_directory/uv-wheel-only"
cp -R "$uv_pristine" "$uv_wheel_only"
expect_success \
  "uv wheel-only profile rejects source builds while preserving lock enforcement" \
  env UV_CACHE_DIR="$temporary_directory/uv-wheel-cache" UV_PROJECT_ENVIRONMENT="$uv_wheel_only/.venv" \
  bash "$uv_wheel_wrapper" "$uv_wheel_only"

uv_drift="$temporary_directory/uv-drift"
cp -R "$uv_pristine" "$uv_drift"
cp "$control/tests/fixtures/python/uv-project/pyproject.drift.toml.template" "$uv_drift/pyproject.toml"
expect_failure \
  "uv --locked rejects pyproject.toml drift" \
  env UV_CACHE_DIR="$temporary_directory/uv-drift-cache" UV_PROJECT_ENVIRONMENT="$uv_drift/.venv-locked" \
  bash "$uv_wrapper" "$uv_drift"
expect_success \
  "uv --frozen reproduces the insecure stale-manifest behavior" \
  env UV_CACHE_DIR="$temporary_directory/uv-frozen-cache" UV_PROJECT_ENVIRONMENT="$uv_drift/.venv-frozen" \
  uv sync --directory "$uv_drift" --frozen --no-build --no-python-downloads --no-progress

uv_missing_lock="$temporary_directory/uv-missing-lock"
mkdir -p "$uv_missing_lock"
cp "$uv_pristine/pyproject.toml" "$uv_missing_lock/pyproject.toml"
expect_status \
  "uv missing lockfile is an input error rather than a clean result" 2 \
  bash "$uv_wrapper" "$uv_missing_lock"

uv_unsupported="$temporary_directory/uv-unsupported"
cp -R "$uv_pristine" "$uv_unsupported"
python3 -c '
from pathlib import Path
path = Path(__import__("sys").argv[1])
path.write_text(path.read_text(encoding="utf-8").replace("version = 1", "version = 999", 1), encoding="utf-8")
' "$uv_unsupported/uv.lock"
expect_failure \
  "uv rejects an unsupported lock schema" \
  env UV_CACHE_DIR="$temporary_directory/uv-unsupported-cache" UV_PROJECT_ENVIRONMENT="$uv_unsupported/.venv" \
  bash "$uv_wrapper" "$uv_unsupported"

cp "$tampered_fixture/python/psb_leaf-1.0.0-py3-none-any.whl" "$uv_fixture/python/psb_leaf-1.0.0-py3-none-any.whl"
uv_tamper="$temporary_directory/uv-tamper"
cp -R "$uv_pristine" "$uv_tamper"
expect_failure \
  "uv rejects a valid but byte-different transitive wheel" \
  env UV_CACHE_DIR="$temporary_directory/uv-tamper-cache" UV_PROJECT_ENVIRONMENT="$uv_tamper/.venv" \
  bash "$uv_wheel_wrapper" "$uv_tamper"

expect_status \
  "uv runtime unavailability is an error" 2 \
  env PSB_UV="$temporary_directory/missing-uv" bash "$uv_wrapper" "$uv_pristine"

python3 "$builder" --output "$temporary_directory/uv-pip-clean" --fixture-root "$fixture_root"
uv_pip_project="$temporary_directory/uv-pip-clean/python"
uv_pip_venv="$temporary_directory/uv-pip-venv"
create_venv "$uv_pip_venv"
expect_success \
  "uv pip sync requires every direct and transitive hash" \
  env UV_DEFAULT_INDEX="file://$temporary_directory/uv-pip-clean/simple" UV_CACHE_DIR="$temporary_directory/uv-pip-cache" PSB_PYTHON="$uv_pip_venv/bin/python" \
  bash "$uv_pip_wrapper" "$uv_pip_project"

echo "PASS native lockfile integrity profiles completed without external network access"
