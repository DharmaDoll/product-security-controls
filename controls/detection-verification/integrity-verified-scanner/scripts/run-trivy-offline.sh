#!/usr/bin/env bash
set -euo pipefail

expected_version="Version: 0.72.0"
expected_release_sha256="bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"
expected_binary_sha256="0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e"

if [[ $# -ne 8 ]]; then
  echo "usage: $0 --trivy PATH --cache-directory PATH --target PATH --output PATH" >&2
  exit 2
fi

trivy_path=""
cache_directory=""
target=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --trivy) trivy_path="$2" ;;
    --cache-directory) cache_directory="$2" ;;
    --target) target="$2" ;;
    --output) output="$2" ;;
    *)
      echo "ERROR unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift 2
done

for path in "$trivy_path" "$cache_directory" "$target"; do
  [[ -e "$path" ]] || {
    echo "ERROR required input is unavailable: $path" >&2
    exit 2
  }
done

release_marker="$(dirname "$trivy_path")/.psb-verified-release"
[[ -f "$release_marker" ]] || {
  echo "ERROR scanner release verification marker is missing" >&2
  exit 2
}
[[ "$(tr -d '\r\n' <"$release_marker")" == "$expected_release_sha256" ]] || {
  echo "ERROR scanner release verification marker does not match policy" >&2
  exit 2
}
actual_binary_sha256="$(sha256sum "$trivy_path")"
actual_binary_sha256="${actual_binary_sha256%% *}"
[[ "$actual_binary_sha256" == "$expected_binary_sha256" ]] || {
  echo "ERROR extracted Trivy binary SHA-256 does not match policy" >&2
  exit 2
}

"$trivy_path" --version | head -n 1 | grep -Fqx "$expected_version" || {
  echo "ERROR Trivy version does not match policy" >&2
  exit 2
}

set +e
"$trivy_path" fs \
  --cache-dir "$cache_directory" \
  --scanners vuln,misconfig,secret \
  --format json \
  --output "$output" \
  --offline-scan \
  --skip-db-update \
  --skip-java-db-update \
  --skip-check-update \
  --skip-vex-repo-update \
  --skip-version-check \
  --disable-telemetry \
  "$target"
scanner_status=$?
set -e

if [[ "$scanner_status" -ne 0 ]]; then
  echo "ERROR Trivy execution failed with status ${scanner_status}" >&2
  exit 2
fi
echo "PASS Trivy completed; raw output requires sanitizing normalization"
