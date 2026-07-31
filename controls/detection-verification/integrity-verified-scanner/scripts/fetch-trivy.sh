#!/usr/bin/env bash
set -euo pipefail

version="0.72.0"
tag="v${version}"
asset="trivy_${version}_Linux-64bit.tar.gz"
checksums="trivy_${version}_checksums.txt"
bundle="${asset}.sigstore.json"
asset_sha256="bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"
binary_sha256="0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e"
checksums_sha256="ebe9d19a774b950e240b1017a038e9b5a002ea068e02023369ff6d241c10c580"
bundle_sha256="fccbe7d4877af44f27e205528626dfeb3ff6efac57c22061f1fccb59e8a80007"
issuer="https://token.actions.githubusercontent.com"
identity="https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/${tag}"

if [[ $# -ne 2 || "$1" != "--output-directory" ]]; then
  echo "usage: $0 --output-directory NEW_DIRECTORY" >&2
  exit 2
fi

output_directory="$2"
if [[ -e "$output_directory" ]]; then
  echo "ERROR output directory already exists: $output_directory" >&2
  exit 2
fi

for command in curl cosign sha256sum tar python3; do
  command -v "$command" >/dev/null || {
    echo "ERROR required command is unavailable: $command" >&2
    exit 2
  }
done

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
base_url="https://github.com/aquasecurity/trivy/releases/download/${tag}"
release_api="https://api.github.com/repos/aquasecurity/trivy/releases/tags/${tag}"

echo "NETWORK downloading pinned Trivy release assets from ${base_url}"
curl --fail --location --silent --show-error \
  --output "${temporary_directory}/release.json" "$release_api"
curl --fail --location --silent --show-error \
  --output "${temporary_directory}/${asset}" "${base_url}/${asset}"
curl --fail --location --silent --show-error \
  --output "${temporary_directory}/${checksums}" "${base_url}/${checksums}"
curl --fail --location --silent --show-error \
  --output "${temporary_directory}/${bundle}" "${base_url}/${bundle}"

python3 - "${temporary_directory}/release.json" "$tag" <<'PY'
import json
import pathlib
import sys

release = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if release.get("tag_name") != sys.argv[2]:
    raise SystemExit("ERROR release API tag does not match policy")
if release.get("immutable") is not True:
    raise SystemExit("ERROR release API does not report an immutable release")
print(f"PASS GitHub reports immutable release {sys.argv[2]}")
PY

python3 - \
  "${temporary_directory}/${asset}" "$asset_sha256" \
  "${temporary_directory}/${checksums}" "$checksums_sha256" \
  "${temporary_directory}/${bundle}" "$bundle_sha256" <<'PY'
import hashlib
import pathlib
import sys

for path_text, expected in zip(sys.argv[1::2], sys.argv[2::2], strict=True):
    path = pathlib.Path(path_text)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(
            f"ERROR integrity mismatch for {path.name}: expected {expected}, got {actual}"
        )
    print(f"PASS SHA-256 {path.name} {actual}")
PY

python3 - "${temporary_directory}/${checksums}" "$asset" "$asset_sha256" <<'PY'
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
expected_name = sys.argv[2]
expected_digest = sys.argv[3]
entries = {}
for line in lines:
    fields = line.split()
    if len(fields) == 2:
        entries[fields[1].lstrip("*")] = fields[0]
if entries.get(expected_name) != expected_digest:
    raise SystemExit("ERROR publisher checksum file does not bind the reviewed asset")
print("PASS publisher checksum file binds the reviewed Trivy asset")
PY

cosign verify-blob \
  --bundle "${temporary_directory}/${bundle}" \
  --certificate-oidc-issuer "$issuer" \
  --certificate-identity "$identity" \
  "${temporary_directory}/${asset}"

mkdir -p "$output_directory"
tar -xzf "${temporary_directory}/${asset}" -C "$output_directory" trivy
printf '%s  %s\n' "$binary_sha256" "${output_directory}/trivy" | sha256sum -c -
cp "${temporary_directory}/${checksums}" "$output_directory/"
cp "${temporary_directory}/${bundle}" "$output_directory/"
printf '%s\n' "$asset_sha256" >"${output_directory}/.psb-verified-release"

echo "PASS installed integrity-verified Trivy ${version} in ${output_directory}"
