#!/usr/bin/env sh
set -eu

image="ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR Docker is required for the Gitleaks scan" >&2
  exit 2
fi

source_directory="$(git rev-parse --show-toplevel)" || exit 2

exec docker run --rm --pull never --network none \
  --mount "type=bind,source=$source_directory,target=/scan,readonly" \
  --workdir /scan "$image" git --staged --redact --no-banner /scan
