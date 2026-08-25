#!/usr/bin/env bash
set -eu

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT

source_repository="${test_root}/source"
mirror_backup="${test_root}/critical-repository.git"
restored_repository="${test_root}/restored.git"
incomplete_repository="${test_root}/incomplete.git"
expected_refs="${test_root}/expected.refs"
restored_refs="${test_root}/restored.refs"
incomplete_refs="${test_root}/incomplete.refs"

git init -q "${source_repository}"
git -C "${source_repository}" config user.name "PSB restore test"
git -C "${source_repository}" config user.email "psb-restore-test@example.invalid"
git -C "${source_repository}" branch -M main

printf '%s\n' 'critical product source' > "${source_repository}/product.txt"
git -C "${source_repository}" add product.txt
git -C "${source_repository}" commit -q -m "Add product source"
git -C "${source_repository}" branch release/1.x
git -C "${source_repository}" tag v1.0.0

git clone -q --mirror "${source_repository}" "${mirror_backup}"
git -C "${mirror_backup}" fsck --full >/dev/null
git -C "${mirror_backup}" for-each-ref \
  --format='%(refname) %(objectname)' refs/heads refs/tags \
  | LC_ALL=C sort > "${expected_refs}"

rm -rf "${source_repository}"

git init -q --bare "${restored_repository}"
git -C "${mirror_backup}" push -q --all "${restored_repository}"
git -C "${mirror_backup}" push -q --tags "${restored_repository}"
git -C "${restored_repository}" for-each-ref \
  --format='%(refname) %(objectname)' refs/heads refs/tags \
  | LC_ALL=C sort > "${restored_refs}"
cmp "${expected_refs}" "${restored_refs}"
printf '%s\n' 'PASS mirror backup preserves branches and tags after source loss'

git init -q --bare "${incomplete_repository}"
git -C "${mirror_backup}" push -q \
  "${incomplete_repository}" refs/heads/main:refs/heads/main
git -C "${incomplete_repository}" for-each-ref \
  --format='%(refname) %(objectname)' refs/heads refs/tags \
  | LC_ALL=C sort > "${incomplete_refs}"

if cmp -s "${expected_refs}" "${incomplete_refs}"; then
  printf '%s\n' 'FAIL incomplete restore was accepted' >&2
  exit 1
fi

printf '%s\n' 'PASS incomplete restore is detected'
