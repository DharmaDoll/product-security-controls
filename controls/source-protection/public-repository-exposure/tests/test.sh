#!/bin/sh
set -eu

CONTROL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERIFY="$CONTROL_DIR/scripts/verify.py"
HISTORY_SCAN="$CONTROL_DIR/scripts/scan-git-history.py"
ORGANIZATION_SCAN="$CONTROL_DIR/scripts/scan-organization-exposure.py"
ORGANIZATION_INDICATORS="$CONTROL_DIR/secure/organization-indicators.json"
GITHUB_DORKS="$CONTROL_DIR/scripts/generate-github-web-dorks.py"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

python3 "$VERIFY" \
  "$CONTROL_DIR/secure/exposure-policy.json" \
  "$CONTROL_DIR/secure/evidence-snapshot.json" \
  >"$TEST_ROOT/secure.out"
grep -q '^ACCEPTED ' "$TEST_ROOT/secure.out"

if python3 "$VERIFY" \
  "$CONTROL_DIR/insecure/exposure-policy.json" \
  "$CONTROL_DIR/insecure/evidence-snapshot.json" \
  >"$TEST_ROOT/insecure.out" 2>"$TEST_ROOT/insecure.err"
then
  echo "insecure exposure profile was unexpectedly accepted" >&2
  exit 1
fi
grep -q '^REJECTED ' "$TEST_ROOT/insecure.out"

if python3 "$VERIFY" "$TEST_ROOT/missing.json" "$TEST_ROOT/missing.json" \
  >"$TEST_ROOT/malformed.out" 2>"$TEST_ROOT/malformed.err"
then
  echo "missing exposure evidence was unexpectedly accepted" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -q '^ERROR ' "$TEST_ROOT/malformed.err"

CLEAN_REPO="$TEST_ROOT/clean-repository"
mkdir "$CLEAN_REPO"
git -C "$CLEAN_REPO" init -q
git -C "$CLEAN_REPO" config user.name "PSB Test"
git -C "$CLEAN_REPO" config user.email "psb-test@example.invalid"
printf '%s\n' 'safe = true' >"$CLEAN_REPO/settings.conf"
git -C "$CLEAN_REPO" add settings.conf
git -C "$CLEAN_REPO" commit -q -m "safe fixture"
python3 "$HISTORY_SCAN" "$CLEAN_REPO" >"$TEST_ROOT/clean-history.out"
grep -q '^ACCEPTED no sensitive-data findings$' "$TEST_ROOT/clean-history.out"
python3 "$ORGANIZATION_SCAN" "$CLEAN_REPO" \
  --indicators "$ORGANIZATION_INDICATORS" \
  >"$TEST_ROOT/clean-organization.out"
grep -q '^ACCEPTED no organization-specific exposure findings$' \
  "$TEST_ROOT/clean-organization.out"

python3 "$GITHUB_DORKS" \
  --indicators "$ORGANIZATION_INDICATORS" \
  --output "$TEST_ROOT/github-global-dorks.md" \
  >"$TEST_ROOT/github-global-dorks.out"
grep -q '^WROTE ' "$TEST_ROOT/github-global-dorks.out"
grep -q 'https://github.com/search?' "$TEST_ROOT/github-global-dorks.md"
grep -q 'type=code' "$TEST_ROOT/github-global-dorks.md"
grep -q ' AND (' "$TEST_ROOT/github-global-dorks.md"
grep -Fq 'content:"corp.example.invalid"' "$TEST_ROOT/github-global-dorks.md"
grep -Fq 'path:*.env OR path:*.yml' "$TEST_ROOT/github-global-dorks.md"
grep -Fq 'NOT is:generated AND NOT is:vendored' \
  "$TEST_ROOT/github-global-dorks.md"
if grep -q 'repo:' "$TEST_ROOT/github-global-dorks.md" \
  || grep -q 'org:' "$TEST_ROOT/github-global-dorks.md"
then
  echo "global attacker-view dorks were unexpectedly repository scoped" >&2
  exit 1
fi

python3 "$GITHUB_DORKS" \
  --indicators "$ORGANIZATION_INDICATORS" \
  --owner example-org \
  --output "$TEST_ROOT/github-owner-dorks.md" \
  >"$TEST_ROOT/github-owner-dorks.out"
grep -q 'org:example-org' "$TEST_ROOT/github-owner-dorks.md"

EXPOSED_REPO="$TEST_ROOT/exposed-repository"
mkdir "$EXPOSED_REPO"
git -C "$EXPOSED_REPO" init -q
git -C "$EXPOSED_REPO" config user.name "PSB Test"
git -C "$EXPOSED_REPO" config user.email "psb-test@example.invalid"
SYNTHETIC_TOKEN='ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
printf '%s\n' "token=$SYNTHETIC_TOKEN" >"$EXPOSED_REPO/temporary.txt"
git -C "$EXPOSED_REPO" add temporary.txt
git -C "$EXPOSED_REPO" commit -q -m "synthetic exposure fixture"
git -C "$EXPOSED_REPO" rm -q temporary.txt
git -C "$EXPOSED_REPO" commit -q -m "remove latest-tree exposure"
SYNTHETIC_EMAIL='developer@corp.example.invalid'
SYNTHETIC_MARKER='INTERNAL-ONLY-SYNTHETIC'
printf '%s\n' \
  "contact=$SYNTHETIC_EMAIL" \
  "classification=$SYNTHETIC_MARKER" \
  >"$EXPOSED_REPO/organization-notes.txt"
git -C "$EXPOSED_REPO" add organization-notes.txt
git -C "$EXPOSED_REPO" commit -q -m "synthetic organization exposure fixture"
git -C "$EXPOSED_REPO" rm -q organization-notes.txt
git -C "$EXPOSED_REPO" commit -q -m "remove organization exposure from latest tree"
if python3 "$HISTORY_SCAN" "$EXPOSED_REPO" \
  >"$TEST_ROOT/exposed-history.out" 2>"$TEST_ROOT/exposed-history.err"
then
  echo "historical synthetic exposure was unexpectedly accepted" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 1
grep -q '^BLOCK github-token ' "$TEST_ROOT/exposed-history.out"
grep -q '^REJECTED ' "$TEST_ROOT/exposed-history.out"
if grep -Fq "$SYNTHETIC_TOKEN" "$TEST_ROOT/exposed-history.out" \
  || grep -Fq "$SYNTHETIC_TOKEN" "$TEST_ROOT/exposed-history.err"
then
  echo "scanner disclosed a matched synthetic value" >&2
  exit 1
fi

if python3 "$ORGANIZATION_SCAN" "$EXPOSED_REPO" \
  --indicators "$ORGANIZATION_INDICATORS" \
  >"$TEST_ROOT/organization.out" 2>"$TEST_ROOT/organization.err"
then
  echo "historical organization exposure was unexpectedly accepted" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 1
grep -q '^BLOCK ORG-DOMAIN-CORPORATE ' "$TEST_ROOT/organization.out"
grep -q '^BLOCK ORG-EMAIL-INTERNAL ' "$TEST_ROOT/organization.out"
grep -q '^BLOCK ORG-MARKER-INTERNAL ' "$TEST_ROOT/organization.out"
grep -q '^REJECTED ' "$TEST_ROOT/organization.out"
for matched_value in \
  'corp.example.invalid' \
  "$SYNTHETIC_EMAIL" \
  "$SYNTHETIC_MARKER"
do
  if grep -Fq "$matched_value" "$TEST_ROOT/organization.out" \
    || grep -Fq "$matched_value" "$TEST_ROOT/organization.err"
  then
    echo "organization scanner disclosed a matched value" >&2
    exit 1
  fi
done

if python3 "$ORGANIZATION_SCAN" "$CLEAN_REPO" \
  --indicators "$CONTROL_DIR/insecure/organization-indicators.json" \
  >"$TEST_ROOT/organization-config.out" \
  2>"$TEST_ROOT/organization-config.err"
then
  echo "unsafe organization indicator configuration was unexpectedly accepted" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -q '^ERROR ' "$TEST_ROOT/organization-config.err"
if python3 "$GITHUB_DORKS" \
  --indicators "$CONTROL_DIR/insecure/organization-indicators.json" \
  >"$TEST_ROOT/unsafe-dorks.out" 2>"$TEST_ROOT/unsafe-dorks.err"
then
  echo "unsafe indicators unexpectedly generated GitHub dorks" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -q '^ERROR ' "$TEST_ROOT/unsafe-dorks.err"

if python3 "$HISTORY_SCAN" "$TEST_ROOT" \
  >"$TEST_ROOT/history-error.out" 2>"$TEST_ROOT/history-error.err"
then
  echo "non-repository history scan was unexpectedly accepted" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -q '^ERROR ' "$TEST_ROOT/history-error.err"

echo "PASS secure exposure policy and sanitized evidence accepted"
echo "PASS insecure and incomplete exposure evidence rejected"
echo "PASS repository-scoped query and public-surface coverage enforced"
echo "PASS deleted synthetic secret found in reachable Git history"
echo "PASS organization domain email and confidentiality marker found in deleted file history"
echo "PASS attacker-view GitHub Web dorks generated globally and with optional owner scope"
echo "PASS matched value suppressed and scanner error distinguished"
