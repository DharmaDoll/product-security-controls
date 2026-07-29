# GitHub Releases Producer and Storage Evidence Collector

## Purpose

This read-only provider adapter creates either:

- the complete `software-producer` bundle containing `producer-policy`,
  `build-policy`, and `publication-manifest`; or
- the `security-monitor` bundle containing `storage-probe`.

The two roles must be run with separate policies, reviewers, credentials, and
receipt locations. One invocation never emits both issuer roles.

## Threat and failure scenario

A release page alone does not establish that the expected artifact and
provenance were published together or remained unchanged. A compromised
release operator, stale policy, or failed monitor could expose:

- a mutable, draft, or prerelease release;
- a missing or duplicate provenance asset;
- an artifact or provenance digest mismatch;
- an asset that is not in the uploaded state;
- a substituted download location or content type;
- provenance published outside the allowed delay;
- an unavailable or malformed GitHub API response recorded as clean.

## GitHub API evidence

Live mode uses a version- and SHA-256-pinned GitHub CLI to make an authenticated
`GET` request to:

```text
repos/{owner}/{repo}/releases/tags/{tag}
```

The request fixes the GitHub hostname, `Accept` media type, and REST API version
`2026-03-10`. The GitHub Releases API currently exposes the release
`immutable` flag and each asset's `state`, `digest`, content type, timestamps,
and browser download URL. For private repositories, use a read-only identity
with only `Contents: read`.

The policy schema is
[`github-releases-collector-policy.schema.json`](../schemas/github-releases-collector-policy.schema.json).
Synthetic fixtures are under
[`tests/fixtures/github-releases-collector/secure/`](../tests/fixtures/github-releases-collector/secure/).

## Producer mode

Set `issuer_role` to `software-producer`. The policy must also provide already
reviewed `producer_policy_evidence` and `build_policy_evidence` records. These
should come from the organization wrapper around `PSB-BUILD-002`; this
collector pins and carries their existing status without converting an
upstream `finding` or `error` to `pass`.

The collector generates the third record, `publication-manifest`, from the
GitHub release snapshot.

```bash
make collect-github-releases-evidence \
  COLLECTOR_POLICY=/absolute/path/to/software-producer-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/software-producer.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/publication-manifest.json \
  GH_CLI=/absolute/path/to/pinned/gh
```

## Independent monitor mode

Set `issuer_role` to `security-monitor`. Run it from monitoring automation that
is operationally separate from the release producer.

```bash
make collect-github-releases-evidence \
  COLLECTOR_POLICY=/absolute/path/to/security-monitor-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/security-monitor.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/storage-probe.json \
  GH_CLI=/absolute/path/to/pinned/gh
```

The monitor confirms the current API-visible release and asset state. It must
run repeatedly throughout the organization's required support and retention
window.

## Offline fixtures

```bash
python3 scripts/collect-github-releases-evidence.py \
  --policy tests/fixtures/github-releases-collector/secure/software-producer-policy.json \
  --output /tmp/software-producer.json \
  --receipt-output /tmp/publication-manifest.json \
  --now 2026-07-29T12:30:00Z

python3 scripts/collect-github-releases-evidence.py \
  --policy tests/fixtures/github-releases-collector/secure/security-monitor-policy.json \
  --output /tmp/security-monitor.json \
  --receipt-output /tmp/storage-probe.json \
  --now 2026-07-29T12:30:00Z
```

`test-fixture` mode performs no network access and is never live evidence.

## Result semantics and receipt

Release-policy violations mark the generated evidence record as
`result: finding`, allowing the cumulative assessment to report `FAIL`. Tool,
API, credential, timeout, input, or parse failures exit `2` without producing
a new bundle.

The receipt retains the API snapshot, normalized timestamps, assets seen,
publication delay, scope digest, and sanitized finding codes. The bundle
records the SHA-256 of the exact receipt bytes. Archive those bytes at the
policy's `receipt_uri` before independently reviewing and pinning the bundle in
the five-role adapter policy.

Receipts can contain repository, asset, and uploader metadata. Store them in
access-controlled evidence storage and do not commit organization receipts.

## Limitations and operational cost

- The collector verifies current API metadata; it does not download each asset
  body. Artifact and provenance content verification remains
  `PSB-REL-001` and the GitHub Actions build-platform collector.
- `immutable: true` and asset digests prevent silent replacement but do not
  guarantee perpetual availability. Continuous probes and an organization
  retention policy remain required.
- The collector writes receipts locally but does not upload them or verify the
  configured archive URI.
- One policy evaluates one artifact/provenance pair. Releases with multiple
  artifacts require one scoped policy per pair or a reviewed aggregation
  adapter.
- Producer-policy and build-policy records are trusted upstream evidence; this
  collector does not reproduce their original verification.
- GitHub Enterprise Server requires a separately reviewed API version,
  hostname, release immutability model, and collector profile.

## References

- [GitHub REST API: releases](https://docs.github.com/en/rest/releases/releases?apiVersion=2026-03-10)
- [GitHub REST API: release assets](https://docs.github.com/en/rest/releases/assets?apiVersion=2026-03-10)
- [GitHub CLI: `gh api`](https://cli.github.com/manual/gh_api)
