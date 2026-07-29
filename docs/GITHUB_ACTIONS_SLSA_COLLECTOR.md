# GitHub Actions Build-Platform Evidence Collector

## Purpose

This read-only provider adapter creates the `build-platform` issuer bundle
needed by the scoped SLSA Build Level 2 assessment. It covers two evidence
types:

- `platform-policy`;
- `build-record`.

It does not create the other producer, consumer, monitoring, or independent
review evidence, and it does not claim that SLSA Build Level 2 is achieved.

## Threat and failure scenario

Fetching an attestation JSON document from an API does not establish that its
signature, subject, signer, source revision, or runner environment is trusted.
An attacker or configuration error could substitute:

- another artifact or source revision;
- a different repository or signer workflow;
- a modified reusable workflow revision;
- a self-hosted runner;
- another build type or builder identity;
- a stale or malformed verification result.

GitHub's documentation likewise warns that attestation signatures, timestamps,
and signer identity must be cryptographically verified. The live collector
therefore uses `gh attestation verify`, not the attestation-list response by
itself.

## Live verification boundary

The collector invokes an absolute, non-symlink GitHub CLI binary whose exact
version and SHA-256 are pinned in the policy. It always supplies:

- `--repo`;
- `--signer-workflow`;
- `--signer-digest`;
- `--source-digest`;
- `--source-ref`;
- `--deny-self-hosted-runners`;
- the SLSA provenance v1 predicate type;
- the GitHub Actions OIDC issuer;
- JSON output.

The policy also pins the exact workflow run and attempt URL. If multiple
attestations exist for one artifact, exactly one must match that invocation.

The local artifact and platform-policy snapshot are also SHA-256 pinned and
must be below the collector policy directory without symlink traversal.
`build_record_uri` identifies the organization's immutable archive location
for the generated receipt; it is distinct from the expected GitHub invocation
URL used for scope binding.

The policy schema is
[`github-actions-build-platform-collector-policy.schema.json`](../schemas/github-actions-build-platform-collector-policy.schema.json).
The synthetic offline policy and verification result are under
[`tests/fixtures/github-actions-build-platform-collector/secure/`](../tests/fixtures/github-actions-build-platform-collector/secure/).

## Run

Record the managed GitHub CLI version and binary digest:

```bash
/absolute/path/to/gh --version
sha256sum /absolute/path/to/gh
```

Set `source` to `live`, pin those values under `github_cli`, remove
`verification_fixture`, and run:

```bash
make collect-github-actions-build-platform \
  COLLECTOR_POLICY=/absolute/path/to/github-collector-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/build-platform.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/build-record.json \
  GH_CLI=/absolute/path/to/pinned/gh
```

The GitHub CLI obtains credentials from its normal protected credential
storage. Do not place a token in the policy, command line, fixture, or output.
For private repositories, grant only the read access needed to retrieve and
verify the repository attestation.

For the deterministic offline fixture:

```bash
python3 scripts/collect-github-actions-build-platform.py \
  --policy tests/fixtures/github-actions-build-platform-collector/secure/policy.json \
  --output /tmp/build-platform.json \
  --receipt-output /tmp/build-record.json \
  --now 2026-07-29T12:30:00Z
```

`test-fixture` mode never runs GitHub CLI and must not be represented as live
evidence.

## Policy checks after cryptographic verification

The collector parses the verified statement and separately checks:

- one subject with the exact local artifact name and SHA-256;
- in-toto Statement v1 and SLSA provenance v1;
- the expected GitHub Actions build type;
- exact workflow repository, path, and ref;
- exactly one resolved source dependency at the scoped commit;
- the expected GitHub-hosted builder identity;
- an exact repository workflow-run attempt URL.

A cryptographically verified statement that violates these expectations
produces a `build-record` with `result: finding`. Collection, tool, parse,
digest, or cryptographic verification failure exits `2` and does not produce a
new bundle. Provider stderr is not copied to the sanitized console result.

The receipt retains the exact verified attestation item, artifact digest,
scope digest, invocation, and sanitized finding codes. The bundle records the
SHA-256 of the bytes actually written to `RECEIPT_OUTPUT`; archive those same
bytes at `build_record_uri` before approving the bundle.
The receipt can contain repository and workflow metadata from the verified
statement. Keep it in access-controlled evidence storage and do not commit
organization receipts to this repository.

## Review and assessment flow

1. Preserve the artifact, workflow snapshot, and raw GitHub CLI verification
   output in the organization's immutable evidence store.
2. Run the collector.
3. Independently review the generated bundle and pin its SHA-256 in the
   five-role adapter policy.
4. Add the other four issuer bundles.
5. Run `make assess-slsa-build-l2-bundles ADAPTER_POLICY=...`.

The review step is intentional. The collector does not silently update the
assessment trust policy.

## Limitations and operational cost

- The collector relies on the installed GitHub CLI implementation and current
  Sigstore trust data; the binary must be updated through a reviewed,
  checksum-verified process.
- Public repositories can use the public Sigstore instance. Private repository
  behavior and token access must be tested in the organization's GitHub plan.
- A completed workflow run or attestation can later become unavailable due to
  retention or deletion. Preserve the verified result in an immutable evidence
  store.
- The collector writes the receipt locally but does not upload it or verify
  that `build_record_uri` is available; the independent review must confirm the
  exact receipt bytes were archived at that location.
- `--deny-self-hosted-runners` rejects self-hosted provenance for this profile;
  separately assessed hosted platforms require another collector policy.
- This adapter does not perform the independent platform capability or signer
  ownership reviews required from the `security-review` role.

## References

- [GitHub CLI: `gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify)
- [GitHub: Using artifact attestations to establish provenance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub REST API: repository attestations](https://docs.github.com/en/rest/repos/attestations?apiVersion=2026-03-10)
