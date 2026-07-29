# SLSA Consumer and Independent-Review Evidence Collectors

## Purpose and control boundary

These collectors complete the five issuer roles used by the scoped SLSA Build
Level 2 assessment. They do not define new controls:

- the `consumer` collector turns a real `PSB-REL-001` verification into the
  three required consumer evidence records;
- the `security-review` collector authenticates the independent evidence
  required by assumptions in `PSB-BUILD-002` and `PSB-BUILD-003`.

The cumulative assessment is an evidence join over existing controls, not an
additional preventive security mechanism.

## Consumer collector

### Threat and target

A registry attacker, release-channel attacker, compromised producer, or
configuration error can present a valid-looking artifact with unrelated,
forged, or policy-incompatible provenance. The target is the exact artifact,
provenance, signature, consumer trust policy, and source revision in the
assessment scope.

The collector is necessary because producer- or platform-side verification
does not prove that the consumer independently validated what it is about to
use. SLSA recommends verifying the envelope signature, artifact subject,
builder identity, build type, source, and external parameters against
consumer expectations.

### Run

The collector pins all input files, the repository-owned `PSB-REL-001`
verifier, the trusted public key, and the exact OpenSSL binary used by that
verifier.

```bash
make collect-slsa-consumer-evidence \
  COLLECTOR_POLICY=/absolute/path/to/consumer-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/consumer.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/consumer-verification.json \
  OPENSSL=/absolute/path/to/pinned/openssl
```

Exit `0` from `PSB-REL-001` produces passing evidence. Exit `1` produces a
finding. Exit `2`, timeout, malformed input, digest mismatch, or tool failure
stops collection with exit `2` and does not replace an existing bundle.

The policy schema is
[`slsa-consumer-collector-policy.schema.json`](../schemas/slsa-consumer-collector-policy.schema.json).
The receipt schema is
[`slsa-consumer-receipt.schema.json`](../schemas/slsa-consumer-receipt.schema.json).

## Security-review collector

### Threat and target

A build platform, producer, or tenant could self-assert that execution is
hosted, that the control plane generates provenance, or that tenants cannot
use the platform signer. The target is a signed, scoped, time-bounded review
record issued by a separately identified security-review role.

The collector checks:

- exact assessment scope and reviewed build-platform identity;
- a reviewer identity different from the producer, platform, and consumer
  identities in scope;
- review time, expiry, and maximum age;
- hosted execution, consistent build process, and control-plane provenance
  generation for target Level 2;
- exact signer identity, platform ownership, no tenant signing capability,
  and reviewed rotation/revocation handling;
- detached review signature using a pinned public key and pinned OpenSSL
  binary.

```bash
make collect-slsa-security-review-evidence \
  COLLECTOR_POLICY=/absolute/path/to/security-review-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/security-review.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/security-review.json \
  OPENSSL=/absolute/path/to/pinned/openssl
```

A valid signature does not make a failing or expired review pass. An invalid
signature is a security finding; an unavailable verifier, malformed record,
digest mismatch, timeout, or unsupported input is an error.

The signed record, collector policy, and receipt schemas are:

- [`slsa-build-platform-security-review.schema.json`](../schemas/slsa-build-platform-security-review.schema.json);
- [`slsa-security-review-collector-policy.schema.json`](../schemas/slsa-security-review-collector-policy.schema.json);
- [`slsa-security-review-receipt.schema.json`](../schemas/slsa-security-review-receipt.schema.json).

## Offline fixtures and full assessment

The `test-fixture` policies under `tests/fixtures/` do not perform live
cryptographic verification and must never be represented as organization
evidence. They exist to exercise pass, finding, and error semantics.

After collecting all five bundles, an independent approver pins their exact
SHA-256 values in the adapter policy and runs:

```bash
make assess-slsa-build-l2-bundles \
  ADAPTER_POLICY=/absolute/path/to/reviewed-adapter-policy.json
```

The end-to-end test replaces every synthetic issuer bundle with collector
output and verifies an 11-record catalog and seven-requirement `PASS`.

## Limitations and operational cost

- The consumer reference verifier uses a fixed-key Ed25519 example. Production
  keyless certificate, transparency-log, timestamp, expiry, and revocation
  requirements need a provider-specific verifier profile.
- The security-review collector authenticates the review record; it does not
  reproduce the underlying audit or inspect the build platform directly.
- Internal reviewers can be organizationally related while still functionally
  independent. The collector checks distinct scoped identities; the
  organization must enforce actual reporting-line and privilege separation.
- Review receipts contain platform and reviewer metadata. Store them in
  access-controlled immutable evidence storage.
- A passing fixture or mapping is not a claim that an organization achieved
  SLSA Build Level 2. A current live assessment for the exact release remains
  required.

## References

- [SLSA v1.2: Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [SLSA v1.2: Build track basics](https://slsa.dev/spec/v1.2/build-track-basics)
- [SLSA v1.2: Assessing build platforms](https://slsa.dev/spec/v1.2/assessing-build-platforms)
