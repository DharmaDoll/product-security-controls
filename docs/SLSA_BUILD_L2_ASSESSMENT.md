# SLSA Build Level 2 Scoped Assessment

## Purpose

The generated `SLSA L2 Coverage` sheet answers whether each SLSA Build L1 and
L2 requirement has reviewed control mappings. It does **not** answer whether a
particular producer, build platform, consumer, source revision, and release
actually satisfy those requirements.

This assessment joins that mapping with current, scoped evidence. It evaluates
all seven cumulative SLSA Build requirements through Level 2 and fails closed
when evidence is missing or its collection fails.

The result is a scoped engineering assessment. It is not certification or a
general compliance claim.

## This is an assessment, not another control

Controls such as `PSB-BUILD-002`, `PSB-BUILD-003`, `PSB-REL-001`, and
`PSB-REL-002` implement and verify individual security outcomes. This
assessment does not introduce another security mechanism and therefore has no
control ID. It joins the evidence produced for those controls and answers a
different question: whether one exact release has complete current evidence
for every cumulative SLSA Build L1 and L2 requirement.

In checklist terms, controls are the individual inspection items; this
assessment is the scoped overall result.

## Threat and failure scenario

An organization can mistakenly infer Level 2 adoption because every framework
row has a mapped control, even though the selected release was built elsewhere,
provenance was not published, the consumer did not validate it, or the
assessment job itself failed.

The evaluator therefore requires:

- an exact scope: producer, build platform, consumer, artifact family, release,
  and full source revision;
- evidence bound to the SHA-256 digest of that exact scope;
- a policy-defined issuer role for every evidence type;
- immutable, authenticated, reviewed, and fresh evidence metadata;
- distinct `FAIL`, `NOT_CHECKED`, and `ERROR` states.

## Evidence contract

Create a JSON document conforming to
[`slsa-build-l2-assessment-input.schema.json`](../schemas/slsa-build-l2-assessment-input.schema.json).
Use the synthetic
[`secure.json`](../tests/fixtures/slsa-build-l2-assessment/secure.json) only as
a structural example, set `source` to `live`, replace every example identity,
and calculate `scope_sha256` from the canonical JSON representation of the
complete `scope` object.

Each evidence type has a separate expected issuer:

| Evidence type | Expected issuer role | Primary control evidence |
|---|---|---|
| `platform-policy` | `build-platform` | `PSB-BUILD-003` |
| `build-record` | `build-platform` | `PSB-BUILD-002`, `PSB-BUILD-003` |
| `platform-capability-assessment` | `security-review` | independent review of `PSB-BUILD-002` assumptions |
| `producer-policy` | `software-producer` | `PSB-BUILD-002` |
| `build-policy` | `software-producer` | `PSB-BUILD-002` |
| `publication-manifest` | `software-producer` | `PSB-REL-002` |
| `storage-probe` | `security-monitor` | independent observation of `PSB-REL-002` |
| `consumer-verification-result` | `consumer` | `PSB-REL-001` |
| `consumer-trust-policy` | `consumer` | `PSB-REL-001` |
| `provenance-signature-verification` | `consumer` | `PSB-REL-001`, `PSB-BUILD-003` |
| `signer-ownership-assessment` | `security-review` | independent review of `PSB-BUILD-003` assumptions |

The same evidence record may support more than one requirement, but duplicate
evidence types and duplicate codes are rejected. The default freshness window
is 24 hours and is defined in
[`slsa-build-l2.json`](../policies/framework-assessments/slsa-build-l2.json).

## Build the catalog from issuer bundles

Do not ask one person to copy 11 `authenticated` and `reviewed` flags into the
catalog. The repository provides a vendor-neutral adapter that assembles one
bundle from each of these roles:

- `build-platform`;
- `software-producer`;
- `consumer`;
- `security-monitor`;
- `security-review`.

Each role bundle follows
[`slsa-build-l2-issuer-bundle.schema.json`](../schemas/slsa-build-l2-issuer-bundle.schema.json).
An independently reviewed adapter policy follows
[`slsa-build-l2-evidence-adapter-policy.schema.json`](../schemas/slsa-build-l2-evidence-adapter-policy.schema.json)
and pins the exact SHA-256 of every bundle. The adapter rejects missing roles,
missing evidence types, duplicate identities, a mismatched scope, digest
tampering, self-review using the same role label, unsafe relative paths, and
symlink traversal.

The organization-owned collector should translate upstream verifier exit codes
without weakening them:

| Upstream verifier exit | Bundle result |
|---:|---|
| 0 | `pass` |
| 1 | `finding` |
| 2 or collection failure | `error` |

The bundle should reference the immutable verifier result and input artifacts,
not merely copy console text. For the current reference controls:

| Issuer bundle | Inputs supplied by the organization |
|---|---|
| `build-platform` | platform policy and platform-issued build record for `PSB-BUILD-002/003` |
| `software-producer` | approved producer/build policy and `PSB-REL-002` publication manifest |
| `consumer` | `PSB-REL-001` trust policy, signature verification, and subject-binding result |
| `security-monitor` | independently collected `PSB-REL-002` storage availability probe |
| `security-review` | platform capability and platform signer-ownership reviews |

After the reviewer pins the five bundles:

```bash
make assess-slsa-build-l2-bundles \
  ADAPTER_POLICY=/absolute/path/to/reviewed-adapter-policy.json
```

This writes the intermediate catalog to
`generated/assessments/slsa-build-l2-evidence.json`, then runs the cumulative
assessment. If catalog assembly fails, Make stops and does not assess a
previous catalog.

The synthetic example is under
[`tests/fixtures/slsa-build-l2-adapter/secure/`](../tests/fixtures/slsa-build-l2-adapter/secure/).
Because it has fixed timestamps, reproduce it with:

```bash
python3 scripts/build-slsa-build-l2-evidence.py \
  --assessment-policy policies/framework-assessments/slsa-build-l2.json \
  --adapter-policy tests/fixtures/slsa-build-l2-adapter/secure/policy.json \
  --output /tmp/slsa-build-l2-evidence.json \
  --now 2026-07-29T12:30:00Z
```

For GitHub Actions, the first provider-specific collector is implemented for
the `build-platform` role. It verifies artifact provenance with pinned GitHub
CLI and strict signer, source, workflow, runner, artifact, and builder
expectations. See
[`GITHUB_ACTIONS_SLSA_COLLECTOR.md`](GITHUB_ACTIONS_SLSA_COLLECTOR.md).

For GitHub Releases, separate producer and monitor executions collect the
`software-producer` and `security-monitor` bundles. See
[`GITHUB_RELEASES_SLSA_COLLECTOR.md`](GITHUB_RELEASES_SLSA_COLLECTOR.md).

The `consumer` and `security-review` bundles are collected with separate trust
policies and credentials. The consumer reruns the
`PSB-REL-001` artifact and provenance verifier. The security-review collector
authenticates a time-bounded independent assessment of platform capability and
signer ownership. See
[`SLSA_CONSUMER_AND_REVIEW_COLLECTORS.md`](SLSA_CONSUMER_AND_REVIEW_COLLECTORS.md).

## Run

```bash
make generate-checklists
make assess-slsa-build-l2 EVIDENCE=/absolute/path/to/live-evidence.json
```

The command writes sanitized JSON and Excel-friendly CSV to
`generated/assessments/`. These host- and organization-specific results are
ignored by Git. Raw scope identities and evidence URIs are intentionally
excluded; the output keeps only the scope digest, requirement status, mapping
IDs, and evidence codes.

For an offline demonstration:

```bash
python3 scripts/assess-slsa-build-l2.py \
  --policy policies/framework-assessments/slsa-build-l2.json \
  --coverage generated/checklists/profiles/slsa-build-l2-coverage.csv \
  --evidence tests/fixtures/slsa-build-l2-assessment/secure.json \
  --json-output /tmp/slsa-build-l2.json \
  --csv-output /tmp/slsa-build-l2.csv \
  --now 2026-07-29T12:30:00Z
```

The fixture has a fixed assessment time and is intended for automated tests.
Use a current organization-owned input for operational runs.

## Result semantics

| Conclusion | Meaning | Exit |
|---|---|---:|
| `PASS` | all seven requirements have complete passing evidence | 0 |
| `FAIL` | at least one complete evidence set contains a security finding | 1 |
| `INCOMPLETE` | required mapping or scoped evidence is missing | 1 |
| `ERROR` | evidence collection or evaluation failed | 2 |

`ERROR` takes precedence over every other conclusion. `FAIL` takes precedence
over `INCOMPLETE`. Scanner or adapter failure is never interpreted as a clean
result.

## Limitations and operational cost

- The evaluator validates the evidence catalog and its binding metadata; it
  does not fetch evidence URIs or independently reproduce every upstream
  signature, platform, storage, or consumer check.
- A pinned bundle digest authenticates the reviewed snapshot against the local
  adapter policy. It does not prove how the collector authenticated the
  original issuer. Organization collectors must use an authenticated channel,
  preserve the raw immutable result, and protect the adapter policy as a trust
  root.
- Organization adapters must create authenticated records from the real
  systems and must not copy self-reported values without verification.
- A `PASS` applies only to the hashed scope and assessment time. It does not
  cover another release, producer, platform, consumer, or later configuration.
- Issuer separation requires coordination between software producers, the
  build platform, consumers, security review, and security monitoring.
- The policy is fixed to SLSA version 1.2, Build track, target Level 2. A
  version or level change requires a reviewed policy and mapping update.
