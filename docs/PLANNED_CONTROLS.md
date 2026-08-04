# Planned Controls: Goals and Implementation Plans

## Purpose

This document turns the prioritized backlog in
[`ROADMAP.md`](ROADMAP.md) into executable implementation plans. `ROADMAP.md`
remains the source of truth for priority. This document records the goal,
boundary, first runnable slice, acceptance criteria, dependencies, and
completion evidence for each planned control.

Planning status:

- `implemented`: a complete E3 control package is present and verified;
- `ready`: scope and prerequisite inputs are available;
- `prototype`: the first executable vertical slice exists while explicitly
  listed expansion work remains;
- `input-required`: an organization-owned source or decision is required before
  implementation;
- `dependency-required`: another planned control must land first;
- `later`: intentionally outside the current implementation wave.

A plan is not evidence that a control exists. A planned ID must not appear as
implemented in generated checklists until its complete `control.yaml`, secure
and insecure examples, tests, expected results, limitations, and reviewed
row-level mappings exist.

## Execution order

```text
Application checklist source ──> reconciliation ──> PSB-CODE-001..003

PSB-BUILD-003 ──> PSB-REL-002 ──> SLSA Build L2 coverage assessment

PSB-CICD-004 ──> PSB-CICD-005 ──> PSB-CICD-006
       │
       └────────> PSB-DETECT-001 ──> reusable Golden Path integration

PSB-REL-002 + PSB-DETECT-001 ──> PSB-REL-003 ──> Golden Path + PSB-GOV-001
PSB-REL-003 + PSB-REL-001 ─────> PSB-REL-004 supplier SBOM trust

PSB-DETECT-001 + PSB-IAC-001 ──> PSB-CONTAINER-001
PSB-BUILD-003 + PSB-REL-002 + PSB-REL-001 ──> image provenance admission

PSB-CICD-006 ────────────────> PSB-CONTAINER-002 (live identity adapter)

PSB-SOURCE-001 + PSB-BUILD-001 ──> PSB-CONTAINER-003 boundary review

PSB-CONTAINER-001 ──> PSB-CONTAINER-004 offline runtime evaluation
PSB-CONTAINER-003 ──> PSB-CONTAINER-004 live sensor adoption

PSB-GOV-002 ──> shared exception enforcement across later controls

PSB-GOV-001 + PSB-DETECT-001 + PSB-GOV-002 ──> PSB-GOV-003
PSB-GOV-003 ──> organization-owned FIRST PSIRT capability profile

PSB-AI-001 ──> PSB-AI-002 ──┐
                             ├──> PSB-AI-003
PSB-AI-004 ──────────────────┘
```

Within one priority, complete one E3 vertical slice before starting the next.
The application-checklist import still requires its organization-owned source.
`PSB-CICD-005`, `PSB-CICD-006`, `PSB-DEPS-004`, `PSB-DETECT-001`, `PSB-REL-003`,
`PSB-REL-004`, `PSB-CONTAINER-001`, and `PSB-CONTAINER-004` are implemented.
Lifecycle-linked artifact-bound SBOM publication now composes into the Golden
Path, a Dependency-Track plus deployment-inventory query adapter extends
`PSB-GOV-001`, and supplier SBOM trust now has a separate signed identity,
signer lifecycle, and quarantine boundary. The container admission identity
now composes with Falco and Sysdig runtime event adapters. Live sensor
installation and host-side enforcement remain dependent on
`PSB-CONTAINER-003`.
The `PSB-CICD-006` provider-neutral E3 slice is implemented; live cloud-provider
adapters remain organization evidence and a dependency for live identity use.

## Prerequisite: application checklist reconciliation

Status: `input-required`  
Control ID: none; this is a data-model and generation prerequisite.

### Goal

Import the organization's existing application vulnerability assessment
workbook or CSV without losing source wording, identifiers, version, or
disposition, then connect each atomic source row to an implemented or planned
control.

### Required input

- the source workbook or CSV;
- source title, owner, version, and publication or review date;
- sheet and column semantics;
- organization-specific rows that must not be published.

No source workbook or CSV is currently present in this repository. Do not infer
the missing checklist from ASVS or from generic vulnerability lists.

### Implementation plan

1. Add a read-only importer with an explicit source schema.
2. Preserve source row ID and wording before normalization.
3. Split compound questions only with a traceable one-to-many relationship.
4. Record each source row as `implemented`, `planned`, `duplicate`,
   `out-of-scope`, or `mapping-review-required`.
5. Generate an application assessment CSV and filterable XLSX worksheet.
6. Add negative fixtures for duplicate IDs, missing source version, unknown
   columns, formula cells, and malformed workbooks.
7. Keep organization evidence and completed answers outside generated guidance.

### Acceptance criteria

- every imported source row has exactly one explicit reconciliation
  disposition;
- source identifiers and original wording remain recoverable;
- no ASVS coverage is claimed without a reviewed requirement-level mapping;
- import failure is distinct from an empty checklist;
- deterministic regeneration succeeds with `make generate`.

## P0: current milestone

### PSB-REL-002 — Provenance publication and distribution

Status: `prototype` — first runnable slice implemented
Domain: `release-integrity`

#### Goal

Ensure every applicable release publishes authenticated provenance alongside
the exact artifact it describes, so consumers can obtain the evidence generated
by `PSB-BUILD-003` and validate it with `PSB-REL-001`.

#### Boundary and non-goals

- `PSB-BUILD-003` owns platform generation and signer authenticity.
- `PSB-REL-001` owns consumer verification and artifact-subject matching.
- `PSB-REL-002` owns publication, discoverability, retention, access, and
  no-downgrade behavior.
- SBOM generation and completeness remain `PSB-REL-003`.

#### Implementation plan

1. Create secure and insecure release-manifest fixtures containing artifact
   digest, provenance digest, media type, release identity, publication
   location, and retention policy.
2. Verify one-to-one artifact/provenance binding and reject mutable or
   unauthenticated locations.
3. Reject a release when provenance is missing, uploaded after an unbounded
   delay, inaccessible to the intended consumer, or silently removed.
4. Distinguish `clean`, `finding`, and publication/storage execution error.
5. Add a no-downgrade negative test for artifact families that previously
   required provenance.
6. Update SLSA Build L2 coverage only after mappings and evidence are reviewed.

#### Acceptance criteria

- `make verify-control CONTROL=PSB-REL-002` runs offline fixtures;
- missing, mismatched, mutable, inaccessible, and malformed evidence fails
  closed;
- sanitized output contains check IDs and reason classes while the manifest
  retains reviewed digests; neither contains credentials or real private
  release URLs;
- the generated SLSA L2 coverage view moves
  `build-l1#producer-distributes-provenance` from `gap` only on reviewed
  evidence;
- no SLSA level achievement claim is made.

#### Implementation result

Implemented in
[`controls/release-integrity/provenance-publication-distribution/`](../controls/release-integrity/provenance-publication-distribution/).
The E3 slice verifies one-to-one artifact/provenance digest binding, immutable
authenticated release-manifest discovery, intended-consumer access, bounded
publication delay, retention, protected-family no-downgrade, and distinct
publication/storage `ERROR` states. The reviewed SLSA mapping supplies evidence
for the distribution requirement but does not claim cumulative level
achievement.

### Cumulative SLSA Build Level 2 assessment

Status: `prototype` — scoped evaluator and offline fixtures implemented.
Control ID: none; this joins control evidence and is not a new control.

The evaluator described in
[`SLSA_BUILD_L2_ASSESSMENT.md`](SLSA_BUILD_L2_ASSESSMENT.md) combines the
seven-row coverage view with 11 types of current evidence for an exact
producer, build platform, consumer, artifact family, release, and source
revision. Secure, finding, absent, execution-error, and malformed fixtures
preserve fail-closed result semantics. The vendor-neutral bundle adapter now
requires all five issuer roles, exact scope binding, independently reviewed
SHA-256 pins, safe local paths, and all 11 evidence types before it produces a
catalog. The GitHub Actions `build-platform` collector is implemented with
pinned GitHub CLI verification, exact signer/source/workflow/artifact binding,
and self-hosted-runner denial. The GitHub Releases collector separately emits
the complete producer bundle and independent storage-monitor bundle with
immutable release, asset digest, location, state, and timing checks. The
consumer collector now reruns the pinned `PSB-REL-001` verifier over exact
artifact, provenance, signature, and consumer-policy inputs. The independent
security-review collector verifies a signed, scoped, expiring assessment of
platform capability and signer ownership. All five role collectors feed one
end-to-end passing fixture. The remaining milestone input is
organization-owned live policies and evidence; until that input yields
`PASS`, this repository makes no Level 2 achievement claim.

## P1: foundational controls

### PSB-CICD-004 — Explicit least-privilege workflow permissions

Status: `prototype` — first E3 vertical slice implemented
Domain: `cicd-security`

#### Goal

Prevent workflow and job tokens from receiving write permissions unrelated to
their task.

#### Boundary and non-goals

- immutable Action references remain `PSB-CICD-001`;
- expression-to-shell injection remains `PSB-CICD-002`;
- static workflow scanner integration remains `PSB-CICD-003`;
- cloud federation trust remains `PSB-CICD-006`.

#### Implementation plan

1. Parse workflow-level and job-level `permissions`.
2. Reject absent implicit permissions, `write-all`, and broad write grants.
3. Model allowed permission sets per job purpose: test, report, release, and
   deploy.
4. Require privileged jobs to use protected environments and trusted refs.
5. Add negative fixtures for inheritance, reusable-workflow permission
   escalation, and unnecessary `id-token: write`.
6. Verify repository workflows without modifying them.

Implemented slice:

- top-level `permissions: {}` and explicit permissions for every job;
- exact sidecar policy sets for test, report, release, and deploy purposes;
- trusted-ref conditions for every write-capable job;
- protected environments for release and deploy;
- `id-token: write` restricted to release and deploy purposes;
- explicit reusable-workflow caller permissions;
- repository-wide workflow coverage and fail-closed unsupported syntax.

#### Acceptance criteria

- every workflow and job resolves to an explicit permission set;
- read-only jobs cannot write contents, packages, security events, or
  attestations;
- `id-token: write` is limited to the exact job that performs federation;
- unsupported YAML syntax and parser errors fail closed.

### PSB-CICD-005 — Fork-safe and untrusted-PR-safe workflows

Status: `prototype` — first E3 vertical slice implemented
Domain: `cicd-security`

#### Goal

Ensure code from forks and untrusted pull requests cannot execute with
privileged credentials, writable tokens, protected environments, or
organization-controlled runner trust.

#### Boundary and non-goals

- general command-injection syntax remains `PSB-CICD-002`;
- job permission minimization remains `PSB-CICD-004`;
- build isolation after a job starts remains `PSB-BUILD-001`.

#### Implementation plan

1. Model event, ref trust, actor trust, checked-out revision, permissions,
   secrets, environment, and runner class.
2. Reject `pull_request_target` execution of untrusted head content.
3. Reject checkout or execution of attacker-controlled revisions in privileged
   jobs.
4. Separate unprivileged PR validation from trusted-branch reporting and
   deployment.
5. Add negative fixtures for fork PRs, changed workflow files, reusable
   workflows, cache poisoning, and self-hosted runner selection.
6. Require manual approval and a new trusted run rather than elevating the
   original untrusted run.

Implemented slice:

- policy-reviewed event and job trust classification with exact repository
  workflow coverage;
- credential-free read-only pull-request jobs on reviewed GitHub-hosted
  runners;
- checkout merge-revision and `persist-credentials: false` enforcement;
- conservative rejection of `pull_request_target`, `workflow_run`, shared PR
  caches, and untrusted reusable-workflow callers;
- separate trusted-branch jobs that cannot depend on an untrusted job in the
  original run;
- fail-closed missing policy, unreviewed workflow, event drift, and unsupported
  YAML behavior.

#### Acceptance criteria

- representative untrusted PR code cannot observe a secret or writable token;
- privileged jobs never execute an unreviewed PR revision;
- event ambiguity and scanner error are not treated as trusted;
- fork-safe behavior is verified with positive and negative fixtures.

### PSB-CODE-001 — Application secret handling

Status: `input-required` on application checklist reconciliation  
Domain: `secure-coding`

#### Goal

Keep application secrets out of source, images, logs, error messages, and
static configuration while supporting safe rotation and startup failure.

#### Boundary and non-goals

- developer Git prevention remains `PSB-SOURCE-002`;
- public repository exposure detection remains `PSB-SOURCE-003`;
- source-platform credential lifecycle remains `PSB-SOURCE-004`;
- CI/cloud federation remains `PSB-CICD-006`.

#### Implementation plan

1. Reconcile application-checklist secret rows and select one minimal reference
   application.
2. Create insecure hardcoded and logged-secret fixtures.
3. Create secure runtime-injection and secret-reference examples with no real
   credential values.
4. Verify redaction, missing-secret startup failure, rotation without rebuild,
   and absence from built artifacts.
5. Add negative tests for stack traces, debug endpoints, configuration dumps,
   and child-process environments.

#### Acceptance criteria

- representative fake secrets never appear in source, logs, response bodies,
  images, or generated evidence;
- missing or unavailable secret providers fail explicitly;
- rotation is demonstrated without changing source or rebuilding the artifact;
- ASVS mappings identify exact reviewed requirements and versions.

### PSB-CODE-002 — Authentication and session lifecycle

Status: `input-required` on application checklist reconciliation  
Domain: `secure-coding`

#### Goal

Provide phishing- and abuse-resistant authentication lifecycle behavior,
including enrollment, login, recovery, session renewal, logout, and
invalidation.

#### Implementation plan

1. Reconcile authentication and recovery source rows.
2. Build a deterministic local authentication fixture without production
   identity integration.
3. Test generic failure responses, rate controls, secure cookie attributes,
   session rotation, inactivity and absolute expiry.
4. Add recovery-token single-use and expiry tests.
5. Verify logout, password reset, account disablement, and risk events revoke
   all required sessions.
6. Document which MFA and IdP evidence remains external.

#### Acceptance criteria

- authentication and recovery tests include negative and replay cases;
- session identifiers rotate at every privilege-changing boundary;
- disabled or recovered accounts cannot reuse prior sessions;
- user enumeration and sensitive logging fixtures fail validation.

### PSB-CODE-003 — Object- and function-level authorization

Status: `input-required` on application checklist reconciliation and
`dependency-required` on the identity model from `PSB-CODE-002`  
Domain: `secure-coding`

#### Goal

Enforce authorization on every object and function at the server boundary,
including tenant separation and denial by default.

#### Implementation plan

1. Reconcile authorization and IDOR source rows.
2. Define subject, tenant, object, action, and policy fixtures.
3. Implement centralized server-side authorization.
4. Add horizontal, vertical, cross-tenant, bulk-operation, alternate-identifier,
   and direct-endpoint negative tests.
5. Verify list/search results do not disclose unauthorized objects.
6. Record deny decisions without logging protected object contents.

#### Acceptance criteria

- changing an object ID never bypasses subject and tenant authorization;
- administrative functions deny ordinary users even when routes are called
  directly;
- missing policy, unknown action, and policy-engine error deny access;
- mappings reference exact reviewed ASVS authorization requirements.

### PSB-DETECT-001 — Integrity-verified security scanner execution

Status: `implemented` — E3 offline vertical slice

Domain: `detection-verification`

#### Goal

Run reproducible vulnerability, secret, container, SBOM, and IaC detection with
pinned tools and data, while keeping `clean`, `finding`, and `scanner error`
unambiguous.

#### Tool boundary

The control is organized around trustworthy detection, not around installing
many scanners.

- Trivy is the initial broad scanner for filesystem, container, IaC, secret,
  and SBOM fixtures.
- Checkov is an IaC-specific secondary engine only where a reviewed fixture
  demonstrates unique policy coverage or useful independent detection.
- `PSB-IAC-001` remains responsible for the organization-owned resolved-plan
  deny contract, provider-side enforcement, and drift controls.
- `PSB-SOURCE-002` remains responsible for pre-commit prevention.
- Application SAST and DAST require separate application controls and must not
  be claimed by a Trivy or Checkov run.

#### Implementation plan

1. Pin exact Trivy and Checkov versions.
2. Download release artifacts only through explicit scripts; verify publisher
   checksum or signature before execution.
3. Pin or record scanner database and policy-bundle identity so a result can be
   reproduced.
4. Create isolated safe fixtures for:
   - vulnerable dependency metadata;
   - container and IaC misconfiguration;
   - synthetic secret;
   - CycloneDX SBOM vulnerability lookup;
   - malformed input and unavailable scanner/database.
5. Normalize exit semantics:
   - `0`: scan completed with no policy finding;
   - `1`: scan completed and found a blocking issue;
   - `2`: scanner, input, policy, database, or integrity error.
6. Compare Trivy and Checkov on the same IaC fixtures. Retain Checkov rules only
   when the documented gap or independent-engine value justifies the
   operational cost.
7. Reject broad ignores; require exact rule, path or resource, owner,
   justification, and expiry.
8. Emit sanitized JSON or SARIF evidence without matched secret values.
9. Integrate the verified command into the Golden Path only after the local
   positive, negative, and error fixtures pass.

#### Acceptance criteria

- tool binaries, Actions, databases, and policy bundles have immutable identity
  and verified integrity;
- network access is explicit and an offline fixture mode is deterministic;
- a missing binary, unavailable database, malformed result, or timeout never
  returns clean;
- Trivy and Checkov overlap is documented at rule/fixture level;
- secret values are redacted from console and saved evidence;
- `make verify-control CONTROL=PSB-DETECT-001` reaches E3 with no production
  registry, cloud, or credential dependency.

#### Implemented evidence

- Trivy `v0.72.0` release, Linux archive, publisher checksum file, and
  Sigstore bundle identities are pinned; the explicit fetch script verifies
  checksum and publisher workflow identity before extraction.
- affected Trivy `0.69.4` through `0.69.6`, tampered bytes, unavailable
  scanner, database mismatch, leaked secret evidence, malformed JSON, wildcard
  exception, and expired exception are negative fixtures.
- normalized offline results cover vulnerability, container
  misconfiguration, IaC misconfiguration, secret, and CycloneDX SBOM
  vulnerability categories without retaining matched secret values.
- Checkov `3.3.8` is pinned in a comparison record but is not adopted because
  the first slice found no unique blocking coverage.
- DockSec `2026.7.5` is adopted only as an optional developer-remediation
  orchestrator because contextual Dockerfile guidance and Compose correlation
  are a documented unique value. Its deterministic gate runs scan-only and
  offline, maps usage or runtime failure to `ERROR`, removes LLM credentials,
  and rejects AI output as authoritative evidence.
- the upstream DockSec Action is not adopted because the reviewed fixed source
  still downloads mutable Hadolint and executes a network-fetched Trivy
  installer through a shell pipeline;
- production database freshness, live registry integration, application
  SAST/DAST, and embedded-malware detection remain explicit limitations.

## P2: exposure reduction and release completeness

### PSB-CODE-004 — Injection prevention

Status: `input-required` on application checklist reconciliation  
Domain: `secure-coding`

#### Goal

Prevent untrusted data from becoming SQL, OS command, template, LDAP, or
browser-executable syntax by using parameterization and context-specific
encoding.

#### First runnable slice

Implement one small reference application with SQL parameterization, safe
process argument construction, and HTML-context output encoding. Add negative
fixtures for alternate encodings, second-order input, and direct sink calls.

#### Acceptance criteria

- insecure fixtures demonstrate data-to-syntax interpretation;
- secure fixtures keep the same payload as data;
- no global sanitizer is claimed to cover every context;
- exact ASVS requirements are mapped only after source-row reconciliation.

### PSB-DEPS-004 — Dependency change review

Status: `implemented` — E3 provider-neutral graph-delta review slice
Domain: `dependency-security`

#### Goal

Block dependency graph changes that introduce unreviewed vulnerabilities,
licenses, provenance gaps, source changes, or policy exceptions.

#### Implemented runnable slice

The control compares normalized base and proposed lock graphs plus pinned
advisory metadata. It produces a review decision for new package, version,
source, transitive edge, vulnerability, license, provenance, approval, and
exception risk. Advisory or policy-engine unavailability is an error.

#### Acceptance criteria

- only dependency changes are evaluated, with direct and transitive context;
- frozen lockfile and artifact integrity remain delegated to `PSB-DEPS-003`;
- an unavailable advisory source cannot approve a change;
- every allow decision has sanitized evidence and every exception expires.

Implemented by
[`controls/dependency-security/dependency-change-review/`](../controls/dependency-security/dependency-change-review/).

### PSB-CICD-006 — Audience-bound cloud OIDC federation

Status: `implemented` — provider-neutral signed exact-claim E3 slice
Domain: `cicd-security`

#### Goal

Replace stored cloud keys with short-lived deployment credentials whose issuer,
audience, subject, repository, ref, environment, and reusable workflow identity
are explicitly trusted.

#### Implemented runnable slice

Use a provider-neutral trust-policy fixture and signed synthetic OIDC claims.
Accept only the protected deploy job and reject fork, pull request, wrong
audience, wrong repository, mutable ref, expired token, and replay cases.

Implemented by
[`controls/cicd-security/audience-bound-oidc-federation/`](../controls/cicd-security/audience-bound-oidc-federation/).

#### Acceptance criteria

- `id-token: write` exists only on the exchange job;
- cloud trust conditions are exact rather than organization-wide wildcards;
- no static cloud credential is present in workflow or repository secrets;
- exchange failure is not interpreted as a skipped clean deployment check.

Source and remaining adapter boundary:

- [`REF-CICD-009`](SECURITY_GUIDANCE_SOURCES.md#ref-cicd-009) informs the
  credential-exposure, exact-claim, job-separation, and provider-side
  authorization requirements. Provider-specific live trust policy and audit
  evidence remain adapters. Package-registry Trusted Publishing remains a
  separate future profile.

### PSB-REL-003 — SBOM generation, binding, and publication

Status: `implemented` — E3 lifecycle identity, artifact binding, completeness,
publication, deployment linkage, and Dependency-Track processing slice

Domain: `release-integrity`

#### Goal

Generate a complete machine-readable SBOM, bind it to the exact release
artifact, publish it with integrity metadata, and detect consumer-side mismatch
or incompleteness.

#### Implemented slice

Generate a CycloneDX fixture from a locked sample, record artifact and SBOM
digests in a release manifest, and verify required direct/transitive components,
identifiers, relationships, and composition completeness.

The slice also pins a Dependency-Track 4.14.3 adapter contract, pre-binds an
exact project UUID and release version, restricts the upload identity to
`BOM_UPLOAD`, requires `BOM_PROCESSED`, and keeps processing failure,
validation failure, timeout, analyzer outage, stale vulnerability data, and
parser failure distinct from clean. `PSB-GOV-001` separately consumes a
read-only exact CVE/PURL portfolio response with complete pagination and links
it back to build evidence.

The lifecycle slice keeps source, build, and deployment observations as
separate documents with unique serials and explicit completeness and authority.
It links immutable commit SHA to artifact SHA-256 to deployment ID. Source is
early feedback, build is the release-authoritative inventory, and deployment
is an operational observation that does not claim complete process-memory
coverage.

#### Acceptance criteria

- the SBOM corresponds to the released artifact, not merely the source tree;
- missing transitive components and artifact mismatch fail validation;
- publication and no-downgrade semantics align with `PSB-REL-002`;
- upload acceptance is not processing success and every error path exits `2`;
- Dependency-Track project UUID, version, SBOM serial, digest, component count,
  composition, and fresh analyzer state match the exact release;
- Golden Path composes the control without duplicating its implementation;
- source build and deployment observations cannot overwrite one another or
  substitute a source-only view for the exact release artifact;
- an impacted artifact can be joined to active deployments by digest without
  trusting a mutable image tag;
- an SBOM is evidence, not proof that dependencies are vulnerability-free.

Planning and implementation source:

- [`REF-REL-001`](SECURITY_GUIDANCE_SOURCES.md#ref-rel-001) supplies the
  versioned API, permission, and event semantics. Dependency-Track remains a
  tool reference rather than a framework mapping source.
- [`REF-REL-002`](SECURITY_GUIDANCE_SOURCES.md#ref-rel-002) and
  [`REF-USER-005`](SECURITY_GUIDANCE_SOURCES.md#ref-user-005) supply reviewed
  lifecycle and format design input without becoming compliance mappings.

### PSB-REL-004 — Supplier SBOM trust and quarantine

Status: `implemented` — E3 signed identity, signer lifecycle, least-privilege
import, quarantine, and operational-error slice

Domain: `release-integrity`

#### Goal

Accept a supplier or platform-team SBOM only when its signature and exact
product, version, artifact digest, signer identity, timestamp, revocation, and
schema expectations verify; quarantine mismatched or unverifiable evidence.

#### Boundary

- `PSB-REL-003` owns SBOMs generated for this organization's exact release
  artifact and the source/build/deployment lifecycle relationship.
- `PSB-REL-004` owns externally supplied SBOM trust, signature verification,
  signer lifecycle, product identity, and quarantine.
- `PSB-GOV-001` may search accepted supplier inventory but does not decide
  whether it is authentic.
- CycloneDX 1.7 is the current implemented adapter. SPDX requires an independently
  version-pinned parser and equivalent identity, relationship, malformed-input,
  and signature negative tests.

#### Implemented slice

Synthetic supplier artifact, CycloneDX 1.7 SBOM, signed envelope, detached
Ed25519 signature, digest-pinned test public key, consumer trust policy, and
signer-status snapshot exercise the pre-import boundary. The verifier
recomputes artifact and SBOM digests, authenticates the signer, binds
supplier/product/version/digest/serial/root identity, enforces bounded
signature and revocation timestamps, restricts the upload identity to one
pre-created project with `BOM_UPLOAD`, and emits distinct `QUARANTINE` or
`ERROR` results without importing failed input into the normal portfolio.

#### Acceptance criteria

- a valid signature over an SBOM for another artifact or product is rejected;
- unknown, expired, or revoked signers and stale revocation evidence fail
  closed;
- unsigned, malformed, unsupported-format, or schema-invalid input is
  quarantined rather than treated as absent risk;
- supplier upload identity cannot mutate unrelated portfolio or policy state;
- sanitized evidence excludes supplier confidential component content and key
  material;
- stale or unavailable signer status and crypto execution failure remain
  `ERROR`, never a clean or accepted result;
- reviewed NIST SSDF mappings describe supporting evidence and do not claim
  that the supplier component is secure or compliant.

### PSB-CONTAINER-001 — Container runtime baseline

Status: `implemented` — E3 offline admission and provenance-composition slice

Domain: `container-cloud-iac-security`

#### Goal

Require immutable image identity, non-root execution, minimal Linux
capabilities, read-only filesystems, bounded resources, and admission
enforcement before a workload runs.

#### Source and control allocation

The duplicate-free source and ownership matrix is maintained in
[`CONTAINER_SECURITY_SOURCE_ALLOCATION.md`](CONTAINER_SECURITY_SOURCE_ALLOCATION.md).

- NIST SP 800-190 supplies product-neutral Section 4 mapping candidates through
  the `nist-sp-800-190` registry;
- SLSA v1.2 applies to the container image as a build artifact: existing
  `PSB-BUILD-002..003` own hosted build and authentic provenance,
  `PSB-REL-002` owns provenance distribution, and `PSB-REL-001` owns consumer
  authenticity and subject-digest verification;
- CIS Docker Benchmark v1.8.0 remains an `input-required` framework candidate
  until an official authorized PDF, digest, recommendation inventory, and
  reuse terms are reviewed;
- `REF-CONTAINER-001` supplies OWASP implementation examples and MUST NOT
  become a framework mapping;
- `PSB-DETECT-001` owns image and runtime vulnerability scanning;
- `PSB-CODE-001` owns secrets excluded from images;
- `PSB-CONTAINER-002` owns registry access and lifecycle;
- `PSB-CONTAINER-003` owns host and daemon hardening;
- `PSB-CONTAINER-004` owns post-admission runtime behavioral monitoring.

#### First runnable slice

Provide insecure and secure Kubernetes workload fixtures plus an admission
decision verifier for digest pinning, security context, capabilities, privilege,
host namespaces, host paths, runtime sockets, read-only root filesystems,
seccomp, and resource limits.

#### SLSA image-provenance integration slice

After the basic workload-policy slice, compose the implemented
`PSB-REL-001` verifier at the admission boundary:

1. resolve the admitted image to an exact OCI manifest digest;
2. obtain the provenance distributed by `PSB-REL-002`;
3. verify provenance authenticity, approved builder and source expectations,
   and exact subject-digest equality through `PSB-REL-001`;
4. reject missing, invalid, unrelated, downgraded, or unverifiable provenance;
5. bind the verified decision to the exact deployment revision and image
   digest without trusting a mutable tag or a user-supplied pass flag.

This slice may map its atomic consumer-verification check to SLSA v1.2
`build-l2#consumer-validates-authenticity` and `build-provenance`. Digest
pinning alone does not earn either mapping. Provenance generation and
distribution mappings stay with `PSB-BUILD-003` and `PSB-REL-002`.

#### Acceptance criteria

- mutable tags and privileged, host-mounted, host-namespace, or runtime-socket
  workloads are rejected;
- non-root, no privilege escalation, capability drop, read-only root
  filesystem, seccomp, and resource limits are verified independently;
- admission error is distinct from allow;
- image vulnerability scanning remains `PSB-DETECT-001`;
- signature or provenance admission is added only with implemented release
  evidence, not by assertion;
- provenance admission rejects a statement whose subject digest is not the
  exact admitted OCI manifest digest and reports verifier unavailability as
  `ERROR`;
- container admission evidence may support the SLSA consumer requirement but
  does not establish a SLSA level or replace the cumulative Build L2
  assessment;
- NIST mappings are attached only to atomic checks with direct evidence;
- no CIS profile or OWASP compliance claim is inferred from the first slice.

#### Implemented evidence

- an API-native `admission.k8s.io/v1` Deployment fixture covers init and
  application containers without requiring a live cluster;
- exact trusted OCI manifest digest, non-root execution, no privilege
  escalation, capability drop, host-boundary isolation, read-only filesystem,
  RuntimeDefault seccomp, CPU, memory, PID, and default-deny network outcomes
  are evaluated independently;
- `PSB-REL-001` is rerun as part of the admission decision and binds signed
  SLSA provenance to the exact OCI manifest bytes rather than a user-supplied
  pass flag;
- weak policy, unsafe workload, provenance mismatch, manifest substitution,
  platform outage, unavailable verifier, and malformed input are negative
  fixtures with distinct deny and error states;
- live API server, registry, CNI, runtime, multiple-image evidence bundles,
  RBAC, and narrow application allow-policy adapters remain limitations.

### PSB-CONTAINER-002 — Container registry security

Status: `ready` for an offline E3 policy slice; live identity adapters follow
`PSB-CICD-006`
Domain: `container-cloud-iac-security`

#### Goal

Protect private and release container registries with authenticated encrypted
transport, repository-scoped least privilege, short-lived workload identity,
immutable release references, auditable writes and reads of sensitive images,
and explicit stale-image quarantine or removal.

#### Boundary and non-goals

- `PSB-CONTAINER-001` owns whether a workload may run an image.
- `PSB-REL-001..002` own artifact signature, provenance verification, and
  publication evidence.
- `PSB-CICD-006` owns cloud or registry workload identity federation.
- `PSB-DETECT-001` owns image vulnerability scanner execution. Embedded
  malware detection remains a documented future scanner slice and is not
  claimed by the implemented control.
- This control owns registry transport, authorization, mutation protection,
  audit, retention, quarantine, and lifecycle evidence.
- Registry retention and access may preserve SLSA provenance, but SLSA
  generation, distribution, and consumer validation remain release-integrity
  evidence and are not remapped to this control.

#### Threat or failure scenario

An external attacker, compromised developer credential, or over-privileged CI
identity pushes or replaces an image, reads a sensitive repository, connects
over an untrusted channel, or keeps a revoked or stale image deployable. A
registry API, audit collector, or lifecycle evaluator failure is then reported
as a clean registry.

#### Assumptions

- the first slice uses a provider-neutral policy and evidence schema;
- a live registry adapter can expose exact repository, actor, action, digest,
  timestamp, and policy state without returning credentials;
- public anonymous pull is a separately reviewed use case and never implies
  anonymous push, delete, or administration.

#### First runnable slice

Provide secure and insecure provider-neutral registry-policy fixtures plus an
offline verifier for:

- TLS-only endpoints and explicit trusted registry identities;
- repository- and action-scoped pull, push, delete, and administration roles;
- denial of anonymous or cross-repository writes;
- immutable release references and protected deletion;
- exact image digest, actor, repository, action, and timestamp audit records;
- explicit deprecation, quarantine, retention, and removal state;
- `ERROR` for missing, malformed, stale, or unavailable evidence.

Use synthetic identities and digests only. A later adapter may normalize OCI
Distribution, cloud registry, or GitHub Container Registry evidence without
changing the control outcome.

#### Provisional source allocation

- NIST SP 800-190: `4.2.1`, `4.2.2`, and `4.2.3`;
- OWASP Docker Security Cheat Sheet: supporting registry and supply-chain
  examples only, not framework mappings;
- CIS Docker Benchmark: exact recommendation mappings remain `input-required`
  until the authorized v1.8.0 source is reviewed.

#### Acceptance criteria

- an insecure endpoint, anonymous write, broad wildcard identity,
  cross-repository push, mutable release replacement, unaudited write, or
  indefinitely deployable stale image is rejected;
- read access for sensitive images and every write or administrative action
  has attributable, redacted audit evidence;
- a lifecycle policy distinguishes active, deprecated, quarantined, and
  removed images without treating scanner failure as quarantine evidence;
- fixture evidence reaches E3 with positive, negative, malformed, and
  unavailable cases;
- no registry vendor feature is presented as proof of complete registry or
  NIST coverage.

### PSB-CONTAINER-003 — Container host and daemon hardening

Status: `ready` for a provider-neutral E3 configuration slice; CIS mapping is
`input-required`
Domain: `container-cloud-iac-security`

#### Goal

Reduce container escape and host takeover impact by minimizing and patching the
container host, constraining daemon and runtime administration, protecting
runtime sockets and files, enforcing user and kernel isolation, and producing
host audit evidence.

#### Boundary and non-goals

- `PSB-SOURCE-001` owns developer-endpoint container socket and workspace
  exposure.
- `PSB-BUILD-001` owns the untrusted CI build sandbox.
- `PSB-CONTAINER-001` owns workload security context and admission.
- This control owns production or shared container host OS, Docker/containerd/
  CRI-O daemon configuration, management ingress, runtime files, patch state,
  and host audit policy.
- Workload behavior after admission remains `PSB-CONTAINER-004`.
- SLSA does not define production container host hardening; do not map these
  checks to a SLSA Build level.

#### Threat or failure scenario

An attacker controlling a container, stolen operator identity, exposed remote
API, or misconfigured automation reaches a privileged runtime socket, weak
daemon, vulnerable shared kernel, writable runtime files, or unnecessary host
service and obtains node-level control. A host assessment that cannot observe
the daemon or kernel incorrectly reports a pass.

#### Assumptions

- the first slice targets Linux hosts and Linux container runtimes;
- Windows container hosts and managed control planes remain `NOT_CHECKED`
  until a provider-specific adapter defines equivalent evidence;
- host inspection is read-only and does not change daemon, kernel, firewall,
  or audit settings.

#### First runnable slice

Provide secure and insecure normalized host-policy fixtures plus a read-only
offline verifier for:

- dedicated minimal container hosts and prohibited mixed workloads;
- supported host OS, kernel, runtime, and daemon patch baselines;
- no unauthenticated TCP daemon, public management endpoint, or workload-mounted
  runtime socket;
- rootless or user-namespace isolation where supported, with documented
  exceptions rather than silent downgrade;
- controlled ownership and restrictive permissions for daemon configuration,
  runtime binaries, sockets, storage, and service units;
- default seccomp plus SELinux or AppArmor enforcement state;
- explicit operator RBAC, management-network restriction, and audit rules;
- `NOT_CHECKED` for organization evidence not supplied and `ERROR` when the
  assessment itself fails.

#### Provisional source allocation

- NIST SP 800-190: `4.3.1`, `4.3.5`, `4.5.1` through `4.5.5`, and
  `4.6`;
- OWASP Docker Security Cheat Sheet: Rules 0, 1, 10, and 11 as reference
  examples;
- CIS Docker Benchmark v1.8.0: primary Docker-specific requirement framework
  after authorized source acquisition and recommendation review.

#### Acceptance criteria

- an exposed daemon API, mounted runtime socket, unsupported patch state,
  general-purpose mixed host, writable protected runtime file, disabled
  isolation profile, or unowned administrator role is rejected;
- a justified platform limitation is a narrow, time-bound exception and never
  an implicit pass;
- host evidence is sanitized and distinguishes `PASS`, `FAIL`,
  `NOT_CHECKED`, and `ERROR`;
- positive, negative, malformed, unsupported, and unavailable fixture cases
  reach E3;
- the verifier does not claim the CIS Level 1 or Level 2 profile until every
  in-scope recommendation and organization-owned evidence has been assessed.

### PSB-CONTAINER-004 — Container runtime threat detection

Status: `implemented` at E3 for the offline provider-neutral evaluator and
synthetic Falco/Sysdig adapters; live adoption remains dependent on the
host-side sensor boundary from `PSB-CONTAINER-003`
Domain: `container-cloud-iac-security`

#### Goal

Detect and support response to post-admission container behavior that violates
the reviewed workload identity, process, filesystem, privilege, network, or
resource baseline, without treating a missing sensor or incomplete event stream
as clean.

#### Boundary and non-goals

- `PSB-DETECT-001` owns pre-deployment vulnerability, secret, image, and IaC
  scanner execution.
- `PSB-CONTAINER-001` owns preventive workload configuration and admission.
- `PSB-CONTAINER-003` owns host and daemon hardening and host audit policy.
- This control owns runtime event collection, workload-identity binding,
  behavioral policy, alert delivery evidence, and bounded response handoff.
- It does not replace application logging, a production SOC, or incident
  command authorization.
- SLSA provenance may supply trusted image identity to event correlation, but
  runtime behavior and alert delivery are not SLSA Build requirements.

#### Threat or failure scenario

A malicious image, exploited application, or escaped process starts an
unexpected executable, changes a protected file, opens a listener, reaches a
forbidden destination, requests new privilege, accesses a runtime socket, or
exhausts resources after passing admission. The sensor, collector, or alert
route becomes unavailable and the absence of events is mistaken for safety.

#### Assumptions

- a runtime adapter can bind every event batch to the admitted workload and
  exact image digest;
- the offline slice evaluates synthetic events and does not install a
  privileged host sensor;
- destructive containment remains outside the automatic detector decision and
  requires a separately authorized response path.

#### Implemented runnable slice

The control provides deterministic synthetic Falco JSON and Sysdig runtime
policy events, a provider-neutral normalizer, a reviewed workload profile, and
an offline evaluator for:

- exact workload, image digest, namespace, Pod UID, container ID, and
  policy-version binding;
- unexpected process and shell execution;
- protected-file mutation and writes outside declared writable paths;
- privilege, capability, namespace, sensitive mount, and runtime-socket access;
- unexpected listeners and denied network destinations;
- CPU, memory, process, restart, or connection abuse signals;
- redacted alert evidence and an owned response route;
- missing sequence, stale events, dropped telemetry, unknown schema, evaluator
  failure, and alert-delivery failure as `ERROR`.

No privileged runtime sensor is installed by this slice. Live Falco, Sysdig,
eBPF, audit, or managed-runtime deployment requires `PSB-CONTAINER-003`
privilege, kernel, performance, integrity, and data-retention review. Falco and
Sysdig are reference adapters rather than mandatory products.

#### Source allocation

- NIST SP 800-190: `4.4.4`; image and runtime software vulnerability
  detection under `4.1.1`, `4.1.3`, and `4.4.1` remains
  `PSB-DETECT-001`;
- OWASP Docker Security Cheat Sheet: Rule 6 runtime-monitoring examples;
- CIS Docker Benchmark: logging and audit mappings only after the authorized
  v1.8.0 recommendation inventory is reviewed;
- Falco and Sysdig provider contracts:
  `REF-CONTAINER-003` and `REF-CONTAINER-004`; these are tool references, not
  framework mappings or mandatory products.

#### Acceptance criteria

- every supported malicious behavior fixture creates the expected sanitized
  alert with exact workload and policy identity;
- expected application behavior does not alert under the reviewed profile;
- dropped, stale, incomplete, malformed, or unavailable telemetry is `ERROR`,
  never clean;
- alert delivery to an owned receiver is tested independently from local
  detection;
- response output is dry-run or authorization-bound and cannot delete
  workloads or evidence merely because one detector fired;
- positive, negative, missing-sensor, malformed-event, and delivery-failure
  cases reach E3.

Implemented by
[`controls/container-cloud-iac-security/runtime-threat-detection/`](../controls/container-cloud-iac-security/runtime-threat-detection/).

### PSB-GOV-002 — Time-bound security exceptions

Status: `ready`  
Domain: `governance-operations`

#### Goal

Make every security exception exact, owned, justified, risk-reviewed,
compensated, approved, and automatically expired.

#### First runnable slice

Validate exception YAML fixtures against exact control/check IDs, target,
owner, approver, reason, compensating controls, creation date, expiry, and
remediation ticket. Generate active, expiring, expired, and invalid views.

#### Acceptance criteria

- wildcard control or target exceptions are rejected;
- expired exceptions fail closed without manual cleanup;
- exception evidence never contains a secret or production payload;
- each control can reference the same exception interface without embedding a
  duplicate exception model.

### PSB-GOV-003 — Exploited-vulnerability prioritization and PSIRT case readiness

Status: `dependency-required` on `PSB-GOV-002`; `PSB-GOV-001` and
`PSB-DETECT-001` are implemented

Domain: `governance-operations`

#### Goal

Turn a vulnerability observation into an accountable product-response case by
binding exact CVE identity, affected product and release, artifact and active
deployment evidence, a validated CVSS v4 vector, fresh complete CISA KEV
status, remediation policy, owner, due decision, and disclosure state.

#### Boundary and non-goals

- `PSB-DETECT-001` owns scanner execution and finding/error semantics.
- `PSB-GOV-001` owns component-to-product-to-artifact-to-deployment impact
  lookup and evidence preservation.
- `PSB-GOV-002` owns risk acceptance and expiring exception evidence.
- This control owns triage inputs, priority decision, accountable case state,
  and response routing; it does not implement a ticketing or notification
  product.
- FIRST PSIRT maturity and the full Services Framework remain a separate
  organization assessment; one passing case fixture does not prove PSIRT
  maturity, capacity, or SLA performance.

#### First runnable slice

1. Normalize a synthetic product-vulnerability case with exact CVE, product,
   version, artifact digest, deployment identity, discovery source, owner, and
   policy identity.
2. Validate canonical CVSS 4.0 vectors, required Base metrics, ordering,
   duplicates, and score/vector consistency using a pinned implementation or
   independently tested algorithm.
3. Consume an offline CISA KEV snapshot fixture with schema identity,
   collection time, catalog metadata, item count, source digest, and complete
   retrieval evidence.
4. Distinguish `listed`, `not-listed`, `not-applicable`, `finding`, and
   evaluation `ERROR`; absence from KEV never produces an automatic low-risk
   decision.
5. Apply an organization-owned priority policy that considers validated
   technical severity, KEV status, product applicability, active deployment,
   exposure, compensating controls, and remediation support state.
6. Require a PSIRT or delegated product-security owner, triage timestamp,
   remediation decision, communication route, and separately governed
   exception when risk is accepted.
7. Emit sanitized evidence without vulnerability exploit content, customer
   data, internal endpoints, or report-submitter identity.

#### Acceptance criteria

- `make verify-control CONTROL=PSB-GOV-003` exercises secure, vulnerable,
  not-listed, stale, partial, malformed, invalid-vector, identity-mismatch,
  unowned, and unavailable-policy fixtures offline;
- a KEV-listed and applicable active product case cannot be lowered solely by
  a CVSS Base score or hand-entered priority;
- a not-listed CVE remains assessed from the other evidence and cannot be
  called unexploited;
- invalid or inconsistent CVSS evidence and stale, partial, schema-changed, or
  unavailable KEV evidence return `ERROR` rather than a low priority;
- product applicability cites exact `PSB-GOV-001` evidence and cannot be
  inferred from package name alone;
- CISA due dates are retained as source data but become organization deadlines
  only through an explicit reviewed policy;
- exception handling composes `PSB-GOV-002` rather than adding another ignore
  format;
- row-level mappings remain provisional until the executable slice and source
  relationships are reviewed.

#### Planning sources

- [`REF-GOV-002`](SECURITY_GUIDANCE_SOURCES.md#ref-gov-002) — CISA KEV;
- [`REF-GOV-003`](SECURITY_GUIDANCE_SOURCES.md#ref-gov-003) — FIRST PSIRT
  Maturity Document;
- [`REF-GOV-004`](SECURITY_GUIDANCE_SOURCES.md#ref-gov-004) — FIRST PSIRT
  Services Framework 1.1;
- [`REF-GOV-005`](SECURITY_GUIDANCE_SOURCES.md#ref-gov-005) — CVSS v4.0.

## P3: extended application and AI development security

### Application controls with IDs assigned after reconciliation

Status: `input-required`

Goals:

- cryptography: approved algorithms, key lifecycle, nonce/IV safety, and
  negative misuse tests;
- file upload: content validation, storage isolation, non-execution, naming,
  size, archive, and retrieval authorization;
- SSRF: parsed destination policy, redirect and DNS handling, metadata-service
  denial, and egress enforcement;
- logging: security event usefulness without secret, token, or sensitive-data
  leakage;
- error handling: safe external responses with correlated internal evidence.

Do not reserve IDs until the application source rows are reconciled and
duplicate boundaries with `PSB-CODE-001..004` are reviewed.

### PSB-AI-001 — Repository-owned AI security guidance

Status: `later`  
Domain: `ai-development-security`

#### Goal

Pin AGENTS and Project CodeGuard guidance to a canonical reviewed source and
measure whether it improves security outcomes against a no-guidance baseline.

#### First runnable slice

Run identical safe benchmark tasks with baseline and guidance-enabled agents.
Measure security-invariant preservation, unsafe recommendation rate, false
blocks, and task success without allowing guidance to modify the benchmark.

### PSB-AI-002 — Skill, MCP, and plugin dependency governance

Status: `dependency-required` on `PSB-AI-001`  
Domain: `ai-development-security`

#### Goal

Treat Skills, MCP servers, plugins, and external prompts as executable or
instructional supply-chain dependencies with immutable identity, integrity,
semantic review, capability limits, and revocation.

#### First runnable slice

Validate a manifest with source commit, digest, requested filesystem/network/
secret capabilities, reviewer, expiry, and benchmark result. Reject mutable,
over-privileged, or unreviewed dependencies.

### PSB-AI-004 — AI coding agent runtime hardening

Status: `prototype` — twelfth runnable slice implemented
Domain: `ai-development-security`  
Primary security functions: `prevent`, `detect`, `verify`, `govern`

#### Threat actor or failure source

- malicious repository content, issue text, documentation, tool output, or web
  content attempting indirect prompt injection;
- compromised or over-privileged MCP servers, Skills, plugins, and agent
  integrations;
- an external attacker operating through a stolen developer or agent identity;
- an AI coding agent that misunderstands scope or selects a high-impact action
  without sufficient human review;
- configuration drift, precedence errors, or a developer enabling a dangerous
  permission-bypass mode.

Protected targets are product source and Git history, agent and repository
policy files, developer credentials, host files and processes, package and
artifact registries, cloud and deployment resources, and data sent to external
services.

#### Goal

Provide one outcome-based runtime policy and verified Claude Code and Codex
adapters so AI coding agents operate with enforced least privilege rather than
depending on prompt instructions or developer attention. Repository-local
content must not be able to broaden managed filesystem, credential, network,
MCP, command, or side-effect authority.

#### Boundary and non-goals

- `PSB-SOURCE-001` owns the underlying endpoint, MDM, EDR, managed environment,
  and OS-level isolation evidence.
- `PSB-SOURCE-004` owns source-platform OAuth, PAT, SSH, and application
  credential lifecycle.
- `PSB-AI-001` owns repository guidance provenance and benchmark effectiveness;
  AGENTS or CLAUDE instruction files are guidance, not an enforcement boundary.
- `PSB-AI-002` owns pinning, integrity, semantic review, capability approval,
  and revocation for Skills, MCP servers, plugins, and external prompts.
- `PSB-AI-003` owns adversarial prompt and document injection scenarios that
  exercise this runtime boundary.
- This control does not silently install hooks, change global developer
  settings, or claim that command-pattern deny rules replace OS sandboxing.

#### Planning references

- [Claude Code Hardening Cheatsheet](SECURITY_GUIDANCE_SOURCES.md#ref-ai-001)
  supplies a product-specific hardening input that must be reconciled with
  current official Claude Code documentation.
- [OWASP AI Agent Security Cheat Sheet](SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)
  supplies product-neutral agent risks and test ideas, not a compliance
  baseline.

#### Assumptions

- product-specific settings and schemas change over time, so each adapter and
  fixture identifies the supported Claude Code or Codex configuration version;
- the provider-neutral policy is canonical and provider settings are adapters,
  not separate tool-organized controls;
- the second provider adapter closes the documented portability gap by proving
  that one policy outcome is not weakened by product-specific configuration
  semantics; it is not a second security tool for duplicate detection;
- deterministic fixtures use synthetic paths, credentials, network
  destinations, and side effects without invoking production services;
- framework mappings remain provisional until exact versions, identifiers,
  row-level rationales, and executable evidence are reviewed.

#### Insecure and secure behavior

Insecure fixtures permit a bypass mode, broad host or workspace writes,
credential-path reads, unrestricted egress, unreviewed MCP side effects, or
destructive source, package, infrastructure, and deployment operations without
approval.

Secure fixtures enforce a sandbox, narrow writable roots, protected
configuration and credential paths, default-deny network access with explicit
destinations, least-privilege MCP capabilities, and mandatory human approval
or denial for high-impact actions. Managed policy cannot be weakened by a
repository-local configuration file.

#### Implementation plan

1. Define a small provider-neutral policy fixture for filesystem roots,
   sensitive paths, network destinations, command classes, MCP capabilities,
   side-effect approvals, bypass modes, audit requirements, and configuration
   precedence.
2. Add isolated insecure and secure adapters for supported Claude Code
   permission, sandbox, hook, MCP, and managed-setting mechanisms.
3. Add isolated insecure and secure adapters for supported Codex sandbox,
   approval, rule, hook, network, MCP or app, and managed-requirement
   mechanisms.
4. Implement a read-only verifier that resolves the effective fixture policy
   and reports `PASS`, `FAIL`, `NOT_CHECKED`, or `ERROR` without changing user
   or global configuration.
5. Reject disabled sandboxes, permission-bypass modes, writes outside approved
   roots, reads of synthetic credential paths, unapproved destinations, broad
   local/private network access, unrestricted sockets, and side-effecting MCP
   operations without approval.
6. Require explicit approval or denial policy for dependency installation,
   commit and push, branch or history rewriting, package publication, database
   mutation, infrastructure changes, cloud administration, and deployment.
   For high-impact actions, bind approval to the actor, tool, target,
   normalized parameters, policy version, timestamp, and expiry; reject replay
   or parameter changes and fail closed when approval validation is
   unavailable.
7. Add negative fixtures for repository-local policy downgrade, settings
   precedence ambiguity, shell or script indirection, malformed configuration,
   unsupported versions, missing hooks, and hook or rule evaluation failure.
8. Emit sanitized evidence containing policy identifiers and decision reasons,
   never command secrets, credential values, private URLs, or unnecessary host
   identifiers.
9. Document operational cost, approval fatigue, false-positive handling,
   command-pattern limitations, network-dependent tasks, emergency access, and
   residual risk from approved but malicious actions.

#### Planned atomic checklist rows

- an enforced sandbox is active and dangerous bypass modes are prohibited;
- writable filesystem scope is limited to approved task roots;
- agent policy, Git metadata, and synthetic credential paths cannot be changed
  or read outside their required access mode;
- network access is denied by default and allowed destinations are explicit;
- local, private, metadata-service, proxy, and socket access is denied unless
  narrowly justified;
- destructive host, source-history, and privilege operations are denied;
- dependency installation, source publication, infrastructure mutation, and
  deployment require an explicit human approval policy;
- high-impact approval is short-lived and bound to the exact actor, tool,
  target, normalized parameters, and policy version, with replay protection;
- high-impact approval issuer is authenticated and one exact approval can be
  consumed by only one concurrent action;
- MCP, plugin, Skill, app, and browser capabilities are least-privileged, with
  side-effecting actions distinguished from reads;
- managed policy has precedence over repository and user convenience settings;
- hook, rule, parser, or policy-engine failure never becomes an allow decision;
- audit evidence is enabled, redacted, access-controlled, and retention-bound;
- indirect prompt and command-indirection fixtures cannot bypass the effective
  policy.

Each row will include a distinct threat actor or failure source, scenario,
target, why-required rationale, owner, verification method, evidence
expectation, and reviewed framework mapping in `control.yaml`.

#### First runnable slice

Create one provider-neutral policy with one Claude Code adapter and one Codex
adapter covering sandbox enforcement, workspace-only writes, synthetic
credential-path denial, network default-deny, explicit approval for source
publication, and rejection of dangerous bypass modes. Verify secure, insecure,
malformed, and repository-downgrade fixtures offline through
`make verify-control CONTROL=PSB-AI-004`.

Implementation: complete in
[`controls/ai-development-security/ai-coding-agent-runtime-hardening/`](../controls/ai-development-security/ai-coding-agent-runtime-hardening/).
The durable phase and remaining-scope record is
[`docs/IMPLEMENTATION_STATUS.md`](../controls/ai-development-security/ai-coding-agent-runtime-hardening/docs/IMPLEMENTATION_STATUS.md).

#### Second runnable slice

Implementation: complete.

The provider-neutral policy now classifies dependency installation, source
commit/publication/history rewrite, package publication, database mutation,
infrastructure and cloud changes, and deployment. A read-only execution gate
binds approval to actor, agent, tool, operation, target, normalized parameters,
policy identity/revision, request digest, issue time, and expiry. Secure,
broad, expired, replayed, target-tampered, parameter-tampered, unclassified,
unavailable-validator, and malformed fixtures verify fail-closed behavior.

At this historical slice boundary, production issuer authentication and atomic
approval consumption remained explicit limitations. The fifth slice closes
those two gaps for the local executable prototype; production key custody and
atomicity with an external side effect remain limitations.

#### Third runnable slice

Implementation: complete.

Claude Code and Codex adapters now require exact synthetic MCP identities and
exact tool sets. The provider-neutral dispatcher verifies declared effects,
target, payload size, and idempotency requirements. Reviewed reads and one
bounded reversible update require no human confirmation, high-impact actions
require exactly one bound approval, and destructive, unknown, ambiguous, or
policy-invalid calls are denied without prompting for an override.

Unreviewed plugin installation, browser control, and computer use are disabled
where the current adapter exposes managed controls. Skill fixtures retain
instruction-only authority. At this historical slice boundary, previously
installed plugin inventory, production MCP behavior, private network controls,
and approval-service production integration remained follow-up work; later
slices add synthetic inventory, approval, and network-boundary evidence while
live production evidence remains incomplete.

#### Fourth runnable slice

Implementation: complete.

Managed-only Claude Code and Codex `PreToolUse` definitions invoke one
provider-neutral gate for all MCP tools. The gate normalizes provider-shaped
input and enforces exact resource, UTF-8 payload size, and idempotency
constraints immediately before execution. Explicit parser, policy, or engine
failure exits `2`; routine writes keep a native prompt fallback for hook
process startup or timeout faults that this static fixture cannot prove block.

#### Fifth runnable slice

Implementation: complete.

Both providers now normalize the exact high-impact request, select only the
digest-named approval envelope, authenticate an active issuer-bound key and
pinned public-key digest with OpenSSL 3, recheck actor, agent, target,
parameters, policy identity, and TTL, and commit approval ID and request digest
uniqueness in a SQLite immediate transaction before returning `allow`.
Malformed, untrusted-key, forged, expired, target-changed, unknown-parameter,
unavailable-verifier, unavailable-actor, corrupt-ledger, sequential replay,
and concurrent-consumer cases fail closed.

The fixture includes only a synthetic public key and precomputed signatures.
Production still requires independent approver authentication, protected
private-key custody, rotation and revocation, managed trust delivery, and
idempotent reconciliation because SQLite cannot be atomic with an external MCP
side effect.

#### Sixth runnable slice

Implementation: complete.

Provider-specific managed endpoint snapshots now reconcile the complete active
MCP and Skill set with exact kind, dependency record, identity, authority,
collection source, and one-hour freshness requirements. Previously installed
or unknown plugins, missing extensions, kind or dependency confusion, stale
snapshots, unavailable collection, and malformed inventory do not pass.

The managed `PreToolUse` gate appends a fixed-schema JSON Lines event before
returning provider output. Events cover allow, deny, and error decisions using
hashed session, request, and approval references without prompt, transcript,
argument, target, body, output, credential, or signature content. Absolute
non-symlink storage, `0700` directory and `0600` file modes, append locking,
size bounds, `fsync`, retention, and export state are verified. Missing or
symlinked audit sinks block with exit `2`.

This is local reference evidence. Production still requires a trustworthy
fleet collector, PSB-AI-002 dependency provenance, managed ownership, rotation,
export ingestion, alerting, and separate review of native OTel, workspace, and
server-side audit coverage.

#### Seventh runnable slice

Implementation: complete.

Network-off remains the ordinary profile. A separate destination-specific
policy and offline verifier now require an exact HTTPS host, port and path
prefix, a managed egress gateway, recent complete DNS evidence containing only
public unicast addresses, and transport binding to one classified connection
address. Cleartext, lookalike, userinfo, fragment, unreviewed port or path,
path traversal, proxy, SOCKS, non-loopback listener, Unix socket, loopback, private,
link-local, multicast, reserved, unspecified, metadata, stale, mismatched, and
DNS-rebinding fixtures do not pass. Gateway, resolver, and malformed evidence
fail as `ERROR`.

The verifier performs no DNS lookup or connection. Production still requires
managed resolver provenance, TLS validation, lower-layer gateway enforcement,
TTL-aware refresh, and live proof that the active product cannot bypass or
fall back around the gateway. Browser, connector, web-search, provider
control-plane, and MCP server-side egress remain separate surfaces.

#### Eighth runnable slice

Implementation: complete.

Synthetic lifecycle assessment now covers managed hook completion, explicit
deny, process not started, timeout, abnormal exit, invalid output, and invalid
permit for both Claude Code and Codex. A provider-neutral downstream policy
allows a side effect only when managed matching, exit zero, valid allow output,
pre-output audit commit, exact request binding, trusted permit state, mandatory
gateway enforcement, gateway audit, and the observed outcome all agree.
Native product continuation after a hook failure remains untrusted; a missing
or invalid permit is denied before the remote side effect. Optional gateway
bypass is a finding, and unavailable or malformed evaluation is `ERROR`.

This is synthetic reference evidence rather than a deployed gateway. Production
still requires issuer authentication, short lifetime, exact audience and
request binding, replay prevention, backend network isolation, live product
failure injection, and observed zero mutations for startup, timeout, exit, and
output faults.

#### Ninth runnable slice

Implementation: complete.

The provider-neutral reconciliation policy now models the transaction boundary
between committed local approval consumption and a remote MCP mutation. Normal
application, timeout-after-apply, timeout-before-apply, retry with a distinct
replacement approval, and unknown outcome are reconciled against one stable
request digest and idempotency key with at most one backend mutation. The
original approval is never restored, automatic retry is disabled, and unknown
or unavailable outcomes block.

Negative fixtures restore and reuse approval, change idempotency identity,
change request content under one key, disable backend idempotency, and report
duplicate mutation. This remains synthetic state evidence. Production requires
durable authenticated backend idempotency records, serialized lookup and
mutation, delayed-delivery tests, network-partition tests, and live mutation
count evidence.

#### Tenth runnable slice

Implementation: complete.

A managed typed-command classifier now keeps reviewed read-only direct argv at
zero HITL, maps direct high-impact operations and completely resolved Git
aliases to one bound approval, and preserves classification through
environment-assignment wrappers. Force push maps to history rewrite rather
than ordinary publication. Shell strings, scripts, task runners, interpreter
code, unknown wrappers, unresolved aliases, and unknown operations are denied
without an override prompt.

Negative fixtures model substring-only automatic allow for shell, Make, and an
unresolved alias. The sample does not claim to parse arbitrary shell languages
or inspect script contents. Production still requires argv-preserving provider
adapters, managed executable and alias resolution, PATH and symlink race
handling, a reviewed typed-operation catalog, and live command-execution
evidence.

#### Eleventh runnable slice

Implementation: complete.

An adopted-fleet telemetry policy and offline verifier now require managed
enrollment and export for both Claude Code and Codex endpoint classes, recent
gap-free ingestion, explicit reject or quarantine accounting, and centralized
metadata-only storage that is immutable to developers and agents. The
centralized field set must exactly match the fixed redacted `AAR-019` audit
schema.

Synthetic delivery tests cover unknown extension, hook failure, audit sink
failure, gateway bypass, approval replay, reconciliation unknown, and command
broker bypass alerts. Missing providers, stale or gap-bearing ingestion, raw
content collection, and incomplete or failed alerts are findings; unavailable
or malformed evaluation is `ERROR`. This is deterministic adoption evidence,
not proof of a deployed collector, authenticated transport, SIEM durability,
live receiver, or operator response.

#### Twelfth runnable slice

Implementation: complete.

A dedicated synthetic collector trust root now authenticates a signed statement
that binds the exact canonical fleet snapshot digest, policy identity,
collection time, monotonic sequence, and previous accepted snapshot digest.
The verifier pins the public-key digest, validates the active issuer and
OpenSSL 3 signature, and compares the statement with a managed checkpoint.

Payload and signature tampering and replay are findings. Unknown keys,
malformed trust, statement, checkpoint, or snapshot state, and unavailable
cryptographic verification are `ERROR`. No private key is committed. Production
still requires protected collector key custody, rotation, revocation,
checkpoint atomicity and rollback protection, and independent trust delivery.

#### Acceptance criteria

- the same outcome assertions pass for the Claude Code and Codex secure
  fixtures and reject both insecure fixtures;
- no verifier or fixture installs hooks, modifies global settings, contacts a
  model, uses a real credential, or accesses a production service;
- bypass, downgrade, malformed input, unsupported configuration, and policy
  evaluation failure return a finding or `ERROR`, never a clean result;
- high-impact action fixtures cannot reuse an expired approval or change a
  target or parameter after approval;
- command-pattern and hook controls are documented as defense in depth rather
  than substitutes for an enforced sandbox and network boundary;
- evidence is deterministic and sanitized, with sensitive values absent from
  console and generated files;
- `control.yaml` uses `check_context_version: "1.0"` and atomic checks with
  reviewed row-level mappings before generated checklist inclusion;
- limitations explicitly cover approved-action abuse, compromised agent
  binaries, endpoint compromise, product-version drift, and human approval
  mistakes.

### PSB-AI-003 — Prompt and document injection containment

Status: `dependency-required` on `PSB-AI-001`, `PSB-AI-002`, and `PSB-AI-004`  
Domain: `ai-development-security`

#### Goal

Ensure untrusted repository content, documents, tool output, and prompts cannot
override repository security invariants or obtain unintended filesystem,
network, credential, or execution authority.

#### First runnable slice

Create non-malicious prompt-injection fixtures that request control removal,
secret access, network exfiltration, unsafe dependency installation, and
privileged execution. Verify denial, sandbox boundaries, audit evidence, and
continued completion of the legitimate task.

## OWASP AI Agent Security Cheat Sheet reconciliation

The
[OWASP AI Agent Security Cheat Sheet](SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)
is a design and test input, not a compliance standard or proof that an agent is
secure. Before implementing a derived requirement, record the exact upstream
repository commit and review the example semantically; the mutable web page is
not an immutable dependency.

| OWASP practice area | Existing disposition | Remaining work |
| --- | --- | --- |
| Tool Security & Least Privilege | `PSB-AI-002` governs extension dependencies and `PSB-AI-004` enforces runtime capabilities and approvals. | Add executable per-resource and read-versus-write authorization fixtures rather than relying only on tool-name patterns. |
| Input Validation & Prompt Injection Defense | `PSB-AI-003` owns prompt/document injection containment; `PSB-AI-004` supplies the runtime boundary. | Exercise retrieved documents, web content, issue text, API responses, and tool output as distinct untrusted sources. |
| Memory & Context Security | Not owned by an existing planned control. | Define isolation, provenance, validation, sensitive-data exclusion, expiry, size limits, integrity, deletion, and poisoning tests. |
| Human-in-the-Loop Controls | `PSB-AI-004` owns coding-agent action classification and approval enforcement. | Verify independent authorization, exact parameter binding, expiry, replay prevention, step-up requirements, idempotency, interruption, and bounded rollback. |
| Output Validation & Guardrails | `PSB-AI-004` denies unauthorized actions and `PSB-AI-003` tests malicious influence. | Add structured tool-call schemas, parameter validation, sensitive-output handling, scope/rate limits, and fail-closed execution gates. |
| Monitoring & Observability | `PSB-AI-004` now writes and verifies fixed-schema redacted allow, deny, and error hook evidence with local retention, export state, and fail-closed sink tests. | Add anomaly detection, approval-drift signals, cost/token/tool-call metrics, adopted export-ingestion evidence, and alert-delivery tests. |
| Multi-Agent Security | Not owned by an existing planned control. | Define authenticated delegation, sender/recipient authorization, message validation, privilege ceilings, isolation, freshness/replay checks, and circuit breakers. |
| Data Protection & Privacy | Credential paths and audit redaction are partial requirements in `PSB-AI-004`; endpoint and credential lifecycle remain `PSB-SOURCE-001` and `PSB-SOURCE-004`. | Define agent-context classification, minimization, encryption, residency where applicable, retention, deletion, and cross-user isolation. |
| Secure Agent Testing & Adversarial Validation | `PSB-AI-001` owns baseline benchmarking, `PSB-AI-003` owns injection scenarios, and every control must reach E3 with negative tests. | Maintain an abuse-case reconciliation view covering tool misuse, privilege escalation, memory poisoning, exfiltration, approval bypass, runaway loops, and multi-agent chaining without duplicating control-local tests. |

The sheet's additional risks map to the same gaps: memory poisoning belongs to
memory/context lifecycle; decision and approval manipulation belongs to
high-impact action integrity; denial of wallet belongs to resource-abuse
controls; and cascading failure belongs to multi-agent trust boundaries.

Do not treat input sanitization, model-based filtering, command deny patterns,
or approval prompts as complete authorization boundaries. Enforcement must
remain outside model output, and failure of schema validation, policy lookup,
approval verification, audit logging, or a circuit breaker must not become an
allow decision.

## Cross-control tool evaluation register

Tools remain implementation mechanisms rather than control boundaries. The
following candidates are tied to an existing outcome and may advance only when
an isolated fixture demonstrates a required gap. Fixed review sources,
licenses, and detailed limitations are recorded in
[`SECURITY_GUIDANCE_SOURCES.md`](SECURITY_GUIDANCE_SOURCES.md).

| Tool | Outcome owner | Current disposition | Next executable decision |
| --- | --- | --- | --- |
| zizmor | `PSB-CICD-003` | adopted | Maintain the separately pinned Action, scanner version, OCI digest, SARIF states, and unprivileged PR gate |
| actionlint | `PSB-CICD-003` | identified comparison candidate | Add only if syntax, expression, reusable-workflow, or embedded-script fixtures expose a required gap not detected by zizmor |
| poutine | `PSB-CICD-003` and the `PSB-CICD-001..005` boundary | identified comparison candidate | Add only for a unique pipeline supply-chain finding; do not duplicate existing SHA, injection, privilege, or untrusted-PR controls |
| cicd-sensor | `PSB-BUILD-001` telemetry adapter | identified pre-release candidate | Prototype only after privilege, kernel support, event schema, redaction, health failure, and integrity requirements are testable |
| OpenSSF Scorecard | governance or supplier-assessment evidence | adopted as guidance only | Implement an adapter only for individually mapped checks with freshness and error semantics; never use the aggregate score as compliance evidence |
| TruffleHog | `PSB-SOURCE-003` organization-operated assessment | introduced as a complementary candidate; not recommended for developer-local hooks | Add only for a demonstrated onboarding, scheduled full-history, incident-response, or credential-verification gap, with controlled egress and distinct scanner-error evidence |

For every candidate, the executable adoption slice must pin the version and
artifact integrity, keep network access explicit, distinguish `clean`,
`finding`, `NOT_CHECKED`, and `ERROR` as applicable, and document update and
exception ownership. Merely cataloguing a tool does not change a control's
maturity or generated checklist rows.

## Cross-control implementation rules

Every planned control must:

1. begin with an explicit threat actor or failure source and protected target;
2. define insecure and secure behavior before selecting tools;
3. keep third-party tools pinned and integrity-verified;
4. provide offline deterministic fixtures where possible;
5. separate `clean`, `finding`, `NOT_CHECKED`, and execution `ERROR`;
6. include at least one security-relevant negative test;
7. produce sanitized expected evidence;
8. declare one atomic checklist row per assessable state;
9. map frameworks at row level with exact pinned versions and reviewed
   rationale;
10. document operational cost, bypasses, false positives, and residual risk;
11. regenerate indexes, mappings, CSV, Markdown, and XLSX;
12. stop at E3 before adding a second provider or tool unless the second
   integration closes a documented gap.

## Roadmap gaps without reserved control IDs

The phase roadmap also names outcomes that do not yet have a prioritized
control ID. They remain visible here so they are not accidentally absorbed into
an unrelated oversized control.

### Software supply-chain integration reconciliation

Goal: verify that security identities and decisions remain connected across
developer environment, SCM, dependency intake, build, evidence generation,
repository operations, release, and CD/GitOps rather than counting isolated
passing tools.

Disposition: use NIST SP 800-204D final, February 2024
([`REF-CICD-012`](SECURITY_GUIDANCE_SOURCES.md#ref-cicd-012)) as section-level
integration guidance. Generate a reconciliation with `implemented`, `planned`,
`gap`, and `out-of-scope` dispositions. Do not create a second SSDF registry or
copy Appendix A mappings; exact SSDF relationships remain in the pinned
`nist-ssdf` registry and require row-level implementation evidence.

### CIS software supply-chain provider profiles

Goal: reconcile authorized CIS GitHub and GitLab Benchmark recommendations
with existing controls and expose only provider-applicable, non-duplicate
adoption checks.

Disposition: source registration is complete as
[`REF-CICD-013`](SECURITY_GUIDANCE_SOURCES.md#ref-cicd-013), but activation is
`input-required`. Obtain the official CIS GitHub Benchmark `1.2.0` and CIS
GitLab Benchmark `1.0.1` PDFs observed on `2026-08-04`, record SHA-256 and reuse
terms, inventory every recommendation, and reconcile it with GitHub guidance,
SSDF, SLSA, OSPS, and existing control checks. Keep the 2022 general Guide
separate from provider Benchmark identifiers.

### FIRST PSIRT capability profile

Goal: assess charter, sponsorship, stakeholders, product inventory,
vulnerability intake, qualification, analysis, remediation, disclosure,
post-incident improvement, training, and metrics without converting missing
organization evidence into a pass.

Disposition: build the profile after `PSB-GOV-003` establishes the case and
priority evidence contract. Use PSIRT Services Framework 1.1 as the detailed
service/function inventory and the mutable PSIRT Maturity Document as the
cumulative Basic, Intermediate, and Advanced view. Snapshot the maturity
source with integrity metadata first. Results must distinguish `PASS`, `FAIL`,
`NOT_CHECKED`, `ERROR`, and reviewed `N/A`; a repository fixture is never a
live PSIRT maturity claim.

### CI runner hardening

Goal: isolate ephemeral hosted and self-hosted runners from prior jobs, host
credentials, management networks, persistent workspace state, and untrusted
pull requests.

Disposition: define the boundary after `PSB-CICD-005` establishes untrusted-run
semantics and `PSB-BUILD-001` containment overlap is reviewed. Do not reserve a
new ID until hosted versus self-hosted evidence and cleanup behavior are
separated.

### Verified external downloads

Goal: require exact versions and publisher checksum or signature verification
for every downloaded CLI, policy bundle, database, and artifact.

Disposition: implement the first reusable download-and-verify interface inside
`PSB-DETECT-001`, because Trivy and Checkov need it immediately. Extract a
separate shared control only when a second domain consumes the same interface
and a unique adoption checklist boundary exists.

### Artifact signing generation

Goal: sign exact release artifact digests with a protected short-lived or
KMS-backed identity and publish verifiable signature material.

Disposition: keep separate from consumer verification in `PSB-REL-001`,
provenance publication in `PSB-REL-002`, and SBOM publication in
`PSB-REL-003`. Review and assign an ID after those release-manifest interfaces
stabilize; do not claim Cosign or other signing generation from documentation
alone.

### Governance metrics and maturity views

Goal: show adoption, exception debt, evidence freshness, unmapped rows, and
control maturity without treating missing assessment data as a passing state.

Disposition: extend generated views after `PSB-GOV-002` defines a canonical
exception lifecycle and organization assessment input remains separate from
repository-owned guidance.

### AI agent memory, context, and data lifecycle

Goal: prevent untrusted or sensitive content from being persisted, retrieved,
or shared outside its intended user, session, task, classification, and
retention boundary.

Disposition: define a separate control boundary after `PSB-AI-004` establishes
the runtime policy interface. Keep memory poisoning fixtures coordinated with
`PSB-AI-003`, but place isolation, provenance, integrity, expiry, deletion, and
data handling in this lifecycle control. Assign an ID after reviewing whether
provider-managed memory can produce E3 local evidence or requires explicit
`NOT_CHECKED` organization evidence.

### High-impact agent action integrity and output validation

Goal: ensure an agent proposal is converted into an executable action only
after independent schema, authorization, scope, approval, freshness, replay,
and policy checks succeed.

Disposition: implement coding-agent permission and approval adapters first in
`PSB-AI-004`. Assign a separate ID when a provider-neutral execution-gate
fixture can demonstrate decision/execution separation, parameter-bound
approvals, structured tool calls, idempotency, and fail-closed behavior without
duplicating application authorization or deployment controls.

### Agent monitoring and resource-abuse limits

Goal: detect security-relevant agent behavior and stop excessive token, cost,
retry, recursion, duration, and tool-call consumption without logging
credentials or sensitive context.

Disposition: keep fixed-schema redacted hook audit, local retention/export
state, and sink-failure behavior in `PSB-AI-004`; reserve a separate control
boundary for anomaly rules, denial-of-wallet limits, organization-owned export
ingestion, and alert delivery. Assign an ID after resource-abuse fixtures and
organization-owned alert evidence are separated.

### Multi-agent trust and delegation

Goal: prevent one compromised or low-trust agent from increasing another
agent's authority or propagating malicious instructions, data, or resource
exhaustion across an agent chain.

Disposition: define authenticated agent identity, explicit delegation scope,
sender and recipient authorization, message schema and provenance, privilege
ceilings, freshness and replay checks, isolated execution, and circuit
breakers. Assign an ID only when single-agent MCP delegation in
`PSB-AI-002/004` is clearly separated from true agent-to-agent communication
and cascading-failure tests.

## Plan maintenance

- Update this document when a planned control changes boundary, dependency, or
  acceptance criteria.
- Update `ROADMAP.md` when priority or control identity changes.
- Remove a section from this document only after the implemented control README
  contains equivalent adoption guidance and the ROADMAP marks it implemented.
- Do not mark a plan complete based only on documentation, a tool installation,
  or a passing secure fixture without a rejected insecure fixture.
