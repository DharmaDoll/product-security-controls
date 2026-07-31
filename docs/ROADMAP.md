# Roadmap

## Phase 0 — Foundation

Deliver:

- repository skeleton;
- AGENTS.md;
- control schema;
- validation script;
- index generator;
- framework registry structure;
- contribution rules.

Do not add multiple security tools yet.

## Phase 1 — First vertical slices

Implement four complete controls:

1. GitHub Actions immutable SHA pinning — implemented as `PSB-CICD-001`
2. Dependency lockfile and update cooldown — cooldown implemented as
   `PSB-DEPS-001`, including managed proxy-only npm／pip／Go／Composer profiles
   and an independent 168-hour verifier; install-time code execution
   default-deny is implemented as
   `PSB-DEPS-002`; normalized frozen lockfile and artifact integrity verification
   is implemented as `PSB-DEPS-003`
3. Secure secret handling in an application
4. Trivy verification for container/IaC/secret examples — implemented as
   `PSB-DETECT-001` with immutable release verification, offline database
   identity, sanitized evidence, and distinct clean/finding/error states

Each must include insecure, secure, tests, expected results, and mappings.

## Phase 2 — Application security controls

Add:

- authentication;
- authorization/IDOR;
- injection;
- cryptography;
- file upload;
- SSRF;
- logging and error handling.

Prioritize ASVS mappings.

Before implementing the individual controls, import the existing application
vulnerability assessment checklist into the generated checklist model. Preserve
the source identifier and wording, record its source/version, split compound
questions into atomic checks where necessary, and review duplicates before
merging. Each resulting row must identify the responsible role, verification
method, expected evidence, and reviewed row-level framework mappings. The
application assessment workbook/CSV is the required input; do not infer missing
checks or claim ASVS coverage before that source is available and reviewed.

Generate an application vulnerability assessment profile in CSV and as a
filterable worksheet. Completion means every imported source row is either
mapped to an implemented/planned control or recorded in a reconciliation report
with an explicit disposition such as duplicate, out of scope, or mapping
review required.

## Phase 3 — CI/CD and supply chain

Add:

- GitHub Actions static analysis — implemented as `PSB-CICD-003`;
- minimal permissions;
- fork-safe workflows;
- dependency review;
- OIDC;
- runner hardening;
- verified downloads;
- container digest pinning.
- container registry transport, least privilege, mutation protection, audit,
  and stale-image lifecycle;
- container host and daemon hardening;
- post-admission container runtime threat detection with fail-closed telemetry.

Build credential, privilege, sandbox, egress, and telemetry containment is
implemented as `PSB-BUILD-001`.

Secure infrastructure golden-path composition is implemented as
`PSB-IAC-001`. It provides a versioned multi-cloud secure-compute module
contract, resolved Terraform plan decision gate, fail-closed policy behavior,
explicit composition of implemented versus planned CI capabilities,
provider-side bypass enforcement requirements, continuous drift detection,
and bounded corrective action. `PSB-DETECT-001`, `PSB-REL-002`,
`PSB-REL-003`, and `PSB-CONTAINER-001` are now implemented components.
`PSB-REL-003` adds distinct source/build/deployment observations,
artifact-bound CycloneDX publication, and a normalized Dependency-Track
processing receipt; artifact signing generation, supplier SBOM trust, and
cloud OIDC profiles remain incomplete.

Also add source-protection controls for public repository exposure, including
GitHub dorking scenarios, secret discovery in current and historical content,
visibility review, and remediation verification. These controls must test
both prevention and detection, and must document the residual risk from forks,
caches, and previously cloned repositories. `PSB-SOURCE-003` implements this
scope with repository-scoped defensive queries, an all-reachable-history
scanner, sanitized multi-surface evidence, credential-first remediation, and
negative tests that distinguish scanner failure from a clean result.

Add developer endpoint hardening controls covering device encryption and lock
policy, OS and tool update enforcement, least privilege, credential storage,
local service exposure, endpoint detection, backup handling, and isolation of
AI development tools. Controls should distinguish device-management policy
from developer-local configuration and should not assume that endpoint
hardening protects a compromised repository or malicious dependency.
`PSB-SOURCE-001` now includes a sanitized read-only Linux assessment for
locally observable signals while leaving organization-owned evidence
`NOT_CHECKED`.

Source-platform access credential lifecycle is implemented as
`PSB-SOURCE-004`. It distinguishes GitHub CLI OAuth tokens, classic and
fine-grained PATs, SSH keys, and GitHub App or workload identities; requires
least privilege, bounded lifetime, protected storage, recurring review,
event-driven revocation, audit evidence, and expiring exceptions; and keeps
actual credential values out of fixtures and generated evidence.

Prioritize ATT&CK, SSDF, and SLSA mappings.

### SLSA Build Level 2 target

Implement only the cumulative SLSA Build L1 and L2 requirements for the first
SLSA milestone. Keep L3 controls out of the Level 2 adoption profile even when
they already exist elsewhere in the repository. A row-level mapping is
supporting evidence, not a claim that the level has been achieved.

Planned control packages:

1. `PSB-BUILD-002` — require a consistent build process on an approved hosted
   build platform — implemented. It provides evidence for the producer
   responsibilities represented by
   `build-l1#producer-appropriate-build-platform`,
   `build-l1#producer-consistent-build`, and
   `build-l2#producer-hosted-build-platform`.
2. `PSB-BUILD-003` — automatically generate authenticated provenance through
   the build platform itself, with build steps unable to forge the platform
   identity — implemented. It provides evidence for
   `build-l1#platform-generates-provenance` and
   `build-l2#platform-authentic-provenance`.
3. `PSB-REL-002` — publish and distribute provenance with each applicable
   release artifact — implemented with one-to-one digest binding, immutable
   authenticated discovery, intended-consumer access, publication timing,
   retention, and no-downgrade verification. It provides evidence for
   `build-l1#producer-distributes-provenance`.
4. Continue using `PSB-REL-001` for consumer-side provenance authenticity and
   artifact-subject validation, mapped to
   `build-l2#consumer-validates-authenticity`.

The `PSB-REL-002` mapping is reviewed against its implementation, negative
tests, distribution trust boundary, and sanitized evidence.
All seven cumulative requirements now have reviewed `mapped-evidence` rows in
the generated `SLSA L2 Coverage` view. The separate end-to-end assessment is
implemented in [`SLSA_BUILD_L2_ASSESSMENT.md`](SLSA_BUILD_L2_ASSESSMENT.md).
It requires current evidence for an exact producer, build platform, consumer,
artifact family, release, and source revision, and distinguishes `PASS`,
`FAIL`, `INCOMPLETE`, and `ERROR`. Milestone completion still requires an
organization-owned live input that produces `PASS`. A vendor-neutral adapter
now verifies five independently reviewed, digest-pinned issuer bundles and
assembles the 11 evidence records without trusting hand-entered status flags.
A GitHub Actions collector now supplies the first provider-specific
`build-platform` bundle by cryptographically verifying artifact provenance
with a version- and digest-pinned GitHub CLI, exact signer/source expectations,
and self-hosted-runner denial. A separate GitHub Releases collector now emits
role-separated `software-producer` publication evidence and an independent
`security-monitor` storage probe using immutable release and asset digest
metadata. The consumer collector now reruns the pinned `PSB-REL-001` verifier,
and the security-review collector authenticates a scoped, expiring assessment
of platform capability and signer ownership. All five issuer roles therefore
have executable collector paths and an end-to-end fixture test. Milestone
completion still requires organization-owned live policies and evidence that
produce `PASS`; repository fixtures and mapping status are not a level claim.
L3 hardening is a later milestone and is not required for this target.

## Phase 4 — Release integrity

Add:

- SBOM;
- checksums;
- artifact attestation;
- provenance;
- signing and verification.

Signed SLSA provenance expectation verification is implemented as
`PSB-REL-001`.
Artifact-bound CycloneDX generation, publication, completeness verification,
fail-closed Dependency-Track ingestion, and distinct source/build/deployment
observation linkage are implemented as `PSB-REL-003`. Supplier-provided signed
SBOM trust and quarantine remain planned as `PSB-REL-004`.

## Phase 5 — AI development security

Add:

- repository-owned AGENTS controls;
- Project CodeGuard baseline comparison;
- Skill pinning;
- Skill semantic review;
- MCP allowlist;
- vendor-neutral AI coding agent runtime hardening profiles for Claude Code,
  Codex, and later adapters;
- managed sandbox, approval, filesystem, credential, network, and side-effect
  policies that repository-local content cannot weaken;
- prompt/document injection fixtures;
- sandbox and network policy;
- agent memory, context isolation, retention, integrity, and sensitive-data
  handling;
- parameter-bound approval and independent authorization for high-impact
  actions;
- structured output and tool-call validation before execution;
- agent security telemetry, anomaly detection, and token, cost, retry, and
  recursion limits;
- multi-agent delegation, communication, privilege-ceiling, replay, and
  cascading-failure controls.

Add AI framework registries together with the first controls that can produce
evidence for them:

- NIST SP 800-218A as the AI-specific SSDF community profile;
- NIST AI RMF 1.0 and NIST AI 600-1 for governance, measurement, and
  generative-AI risk management;
- OWASP Top 10 for LLM Applications 2025 as a coarse secondary risk taxonomy.

Keep the roles separate: SP 800-218A supplies lifecycle practices, AI RMF and
AI 600-1 supply risk-management outcomes, and OWASP LLM Top 10 plus MITRE
ATLAS classify risks and attacker behavior. None of these mappings alone
proves that an AI system is secure. Track revisions to AI RMF and emerging
agentic-AI guidance, but do not pin drafts or unstable identifiers into
controls.

## Phase 6 — Governance and generated views

Add:

- exception expiry;
- metrics;
- adoption profiles;
- generated framework indexes;
- control maturity dashboard;
- repository template documentation.

SBOM impact search and evidence-first supply-chain incident response planning is
implemented as `PSB-GOV-001`, including a normalized read-only
Dependency-Track exact CVE/PURL portfolio adapter that requires complete
pagination and links project UUID/version and SBOM serials back to build
evidence.

## Prioritized control backlog

This section is the ordering source for new control packages. Phase sections
describe scope; this backlog describes implementation priority. Proposed IDs
are reserved for planning and may be adjusted before implementation if the
application checklist reconciliation identifies a better boundary.
Detailed goals, control boundaries, implementation slices, dependencies, and
acceptance criteria are maintained in
[`PLANNED_CONTROLS.md`](PLANNED_CONTROLS.md).

### P0 — Current milestones

1. Import and reconcile the existing application vulnerability assessment
   checklist as described in Phase 2. This is a generation/data-model task and
   does not become a documentation-only control.
2. `PSB-BUILD-002` — consistent build process on an approved hosted build
   platform — implemented.
3. `PSB-BUILD-003` — platform-generated and platform-authenticated provenance
   — implemented.
4. `PSB-REL-002` — provenance publication and distribution with release
   artifacts — implemented.

`PSB-BUILD-002` closes three producer-side gaps and `PSB-BUILD-003` closes two
platform-side gaps. Item 4 closes the final provenance-distribution mapping gap
together with the existing consumer verification in `PSB-REL-001`. Do not
start a new SLSA L3 milestone until the cumulative L1+L2 assessment is complete.

### P1 — Foundational product-security controls

1. `PSB-IAC-001` — secure-by-default IaC modules, resolved-plan PaC decision
   gate, provider enforcement, and bounded drift remediation — implemented.
2. `PSB-SOURCE-004` — source-platform OAuth, PAT, SSH, and App credential
   lifecycle with least privilege, expiration, protected storage, inventory,
   revocation, and audit evidence — implemented.
3. `PSB-CICD-004` — explicit least-privilege workflow and job permissions,
   rejecting broad write scopes — implemented with workflow deny-all,
   purpose-bound exact job policies, OIDC scoping, trusted-ref conditions,
   protected-environment requirements, and repository-wide verification.
4. `PSB-CICD-005` — fork-safe and untrusted-PR-safe workflows with no privileged
   credential exposure or execution through `pull_request_target` — implemented
   with credential-free hosted PR jobs, safe checkout, conservative cache and
   cross-run rejection, new trusted-run separation, repository-wide policy
   coverage, and fail-closed negative tests.
5. `PSB-CODE-001` — application secret handling with externalized secrets,
   rotation-safe configuration, and negative leakage tests.
6. `PSB-CODE-002` — authentication and session lifecycle, including secure
   recovery and invalidation behavior.
7. `PSB-CODE-003` — object- and function-level authorization with IDOR negative
   tests.
8. `PSB-DETECT-001` — pinned, integrity-verified Trivy verification for
   filesystem, container, IaC, secret, and SBOM fixtures, with scanner errors
   distinct from clean results — implemented with checksum and Sigstore
   verification, known affected-version rejection, database identity,
   secret-safe normalization, exact expiring exceptions, and a documented
   Checkov non-adoption decision. An optional DockSec `2026.7.5` adapter now
   adds Dockerfile and Compose remediation feedback through an offline
   scan-only fail-closed gate; AI output remains non-authoritative and the
   upstream Action is rejected because its internal downloads are mutable.

### P2 — Exposure reduction and release completeness

1. `PSB-CODE-004` — injection prevention using parameterization and
   context-specific output handling.
2. `PSB-SOURCE-003` — public repository exposure review, repository-scoped
   GitHub dorking scenarios, current/history secret detection, non-code surface
   evidence, and credential-first remediation — implemented ahead of the
   remaining P2 backlog.
3. `PSB-DEPS-004` — dependency review that blocks unreviewed risk changes and
   fails closed when advisory or policy evaluation cannot run.
4. `PSB-CICD-006` — short-lived, audience-bound OIDC federation without stored
   cloud credentials.
5. `PSB-REL-003` — SBOM generation, artifact binding, publication,
   completeness checks, consumer-side mismatch handling, and fail-closed
   Dependency-Track processing — implemented with nine atomic checks,
   positive and negative fixtures, distinct source/build/deployment
   observations, runtime error states, and Golden Path plus `PSB-GOV-001`
   composition.
6. `PSB-REL-004` — signed supplier SBOM product/artifact identity, signer
   lifecycle, revocation freshness, schema validation, and quarantine.
7. `PSB-CONTAINER-001` — immutable image digests, non-root execution, minimal
   capabilities, admission-policy verification, and a follow-on composition
   that applies existing `PSB-REL-001` SLSA provenance verification to the
   exact admitted OCI manifest digest — implemented with API-native Kubernetes
   fixtures, nine atomic admission checks, default-deny network policy,
   platform PID and fail-closed evidence, and actual `PSB-REL-001` verifier
   composition.
8. `PSB-CONTAINER-002` — registry transport, repository-scoped authorization,
   short-lived identity, immutable release protection, audit, and image
   lifecycle enforcement.
9. `PSB-CONTAINER-003` — minimal patched container hosts, protected daemon and
   runtime sockets, user and kernel isolation, management restriction, and
   host audit policy.
10. `PSB-CONTAINER-004` — workload-bound runtime event detection, alert
   delivery, telemetry failure handling, and authorization-bound response
   handoff.
11. `PSB-GOV-002` — narrow, owned, justified, and time-bound security exceptions
   with expiry enforcement.

### P3 — Extended application and AI development security

1. Split the reviewed application checklist remainder into executable controls
   for cryptography, file upload, SSRF, logging, and error handling. Assign IDs
   only after source-row reconciliation to avoid premature or duplicate control
   boundaries.
2. `PSB-AI-001` — repository-owned AGENTS and Project CodeGuard guidance pinned
   to a canonical source and benchmarked against a no-guidance baseline.
3. `PSB-AI-002` — Agent Skill, MCP server, and plugin pinning, integrity
   verification, semantic review, and least-privilege enforcement.
4. `PSB-AI-004` — prototype first slice implemented for Claude Code and Codex
   sandbox, workspace, synthetic credential, network-off, source-publication
   approval, bypass, and managed-precedence outcomes. The second slice adds
   classified high-impact actions plus actor, agent, target, parameter,
   policy-version, TTL, and replay-bound approval verification. The third slice
   adds exact managed MCP identities and tools, constrained automatic
   reversible writes, zero-HITL reads, and one-HITL high-impact routing. The
   fourth slice connects managed `PreToolUse` gates. The fifth authenticates
   digest-selected approvals with a pinned issuer key and atomically limits
   local consumption to one hook allow. The sixth reconciles recent complete
   installed runtime inventories and writes fixed-schema redacted allow, deny,
   and error audit events before provider output. The seventh keeps network-off
   as the default and adds exact managed HTTPS destinations, public-address
   classification, connected-address binding, and private/local/metadata,
   proxy, socket, stale-DNS, and DNS-rebinding negative tests. Continue with
   an eighth synthetic slice that requires a downstream request-bound permit
   so hook startup, timeout, abnormal-exit, invalid-output, and invalid-permit
   cases cannot reach a side effect. The ninth reconciles uncertain external
   outcomes with stable request identity, backend idempotency, no approval
   restoration, distinct retry approval, and an unknown-outcome block.
   The tenth adds typed direct-argv classification and denies shell, script,
   task-runner, interpreter, unresolved-alias, and unknown indirection without
   increasing HITL prompts. The eleventh adds both-provider managed fleet
   enrollment, fresh gap-free export ingestion, centralized metadata-only
   storage, and synthetic delivery tests for required runtime alerts. The
   twelfth authenticates the exact fleet snapshot and monotonic sequence with
   a dedicated digest-pinned collector key and rejects payload/signature
   tampering and replay. Continue with live product, gateway,
   delayed-delivery, backend, command-broker, collector, key-custody, SIEM,
   checkpoint, and receiver evidence.
5. `PSB-AI-003` — prompt/document injection fixtures that verify the
   `PSB-AI-004` runtime boundary and repository security invariants.
6. Reconcile the remaining OWASP AI Agent Security Cheat Sheet outcomes into
   separate executable controls for memory/context/data lifecycle,
   high-impact action integrity and output validation, monitoring and
   denial-of-wallet limits, and multi-agent trust boundaries. Assign IDs only
   after reviewing overlap with `PSB-AI-002..004`, `PSB-SOURCE-001`, and the
   repository-wide E3 testing requirement.

Within a priority, implement one reviewable vertical slice at a time. Every new
control must meet the repository definition of done, including insecure and
secure behavior where applicable, automated negative tests, sanitized evidence,
limitations, and reviewed row-level mappings.

## Planned framework adoption after Phase 5

Add the following only with a concrete implementation and automated evidence:

- CIS Docker Benchmark v1.8.0 as the Docker-specific configuration benchmark
  for `PSB-CONTAINER-001..004`, with recommendation ownership split by
  workload admission, registry, host or daemon, and runtime-detection outcome.
  Activation is `input-required` until an official authorized PDF, SHA-256,
  recommendation inventory, and reuse terms are reviewed; do not use
  third-party PDF mirrors;
- CIS Software Supply Chain Security Benchmark controls that add unique,
  automatable checks beyond the pinned GitHub security guidance;
- AWS security guidance as an AWS provider profile when AWS-specific IAM,
  CI/CD, artifact, or deployment controls exist;
- Google Cloud software supply-chain guidance and Binary Authorization as a
  GCP provider profile when corresponding provenance and admission controls
  exist;
- NIST SP 800-61 Rev. 3 when incident-response execution, evidence
  preservation, and recovery controls extend `PSB-GOV-001`;
- CISA SBOM consumption guidance when SBOM origin, integrity, completeness,
  and mismatch handling are executable;
- supplier due-diligence guidance such as NIST SP 1326 when supplier and
  acquisition governance becomes an implemented control.

NIST CSF, CIS Controls, OWASP Top 10, and cloud architecture frameworks remain
secondary rollups. Do not add them as primary control requirements unless a
documented gap cannot be covered by ASVS, SSDF, SLSA, OSPS, or a more specific
control source.
