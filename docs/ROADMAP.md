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
   `PSB-DEPS-001`; install-time code execution default-deny is implemented as
   `PSB-DEPS-002`; normalized frozen lockfile and artifact integrity verification
   is implemented as `PSB-DEPS-003`
3. Secure secret handling in an application
4. Trivy verification for container/IaC/secret examples

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

Build credential, privilege, sandbox, egress, and telemetry containment is
implemented as `PSB-BUILD-001`.

Secure infrastructure golden-path composition is implemented as
`PSB-IAC-001`. It provides a versioned multi-cloud secure-compute module
contract, resolved Terraform plan decision gate, fail-closed policy behavior,
explicit composition of implemented versus planned CI capabilities,
provider-side bypass enforcement requirements, continuous drift detection,
and bounded corrective action. It does not mark the planned Trivy, SBOM,
provenance distribution, artifact signing, or cloud OIDC profiles complete.

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
   release artifact. This is intended to address
   `build-l1#producer-distributes-provenance`.
4. Continue using `PSB-REL-001` for consumer-side provenance authenticity and
   artifact-subject validation, mapped to
   `build-l2#consumer-validates-authenticity`.

The planned `PSB-REL-002` mapping remains provisional until its implementation,
negative tests, distribution trust boundaries, and sanitized evidence exist.
Completion of this milestone requires all seven cumulative
requirements to move from `gap` to reviewed evidence in the generated
`SLSA L2 Coverage` view,
followed by a separate end-to-end assessment of the producer, build platform,
and consumer. L3 hardening is a later milestone and is not required for this
target.

## Phase 4 — Release integrity

Add:

- SBOM;
- checksums;
- artifact attestation;
- provenance;
- signing and verification.

Signed SLSA provenance expectation verification is implemented as
`PSB-REL-001`.

## Phase 5 — AI development security

Add:

- repository-owned AGENTS controls;
- Project CodeGuard baseline comparison;
- Skill pinning;
- Skill semantic review;
- MCP allowlist;
- prompt/document injection fixtures;
- sandbox and network policy.

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
implemented as `PSB-GOV-001`.

## Prioritized control backlog

This section is the ordering source for new control packages. Phase sections
describe scope; this backlog describes implementation priority. Proposed IDs
are reserved for planning and may be adjusted before implementation if the
application checklist reconciliation identifies a better boundary.

### P0 — Current milestones

1. Import and reconcile the existing application vulnerability assessment
   checklist as described in Phase 2. This is a generation/data-model task and
   does not become a documentation-only control.
2. `PSB-BUILD-002` — consistent build process on an approved hosted build
   platform — implemented.
3. `PSB-BUILD-003` — platform-generated and platform-authenticated provenance
   — implemented.
4. `PSB-REL-002` — provenance publication and distribution with release
   artifacts.

`PSB-BUILD-002` closes three producer-side gaps and `PSB-BUILD-003` closes two
platform-side gaps. Item 4 closes the final provenance-distribution gap together
with the existing consumer verification in `PSB-REL-001`. Do not start a new
SLSA L3 milestone until the cumulative L1+L2 assessment is complete.

### P1 — Foundational product-security controls

1. `PSB-IAC-001` — secure-by-default IaC modules, resolved-plan PaC decision
   gate, provider enforcement, and bounded drift remediation — implemented.
2. `PSB-SOURCE-004` — source-platform OAuth, PAT, SSH, and App credential
   lifecycle with least privilege, expiration, protected storage, inventory,
   revocation, and audit evidence — implemented.
3. `PSB-CICD-004` — explicit least-privilege workflow and job permissions,
   rejecting broad write scopes.
4. `PSB-CICD-005` — fork-safe and untrusted-PR-safe workflows with no privileged
   credential exposure or execution through `pull_request_target`.
5. `PSB-CODE-001` — application secret handling with externalized secrets,
   rotation-safe configuration, and negative leakage tests.
6. `PSB-CODE-002` — authentication and session lifecycle, including secure
   recovery and invalidation behavior.
7. `PSB-CODE-003` — object- and function-level authorization with IDOR negative
   tests.
8. `PSB-DETECT-001` — pinned, integrity-verified Trivy verification for
   filesystem, container, IaC, secret, and SBOM fixtures, with scanner errors
   distinct from clean results.

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
   completeness checks, and consumer-side mismatch handling.
6. `PSB-CONTAINER-001` — immutable image digests, non-root execution, minimal
   capabilities, and admission-policy verification.
7. `PSB-GOV-002` — narrow, owned, justified, and time-bound security exceptions
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
4. `PSB-AI-003` — prompt/document injection fixtures with sandbox, network, and
   security-invariant tests.

Within a priority, implement one reviewable vertical slice at a time. Every new
control must meet the repository definition of done, including insecure and
secure behavior where applicable, automated negative tests, sanitized evidence,
limitations, and reviewed row-level mappings.

## Planned framework adoption after Phase 5

Add the following only with a concrete implementation and automated evidence:

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
