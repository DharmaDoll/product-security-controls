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
- dependency review — implemented as `PSB-DEPS-004`;
- OIDC;
- runner hardening — implemented as `PSB-CICD-007`;
- verified downloads;
- container digest pinning.
- container registry transport, least privilege, mutation protection, audit,
  and stale-image lifecycle;
- container host and daemon hardening;
- post-admission container runtime threat detection with fail-closed telemetry.
- outside-in external attack-surface discovery that reconciles verified owned
  domains, Certificate Transparency, public DNS, and HTTPS metadata with a
  current owned inventory while keeping shared infrastructure and intrusive
  scanning outside the boundary — implemented as `PSB-DETECT-003`.

Build credential, privilege, sandbox, egress, and telemetry containment is
implemented as `PSB-BUILD-001`.

CI runner hardening is implemented as `PSB-CICD-007`. It separates
provider-owned hosted lifecycle evidence from organization-owned self-hosted
evidence and verifies exact trust routing, digest-identified images, JIT
one-job lifecycle, clean startup, metadata／management／host-socket isolation,
bounded registration authority, teardown, external log correlation, and
fail-closed evidence health. Live fleet adapters remain adoption work.

Privileged CI/CD control-plane change assurance is implemented as
`PSB-CICD-008`. It covers human administrator changes outside repository
workflows across SCM, CI, cloud federation, artifact registry, and signing
services. The E3 contract requires a named phishing-resistant administrator,
bounded recently reauthenticated session, exact target and before-after policy
digests, independent approval, provider execution and audit correlation, and a
one-hour independently reviewed emergency path. Cross-service collector gaps,
stale or malformed input, and credential-bearing evidence fail closed. Live
provider adapters, organization membership, authenticator custody, and audit
backend assurance remain adoption evidence. A first read-only GitHub
normalization adapter now joins organization audit events to stable actor and
request identities, exact old／new setting digests, external session assurance,
and the reviewed change register. It strips provider token metadata and rejects
missing joins or tampering. A bounded GitHub REST collector now adds fixed API
version and query,
complete cursor pagination, field allow-listing, atomic output, and fail-closed
rate-limit／network／loop handling. Environment protection, runner-group current
state, repository／organization branch-ruleset history, and legacy branch
force-push, deletion, administrator-enforcement, and CODEOWNER-review adapters are implemented; broader Actions policy, other
legacy branch settings, and ruleset lifecycle events still need separate state
joins. Remaining provider adapters are adoption work.

Secure infrastructure golden-path composition is implemented as
`PSB-IAC-001`. It provides a versioned multi-cloud secure-compute module
contract, resolved Terraform plan decision gate, fail-closed policy behavior,
explicit composition of implemented versus planned CI capabilities,
provider-side bypass enforcement requirements, continuous drift detection,
and bounded corrective action. `PSB-DETECT-001`, `PSB-REL-002`,
`PSB-REL-003`, `PSB-CONTAINER-001`, `PSB-CONTAINER-004`, and
`PSB-CICD-006` are now implemented components. The OIDC control adds signed
exact-claim federation, stored-key removal, and bounded credential receipts.
`PSB-REL-003` adds distinct source/build/deployment observations,
artifact-bound CycloneDX publication, and a normalized Dependency-Track
processing receipt. `PSB-REL-004` adds signed supplier product/artifact
identity, signer lifecycle, least-privilege intake, and fail-closed
quarantine. `PSB-REL-005` adds exact digest signing requests, short-lived
workload authorization, non-exportable sign-only signer policy, immutable
signature publication, transparency receipts, and fail-closed release gating.
`PSB-CONTAINER-002` adds TLS-only exact registry trust,
repository/action-scoped authorization, short-lived identity binding,
protected release immutability, attributable audit correlation, bounded image
lifecycle, and fail-closed evidence health. Provider-specific live signing,
OIDC, transparency-log, or registry adapters remain incomplete.
`PSB-CONTAINER-003` adds dedicated minimal Linux host scope, exact patch
baselines, private daemon control, protected runtime paths, kernel isolation,
operator and audit boundaries, and hardware-backed node trust with distinct
`NOT_CHECKED` and `ERROR` states. Live host adapters remain incomplete.

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
actual credential values out of fixtures and generated evidence. Its GitHub
MCP adapter now prefers organization-approved remote or memory-only OAuth,
uses a dedicated fine-grained PAT only as a fallback, resolves the protected
secret reference only for the exact MCP child, and binds the default read-only
toolset to `PSB-AI-002` dependency and `PSB-AI-004` runtime ownership. Live IDE
secret storage and process inheritance evidence remain `NOT_CHECKED`.

GitHub Organization governance is implemented as `PSB-SOURCE-006`. Its E3
provider-neutral contract binds a complete fresh secret-free snapshot to one
stable organization and exact policy bytes; evaluates SSO／provisioning,
bounded Owners, member／team／outside-collaborator access, restrictive
repository defaults, Organization Actions policy, installed applications,
repository security-configuration coverage, and independent audit／drift／alert
health; and returns `ERROR` for stale, partial, malformed, count-mismatched,
secret-bearing, or adapter-failure evidence. Live GitHub and IdP collectors,
hosted enforcement, and remediation remain organization adoption work.

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
SBOM product/artifact identity, signer status, and quarantine are implemented
as `PSB-REL-004`.
Exact release-artifact signing generation is implemented as `PSB-REL-005` with
an offline E3 contract for immutable subject identity, five-minute exact
authorization, active non-exportable sign-only signer state, cryptographic
statement binding, immutable publication, transparency receipt, and release
failure blocking. Live KMS／HSM／keyless, OIDC, transparency, and publication
adoption remains organization evidence.

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
  cascading-failure controls;
- application-facing AI gateway enforcement for approved providers, workload
  identity, exact destination, data classification, minimization, PII and
  secret egress policy, fail-closed routing, and sanitized telemetry;
- AI model, dataset, AIBOM or ML-BOM, serialized-weight, and RAG corpus
  provenance with integrity verification, safe loading, quarantine, and
  poisoning tests. The model／dataset acquisition subset is implemented as
  `PSB-DEPS-005`; RAG corpus authorization, retrieval isolation, provenance,
  revocation, and an inert poisoning case are implemented as `PSB-AI-011`;
  live connectors, vector stores, deletion propagation, and semantic poisoning
  remain follow-on evidence;
- threat-model-driven AI TEVV and red-team release gates with pinned test
  suites, deterministic scenarios, result health, and scanner failures kept
  distinct from clean results — the provider-neutral E3 evidence contract is
  implemented as `PSB-DETECT-002`; live model, external judge, red-team, runner,
  and production release-gate adoption remain follow-on evidence;
- rogue-agent stop, kill-switch, bounded fallback, recovery, and AI incident
  evidence that cannot be disabled by model or repository content.

Add AI framework registries together with the first controls that can produce
evidence for them:

- OWASP Top 10 for Agentic Applications 2026 as a coarse agentic risk taxonomy
  — implemented with all `ASI01..ASI10` identifiers and reviewed mappings for
  `PSB-AI-001..011`, the GitHub MCP slice in `PSB-SOURCE-004`, and the
  threat-derived release-gate slice in `PSB-DETECT-002`;
- OWASP AISVS 1.0 as the detailed AI-specific verification requirement
  framework — implemented with the complete 191-requirement locked release
  inventory, immutable source identity, reviewed atomic mappings to existing
  AI controls, and a generated coverage profile that preserves unmapped
  requirements as gaps without claiming an AISVS level;
- NIST SP 800-218A as the AI-specific SSDF community profile;
- NIST AI RMF 1.0 and NIST AI 600-1 for governance, measurement, and
  generative-AI risk management;
- OWASP Top 10 for LLM Applications 2025 as a coarse secondary risk taxonomy.

Keep the roles separate: AISVS supplies AI-specific testable requirements,
SP 800-218A supplies lifecycle practices, AI RMF and AI 600-1 supply
risk-management outcomes, OWASP LLM and Agentic Top 10 classify broad risks,
and MITRE ATLAS classifies attacker behavior. None of these
mappings alone proves that an AI system is secure. Track revisions to AI RMF
and agentic-AI guidance, and do not pin drafts or unstable identifiers into
controls. The released OWASP Agentic `2026` baseline is no longer tracked as a
draft; a future revision still requires explicit registry and mapping review.

## Phase 6 — Governance and generated views

Add:

- exception expiry;
- metrics;
- adoption profiles;
- generated framework indexes;
- control maturity dashboard — implemented as generated catalog-governance
  CSV, Markdown, and XLSX views;
- repository template documentation.

SBOM impact search and evidence-first supply-chain incident response planning is
implemented as `PSB-GOV-001`, including a normalized read-only
Dependency-Track exact CVE/PURL portfolio adapter that requires complete
pagination and links project UUID/version and SBOM serials back to build
evidence.

Time-bound exception governance is implemented as `PSB-GOV-002`. Its shared
YAML contract binds exact control/check and target scope to independent roles,
risk, compensation, approval, remediation, and expiry. A complete fresh
SHA-256-bound register derives active, expiring, expired, and invalid views;
missing, stale, unsafe, or tampered evidence remains `ERROR`.

Catalog governance and maturity views are implemented without adding a
documentation-only control. The generated views count reference status,
evidence level, verification type, mapping debt, and assessment adapters per
control. Organization adoption, evidence freshness, and `PSB-GOV-002`
exception debt remain explicit `NOT_CHECKED` fields until organization-owned
input is supplied; repository `E3` fixtures are never promoted into live
adoption or maturity claims.

Add product-vulnerability response capabilities that compose the existing
impact lookup with CISA KEV, CVSS v4.0, and FIRST PSIRT guidance. The first
executable boundary is implemented as `PSB-GOV-003`, with exact scanner and
product-impact identity, integrity-bound offline KEV and CVSS evidence,
policy-derived priority and deadlines, accountable case routing, and
`PSB-GOV-002` exception composition. The broader FIRST maturity and service
inventory remains a separate organization-owned assessment profile so
repository fixtures cannot claim that a live PSIRT is mature.

Supply-chain credential exposure containment and rotation assurance is
implemented as `PSB-GOV-004`. It composes `PSB-SOURCE-003`, `PSB-SOURCE-004`, and
`PSB-GOV-001` rather than duplicating exposure detection, ordinary credential
lifecycle, or artifact-impact lookup. The control must cover source, CI,
package-publishing, registry, cloud-deployment, SSH, and signing credentials;
distinguish revocation, replacement, session invalidation, signer distrust,
and short-lived-token response; verify that old authority is denied after all
known consumers migrate; and keep incomplete inventory or provider failure
distinct from successful rotation. Its E3 slice is provider-neutral,
secret-free, authorization-gated, and dry-run; it verifies reusable bearer,
signer, and short-lived-session response paths while live mutation remains
`NOT_CHECKED` until provider adapters are reviewed.

Deployed-artifact refresh closure is implemented as `PSB-GOV-005`. It composes
`PSB-GOV-001`, `PSB-GOV-003`, build／release integrity, registry lifecycle, and
container admission evidence to connect an exact active digest and current risk
to an owned deadline, clean rebuild, immutable replacement, admission across
the original target scope, and independent proof that the old digest is no
longer active. `NOT_AFFECTED`, `IN_PROGRESS`, `OVERDUE`, `REMEDIATED`, semantic
`FINDING`, and evidence `ERROR` remain distinct. Live provider adapters remain
organization evidence.

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
   does not become a documentation-only control. The source-preserving
   CSV／XLSX importer, exact manifest, reconciliation contract, private-row
   redaction, deterministic profile generation, and fail-closed negative tests
   are implemented; the actual organization source remains `INPUT_REQUIRED`.
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
   revocation, and audit evidence — implemented. GitHub MCP adds OAuth-first,
   dedicated fine-grained PAT fallback, child-only secret delivery, default
   read-only toolsets, and explicit AI-002/004 ownership with live endpoint
   adoption left `NOT_CHECKED`.
3. `PSB-CICD-004` — explicit least-privilege workflow and job permissions,
   rejecting broad write scopes — implemented as a configuration-first
   reference with workflow deny-all, job-operation permission review, OIDC
   scoping, trusted-ref conditions, protected-environment requirements, shared
   `PSB-CICD-003` static analysis, and formal live manual verification.
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
9. `PSB-GOV-004` — supply-chain credential exposure containment and rotation
   assurance — implemented at E3. It correlates a
   secret-free credential inventory with source, CI, package, registry, cloud,
   SSH, signing, release, artifact, and deployment evidence; require
   credential-class-specific containment; migrate every known consumer; and
   independently proves old-authority denial before closure. Live provider
   mutation remains `NOT_CHECKED`.
10. `PSB-GOV-005` — deployed artifact freshness, bounded clean rebuild,
    replacement admission, and old-digest removal closure — implemented at E3
    with exact inventory and evidence identity, policy-derived deadlines,
    distinct lifecycle states, sanitized output, and fail-closed negative
    fixtures. Live scanner／build／registry／cluster adapters remain external.
11. `PSB-CICD-008` — privileged CI/CD control-plane change assurance —
    implemented at E3 with named phishing-resistant administrator sessions,
    exact before-after policy identity, independent approval, provider audit
    correlation, bounded emergency review, complete cross-service inventory,
    and fail-closed evidence handling. GitHub environment and runner-group
    fragments plus the AWS IAM workload-trust fragment are implemented with
    stable provider identities and current-state joins. AWS ECR repository
    access-policy changes are also implemented with repository-generation
    binding. AWS KMS signing-key policy changes now bind `PutKeyPolicy`, stable
    Key ID／ARN, signing purpose, current policy, and reviewed human session
    while rejecting the lockout-safety bypass. GitHub repository and
    organization branch／tag ruleset updates now bind stable source／ruleset IDs
    and exact before／after history versions. Repository-scoped push updates
    additionally bind a private／internal root and complete fork-network digest;
    legacy branch force-push, deletion, administrator-enforcement, and CODEOWNER-review updates now bind the
    audit action to stable repository／branch identity and current protection state. Other legacy
    branch settings, create／delete／organization-wide push rulesets,
    CI／registry, Azure, GCP, and non-policy
    signing operations remain external.
12. `PSB-SOURCE-006` — GitHub Organization governance — implemented at E3
    with stable-ID complete inventory, policy-digest binding, SSO／provisioning,
    Owner and collaborator review, restrictive repository defaults,
    Organization Actions and App policy, complete security-configuration
    coverage, independent audit／drift／alert health, and fail-closed evidence.
    Live GitHub／IdP collection and mutation remain external adoption work.

### P2 — Exposure reduction and release completeness

1. `PSB-CODE-004` — injection prevention using parameterization and
   context-specific output handling.
2. `PSB-CODE-005` — Unicode source deception prevention — implemented at E3
   for Python with an integrity-bound escaped fixture, explicit bidi／invisible／
   tag policy, ASCII and NFKC-stable identifier checks, sanitized evidence, and
   fail-closed UTF-8／syntax／policy handling. Other language tokenizers and live
   repository enforcement remain follow-on work.
3. `PSB-SOURCE-003` — public repository exposure review, repository-scoped
   GitHub dorking scenarios, current/history secret detection, non-code surface
   evidence, and credential-first remediation — implemented ahead of the
   remaining P2 backlog.
4. `PSB-DEPS-004` — implemented at E3 with exact base-to-head graph delta,
   direct/transitive edge context, source, vulnerability, license, provenance,
   non-author approval, expiring exception, and fail-closed advisory evidence.
5. `PSB-CICD-006` — short-lived, audience-bound OIDC federation without stored
   cloud credentials — implemented at E3 with signed JWT, immutable repository
   identity, exact audience/context/reusable-workflow claims, replay rejection,
   stored-secret inventory, and bounded exchange receipt fixtures.
6. `PSB-REL-003` — SBOM generation, artifact binding, publication,
   completeness checks, consumer-side mismatch handling, and fail-closed
   Dependency-Track processing — implemented with nine atomic checks,
   positive and negative fixtures, distinct source/build/deployment
   observations, runtime error states, and Golden Path plus `PSB-GOV-001`
   composition.
7. `PSB-REL-004` — signed supplier SBOM product/artifact identity, signer
   lifecycle, revocation freshness, schema validation, and quarantine —
   implemented with eight atomic checks, positive and negative signed
   fixtures, least-privilege project binding, and distinct quarantine versus
   verification-error states.
8. `PSB-REL-005` — exact release-artifact signing generation — implemented at
   E3 with immutable artifact／release／source identity, short-lived scoped
   authorization, active non-exportable sign-only signer policy, signed
   cross-object binding, immutable publication／transparency receipt, and
   fail-closed release gating. Live KMS／HSM／keyless adapters remain external
   evidence; this is not a SLSA Build level mapping.
9. `PSB-CONTAINER-001` — immutable image digests, non-root execution, minimal
   capabilities, admission-policy verification, and a follow-on composition
   that applies existing `PSB-REL-001` SLSA provenance verification to the
   exact admitted OCI manifest digest — implemented with API-native Kubernetes
   fixtures, nine atomic admission checks, default-deny network policy,
   platform PID and fail-closed evidence, and actual `PSB-REL-001` verifier
   composition.
10. `PSB-CONTAINER-002` — registry transport, repository-scoped authorization,
   short-lived identity, immutable release protection, audit, and image
   lifecycle enforcement — implemented with seven atomic checks, positive and
   negative provider-neutral fixtures, operation-to-audit correlation,
   protected-tag history, and distinct evidence `ERROR` states.
11. `PSB-CONTAINER-003` — minimal patched container hosts, protected daemon and
   runtime sockets, user and kernel isolation, management restriction, and
   host audit policy — implemented with nine atomic checks, protected-path
   integrity, hardware-backed node trust, time-bound isolation exceptions, and
   distinct `PASS`, `FAIL`, `NOT_CHECKED`, and `ERROR` outcomes.
12. `PSB-CONTAINER-004` — implemented at E3 with workload-bound Falco and
   Sysdig event adapters, six behavior categories, sensor/drop/sequence health,
   alert delivery failure handling, sanitized evidence, and
   authorization-bound response handoff. Live privileged sensor deployment
   remains provider-specific follow-on work extending `PSB-CONTAINER-003`.
13. `PSB-GOV-002` — implemented at E3 with exact cataloged control/check and
    target scope, distinct owner/risk-reviewer/approver roles, bounded expiry,
    compensating controls, approval and remediation tickets, complete
    SHA-256-bound register evidence, sanitized output, and distinct active,
    expiring, expired, invalid, and `ERROR` outcomes.
14. `PSB-GOV-003` — exact product-vulnerability triage that combines validated
    CVSS v4 vectors, fresh complete CISA KEV evidence, product/artifact/
    deployment applicability, accountable PSIRT ownership, and policy-bound
    remediation priority without treating source failure as low risk —
    implemented at E3 with listed, not-listed, not-applicable, risk-accepted,
    governance-failure, and evidence-`ERROR` fixtures.
15. `PSB-DETECT-003` — external attack-surface discovery and ownership
    reconciliation — implemented at E3 with verified domain roots, complete
    fresh Certificate Transparency／public DNS／HTTPS metadata observations,
    owned-name／delegated-service／shared-infrastructure attribution, exact
    owner and exposure decisions, unknown／unexpected／expired／reappeared
    findings, sanitized evidence, and fail-closed source health. Live provider
    collectors, arbitrary IP／port discovery, credential validation, intrusive
    probes, and organization adoption remain external evidence.

### P3 — Extended application and AI development security

1. Split the reviewed application checklist remainder into executable controls
   for cryptography, file upload, SSRF, logging, and error handling. Assign IDs
   only after source-row reconciliation to avoid premature or duplicate control
   boundaries.
2. `PSB-AI-001` — implemented at E3 with SHA-256-bound repository AGENTS,
   repository-owned Project CodeGuard profile, semantic review and experiment
   procedure; an identical-condition 4-task x 2-repetition paired benchmark;
   separate security, task-success, and false-block metrics; mutable downgrade,
   tamper, incomplete, unavailable, regression, and sensitive-evidence negative
   tests; and a synthetic-only `PILOT` / live `NOT_CHECKED` claim boundary.
3. `PSB-AI-002` — implemented at E3 with five synthetic Skill, MCP server,
   plugin, and external-prompt dependency records; exact HTTPS source commit
   and artifact digest; license, owner, independent semantic review, expiry,
   dependency-specific capability allow-lists, identity-bound PSB-AI-001
   benchmark results, fresh complete revocation evidence, and exact PSB-AI-004
   runtime handoff. GitHub official MCP authentication guidance is reconciled
   through `PSB-SOURCE-004`, while live publisher identity, remote MCP
   deployment attestation, mirror retention, and revocation collectors remain
   deployment evidence.
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
5. `PSB-AI-003` — implemented at E3 with six inert repository-document,
   issue, Web, API, tool-output, and direct-prompt fixtures; exact source and
   AI-001／002／004 policy identity binding; five denied action classes;
   root-goal and trust preservation; pre-action redacted audit; legitimate
   task continuation; and distinct `FAIL`, evidence `ERROR`, and live
   `NOT_CHECKED` outcomes.
6. `PSB-AI-005` — implemented at E3 with source-bound write admission,
   classification, poisoned and sensitive-data exclusion, actual byte and TTL
   limits, exact user／session／task isolation, cross-scope retrieval denial,
   bounded payload deletion and tombstones, sanitized fail-closed evidence,
   and a provider-managed memory `NOT_CHECKED` boundary.
7. `PSB-AI-006` — implemented at E3 with strict proposal and result schemas,
   canonical request identity, independent action and resource policy,
   exact AI-004 authorization and execution binding, single dispatch and
   replay denial, uncertain-outcome quarantine, sanitized evidence, and a
   provider／gateway／backend `NOT_CHECKED` boundary.
8. `PSB-AI-007` — implemented at E3 with exact AI-004 telemetry binding,
   per-session token, integer cost, duration, tool, high-impact action, retry,
   recursion and anomaly limits, warning read-only restriction, hard circuit
   breaking, verified alert receipts, evidence `ERROR`, and live provider／
   billing／gateway／receiver `NOT_CHECKED` boundaries.
9. `PSB-AI-008` — implemented at E3 with exact AI-004／006／007 and parent
   request bindings, Ed25519 agent and response identities, explicit
   sender-recipient edge, capability／tenant／resource／classification／budget
   ceilings, freshness, replay, one-hop, credential-free isolation, and
   fail-closed evidence. Live key custody, transport, atomic ledgers,
   concurrent fan-out, provider isolation, and recovery remain `NOT_CHECKED`.
10. `PSB-AI-009` — implemented at E3 with an out-of-band control plane,
    AI-007／008 trigger binding, signed exact-session containment, model／tool／
    delegation／memory stop, distributed authority revocation, evidence-first
    quarantine, model-free bounded fallback, root-cause and replay readiness,
    independent dual-control recovery, and a new-identity read-only canary.
    Live gateways, key custody, distributed revocation, process termination,
    SIEM and incident workflow remain `NOT_CHECKED`.
11. `PSB-AI-010` — implemented at E3 with a signed five-minute application
    workload identity, mandatory HTTPS gateway, exact provider／model／tenant／
    region／training／retention tuple, classification, minimization, local
    redaction, prohibited-class denial, bypass detection, content-free audit,
    and fail-closed health. Live application egress, IdP, provider contract,
    response and non-text filtering, and telemetry remain `NOT_CHECKED`.
12. Use the OWASP Agentic Top 10 registry as the risk-coverage view for these
    slices: `ASI01`, `ASI03`, `ASI04`, `ASI06`, `ASI07`, `ASI08`, and a bounded
    subset of `ASI09` are now implemented-partial through PSB-AI-003／011,
    PSB-SOURCE-004／PSB-AI-004／010, PSB-AI-001／002／004／011,
    PSB-AI-005／011, PSB-AI-008, PSB-AI-007／008／009, and PSB-AI-006
    respectively. `PSB-DETECT-002` adds release-gate scenario evidence for
    bounded subsets of `ASI01`, `ASI02`, `ASI05`, `ASI06`, and `ASI08` without
    converting one synthetic test into complete category coverage. `ASI10` is
    implemented-partial by `PSB-AI-009`; fleet-wide kill, distributed rollback,
    concurrent containment and full-authority recovery remain gaps. Multi-agent
    concurrency remains an `ASI08` gap and human decision quality remains an `ASI09` gap. Do
    not mark an entire risk category covered from one control or roadmap text
    alone.
13. `PSB-DEPS-005` — implemented at E3 with immutable model／dataset source and
    exact bytes, CycloneDX 1.7 ML-BOM relationships, Safetensors-only
    non-executing structural inspection, pinned loader handoff, signed
    exact-material inspection, current signer lifecycle, dataset license／use
    authorization, quarantine, exact staging deployment handoff, and distinct
    evidence `ERROR`. Live registry／HSM／scanner／dataset governance evidence and
    semantic model or data poisoning detection remain `NOT_CHECKED`.
14. `PSB-AI-011` — implemented at E3 with source ownership and authorization,
    exact source／chunk／snapshot integrity, `PSB-DEPS-005` embedding-model
    binding, pre-embedding poisoned-source quarantine, tenant／classification
    scope at ingestion and retrieval, exact scenario result sets, result-level
    provenance, and bounded revocation／deletion／retrieval denial. Live source
    connectors／parsers／embedding services／vector stores／caches／replicas and
    semantic-poisoning detection remain `NOT_CHECKED`.
15. `PSB-DETECT-002` — implemented at E3 with exact release candidate and
    DEPS-005／AI-003／004／010／011 bindings, immutable synthetic evaluator and
    reviewed scenario suite, six inert threat-derived cases, separate
    deterministic and five-run probabilistic decisions, independently owned
    current thresholds, known-safe／known-vulnerable calibration,
    credential-free network-free execution, sanitized evidence, and exact
    release-decision binding. `FAIL`, `INCOMPLETE`, and `ERROR` cannot produce
    release permission. Live model／provider／judge／red-team／runner／production
    gate evidence remains `NOT_CHECKED`.
16. Reconcile the seven-layer product-security and AI portfolio view from
    [`REF-AI-003`](SECURITY_GUIDANCE_SOURCES.md#ref-ai-003). Existing controls
    retain their current domain ownership. Treat live RAG and TEVV adapters as
    adoption evidence for `PSB-AI-011` and `PSB-DETECT-002`. Extend the AI
    application gateway and rogue-agent containment only with live enforcement,
    fleet recovery and incident-system evidence.
    Keep AI governance, training, security champions, KPI targets, PSIRT
    capability, and customer assurance as organization-owned profiles rather
    than documentation-only technical controls.
17. The pinned GitHub guidance registry includes the reviewed administration
    subset for repository／organization Actions policy, CODEOWNERS, rulesets,
    SAML／SCIM, audit events, and credential types. `PSB-SOURCE-006` now maps
    the unique Organization posture, access-review, Actions／App,
    repository-coverage, and monitoring boundary to that registry.
    Reconcile デジタル庁 DS-202 and NSA／CISA CI/CD guidance as
    tool-independent design sources, not compliance frameworks. DS-202 and its
    GitHub Actions／Terraform appendix have official PDF SHA-256 values;
    NSA／CISA Version 1.0 remains artifact-integrity `input-required` because
    the official endpoint did not permit automated byte retrieval. Keep the
    FLATT organization-monitoring presentation non-normative, Allstar
    unadopted, and Checkov's GitHub configuration policies rejected until a
    unique executable gap is demonstrated.
18. Adopt the pinned SITF `1.0.0` technique library as a threat-taxonomy
    coverage profile, not a compliance framework. Reconcile every one of the
    81 endpoint／VCS／CI/CD／registry／production techniques to exact checks or an
    owned gap, generate four synthetic cross-component attack flows, and fail
    closed on incomplete inventory or stale references. `PSB-CODE-005` now
    closes the Python-source Unicode stealth slice with exact bidi, invisible,
    identifier, normalization, and fail-closed checks. `PSB-CICD-009` now
    closes action cache poisoning through signed provenance, exact trust and
    producer identities, byte／path／lifetime binding, and fail-closed restore.
    `PSB-SOURCE-005` now closes the VCS mass-deletion slice through stable-ID
    inventory, bounded destructive actions, attacker-separated retained recovery
    copies, and exact isolated full-scope restore drills; audit and containment
    compose from their owning controls.
    Prioritize remaining endpoint／CI／registry／production destructive recovery,
    exfiltration, malicious service provisioning, and sensor／agent poisoning
    gaps in later vertical slices.

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
- CIS Software Supply Chain Security provider profiles. The official discovery
  page listed CIS GitHub Benchmark `1.2.0` and CIS GitLab Benchmark `1.0.1` on
  `2026-08-04`; both remain `input-required` until authorized official PDFs,
  SHA-256 values, recommendation inventories, and reuse terms are reviewed.
  The general 2022 Guide and provider Benchmarks must not be treated as
  interchangeable, and only unique automatable checks beyond existing GitHub,
  SSDF, SLSA, and OSPS coverage may be added;
- NIST SP 800-204D final, February 2024, as cross-control integration guidance
  for developer environment, SCM, build, repository, evidence, commit, and
  CD/GitOps trust boundaries — implemented as a validated 12-row reconciliation
  with exact current check evidence and explicit planned, gap, and out-of-scope
  dispositions. The CSV, Markdown, and `SSC Integration` XLSX sheet are generated
  from one reviewed policy source. This remains a reconciliation view rather
  than a duplicate framework registry; exact SSDF mappings continue to use the
  existing `nist-ssdf` registry;
- Wiz Research SITF `1.0.0` at immutable commit
  `d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59` as a threat-taxonomy coverage
  profile — implemented with an integrity-recorded 81-technique registry,
  complete reconciliation, synthetic attack flows, generated views, and
  fail-closed tests. The upstream license metadata inconsistency is recorded,
  the Japanese lecture companion remains non-normative, and no compliance or
  complete-mitigation claim is inferred;
- FIRST PSIRT Services Framework 1.1 and the PSIRT Maturity Document as sources
  for an organization-owned capability profile after `PSB-GOV-003` — the
  integrity-recorded source, 31-service inventory, 18-row cumulative profile,
  CSV／Markdown, and workbook sheets are implemented. Missing live evidence
  remains `NOT_CHECKED` and no maturity level is inferred from repository
  fixtures;
- FIRST CVSS v4.0 specification revision 1.2 and the live CISA KEV catalog as
  data semantics for `PSB-GOV-003`, not as compliance frameworks;
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
