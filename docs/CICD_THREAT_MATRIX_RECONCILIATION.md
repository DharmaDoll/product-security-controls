# CI/CD Threat Matrix Reconciliation

## Purpose and boundary

This document reconciles the community
[Common Threat Matrix for CI/CD Pipeline](SECURITY_GUIDANCE_SOURCES.md#ref-cicd-011)
with this repository's threat model, implemented controls, and planned work.
It is a design and backlog aid, not a formal framework assessment.

The reviewed source snapshot is
[`rung/threat-matrix-cicd` README at
`6740b16ac8066116c24c3e95eefdc317f9790b04`](https://github.com/rung/threat-matrix-cicd/blob/6740b16ac8066116c24c3e95eefdc317f9790b04/README.md),
dated `2026-05-31`. It describes itself as ATT&CK-like, but it is not MITRE
ATT&CK. The source has no stable technique identifiers or versioned release.
The row numbers below are local review aids only and MUST NOT be recorded as
framework mapping identifiers in `control.yaml`.

The source repeats some technique labels under more than one tactic. This
review consolidates those repetitions into 28 unique labels while retaining
all tactic occurrences.

## Authoritative and public-sector source cross-check

The 28 rows below remain keyed only to the pinned community matrix. Two
public-sector sources are used as independent design cross-checks and do not
lend their headings or recommendation numbers to `control.yaml`:

- [`REF-CICD-015`](SECURITY_GUIDANCE_SOURCES.md#ref-cicd-015) — デジタル庁
  DS-202, including the integrity-recorded GitHub Actions／Terraform appendix;
- [`REF-CICD-016`](SECURITY_GUIDANCE_SOURCES.md#ref-cicd-016) — NSA／CISA
  *Defending Continuous Integration/Continuous Delivery Environments*, June
  2023, Version 1.0. Its official PDF digest remains `input-required`, so it is
  reviewed guidance rather than an artifact-backed mapping source.

| Cross-check theme | Existing evidence and owner | Remaining boundary |
|---|---|---|
| Developer and administrator identity | `PSB-SOURCE-001`, `PSB-SOURCE-004`, and `PSB-CICD-008` address endpoint state, credential lifecycle, named administrators, bounded sessions, and privileged-change evidence. | Live GitHub SAML／SCIM enforcement, credential authorization, deprovisioning, and IdP recovery evidence remain organization-owned and provider-specific. |
| Repository, branch, workflow-definition, and two-person change protection | `PSB-CICD-005` separates untrusted PR execution; `PSB-CICD-008` collects branch／tag／push ruleset and selected legacy branch changes. | Current CODEOWNERS coverage, required code-owner review, stale approvals, all ruleset selectors, administrator bypass, and protected workflow paths are not yet verified end to end. |
| Least privilege and separation of duties | `PSB-CICD-004` verifies explicit job-token permissions; `PSB-BUILD-001` separates untrusted build from credentialed deployment; `PSB-CICD-008` requires independent approval for privileged settings. | Organization and enterprise Actions defaults, custom roles, environment approvers, and live privilege inventories require provider evidence. |
| Short-lived credentials, secrets, and federation | `PSB-SOURCE-004`, `PSB-CICD-004..006`, and `PSB-BUILD-001` cover credential lifecycle, token permissions, exact-claim federation, and credential-free untrusted builds. | Live issuer, IdP, secret-manager, cloud authorization, masking, and revocation evidence remain external. |
| Audit logging and control-plane monitoring | `PSB-CICD-008` binds selected provider audit events to exact actor, request, target, and resulting state. | Complete GitHub event coverage, independent retention, organization-wide drift, alert delivery, and provider compromise remain outside local fixtures. |
| Dependency, scanner, and SBOM layers | `PSB-DEPS-001..004`, `PSB-DETECT-001`, and `PSB-REL-003..004` separate acquisition, execution, integrity, review, scanner failure, and SBOM lifecycle evidence. | Unknown malicious-but-valid dependencies, live database freshness, and organization portfolio completeness remain residual risk. |
| Build, artifact authenticity, and release | `PSB-BUILD-001..003` and `PSB-REL-001..005` address containment, platform selection, provenance, consumer verification, publication, lifecycle SBOM, and exact artifact signing. | Live signing authority, provider build assurance, artifact-store policy, and production deployment binding still need provider adapters. |
| Runner, endpoint, network, and runtime boundaries | `PSB-SOURCE-001`, `PSB-CICD-007`, and `PSB-BUILD-001` address managed endpoints, one-job runners, clean images, teardown, egress, and runtime containment. | Live network segmentation, EDR, provider-hosted isolation, telemetry health, and complete fleet inventory remain organization evidence. |

This cross-check confirms that the primary missing GitHub outcomes are hosted
administration evidence rather than another workflow linter. The pinned GitHub
administration collection now records Actions policy, CODEOWNERS, rulesets,
SAML／SCIM, audit-event, and credential references. `REF-CICD-017` supplies
non-normative Japanese operational context, while `REF-CICD-018` records
Allstar only as an unadopted organization-monitoring candidate.

## Disposition rules

- `existing-partial`: one or more implemented controls reduce, detect, or
  verify part of the behavior. It does not mean that the whole technique is
  mitigated.
- `planned`: the primary missing outcome is already named in
  `PLANNED_CONTROLS.md` or `ROADMAP.md`, including an explicitly unreserved
  roadmap gap.
- `gap`: no implemented control or existing plan owns the primary outcome.
  The row names a candidate boundary, but does not reserve a control ID.

The resulting inventory is 17 `existing-partial`, 3 `planned`, and 8 `gap`
rows. Mappings remain provisional until a later control change supplies
executable evidence and follows the normal framework review process.

## Technique reconciliation

| Row | Upstream tactic(s) | Upstream technique label | Disposition | Existing evidence and boundary | Planned owner or explicit gap |
|---|---|---|---|---|---|
| 01 | Initial Access; Execution | Supply Chain Compromise on CI/CD | `existing-partial` | `PSB-CICD-001`, `PSB-DEPS-001..004`, `PSB-BUILD-001..003`, and `PSB-REL-001..003` address immutable Actions, dependency timing/execution/integrity/change review, contained and hosted builds, provenance, consumer verification, and lifecycle SBOM evidence. They do not prove every upstream tool, image, or maintainer trustworthy. | Malicious-but-valid upstream content and ecosystem evidence gaps remain residual risk. |
| 02 | Initial Access | Valid Account of Git Repository (Personal Token, SSH key, Login password, Browser Cookie) | `existing-partial` | `PSB-SOURCE-001` hardens the developer endpoint and `PSB-SOURCE-004` governs source credentials. Hosted-service session policy, network restriction, and organization administrator enforcement remain external evidence. | No new ID; later provider adapters may verify source-platform identity and session controls. |
| 03 | Initial Access | Valid Account of CI/CD Service (Personal Token, Login password, Browser Cookie) | `gap` | `PSB-CICD-004` limits job-token permissions but does not govern human or service access to the CI/CD control plane. | Candidate boundary: CI/CD control-plane identity, phishing-resistant authentication, session policy, access review, and break-glass administration. |
| 04 | Initial Access | Valid Admin account of Server hosting Git Repository | `gap` | Source credentials and endpoints are covered, but self-managed Git server administration is not. | Candidate boundary: Git hosting administration-plane hardening, privileged access, patching, network restriction, and audit. |
| 05 | Execution; Persistence | Modify CI/CD Configuration | `existing-partial` | `PSB-CICD-001..005` verify immutable dependencies, safe interpolation, workflow analysis, least privilege, and untrusted-PR separation. Repository rulesets, CODEOWNERS, and signed-change enforcement still require provider evidence. | Later provider adapters should verify protected workflow paths and administrator bypass behavior. |
| 06 | Execution; Persistence | Inject code to IaC configuration | `existing-partial` | `PSB-IAC-001` provides approved modules, resolved-plan Policy as Code, fail-closed decisions, provider-side enforcement requirements, and drift handling; `PSB-BUILD-001` limits build impact; `PSB-DETECT-001` supplies an integrity-verified scanner interface. Alternate deployment paths and malicious provider execution remain residual risks. | Organization-specific resolved-plan policy and live provider enforcement adapters remain necessary. |
| 07 | Execution; Persistence | Inject code to source code | `existing-partial` | `PSB-CICD-005` keeps untrusted PR code out of privileged execution and `PSB-BUILD-001` contains untrusted builds. Neither control determines whether reviewed source is intentionally malicious. | Code-review governance and application-specific secure-coding controls remain necessary. |
| 08 | Execution; Persistence | Inject bad dependency | `existing-partial` | `PSB-DEPS-001..004` enforce cooldown, install-script denial, frozen resolution, artifact integrity, and focused direct/transitive change review; `PSB-DETECT-001` adds verified vulnerability scanning. They do not establish maintainer intent or vulnerability-free content. | Malicious-but-not-yet-known-vulnerable content remains residual risk. |
| 09 | Execution | SSH to CI/CD pipelines | `existing-partial` | `PSB-CICD-007` denies ordinary interactive runner ingress, separates break-glass authority, and verifies bounded registration evidence. | CI/CD service control-plane administration and live identity enforcement remain provider-specific. |
| 10 | Execution (Production) | Modify the configuration of Production environment | `existing-partial` | `PSB-IAC-001` verifies approved resolved plans, provider enforcement requirements, drift detection, and bounded correction; `PSB-CICD-006` adds an exact-claim and resource-bound deployment identity contract. Direct console/API mutation using stolen production credentials remains outside its local evidence. | Provider-specific live trust, audit, and production authorization still need adapters. |
| 11 | Execution (Production) | Deploy modified applications or server images to production environment | `existing-partial` | `PSB-BUILD-003` creates platform provenance, `PSB-REL-001` verifies artifact identity and provenance, `PSB-REL-002` publishes provenance, and `PSB-CONTAINER-001` binds that verification to the exact OCI digest at admission. | Live cluster and registry adapters plus the unreserved artifact-signing-generation gap remain relevant. |
| 12 | Persistence | Compromise CI/CD Server | `existing-partial` | `PSB-BUILD-001` isolates untrusted builds, `PSB-BUILD-002` requires an approved hosted build platform, and `PSB-CICD-007` verifies runner-specific one-job isolation and teardown. | CI/CD service-control-plane compromise and availability remain residual. |
| 13 | Persistence; Defense Evasion | Implant CI/CD runner images | `existing-partial` | `PSB-CICD-007` requires exact image digests, verified provenance, supported runner versions, clean startup, and image replacement for self-hosted runners. | Live image-signature, version-support, startup-probe, and provider-hosted image adapters remain necessary. |
| 14 | Privilege Escalation | Get credential for Deployment(CD) on CI stage | `existing-partial` | `PSB-BUILD-001` separates untrusted build and credentialed deployment, `PSB-CICD-004` restricts job permissions, and `PSB-CICD-006` verifies signed exact-claim federation plus bounded credential issuance offline. | Provider-specific live trust and issuance evidence remain an adapter boundary. |
| 15 | Privilege Escalation; Lateral Movement | Privileged Escalation and compromise other CI/CD pipeline | `existing-partial` | `PSB-BUILD-001` limits credentials, egress, and build privilege, `PSB-CICD-004` minimizes workflow permissions, and `PSB-CICD-007` verifies exact runner scope, internal-network denial, and no underlying host reuse. | Provider tenant isolation and live cross-fleet segmentation evidence remain necessary. |
| 16 | Defense Evasion | Add Approver using Admin permission | `gap` | Current workflow controls do not govern who may administer approvers, rulesets, or protected environments. | Candidate boundary: privileged repository administration and approver lifecycle with independent, auditable review. |
| 17 | Defense Evasion | Bypass Review | `gap` | `PSB-CICD-005` rejects unsafe trust elevation inside a workflow, but it does not verify branch protection, administrator bypass, stale approvals, or deployment approval policy. | Candidate boundary: protected-change and deployment-review enforcement, including administrator and emergency bypass evidence. |
| 18 | Defense Evasion | Access to Secret Manager from CI/CD kicked by different repository | `existing-partial` | `PSB-CICD-006` rejects signed wrong-repository and fork tokens using exact repository ID, workflow, environment, subject, audience, and resource-bound authorization fixtures. | A live provider trust-policy and audit adapter is still required before production adoption. |
| 19 | Defense Evasion | Modify Caches of CI/CD | `existing-partial` | `PSB-CICD-005` rejects shared untrusted-PR cache and artifact promotion paths. Cache namespace, provenance, lifetime, restore-key breadth, and cross-workflow poisoning are not comprehensively verified. | Extend only after a distinct cache-integrity outcome and fixtures are defined. |
| 20 | Credential Access | Dumping Env Variables in CI/CD | `existing-partial` | `PSB-BUILD-001` keeps credentials out of untrusted builds, `PSB-CICD-004` reduces token privilege, and `PSB-SOURCE-002` blocks secret material before commit. Credentialed-job log redaction and runtime secret access remain outside current evidence. | Provider-specific masking, secretless execution, and runtime detection may require a later control. |
| 21 | Credential Access | Access to Cloud Metadata | `existing-partial` | `PSB-CICD-007` requires policy and in-namespace probes to deny IPv4 and IPv6 metadata paths, while `PSB-BUILD-001` provides job-level default-deny egress. | Platform-specific live firewall and metadata adapters remain necessary. |
| 22 | Credential Access | Read credentials file | `existing-partial` | `PSB-BUILD-001` requires credential-free untrusted builds and a read-only root, `PSB-CICD-007` rejects host, cloud, and SSH credential state at runner startup, and `PSB-SOURCE-001` plus `PSB-SOURCE-004` protect developer credentials. | Credentialed-job secret mounts and provider masking remain outside this runner evidence slice. |
| 23 | Credential Access | Get credential from CI/CD Admin Console | `gap` | No implemented control verifies secret visibility, export, or audit behavior in a CI/CD administration console. | Candidate boundary: CI/CD secret-administration least privilege, dual control, redaction, export prevention, and access logs. |
| 24 | Lateral Movement | Exploitation of Remote Services | `existing-partial` | `PSB-BUILD-001` constrains job egress and privilege, while `PSB-CICD-007` denies ordinary management ingress, management-network reachability, internal-network access, and host runtime sockets. | Live segmentation and CI service-control-plane remote-service evidence remain provider-specific. |
| 25 | Lateral Movement | (Monorepo) Get credential of different folder's context | `gap` | Current controls do not verify path-scoped workflow authorization, secret contexts, or deployment identities inside a monorepo. | Candidate boundary: monorepo path ownership and per-component secret, environment, workflow, and deployment isolation. |
| 26 | Exfiltration | Exfiltrate data in Production environment | `gap` | Build credential separation reduces one entry path, but production data authorization, egress, audit, and abnormal-volume detection are not implemented. | Candidate boundary belongs at the application/cloud data plane; `PSB-CICD-006` can reduce deployment-identity exposure but cannot own production data loss prevention. |
| 27 | Exfiltration | Clone Git Repositories | `existing-partial` | `PSB-SOURCE-004` minimizes source credential scope and lifetime and `PSB-SOURCE-001` protects endpoints. Repository network restriction, bulk-clone detection, rate limits, and read-access audit are provider responsibilities. | Add a provider adapter only when it can produce deterministic read-access and bulk-export evidence. |
| 28 | Impact | Denial of Services | `gap` | Existing resource limits for other domains do not verify CI concurrency, quota exhaustion, costly workflow abuse, runner starvation, or production deployment DoS. | Candidate boundary: CI/CD availability and cost-abuse guardrails with quotas, concurrency policy, cancellation, rate limits, and alert evidence. |

## Use in future planning

When a gap is promoted into a control plan:

1. define a product-security-domain outcome rather than copying an upstream
   technique label;
2. identify insecure and secure behavior plus failure-state evidence;
3. reserve a control ID only after overlap with the controls above is resolved;
4. keep this source as guidance provenance, not a formal framework mapping;
5. update the row disposition only after tests and control metadata exist.

Scanner or telemetry adoption must continue to distinguish a clean result from
an execution or collection failure. No row authorizes a new dependency merely
because the upstream source recommends a tool or mitigation.
