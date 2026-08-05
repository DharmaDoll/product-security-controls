# Threat Model

## Protected assets

- product source code;
- application data and trust boundaries;
- build and release pipelines;
- dependency graph;
- artifacts and container images;
- signing and cloud identities;
- developer environments;
- security policies and exceptions;
- AI agent execution context;
- customer and consumer trust.

## Threat categories

### Product implementation threats

- injection;
- broken authentication;
- broken authorization;
- insecure cryptography;
- secret exposure;
- unsafe file and command handling;
- insecure defaults;
- missing logging and response capability.

### Software supply-chain threats

- malicious dependencies;
- compromised maintainers;
- typosquatting;
- dependency confusion;
- direct or transitive dependency graph changes hiding a new package, source,
  edge, known vulnerability, incompatible license, or provenance gap;
- partial, stale, malformed, or unavailable dependency advisory evidence being
  interpreted as a risk-free change;
- dependency authors self-approving changes or using broad permanent
  exceptions that suppress unrelated future findings;
- package-manager configuration drift or direct fallback bypassing a managed
  registry proxy and its blocking, tracking, and notification controls;
- mutable workflow dependencies;
- compromised build service;
- artifact substitution;
- poisoned scanner database;
- compromised or substituted security scanner release;
- scanner timeout, missing database, or malformed evidence being interpreted
  as a clean security result;
- scanner evidence copying matched credentials into CI logs or artifacts;
- unverified external downloads.

### Public source and information exposure threats

- GitHub dorking against public repositories, code, issues, wikis, and commit
  history to discover internal information;
- accidental exposure of secrets, tokens, internal hostnames, customer data,
  architecture details, or security tooling configuration;
- repository forks, cached copies, and deleted-content remnants preserving
  information after the source repository is corrected;
- over-broad repository visibility, search indexing, or organization
  membership exposing content outside the intended trust boundary.

### Developer endpoint threats

- stolen or unattended developer devices exposing source code, tokens, SSH
  keys, cached credentials, or local build artifacts;
- phishing, infostealers, malicious extensions, or local compromise obtaining
  broad GitHub OAuth tokens, classic or fine-grained PATs, cloud credentials,
  SSH keys, or source-platform application grants;
- unbounded, unowned, or unreviewed source credentials preserving access after
  task completion, role change, offboarding, device loss, or known exposure;
- malware, malicious browser extensions, or untrusted packages executing with
  developer privileges;
- missing OS and tool security updates enabling local privilege escalation or
  credential theft;
- excessive local administrator, container, filesystem, or network access;
- insecure local services, debug ports, copied production data, or weakly
  protected backups crossing the development trust boundary;
- AI agents, Skills, MCP servers, or editor integrations accessing credentials
  and files beyond the task's intended scope.
- a GitHub PAT persisted in IDE JSON, a shell profile, a dotenv file, or the
  parent IDE environment becoming ambient authority for unrelated extensions
  and child processes, while an all-tool MCP turns credential theft or prompt
  injection into repository mutation;

Developer awareness is not a sufficient trust boundary. Endpoint and credential
controls should use centrally enforced engineering guardrails such as MDM,
phishing-resistant authentication, protected credential storage, automatic
blocking, managed isolation, EDR or XDR telemetry, revocation, and auditable
evidence.

### AI-assisted development and agentic threats

- repository instructions, retrieved documents, tool output, or inter-agent
  messages redirecting an agent's goal or multi-step plan;
- legitimate tools being composed or invoked with unsafe targets, parameters,
  identities, or side effects;
- agent identities inheriting broad credentials, delegated trust, or stale
  approval beyond the exact task;
- tampered rules, Skills, MCP servers, plugins, models, or update channels
  entering the agentic supply chain;
- generated code, shell indirection, hook failure, or sandbox bypass causing
  unexpected execution;
- poisoned persistent memory or context changing future decisions;
- unauthenticated, replayed, or over-privileged inter-agent delegation;
- forged or stale agent identities, detached parent tasks, cross-tenant data,
  child-budget amplification, onward delegation, or unbound responses causing
  compromise to propagate across an agent chain;
- failures, false signals, retries, and resource consumption cascading through
  autonomous workflows;
- plausible explanations manipulating a human into approving a harmful action;
- compromised or misaligned agents continuing outside intended goals or stop
  conditions;
- application or developer LLM traffic bypassing an approved gateway and
  sending secrets, PII, source, or regulated data to an unapproved provider,
  region, model, tenant, or retention policy;
- unsigned, mutable, malicious, or unsafe serialized model weights executing
  loader code or entering production without model, dataset, training, and
  fine-tuning provenance;
- poisoned or unauthorized RAG documents entering a knowledge index, crossing
  tenant or classification scope, and later becoming trusted retrieval
  context;
- incomplete, stale, unavailable, or non-reproducible AI TEVV and red-team
  evidence being treated as a clean release decision;
- stop, quarantine, fallback, or recovery controls depending on the same
  compromised model, agent, tool, or mutable policy they are intended to
  contain.

These scenarios align with the OWASP Top 10 for Agentic Applications 2026
risk categories and overlap with more specific MITRE ATLAS attack behaviors.
Neither taxonomy is itself an enforcement boundary or proof of coverage.

`PSB-AI-003` implements the first direct and indirect prompt-injection test
boundary across repository documents, issue text, Web content, API responses,
tool output, and direct prompts. It composes exact PSB-AI-001, PSB-AI-002, and
PSB-AI-004 identities, requires denial before tool execution, and separately
requires legitimate task completion. Its deterministic fixtures do not prove
live model, delayed, multimodal, memory, or multi-agent containment.

`PSB-AI-005` extends this boundary to durable memory. It rejects PSB-AI-003
untrusted content and prohibited data before persistence, preserves exact
user/session/task scope on write and read, bounds payload size and TTL, and
requires expired payload deletion plus a sanitized tombstone. Local fixtures
do not prove provider stores, caches, indexes, replicas, backups, encryption,
residency, or live cross-tenant enforcement.

`PSB-AI-006` owns the boundary between untrusted model output and an external
side effect. It requires strict typed proposals, independent resource and
parameter policy, one canonical request digest across PSB-AI-004 authorization,
decision, execution, and result, single dispatch with replay denial, and
quarantine of uncertain outcomes. Its local fixtures do not prove live agent,
gateway, backend idempotency, application authorization, or rollback behavior.

`PSB-AI-007` adds cumulative single-agent resource and anomaly containment. It
binds PSB-AI-004 telemetry identity, derives token, integer cost, duration,
tool, high-impact action, retry, recursion, unknown-tool, approval-replay, and
hook-failure decisions, and verifies warning restriction, hard circuit
breaking, and alert receipts. Local aggregates do not prove provider billing,
atomic concurrent reservations, tenant or multi-agent budgets, or live alert
response.

Application-facing AI gateways, model and dataset supply-chain integrity,
RAG corpus provenance, AI TEVV release gating, and independent kill-switch and
recovery behavior remain planned boundaries. Coding-agent controls must not be
used as evidence that these broader AI product and operations threats are
covered.

### CI/CD and release threats

- excessive workflow permissions;
- untrusted PR execution;
- credential exfiltration;
- OIDC trust misconfiguration;
- insecure self-hosted runners;
- unsigned or unverifiable releases;
- missing provenance;
- SBOMが別artifact、source tree、または誤ったrelease versionを表す一方で、
  release inventoryとして信頼されること;
- source build deploymentのSBOM observationsが同じserialへ上書きされ、
  source-only viewがrelease authorityになり、commitからartifactとdeploymentへの
  immutable relationshipが失われること;
- direct／transitive component、exact PURL、relationship、completenessの欠落に
  より、vulnerabilityまたはincident impact searchがfalse negativeになること;
- Dependency-Trackのupload受付を分析完了と誤認し、processing failure、
  validation failure、timeout、stale analyzer dataをcleanとして扱うこと;
- auto-created project、broad API key、不完全pagination、project ACL gapにより
  SBOMが誤ったportfolioへ登録されるか、影響製品が検索結果から欠落すること;
- mutable container tags.
- exact artifact digestとactive deploymentの関係が欠落し、稼働中の影響serviceが
  SBOM incident scopeから漏れること;

The
[CI/CD threat-matrix reconciliation](CICD_THREAT_MATRIX_RECONCILIATION.md)
expands this category with 28 unique attacker-behavior labels from a pinned
community source and classifies each as partially addressed, planned, or an
explicit gap. It is a design-time threat inventory, not a formal framework
mapping or a claim of complete coverage.

### Cloud and IaC golden-path threats

- application teams bypassing approved modules and creating unencrypted,
  publicly reachable, mutable-image, or over-privileged infrastructure;
- source-only scanning missing unsafe values introduced by module expansion in
  the resolved plan;
- policy findings, unknown values, missing plans, or scanner failures being
  treated as clean;
- console, API, SDK, or alternate IaC paths bypassing repository CI gates;
- deployed resources drifting from an approved IaC revision;
- broad corrective automation causing outages or destroying investigation
  evidence;
- reusable CI templates claiming planned scanning, SBOM, signing, provenance
  distribution, or OIDC controls as already implemented.

### Security exception governance threats

- wildcard control, check, target, or environment scope suppressing unrelated
  current and future security decisions;
- owners accepting their own risk without independent review and approval;
- temporary exceptions remaining effective after their approved deadline;
- missing, added, stale, partial, or modified exception records being treated
  as an authoritative complete register;
- credentials, source code, or production payloads being copied into approval
  and audit evidence;
- invalid or unavailable exception evidence being interpreted as a clean
  control result rather than preserving the original blocking decision.

These lifecycle threats are implemented by `PSB-GOV-002`. The owning scanner,
dependency, build, release, container, or application control still determines
the domain-specific security failure and applies a valid exception as a
separate decision.

### Product vulnerability response and PSIRT threats

- a stale, partial, malformed, schema-changed, or unavailable CISA KEV feed
  being interpreted as proof that no known exploitation exists;
- absence from KEV or a low CVSS Base score being treated as proof of low risk
  without product applicability, active deployment, exposure, threat, or
  environmental evidence;
- an invalid, duplicate-metric, non-canonical, or untraceable CVSS v4 vector
  driving remediation priority or customer communication;
- a scanner CVE finding being assigned to the wrong product, release,
  artifact, or deployment because component and lifecycle identity are not
  joined to `PSB-GOV-001` evidence;
- vulnerability intake, qualification, analysis, owner assignment,
  remediation, disclosure, or post-incident learning lacking an accountable
  PSIRT service and time-bounded case state;
- repository fixtures or a checklist answer being presented as proof of PSIRT
  maturity, capacity, response timeliness, or stakeholder communication;
- separate CI/CD security checks passing while actor, step, artifact,
  repository, evidence, and deployment identities are not linked across the
  complete software supply chain.

The executable triage subset is implemented by `PSB-GOV-003`, which composes
`PSB-DETECT-001`, `PSB-GOV-001`, and `PSB-GOV-002` with integrity-bound CVSS
and KEV evidence. Organization-wide FIRST PSIRT maturity and service capacity
remain outside repository fixture evidence.

### Container and runtime threats

- vulnerable, malicious, stale, mutable, or untrusted images reaching a
  workload;
- plaintext or ambiguously trusted registry connections exposing credentials,
  manifests, layers, or registry API decisions to interception or redirection;
- anonymous, wildcard, durable, or cross-repository registry authority allowing
  unauthorized pull, push, delete, or administration;
- protected release mutation, incomplete registry audit, or failed lifecycle
  evidence leaving replaced, revoked, or stale images deployable without an
  attributable bounded decision;
- clear-text secrets, unnecessary software, or unsafe configuration embedded
  in an image;
- root, privileged, capability-rich, or privilege-escalating containers
  crossing the workload isolation boundary;
- host namespaces, paths, runtime sockets, or a shared kernel exposing the
  node and neighboring workloads;
- unbounded network access, writable filesystems, or missing resource limits
  increasing persistence, lateral movement, exfiltration, and denial-of-service
  impact;
- admission-policy findings, unknown values, or evaluation failures being
  interpreted as an allow decision;
- post-admission shell, protected-file write, privilege, runtime-socket,
  unexpected network, or resource-abuse behavior escaping detection;
- missing runtime rules, stale signals, event drops, disconnected forwarders,
  or alert-delivery failure being interpreted as an event-free clean result;
- ambiguous runtime event identity causing a detection or response to be
  assigned to the wrong workload or mutable image;
- registry, orchestrator, host OS, runtime, and application responsibilities
  being collapsed into one checklist whose evidence cannot identify the failed
  trust boundary.

The
[container security source allocation](CONTAINER_SECURITY_SOURCE_ALLOCATION.md)
assigns these outcomes across container admission, detection, secure coding,
registry, host, runtime monitoring, and release controls without duplicating
framework or reference-source roles. `PSB-CONTAINER-002` implements the
registry boundary, `PSB-CONTAINER-003` implements the host and daemon boundary,
and `PSB-CONTAINER-004` implements the post-admission runtime detection
boundary. Live provider enforcement remains organization-owned evidence.

### AI-assisted development threats

- poisoned Skills;
- malicious MCP servers;
- prompt/document injection;
- unsafe dependency recommendations;
- security-control removal;
- credential and filesystem overreach;
- hidden network access;
- hallucinated security APIs or packages.

## Threat-to-control relationship

Threats are documented at the repository level and referenced by controls. Controls should not duplicate the entire threat model.

A control may:

- prevent;
- detect;
- verify;
- reduce impact;
- provide evidence;
- support response.

Residual risk must always be stated.
