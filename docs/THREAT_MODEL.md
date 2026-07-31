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

Developer awareness is not a sufficient trust boundary. Endpoint and credential
controls should use centrally enforced engineering guardrails such as MDM,
phishing-resistant authentication, protected credential storage, automatic
blocking, managed isolation, EDR or XDR telemetry, revocation, and auditable
evidence.

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
- direct／transitive component、exact PURL、relationship、completenessの欠落に
  より、vulnerabilityまたはincident impact searchがfalse negativeになること;
- Dependency-Trackのupload受付を分析完了と誤認し、processing failure、
  validation failure、timeout、stale analyzer dataをcleanとして扱うこと;
- auto-created project、broad API key、不完全pagination、project ACL gapにより
  SBOMが誤ったportfolioへ登録されるか、影響製品が検索結果から欠落すること;
- mutable container tags.

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

### Container and runtime threats

- vulnerable, malicious, stale, mutable, or untrusted images reaching a
  workload;
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
- registry, orchestrator, host OS, runtime, and application responsibilities
  being collapsed into one checklist whose evidence cannot identify the failed
  trust boundary.

The
[container security source allocation](CONTAINER_SECURITY_SOURCE_ALLOCATION.md)
assigns these outcomes across container admission, detection, secure coding,
registry, host, runtime monitoring, and release controls without duplicating
framework or reference-source roles. The previously unowned boundaries are
reserved as `PSB-CONTAINER-002` for registry security,
`PSB-CONTAINER-003` for host and daemon hardening, and `PSB-CONTAINER-004` for
post-admission runtime detection.

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
