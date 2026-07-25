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
2. Dependency lockfile and update cooldown
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

## Phase 3 — CI/CD and supply chain

Add:

- minimal permissions;
- fork-safe workflows;
- dependency review;
- OIDC;
- runner hardening;
- verified downloads;
- container digest pinning.

Also add source-protection controls for public repository exposure, including
GitHub dorking scenarios, secret discovery in current and historical content,
visibility review, and remediation verification. These controls must test
both prevention and detection, and must document the residual risk from forks,
caches, and previously cloned repositories.

Add developer endpoint hardening controls covering device encryption and lock
policy, OS and tool update enforcement, least privilege, credential storage,
local service exposure, endpoint detection, backup handling, and isolation of
AI development tools. Controls should distinguish device-management policy
from developer-local configuration and should not assume that endpoint
hardening protects a compromised repository or malicious dependency.

Prioritize ATT&CK, SSDF, and SLSA mappings.

## Phase 4 — Release integrity

Add:

- SBOM;
- checksums;
- artifact attestation;
- provenance;
- signing and verification.

## Phase 5 — AI development security

Add:

- repository-owned AGENTS controls;
- Project CodeGuard baseline comparison;
- Skill pinning;
- Skill semantic review;
- MCP allowlist;
- prompt/document injection fixtures;
- sandbox and network policy.

## Phase 6 — Governance and generated views

Add:

- exception expiry;
- metrics;
- adoption profiles;
- generated framework indexes;
- control maturity dashboard;
- repository template documentation.
