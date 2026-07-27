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
