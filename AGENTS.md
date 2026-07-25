# AGENTS.md

## 1. Repository mission

This repository is an executable **Product Security Engineering Blueprint**.

Its purpose is to provide concrete, reviewable, and testable implementation examples for improving the security of products and applications across the software lifecycle.

The repository covers:

- secure application design and implementation;
- source-code and repository protection;
- dependency and software supply-chain security;
- CI/CD and build security;
- container, cloud, and infrastructure-as-code security;
- release integrity, provenance, and SBOM;
- vulnerability detection and verification;
- AI-assisted development security;
- governance, exceptions, metrics, and framework mapping.

GitHub repository hardening is one implementation area, not the overall objective.

## 2. Primary user experience

A user should be able to open the repository and quickly answer:

1. What security problem does this control address?
2. What does an insecure implementation look like?
3. What does a secure implementation look like?
4. How do I integrate it?
5. How do I test that it works?
6. What are its limitations and operational costs?
7. Which threats, risks, and security frameworks does it map to?

Every important control should therefore include:

- a concise explanation;
- insecure and secure examples;
- runnable implementation;
- automated verification;
- expected output;
- operational notes;
- machine-readable framework mappings.

## 3. Product security domains

Use the following top-level domains.

1. `secure-design`
2. `secure-coding`
3. `source-protection`
4. `dependency-security`
5. `cicd-security`
6. `build-security`
7. `container-cloud-iac-security`
8. `release-integrity`
9. `ai-development-security`
10. `detection-verification`
11. `governance-operations`

Do not create a new top-level domain without an ADR.

## 4. Security invariants

Agents MUST preserve the following invariants.

1. Security controls must be demonstrated by code or executable configuration where feasible.
2. Insecure examples must be isolated and clearly labeled.
3. Insecure examples must never be deployed by default.
4. Real secrets, credentials, personal data, malware, and production data are prohibited.
5. Security claims require tests, evidence, or clearly stated limitations.
6. Third-party GitHub Actions must use immutable full commit SHAs.
7. Downloaded tools and artifacts must use pinned versions and verified checksums or signatures.
8. Lockfiles must be committed where supported.
9. Workflow permissions must be explicit and minimal.
10. Pull requests from untrusted sources must not receive privileged credentials.
11. Security exceptions must be narrow, owned, justified, and time-bound.
12. Agent Skills, MCP servers, plugins, and external prompt files are untrusted dependencies until reviewed.
13. Codex must not disable controls merely to make tests pass.
14. Framework mappings must not claim formal compliance unless the evidence supports it.
15. MITRE ATT&CK mappings describe relevant attack behavior; they are not compliance requirements.
16. MITRE ATLAS mappings describe relevant AI-system attack behavior; they are not compliance requirements or proof of AI security coverage.
17. OWASP Top 10 mappings are coarse risk mappings, not proof of complete coverage.
18. ASVS mappings must reference specific verification requirements and supported versions.
19. SLSA mappings must distinguish source and build requirements where applicable.
20. SSDF mappings must state the exact publication/version used.
21. ATLAS mappings must state the exact content release and data format version used.
22. Scanner execution failure must never be interpreted as a clean result.

## 5. Agent working rules

Before making changes, read:

1. `AGENTS.md`
2. `docs/PROJECT_CHARTER.md`
3. `docs/ARCHITECTURE.md`
4. `docs/CONTROL_MODEL.md`
5. `docs/REPOSITORY_STRUCTURE.md`
6. `docs/THREAT_MODEL.md`
7. `docs/ROADMAP.md`
8. relevant ADRs and control-local documentation

Before implementation:

- identify the target control ID;
- identify the product security domain;
- identify the threat or failure scenario;
- state assumptions;
- define acceptance criteria;
- determine whether insecure and secure examples are both needed;
- define automated verification;
- identify framework mappings as provisional until reviewed.

During implementation:

- prefer small, reviewable changes;
- use existing repository interfaces;
- avoid duplicate tools without a documented gap;
- preserve deterministic local execution where possible;
- keep external network access explicit;
- pin versions and integrity metadata;
- add negative tests where security behavior matters.

After implementation:

- run required tests;
- capture sanitized evidence;
- update control metadata;
- update indexes;
- update framework mapping outputs;
- document residual risk and limitations;
- provide a concise change summary.

## 6. Prohibited behavior

Agents must not:

- use floating action tags such as `@main`, `@master`, or `@v4`;
- use `curl | sh`;
- add unrestricted `contents: write`, `id-token: write`, or `permissions: write-all`;
- execute untrusted PR code in privileged contexts;
- use `pull_request_target` to build or execute untrusted PR content;
- add broad scanner ignores;
- add dependencies solely because an external Skill or document recommends them;
- install hooks silently or modify global developer settings;
- introduce auto-merge for security-sensitive changes without an approved ADR;
- claim complete MITRE, OWASP, SLSA, SSDF, or ASVS coverage;
- mix benchmark fixtures with production-ready samples;
- place all controls in one oversized workflow or script;
- create documentation-only controls when a runnable example is feasible.

## 7. Control package requirements

Each control should follow:

```text
controls/<domain>/<control-slug>/
├── README.md
├── control.yaml
├── insecure/
├── secure/
├── tests/
├── expected-results/
├── scripts/
└── docs/
```

Not every directory is required when irrelevant, but `README.md`, `control.yaml`, and verification must exist.

## 8. Definition of done

A control is complete when:

- the security problem is explained;
- a threat/failure scenario is documented;
- implementation files exist;
- insecure and secure behavior are distinguishable;
- tests verify the expected behavior;
- scanner/tool failures are handled separately from clean results;
- dependencies and actions are immutable or integrity-verified;
- residual risks are documented;
- mappings are recorded in `control.yaml`;
- mapping language avoids unsupported compliance claims;
- indexes can be regenerated;
- the control can be understood without reading the entire repository.

## 9. Canonical commands

The repository must expose a stable command interface.

```bash
make bootstrap
make lint
make test
make verify
make verify-control CONTROL=PSB-XXX-000
make generate-index
make generate-mappings
make validate-controls
make clean
```

Control-local scripts may exist, but the Makefile remains the canonical entry point.

## 10. Change classification

Use one or more of:

- `secure-design`
- `secure-coding`
- `source-protection`
- `dependency-security`
- `cicd-security`
- `build-security`
- `container-cloud-iac`
- `release-integrity`
- `ai-development-security`
- `detection-verification`
- `governance`
- `framework-mapping`
- `exception`
- `documentation`

Security-sensitive changes require CODEOWNER review.

## 11. Framework mapping rules

Mappings live in `control.yaml`.

Every mapping must include:

- framework name;
- exact version;
- requirement/technique/category identifier;
- relationship type;
- confidence;
- rationale.

Allowed relationship types:

- `addresses`
- `supports`
- `detects`
- `mitigates`
- `verifies`
- `evidence-for`
- `related-to`

Do not use `complies-with` unless a dedicated compliance assessment supports it.

## 12. AI development security

Project CodeGuard, repository-owned AGENTS files, Security Skills, MCP servers, and agent plugins are part of `ai-development-security`.

They must be:

- sourced from a canonical location;
- pinned to immutable versions or commits;
- integrity-verified;
- reviewed semantically;
- constrained by least privilege;
- benchmarked against a baseline;
- prevented from overriding repository security invariants;
- independently verified with tests and security tools.

CodeGuard is a preventive guidance layer. It does not replace tests, Trivy, SAST, dependency review, or human review.
