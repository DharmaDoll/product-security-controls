# Architecture

## Conceptual model

```text
Threats and failure scenarios
            ↓
Product Security controls
            ↓
Concrete secure implementations
            ↓
Automated verification and evidence
            ↓
Framework mappings and adoption guidance
```

## Repository layers

### 1. Control catalog

`controls/` contains individually understandable and testable security controls.
Each package starts with a validated one-page README overview of the problem,
threat source, target, action, success state, and residual boundary, followed by
the executable implementation and machine-readable atomic checks.
`controls/README.md` is the generated human entry point grouped by product
security domain and links directly to every implemented control package.

### 2. Shared tooling

`tools/`, `scripts/`, and `Makefile` provide common validation and generation functions.

### 3. Framework registry

`frameworks/` stores versioned identifiers and metadata for mapping validation.

### 4. Generated views

`generated/` contains indexes and reverse mappings produced from `control.yaml`.
The human-facing `controls/README.md` is also generated from the same metadata
so the root navigation and exported views do not require a second catalog
source.

Catalog-governance CSV, Markdown, and XLSX sheets are generated from the same
metadata. They separate repository implementation status and reference
evidence level from organization adoption, evidence freshness, and exception
debt; absent organization input remains `NOT_CHECKED`.

An optional organization application-assessment source is imported through a
digest-bound read-only manifest and explicit reconciliation contract. It is not
converted into a control automatically. Missing input remains
`INPUT_REQUIRED`, public source rows become a separate generated profile, and
organization-only wording is not exported.

The NIST SP 800-204D supply-chain integration profile is a separate reviewed
policy source, not a framework registry or control package. Its generated
CSV, Markdown, and XLSX view resolves exact control/check references and keeps
`implemented`, `planned`, `gap`, and `out-of-scope` dispositions visible across
developer, SCM, dependency, build, release, registry, and deployment identity
handoffs. Missing or invalid profile input fails generation.

The SITF threat-taxonomy registry is paired with a complete 81-technique
reconciliation and repository-owned synthetic attack flows. Its generated CSV,
Markdown, and XLSX views keep direct implementation separate from partial
support and owned gaps across endpoint, VCS, CI/CD, registry, and production.
Unknown or missing techniques, stale check references, or single-component
flows fail generation. These views are not compliance or live-adoption claims.

The AISVS requirement registry is paired with a complete 191-requirement
coverage view. Exact reviewed atomic mappings are shown as `mapped-evidence`;
every other requirement remains an explicit `gap`. The view does not infer
complete requirement satisfaction, live adoption, or an AISVS verification
level.

The FIRST PSIRT organization-assessment profile is likewise separate from the
control catalog. It pins observed source identities, preserves the Services
Framework service inventory, and generates cumulative Basic, Intermediate, and
Advanced rows. Existing governance checks are supporting references only;
organization result and evidence freshness remain `NOT_CHECKED` in public
outputs.

### 5. Experiments

`experiments/` contains comparative evaluations such as CodeGuard-enabled versus baseline Codex execution.

## Trust model

The following are external or semi-trusted inputs:

- package registries;
- container registries;
- public DNS, Certificate Transparency, HTTPS metadata, and external asset
  inventory observations;
- GitHub Actions;
- scanner databases;
- Security Skills;
- MCP servers;
- AI-generated code;
- framework mapping data;
- organization-owned assessment workbooks and reconciliation files;
- downloaded tools;
- pull-request content.

Controls must explicitly document which trust boundary they address.

## Prevent, detect, verify, respond

Controls should identify their primary function.

- `prevent`
- `detect`
- `verify`
- `respond`
- `govern`

Example:

- CodeGuard: prevent/support
- secure coding tests: verify
- Trivy: detect/verify
- Dependency Review: detect/prevent
- SBOM: evidence/support
- incident playbook: respond
