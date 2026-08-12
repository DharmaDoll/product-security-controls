# Repository Structure

```text
.
├── AGENTS.md
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── Makefile
├── .codex/
│   └── prompts/
├── controls/
│   ├── README.md
│   ├── secure-design/
│   ├── secure-coding/
│   ├── source-protection/
│   ├── dependency-security/
│   ├── cicd-security/
│   ├── build-security/
│   ├── container-cloud-iac-security/
│   ├── release-integrity/
│   ├── ai-development-security/
│   ├── detection-verification/
│   └── governance-operations/
├── experiments/
│   └── codeguard/
├── frameworks/
│   ├── github-security-guidance/
│   ├── cisa-product-security-bad-practices/
│   ├── mitre-attack/
│   ├── mitre-atlas/
│   ├── nist-sp-800-190/
│   ├── openssf-osps-baseline/
│   ├── owasp-agentic-top10/
│   ├── owasp-top10/
│   ├── owasp-asvs/
│   ├── slsa/
│   └── nist-ssdf/
├── inputs/
│   └── application-vulnerability-assessment/ # optional reviewed source manifest
├── schemas/
│   ├── control.schema.json
│   └── framework assessment contracts
├── scripts/
│   ├── validate-controls/
│   ├── generate-index/
│   ├── generate-mappings/
│   └── verify-integrity/
├── tests/
├── generated/
│   ├── CONTROL_INDEX.md
│   ├── mappings/
│   ├── checklists/
│   │   ├── governance/       # catalog readiness and explicit NOT_CHECKED organization fields
│   │   └── profiles/         # framework and cross-control reconciliation views
│   └── assessments/          # ignored host-specific output
├── docs/
│   ├── PROJECT_CHARTER.md
│   ├── ARCHITECTURE.md
│   ├── CONTROL_MODEL.md
│   ├── APPLICATION_CHECKLIST_IMPORT.md
│   ├── REPOSITORY_STRUCTURE.md
│   ├── THREAT_MODEL.md
│   ├── CICD_THREAT_MATRIX_RECONCILIATION.md
│   ├── CONTAINER_SECURITY_SOURCE_ALLOCATION.md
│   ├── FRAMEWORK_MAPPING.md
│   ├── CODEX_WORKFLOW.md
│   ├── PLANNED_CONTROLS.md
│   ├── SECURITY_GUIDANCE_SOURCES.md
│   ├── SLSA_BUILD_L2_ASSESSMENT.md
│   ├── GITHUB_ACTIONS_SLSA_COLLECTOR.md
│   ├── GITHUB_RELEASES_SLSA_COLLECTOR.md
│   ├── SLSA_CONSUMER_AND_REVIEW_COLLECTORS.md
│   ├── ROADMAP.md
│   └── adr/
└── policies/
    ├── exceptions/
    ├── framework-assessments/
    ├── integration/          # reviewed cross-control identity handoff sources
    └── organization-assessments/ # public templates with NOT_CHECKED live fields
```

## Design rule

Do not organize the repository around tools.

Bad:

```text
trivy/
semgrep/
codeguard/
dependabot/
```

Good:

```text
dependency-security/package-integrity/
cicd-security/action-sha-pinning/
ai-development-security/security-skill-governance/
```

Tools are referenced inside controls.

Generated checklist CSV, Markdown, and XLSX files are derived from atomic
`checks` and check-level mapping links in `control.yaml`. Regenerate them with
`make generate-checklists`; do not maintain a separate spreadsheet source.

`policies/integration/supply-chain-reconciliation.json` is the reviewed source
for the generated NIST SP 800-204D section-level integration view. It references
exact existing checks and preserves planned, gap, and out-of-scope rows; it is
not a second framework registry and its `SCIR-*` IDs are repository identifiers.

`policies/organization-assessments/first-psirt-capability.json` preserves the
integrity-recorded FIRST source identities, service catalog, cumulative
maturity rows, and exact supporting check references. Its generated public
views never claim that a live PSIRT exists, has capacity, or achieved a level.

The domain-grouped [`controls/README.md`](../controls/README.md) and flat
`generated/CONTROL_INDEX.md` are both derived from `control.yaml`. Regenerate
them with `make generate-index`; `make lint` rejects stale catalog views.

Each control package's `README.md` begins with the validated
`このcontrolを一枚で理解する` table defined in
[`CONTROL_MODEL.md`](CONTROL_MODEL.md#one-page-readme-contract). This
human-readable overview and the machine-readable `control.yaml` serve different
views of the same boundary; neither replaces the other.
