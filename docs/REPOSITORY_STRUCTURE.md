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
│   ├── openssf-osps-baseline/
│   ├── owasp-top10/
│   ├── owasp-asvs/
│   ├── slsa/
│   └── nist-ssdf/
├── schemas/
│   └── control.schema.json
├── scripts/
│   ├── validate-controls/
│   ├── generate-index/
│   ├── generate-mappings/
│   └── verify-integrity/
├── tests/
├── generated/
│   ├── CONTROL_INDEX.md
│   └── mappings/
├── docs/
│   ├── PROJECT_CHARTER.md
│   ├── ARCHITECTURE.md
│   ├── CONTROL_MODEL.md
│   ├── REPOSITORY_STRUCTURE.md
│   ├── THREAT_MODEL.md
│   ├── FRAMEWORK_MAPPING.md
│   ├── CODEX_WORKFLOW.md
│   ├── ROADMAP.md
│   └── adr/
└── policies/
    └── exceptions/
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
