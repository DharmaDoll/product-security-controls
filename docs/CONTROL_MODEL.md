# Control Model

## Control identity

Control IDs follow:

```text
PSB-<DOMAIN>-<NUMBER>
```

Examples:

- `PSB-CODE-001`
- `PSB-DEPS-003`
- `PSB-CICD-004`
- `PSB-AI-002`

## Required control metadata

Each `control.yaml` contains:

```yaml
id: PSB-CICD-001
title: Pin GitHub Actions to immutable commits
domain: cicd-security
summary: Prevent silent changes in third-party workflow dependencies.

security_functions:
  - prevent
  - verify

threats:
  - id: SUPPLY-CHAIN-MUTABLE-ACTION
    description: A mutable Action tag is changed or compromised.

implementations:
  insecure:
    - insecure/workflow.yml
  secure:
    - secure/workflow.yml

verification:
  commands:
    - make verify-control CONTROL=PSB-CICD-001
  expected:
    - all third-party actions use full commit SHAs
    - workflow permissions remain minimal

mappings:
  - framework: mitre-attack
    version: "<pinned-version>"
    id: T1195
    relationship: mitigates
    confidence: medium
    rationale: Reduces exposure to software supply-chain compromise.
  - framework: nist-ssdf
    version: "<pinned-version>"
    id: "<practice-or-task>"
    relationship: supports
    confidence: high
    rationale: Protects development and build dependencies.

limitations:
  - A pinned commit can still contain malicious code.
  - Upstream review and controlled updates remain necessary.

status: planned
owner: product-security
```

## Control maturity

- `idea`
- `planned`
- `prototype`
- `reference`
- `adopted`
- `deprecated`

## Evidence levels

- `E0`: documentation only
- `E1`: configuration example
- `E2`: automated static verification
- `E3`: executable positive and negative tests
- `E4`: reproducible end-to-end evidence

The default target is E3. High-value controls should reach E4.
