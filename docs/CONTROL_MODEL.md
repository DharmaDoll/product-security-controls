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

checks:
  - id: ACT-001
    title: External Actions use full commit SHAs
    required_state: full 40-character commit SHA
    responsible_role: repository-admin
    applies_to:
      - ci-workflow
    verification:
      type: automated
      method: make verify-control CONTROL=PSB-CICD-001
      expected: mutable Action references are rejected
      evidence:
        - sanitized verifier output
    mapping_status: reviewed

mappings:
  - framework: mitre-attack
    version: "<pinned-version>"
    id: T1195
    relationship: mitigates
    confidence: medium
    rationale: Reduces exposure to software supply-chain compromise.
    applies_to:
      - ACT-001
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

## Atomic adoption checks

`checks` are the source for generated adoption checklists. One check describes
one assessable required state. Compound expectations must be split so a user can
assign responsibility and record an unambiguous result.

`responsible_role` identifies the primary adopter. `verification.type`
distinguishes local automation from manual or organization-owned evidence.
Framework mappings use `applies_to` to link a reviewed rationale to specific
checks. A check with no reviewed relationship uses `mapping_status: unmapped`;
the parent control's mappings must not be copied to it implicitly.

Framework-specific adoption profiles are derived from pinned framework registry
metadata and the row-level `applies_to` links. A cumulative level profile, such
as SLSA Build L2, includes requirements whose `minimum_level` is at or below the
target and excludes higher-level requirements. Its coverage view must retain
unmapped requirements as explicit gaps. A mapped row is evidence relevant to a
requirement; it is not by itself a framework level or compliance claim.

## Read-only assessments

A control may expose an `assessment` command when it can inspect an adopted
target without changing it. Assessment output uses `PASS`, `FAIL`,
`NOT_CHECKED`, `ERROR`, and reviewed `N/A` as distinct states. An execution or
input failure must be `ERROR`, never a clean result.

Host-specific output follows `schemas/assessment-result.schema.json`, excludes
secrets and unnecessary host identifiers, and is written below the ignored
`generated/assessments/` directory. Fixture verification and live assessment
remain separate: a passing secure fixture is not evidence that a live endpoint
meets the requirement.

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
