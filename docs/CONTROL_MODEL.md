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

Every control declares `check_context_version: "1.0"`. Every check must
include:

- `context.threat_actor`: who or what creates the threat, including accidental
  actors, compromised identities, automation failures, or external attackers;
- `context.attack_or_failure_scenario`: the concrete action or failure that
  affects this row's target;
- `context.why_required`: why this specific check changes the outcome and why
  another row does not make it redundant.

`applies_to` remains the machine-readable target scope. The context fields make
each generated spreadsheet row understandable when filtered or exported
without the parent README. They must be specific to the row and must not repeat
the same generic control summary across every check.

Context is reviewed control metadata, not generated filler. Do not copy one
generic paragraph across rows merely to satisfy validation.

## Top-level verification modes

The top-level `verification` object describes how the reference control itself
can be checked. Existing controls without an explicit `type` remain
`automated` for backward compatibility.

- `automated` and `hybrid` controls declare executable `commands` and ship
  `tests/test.sh`.
- `manual` and `external-evidence` controls declare a `procedure` link such as
  `README.md#verification` and do not add a test merely to satisfy the runner.
- A manual or external-evidence control is reported as `NOT_CHECKED`, never as
  verified, until an adopter performs the linked procedure with live evidence.
- `make verify` may skip non-automated controls while reporting their count.
  Selecting one directly with `make verify-control CONTROL=<id>` returns exit
  `2` together with its procedure link so automation cannot mistake it for a
  passing test.

Use `manual` only when the security outcome depends on semantic review,
provider configuration, or organization operation that a repository fixture
cannot prove. A copyable secure configuration is still an implementation; its
presence is not evidence that an organization activated it. If a meaningful
read-only check or safe end-to-end test becomes available, change the mode to
`hybrid` or `automated` and add the corresponding negative and failure tests.

## Imported application assessment profiles

An organization-owned application vulnerability assessment is a source profile,
not a control package and not a substitute for executable `PSB-CODE-*`
implementations. Its original row ID and wording remain source-owned. A separate
reconciliation record may split one compound source row into multiple atomic
rows, but must retain a traceable `same-as-source` or `split-from` relationship.

Every imported source row has an explicit `implemented`, `planned`, `duplicate`,
`out-of-scope`, or `mapping-review-required` disposition. Framework mappings
use exact registry version and identifier fields and remain row-specific;
missing mappings are not inferred from a referenced control. Missing source,
manifest, version, row, or reconciliation is an input or import error, never a
zero-row clean assessment.

Public generated views exclude organization-only wording and completed
assessment evidence. The source manifest, importer behavior, output contract,
and use of repository-external private input are defined in
[`APPLICATION_CHECKLIST_IMPORT.md`](APPLICATION_CHECKLIST_IMPORT.md).

## One-page README contract

`control.yaml` is the machine-readable source for generated checklist rows.
The control `README.md` is the human entry point and must answer the control
boundary without requiring the reader to reconstruct it from implementation
files.

The first H2 in every control README is exactly:

```markdown
## このcontrolを一枚で理解する
```

It contains these exact, non-empty items. A compact Markdown table or six
`###` labeled prose blocks may be used; choose the format that makes the
control easiest to scan.

| Row | Required content |
|---|---|
| `セキュリティ上の問題` | The unsafe condition and security consequence |
| `誰から、または何から守るか` | Attacker, compromised component, mistake, or service failure |
| `何が対象か` | Concrete assets, identities, workflows, artifacts, or control planes |
| `何をするか` | Preventive, detective, verification, response, or governance action |
| `成功状態` | Observable accepted state and relevant fail-closed behavior |
| `対象外・残余リスク` | Explicit boundary that this control does not prove or mitigate |

The overview is concise and is not a replacement for insecure and secure
examples, integration, verification and expected output, operational notes,
limitations, references, or atomic check metadata. `make validate-controls`
rejects a missing, duplicated, misplaced, empty, or placeholder item.

Framework-specific adoption profiles are derived from pinned framework registry
metadata and the row-level `applies_to` links. A cumulative level profile, such
as SLSA Build L2, includes requirements whose `minimum_level` is at or below the
target and excludes higher-level requirements. Its coverage view must retain
unmapped requirements as explicit gaps. A mapped row is evidence relevant to a
requirement; it is not by itself a framework level or compliance claim.

The AISVS 1.0 profile retains all 191 pinned requirements across Levels 1, 2,
and 3. `mapped-evidence` means only that an exact repository check has a reviewed
relationship to that requirement; all other rows remain `gap`. The profile does
not infer complete requirement satisfaction, live adoption, or an AISVS level,
and it preserves the upstream assumption that AISVS Level N is assessed with
ASVS Level N.

Cross-control integration profiles use repository-owned row IDs and exact
full check references to test whether an identity or security decision survives
handoffs between controls. They do not add framework identifiers to
`control.yaml`. The NIST SP 800-204D profile requires one of `implemented`,
`planned`, `gap`, or `out-of-scope` for every row. Implemented rows require
resolvable current checks; planned and gap rows require an owner and remaining
work; out-of-scope rows require an owned boundary rationale. A missing,
malformed, or stale reference is a generation error, never an empty clean view.

Threat-taxonomy coverage profiles must reconcile every identifier in their
pinned registry, not only identifiers that already have mappings. SITF uses
`implemented`, `planned`, `gap`, and `out-of-scope`: `implemented` requires an
exact current check that directly addresses the primary technique behavior;
partial controls stay `gap` with supporting references, an owner, and remaining
work. Synthetic attack flows must reference reconciled identifiers and cross at
least three framework components. Neither a row nor a flow is a compliance,
organization-adoption, or complete-mitigation claim.

Organization capability profiles may reference exact repository checks as
supporting evidence, but must not turn fixture success into an organization
result. The FIRST PSIRT profile records integrity-bound source snapshots,
service references, responsible roles, and required organization evidence.
Its public `Assessment Result` and `Evidence Freshness` fields remain
`NOT_CHECKED`. Maturity levels are cumulative: Level 2 requires all applicable
Level 1 and Level 2 rows, and Level 3 also requires Level 3 rows. Missing source
identity, unknown check/service references, or malformed input fails generation.

## Security exception contract

Controls do not invent weaker local exception lifecycle semantics. The shared
`psb-security-exception/v1` contract and fail-closed reference evaluator are
owned by `PSB-GOV-002`. An exception binds one exact control/check pair, target,
environment, accountable roles, risk, compensating controls, approval,
remediation, creation, and expiry.

The control that raises a security decision still owns its domain-specific
risk evaluation. It consumes only currently `ACTIVE` or `EXPIRING` decisions
from the shared interface and records exception application separately; a
valid exception does not rewrite the underlying check to `PASS`. `EXPIRED` or
`INVALID` decisions fail, and unavailable or untrustworthy register evidence is
`ERROR`.

See [`policies/exceptions/README.md`](../policies/exceptions/README.md) for the
repository policy and the staged migration rule for existing local formats.

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

## Control verification modes

Top-level `verification.type` may be `automated`, `hybrid`, `manual`, or
`external-evidence`. It defaults to `automated` for existing controls.

`automated` and `hybrid` controls require `tests/test.sh`. `manual` and
`external-evidence` controls do not: adding a no-op test, checking README text,
or accepting a self-asserted fixture would create false assurance. The
canonical `make verify-control` command reports these controls as
`NOT_CHECKED` and points to their README procedure; it does not promote the
absence of an automated test into a clean security result.

Manual verification must identify the live setting or operation, responsible
role, safe procedure, expected observable state, evidence authority, and the
conditions that remain `NOT_CHECKED` or `ERROR`. A copyable configuration may
still be an `E1` implementation even when its security effect can only be
confirmed in the provider environment.

## Catalog governance views

`generated/checklists/governance/` summarizes repository-owned metadata per
control: catalog status, reference evidence level, verification type,
assessment-adapter availability, and reviewed, provisional, or unmapped check
counts. These fields describe the blueprint implementation, not an adopting
organization.

Organization adoption, evidence freshness, active or expiring exceptions, and
expired or invalid exception debt require organization-owned assessment and a
current `PSB-GOV-002` register. Generated public views initialize every such
field to `NOT_CHECKED`. They must never derive `PASS` or adoption from
`prototype`, `adopted`, `E3`, a framework mapping, or a successful fixture.
Completed assessments are recorded only in a copied assessment workbook or an
organization evidence system and are not committed as public guidance.

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
