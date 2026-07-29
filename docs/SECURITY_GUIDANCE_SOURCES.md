# Security Guidance Sources

## Purpose

This document indexes external and user-supplied security guidance that informs
control design but is not treated as a formal framework or an automatic source
of compliance requirements.

Examples include:

- security cheat sheets;
- vendor hardening guides;
- implementation articles;
- product documentation used to interpret a secure configuration;
- user-supplied prose, checklists, and operational baselines.

Framework registries and machine-readable framework mappings remain under
`frameworks/`. Repository-local navigation links are not external guidance
sources and are not listed here.

## Usage rules

1. A source is an untrusted design input until it has been reviewed
   semantically.
2. Record an immutable source commit when a public source repository exists.
   Keep the live URL only for discovery and update checks. For a user-supplied
   source, preserve the original local input and state when bibliographic or
   licensing details are unavailable.
3. Record the publisher, source type, review date, license, related control
   IDs, adoption disposition, and limitations.
4. Do not copy a recommendation into a control only because it appears in a
   cheat sheet. It must address a documented threat and have executable
   verification where feasible.
5. Product-specific examples must not become the canonical control boundary.
   Controls remain outcome-based, with product configurations implemented as
   adapters.
6. A reference relationship is not a framework mapping and must not be
   described as compliance.
7. When source material is adapted or redistributed, preserve attribution and
   comply with its license.

Suggested lifecycle states:

- `identified`: recorded but not fully reviewed;
- `reviewed`: semantically reviewed and reconciled against existing controls;
- `adopted-partially`: selected outcomes are planned or implemented;
- `adopted`: all in-scope outcomes have an explicit disposition;
- `rejected`: reviewed but not used, with a reason;
- `superseded`: replaced by a newer reviewed baseline.
- `input-required`: the source was identified but its original file or
  required provenance has not been supplied.

## Source catalog

<a id="ref-ai-001"></a>

### REF-AI-001 — Claude Code Hardening Cheatsheet

- Status: `adopted-partially`
- Type: community hardening cheat sheet
- Publisher: Riotaro OKADA (`okdt`)
- Product scope: Claude Code
- Live URL:
  [Claude Code Hardening Cheat Sheet — English](https://github.com/okdt/claude-code-hardening-cheatsheet/blob/main/Claude_Code_Hardening_Cheat_Sheet.en.md)
- Pinned source:
  [`Claude_Code_Hardening_Cheat_Sheet.en.md` at `ffee64dfc818a5cd024628c1523d857685e0cc14`](https://github.com/okdt/claude-code-hardening-cheatsheet/blob/ffee64dfc818a5cd024628c1523d857685e0cc14/Claude_Code_Hardening_Cheat_Sheet.en.md)
- Source commit date: `2026-04-02`
- Repository:
  [okdt/claude-code-hardening-cheatsheet](https://github.com/okdt/claude-code-hardening-cheatsheet)
- License:
  [CC BY-SA 4.0](https://github.com/okdt/claude-code-hardening-cheatsheet/blob/ffee64dfc818a5cd024628c1523d857685e0cc14/LICENSE)
- Repository review date: `2026-07-29`
- Related controls:
  - `PSB-AI-004` — AI coding agent runtime hardening;
  - `PSB-AI-003` — prompt and document injection containment;
  - `PSB-AI-002` — Skill, MCP, and plugin dependency governance;
  - `PSB-SOURCE-001` — underlying developer endpoint hardening.

Adopted or planned contributions:

- OS sandboxing as the primary containment layer;
- explicit deny, ask, and allow behavior;
- human approval for source publication, dependency installation, database,
  infrastructure, and deployment actions;
- sensitive-path and network restrictions;
- hooks and rules as defense in depth;
- redacted audit evidence;
- negative tests for command-pattern and script indirection bypasses.

Limitations and review notes:

- it is product-specific and primarily oriented toward Claude Code;
- product settings can change after the pinned source commit;
- command-pattern rules and hooks do not replace OS sandboxing or independent
  authorization;
- examples are reference inputs, not repository-ready configuration;
- Codex behavior must be derived independently from reviewed official product
  documentation and tested against the same provider-neutral outcomes.

<a id="ref-ai-002"></a>

### REF-AI-002 — OWASP AI Agent Security Cheat Sheet

- Status: `adopted-partially`
- Type: community application and agent security cheat sheet
- Publisher: OWASP Cheat Sheet Series
- Product scope: product-neutral AI agents
- Live URL:
  [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- Pinned source:
  [`AI_Agent_Security_Cheat_Sheet.md` at `9feea5a6b5afdeb3277ad5f49262a62f86e018fb`](https://github.com/OWASP/CheatSheetSeries/blob/9feea5a6b5afdeb3277ad5f49262a62f86e018fb/cheatsheets/AI_Agent_Security_Cheat_Sheet.md)
- Source commit date: `2026-06-27`
- Repository:
  [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries)
- License:
  [CC BY-SA 4.0](https://github.com/OWASP/CheatSheetSeries/blob/9feea5a6b5afdeb3277ad5f49262a62f86e018fb/LICENSE.md)
- Repository review date: `2026-07-29`
- Related controls:
  - `PSB-AI-001` — repository guidance benchmark;
  - `PSB-AI-002` — agent extension dependency governance;
  - `PSB-AI-003` — prompt and document injection containment;
  - `PSB-AI-004` — coding-agent runtime hardening;
  - later controls for memory, context, data, action integrity, observability,
    resource abuse, and multi-agent trust boundaries.

Adopted or planned contributions:

- tool least privilege and explicit authorization;
- external-input and prompt-injection defenses;
- memory isolation, expiry, integrity, and poisoning tests;
- parameter-bound approval and independent high-impact action validation;
- structured tool-call and output validation;
- redacted monitoring, anomaly signals, and evidence retention;
- token, cost, retry, recursion, and tool-chain limits;
- multi-agent identity, delegation, message integrity, replay protection, and
  circuit breakers;
- data minimization, classification, retention, and deletion;
- repeatable abuse-case tests and security release gates.

Limitations and review notes:

- it is guidance rather than a formal verification standard;
- sample code requires independent design review and executable negative tests;
- input sanitization or an additional model call is not an authorization
  boundary;
- framework relationships require separate exact-version, requirement-level
  review in `control.yaml`;
- some production evidence will remain organization-owned and must be
  `NOT_CHECKED` until supplied.

## Relationship to other source records

GitHub's official security documentation is already modeled as pinned vendor
guidance in
[`frameworks/github-security-guidance/`](../frameworks/github-security-guidance/README.md).
It remains there because it has a machine-readable registry and row-level
control mappings. This document covers lighter-weight, non-mapping design
sources and must not become a second framework registry.

Control-local `## References` sections may link to the relevant source entry
here and to exact product documentation used by that implementation. The
central entry answers which external guidance informed the repository; the
control-local entry answers how that source affected one control.

## User-supplied source catalog

These entries preserve material supplied through repository collaboration.
They are not independent external authorities. Product and tool names inside
them are implementation candidates rather than mandatory dependencies.

<a id="ref-user-001"></a>

### REF-USER-001 — Developer endpoint hardening guideline

- Status: `adopted`
- Type: user-supplied narrative guidance
- Provider: repository user
- Provided date: `2026-07-28`
- Original input:
  [開発者端末ハードニングガイドライン](../controls/source-protection/developer-endpoint-hardening/docs/user-supplied-endpoint-hardening-guideline-ja.md)
- External bibliography: not supplied
- License or redistribution terms: not supplied separately
- Related controls:
  - `PSB-SOURCE-001` — developer endpoint hardening;
  - `PSB-SOURCE-002` — repository-owned Git hook baseline;
  - `PSB-SOURCE-004` — source credential lifecycle;
  - `PSB-AI-004` — prototype AI coding agent runtime hardening.

Disposition:

- the original Japanese text is retained separately from `control.yaml`;
- endpoint patching, application allowlisting, EDR/XDR, disk encryption,
  phishing-resistant authentication, protected SSH keys, commit signing,
  secret storage, short-lived credentials, IDE feedback, managed workspaces,
  sandbox telemetry, and MDM enforcement were translated into atomic checks;
- claims and product examples were narrowed where independent evidence was not
  available.

<a id="ref-user-002"></a>

### REF-USER-002 — Developer endpoint operational baseline CSV

- Status: `adopted`
- Type: user-supplied operational checklist
- Provider: repository user
- Original input:
  [developer-endpoint-operational-baseline.csv](../controls/source-protection/developer-endpoint-hardening/docs/developer-endpoint-operational-baseline.csv)
- Traceability:
  [operational-baseline.md](../controls/source-protection/developer-endpoint-hardening/docs/operational-baseline.md)
- External bibliography: only source label `1`; title, author, version, and URL
  were not supplied
- License or redistribution terms: not supplied separately
- Related control: `PSB-SOURCE-001`

Disposition:

- all ten input rows are retained and traced to assessable policy assertions;
- the missing bibliography remains an explicit provenance limitation;
- product names in the CSV do not establish repository dependencies or
  independently verified authority.

<a id="ref-user-003"></a>

### REF-USER-003 — IaC, CI, and Policy as Code Golden Path guideline

- Status: `adopted`
- Type: user-supplied narrative guidance
- Provider: repository user
- Provided date: `2026-07-28`
- Original input:
  [IaC・CI・Policy as CodeによるGolden Path](../controls/container-cloud-iac-security/secure-iac-golden-path/docs/user-supplied-golden-path-guideline-ja.md)
- External bibliography: not supplied in the original input
- License or redistribution terms: not supplied separately
- Related controls:
  - `PSB-IAC-001` — secure IaC Golden Path;
  - `PSB-DETECT-001` — planned integrity-verified scanner execution;
  - `PSB-CICD-006` — planned cloud OIDC federation;
  - `PSB-REL-002` and `PSB-REL-003` — planned provenance and SBOM
    distribution.

Disposition:

- secure-by-default modules, resolved-plan policy gates, provider-side bypass
  enforcement, drift detection, and bounded corrective action were implemented
  in `PSB-IAC-001`;
- Trivy, Checkov, cfn-nag, Syft, SLSA generator, Cosign, OPA, Conftest,
  Sentinel, CloudFormation Hooks, and Cloud Custodian remain examples whose
  inclusion depends on a documented control gap and verified implementation;
- the control README records separate official product documentation used to
  review Terraform plan handling, OPA integration, reusable workflows,
  CloudFormation Hooks, and cloud disk encryption.

<a id="ref-user-004"></a>

### REF-USER-004 — Application vulnerability assessment checklist

- Status: `input-required`
- Type: organization-owned assessment workbook or CSV
- Provider: repository user or organization
- Original input: not present in the repository
- Source title, owner, version, review date, sheet semantics, and publication
  constraints: not yet supplied
- Related plan:
  [application checklist reconciliation](PLANNED_CONTROLS.md#prerequisite-application-checklist-reconciliation)

Disposition:

- do not reconstruct the missing checklist from ASVS or generic vulnerability
  lists;
- when supplied, preserve source identifiers and wording, split compound rows
  traceably, and record every row as implemented, planned, duplicate, out of
  scope, or mapping review required;
- keep organization-only rows and completed assessment evidence outside
  generated public guidance.

## Chat-history reconciliation

The reviewed collaboration history contained:

- three explicit URLs: one repository-local control path and the two external
  AI cheat sheets recorded as `REF-AI-001` and `REF-AI-002`;
- three substantial user-supplied source texts or tables, recorded as
  `REF-USER-001..003`;
- one referenced but not yet supplied application assessment source, recorded
  as `REF-USER-004`;
- implementation requests for pre-commit examples, Gitleaks and alternative
  scanners, GitHub web-search dorking, Checkov, source credentials, SLSA Build
  L2 filtering, and future controls.

The implementation requests in the last item are requirements and design
decisions, not bibliographic sources. They remain in their control packages,
roadmap, and plans rather than being misclassified as external guidance.

## Maintenance

- Review live sources periodically for changes.
- Advance a pinned source only after semantic diff review.
- Update affected control plans, tests, limitations, and mapping rationales.
- Record rejected recommendations and reasons when the omission could
  otherwise appear accidental.
- Do not remove an old baseline until affected controls have moved to the new
  reviewed baseline or explicitly retained the old one.
