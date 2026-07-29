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

<a id="ref-cicd-001"></a>

### REF-CICD-001 — GitHub Advisory Database for GitHub Actions

- Status: `adopted-partially`
- Type: official vendor vulnerability database and operational data source
- Publisher: GitHub
- Product scope: third-party GitHub Actions
- Live reviewed-Actions query:
  [GitHub Advisory Database](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aactions)
- Versioned API:
  [Global security advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)
- API version: `2022-11-28`
- Repository review date: `2026-07-30`
- Related control: `PSB-CICD-001`

Adopted contribution:

- collect only `type=reviewed` and `ecosystem=actions` records through a
  versioned API;
- bind Action package, reviewed release version, commit SHA, and release URL in
  a local inventory;
- block an inventory release matching an active advisory version range;
- treat stale, incomplete, malformed, unavailable, or unsupported version-range
  evidence as an error rather than a clean result.

Limitations:

- the database and web query are dynamic and cannot be pinned as a static
  framework release;
- advisory publication and correction can lag vulnerability discovery;
- advisory ranges identify versions rather than commit SHAs, so release-to-SHA
  binding remains separate reviewed evidence;
- reviewed advisories do not cover all unreviewed reports, malware, nested
  dependencies, or malicious-but-not-vulnerable Actions.

<a id="ref-cicd-002"></a>

### REF-CICD-002 — zizmor

- Status: `adopted`
- Type: GitHub Actions security static analyzer
- Publisher: zizmor project
- Live URL: [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor)
- Pinned reference source:
  [`zizmorcore/zizmor` at `6ea55f583ef6681a59b1c180950e47861a3c0293`](https://github.com/zizmorcore/zizmor/tree/6ea55f583ef6681a59b1c180950e47861a3c0293)
- License:
  [MIT](https://github.com/zizmorcore/zizmor/blob/6ea55f583ef6681a59b1c180950e47861a3c0293/LICENSE)
- Repository review date: `2026-07-30`
- Related control: `PSB-CICD-003`

Adopted contribution:

- statically analyze GitHub Actions workflows for security-relevant
  configuration defects;
- keep the pull-request blocking job unprivileged and separate from trusted
  SARIF reporting;
- distinguish a clean result, a policy finding, malformed output, and scanner
  execution failure;
- pin the executable Action, scanner version, and OCI digest independently of
  this reference-source snapshot.

Limitations and adoption boundary:

- the pinned source above is a review reference, not the executable identity;
  `PSB-CICD-003` records the separately pinned Action commit, scanner version,
  and image digest;
- static analysis does not observe runtime process, filesystem, network, or
  credential use;
- online-only audits are intentionally disabled in the adopted untrusted-PR
  path so a token is not injected into the scanner;
- new analyzers are not added alongside zizmor unless an isolated fixture
  demonstrates a unique required finding or workflow-validation gap.

<a id="ref-cicd-003"></a>

### REF-CICD-003 — actionlint

- Status: `identified`
- Type: GitHub Actions workflow linter
- Publisher: actionlint project
- Live URL: [rhysd/actionlint](https://github.com/rhysd/actionlint)
- Pinned reference source:
  [`rhysd/actionlint` at `011a6d15e749bb3f2d771eed9c7aa0e7e3e10ee7`](https://github.com/rhysd/actionlint/tree/011a6d15e749bb3f2d771eed9c7aa0e7e3e10ee7)
- License:
  [MIT](https://github.com/rhysd/actionlint/blob/011a6d15e749bb3f2d771eed9c7aa0e7e3e10ee7/LICENSE.txt)
- Repository review date: `2026-07-30`
- Related control: `PSB-CICD-003`

Potential contribution:

- validate workflow syntax, expression types, Action inputs and outputs,
  reusable-workflow interfaces, and embedded shell or Python code;
- complement a security analyzer only where a deterministic fixture proves a
  defect that the adopted zizmor path does not detect.

Disposition and limitations:

- it is not currently installed, downloaded, or executed by this repository;
- adoption requires a pinned version and artifact checksum or signature,
  clean/finding/error exit semantics, negative fixtures, and an explicit
  decision about optional ShellCheck or pyflakes dependencies;
- general lint quality must not be presented as proof that workflow privilege,
  event trust, or runtime behavior is secure.

<a id="ref-cicd-004"></a>

### REF-CICD-004 — poutine

- Status: `identified`
- Type: CI/CD pipeline vulnerability scanner
- Publisher: BoostSecurity
- Live URL:
  [boostsecurityio/poutine](https://github.com/boostsecurityio/poutine)
- Pinned reference source:
  [`boostsecurityio/poutine` at `bd4c1f86fe8cfe61b456f1ea2b2106ce0cac51d6`](https://github.com/boostsecurityio/poutine/tree/bd4c1f86fe8cfe61b456f1ea2b2106ce0cac51d6)
- License:
  [Apache-2.0](https://github.com/boostsecurityio/poutine/blob/bd4c1f86fe8cfe61b456f1ea2b2106ce0cac51d6/LICENSE)
- Repository review date: `2026-07-30`
- Related control: `PSB-CICD-003`

Potential contribution:

- evaluate supply-chain vulnerabilities across CI/CD pipeline definitions and
  broader repository or organization inventory;
- provide a comparison candidate when the required scope extends beyond the
  GitHub Actions findings exercised by the current zizmor fixtures.

Disposition and limitations:

- it is not currently installed, downloaded, or executed by this repository;
- adoption requires a documented finding category not already covered by
  `PSB-CICD-001..005`, a pinned and integrity-verified executable, offline
  fixtures where feasible, redacted evidence, and fail-closed scanner errors;
- organization-wide discovery may require network access and authentication,
  which must be isolated from untrusted pull-request execution;
- broad scanner coverage must not collapse separate control outcomes into one
  tool-oriented control.

<a id="ref-cicd-005"></a>

### REF-CICD-005 — GitHub Actions Best Practice 2025

- Status: `adopted-partially`
- Type: practitioner conference slide and implementation guidance
- Publisher and author: Shunsuke Suzuki
- Presentation date: `2025-03-11`
- Live URL:
  [GitHub Actions Best Practice 2025](https://suzuki-shunsuke.github.io/slides/github-actions-best-practice-2025)
- Pinned source:
  [`marp/github-actions-best-practice-2025.md` at `9a323208ecda2b3e27ffe279098537182566cee0`](https://github.com/suzuki-shunsuke/slides/blob/9a323208ecda2b3e27ffe279098537182566cee0/marp/github-actions-best-practice-2025.md)
- License:
  [MIT](https://github.com/suzuki-shunsuke/slides/blob/9a323208ecda2b3e27ffe279098537182566cee0/LICENSE)
- Repository review date: `2026-07-30`
- Related controls:
  - `PSB-CICD-001` — immutable Action references;
  - `PSB-CICD-003` — workflow static analysis;
  - `PSB-CICD-004` — explicit least-privilege token permissions;
  - `PSB-CICD-005` — fork and untrusted-PR isolation.

Adopted contribution:

- default-restricted and job-explicit `GITHUB_TOKEN` permissions;
- `persist-credentials: false` when checked-out source does not need retained
  credentials;
- full commit SHA pinning for third-party Actions;
- CI enforcement of reviewed workflow rules;
- treating fork pull requests as untrusted rather than using
  `pull_request_target` to execute their code.

Disposition and limitations:

- organization token settings, branch rulesets, required-check aggregation,
  self-approval prevention, and organization-wide remediation tooling are
  useful outcomes but are not all executable controls in this repository;
- named tools and Apps in the slides are examples, not adopted dependencies;
- availability, defaults, and product behavior may change after the pinned
  source, so GitHub-specific claims still require current official
  documentation and tests;
- performance and developer-experience recommendations are outside the
  security-control scope unless they affect bypass or evidence completeness.

<a id="ref-cicd-006"></a>

### REF-CICD-006 — GitHub のセキュリティ改善

- Status: `adopted-partially`
- Type: practitioner implementation article and incident-informed hardening
  guidance
- Publisher: Zenn
- Author: Shunsuke Suzuki
- Published date: `2025-04-07`
- Page-displayed update date: `2025-09-17`
- Live URL:
  [GitHub のセキュリティ改善](https://zenn.dev/shunsuke_suzuki/articles/github-security-2025)
- Immutable public source: not identified; retain the live URL and review date
  and re-review content changes
- License or redistribution terms: no article-specific reusable-content
  license identified; link and paraphrase only
- Repository review date: `2026-07-30`
- Related controls:
  - `PSB-CICD-001`, `PSB-CICD-003`, `PSB-CICD-004`, and `PSB-CICD-005`;
  - `PSB-SOURCE-004` — PAT, GitHub App, OAuth, and SSH credential lifecycle;
  - `PSB-DEPS-001` — dependency release cooldown.

Adopted contribution:

- inventory and minimize PAT and GitHub App use, repositories, and
  permissions;
- prefer narrowly scoped Environment secrets over unnecessarily broad
  repository secrets;
- review local plaintext secret storage separately from CI configuration;
- combine Action SHA pinning, minimum release age, signed changes, and
  `pull_request_target` avoidance as distinct layers.

Disposition and limitations:

- personal OSS maintenance choices and product-specific automation are examples
  rather than universal control requirements;
- pull-based cross-repository publication, tag rules, and organization-wide
  application cleanup need separate executable evidence before becoming
  checklist requirements;
- later edits to the live article are not automatically adopted.

<a id="ref-cicd-007"></a>

### REF-CICD-007 — 社内用GitHub Actionsのセキュリティガイドライン

- Status: `identified`
- Type: enterprise implementation article and self-checklist case study
- Publisher: Mercari Engineering
- Published date: `2023-06-09`
- Live URL:
  [社内用GitHub Actionsのセキュリティガイドライン](https://engineering.mercari.com/blog/entry/20230609-github-actions-guideline/)
- Corroborating presentation:
  [Creating Security Guidelines for the Internal Use of GitHub Actions](https://speakerdeck.com/mercari/creating-security-guidelines-for-the-internal-use-of-github-actions)
- Immutable public source: not identified
- License or redistribution terms: no reusable-content license identified;
  link and paraphrase only
- Repository review date: `2026-07-30`
- Related controls:
  - `PSB-CICD-002` — untrusted expression and command-injection boundary;
  - `PSB-CICD-004` — minimum workflow permissions;
  - `PSB-CICD-005` — untrusted-PR event and credential separation;
  - generated adoption checklists — periodic role-owned self-assessment.

Potential contribution:

- explain threat scenarios before presenting mitigations;
- connect repository-local guidance to a periodically repeated self-checklist;
- protect workflow ownership and review paths, including `.github` and
  `CODEOWNERS`;
- review triggers, permissions, third-party code, and credential exposure as
  separate checklist rows.

Disposition and limitations:

- the original blog could not be bound to an immutable public source during
  this review; the public presentation corroborates its purpose and selected
  topics but is not a byte-equivalent copy;
- detailed recommendations remain `identified` until the article is reviewed
  completely and reconciled row by row;
- an enterprise case study is not proof that the same organization settings
  or process fit every adopter.

<a id="ref-cicd-008"></a>

### REF-CICD-008 — GitHub Actionsの脆弱な構成の検知ツール比較

- Status: `adopted-partially`
- Type: security engineering tool comparison and incident analysis
- Publisher: GMO Flatt Security
- Published date: `2026-07-07`
- Live URL:
  [GitHub Actionsの脆弱な構成の検知ツール、任せられる範囲と人が見極めるべきリスク](https://blog.flatt.tech/entry/2026-github-actions-security-part4)
- Immutable public source: not identified
- License or redistribution terms: no reusable-content license identified;
  link and paraphrase only
- Repository review date: `2026-07-30`
- Related guidance and controls:
  - `PSB-CICD-003` — adopted zizmor execution and SARIF semantics;
  - `REF-CICD-002..004` — zizmor, actionlint, and poutine tool boundaries;
  - `REF-GOV-001` — OpenSSF Scorecard as evidence rather than compliance;
  - later evaluation of Checkov or CodeQL only for a demonstrated unique gap.

Adopted contribution:

- compare scanners by detectable outcome instead of treating tool count as
  coverage;
- distinguish workflow-text findings from repository-setting, identity,
  environment-protection, and runtime gaps;
- use incident cases to test whether a scanner could have found the initial
  weakness and which later attack stages remain outside its visibility;
- keep human review and independent controls for permissions, immutable
  releases, static credentials, and AI-agent configuration.

Disposition and limitations:

- comparison results are time-bound to the reviewed tool versions and rule
  sets, and do not establish current exhaustive coverage;
- article workflow snippets are illustrative and must not override this
  repository's full-SHA, least-privilege, or untrusted-PR invariants;
- a tool being discussed does not authorize adding it as a dependency.

<a id="ref-cicd-009"></a>

### REF-CICD-009 — OIDC・Trusted Publishingの残存リスクと軽減策

- Status: `adopted-partially`
- Type: security engineering identity analysis and implementation guidance
- Publisher: GMO Flatt Security
- Published date: `2026-07-02`
- Live URL:
  [OIDC・Trusted Publishingでも残るGitHub Actionsの認証情報漏洩リスクと軽減策](https://blog.flatt.tech/entry/2026-github-actions-security-part3)
- Immutable public source: not identified
- License or redistribution terms: no reusable-content license identified;
  link and paraphrase only
- Repository review date: `2026-07-30`
- Related controls and plans:
  - `PSB-CICD-004` — restrict `id-token: write` to the exchange job;
  - `PSB-CICD-005` — keep untrusted PR code out of credentialed jobs;
  - `PSB-BUILD-001` — separate untrusted build from credentialed deployment;
  - `PSB-CICD-006` — planned exact audience, subject, repository, workflow,
    environment, and cloud trust claims;
  - future package-registry Trusted Publishing profile — not yet reserved.

Adopted contribution:

- treat OIDC as short-lived credential issuance rather than prevention of
  credential theft;
- separate authentication and publication from untrusted build or test code;
- bind trust to exact stable repository identity, workflow, environment,
  audience, and provider-side authorization;
- minimize downstream cloud or registry permissions and retain independent
  audit evidence.

Disposition and limitations:

- cloud workload federation and package-registry Trusted Publishing are
  separate adoption boundaries and must not be collapsed into one control;
- exact claim support, credential lifetime, and cleanup behavior vary by
  provider and require current official documentation plus provider fixtures;
- the article informs `PSB-CICD-006` but does not make that planned control
  implemented.

<a id="ref-cicd-010"></a>

### REF-CICD-010 — Preventing pwn requests

- Status: `adopted`
- Type: official vendor security research and vulnerable-workflow analysis
- Publisher: GitHub Security Lab
- Author: Jaroslav Lobačevski
- Published date: `2021-08-03`
- Live URL supplied during review:
  [GitHub Actions: preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- Current canonical URL:
  [Keeping your GitHub Actions and workflows secure Part 1](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- Immutable public article source: not identified
- License or redistribution terms: no article-specific reusable-content
  license identified; link and paraphrase only
- Repository review date: `2026-07-30`
- Related control: `PSB-CICD-005`

Adopted contribution:

- treat every fork pull request and its derived artifacts as untrusted input;
- reject privileged execution of an explicitly checked-out PR head under
  `pull_request_target`;
- keep build and test on credential-free `pull_request` jobs;
- use a separate trusted execution only for narrowly validated passive results,
  without executing the PR artifact;
- do not use actor identity, labels, or stale approval as a durable trust
  transition.

Disposition and limitations:

- `PSB-CICD-005` deliberately uses a conservative first slice that rejects
  `pull_request_target` and `workflow_run` rather than implementing every
  metadata-only exception shown by the article;
- GitHub updated the article's example after initial publication, so review
  date and current canonical URL matter;
- platform-default improvements do not cover every privileged event, manual
  checkout, script-based fetch, reusable workflow, cache, or artifact path;
- the article is design rationale, while the control's positive and negative
  fixtures remain the executable evidence.

<a id="ref-cicd-011"></a>

### REF-CICD-011 — Common Threat Matrix for CI/CD Pipeline

- Status: `reviewed`
- Type: community CI/CD threat taxonomy and mitigation catalog
- Publisher: repository maintained by Hiroki Suezawa (`rung`); the source
  states that the matrix was created by Mercari Security Team and reviewed by
  its Platform Team
- Live URL:
  [rung/threat-matrix-cicd](https://github.com/rung/threat-matrix-cicd)
- Pinned source:
  [`README.md` at `6740b16ac8066116c24c3e95eefdc317f9790b04`](https://github.com/rung/threat-matrix-cicd/blob/6740b16ac8066116c24c3e95eefdc317f9790b04/README.md)
- Source commit date: `2026-05-31`
- License or redistribution terms: not declared in the repository at the
  reviewed commit; link and paraphrase only, and do not redistribute its
  matrix images or text until reuse terms are clarified
- Repository review date: `2026-07-30`
- Reconciliation:
  [`CICD_THREAT_MATRIX_RECONCILIATION.md`](CICD_THREAT_MATRIX_RECONCILIATION.md)
- Related controls and plans:
  - implemented CI/CD, build, dependency, release, IaC, and source-protection
    controls listed in the reconciliation;
  - `PSB-CICD-006`, `PSB-DEPS-004`, `PSB-DETECT-001`, and `PSB-REL-003`;
  - roadmap gaps for CI runner hardening and artifact-signing generation.

Adopted contribution:

- use the source as a design-time inventory of attacker behaviors across CI,
  CD, source hosting, secret management, and production boundaries;
- consolidate its repeated entries into 28 unique technique labels;
- identify which labels have partial executable evidence, a planned owner, or
  no current control owner;
- use explicit gaps to inform later control planning without silently
  expanding an existing control.

Disposition and limitations:

- the source describes itself as an ATT&CK-like matrix and uses similar tactic
  classification, but it is not MITRE ATT&CK and is not a compliance
  framework;
- it publishes no stable technique identifiers, versioned release, or declared
  machine-readable schema, so source labels must not be used as
  `control.yaml` mapping identifiers;
- an existing control in the reconciliation means that it reduces or verifies
  part of a technique, not that the technique is completely mitigated;
- the pinned source is a review baseline only; future source changes require
  semantic diff review before the reconciliation is advanced.

<a id="ref-build-001"></a>

### REF-BUILD-001 — cicd-sensor

- Status: `identified`
- Type: eBPF-based CI/CD runtime security sensor
- Publisher: cicd-sensor project
- Live URL: [cicd-sensor/cicd-sensor](https://github.com/cicd-sensor/cicd-sensor)
- Pinned reference source:
  [`cicd-sensor/cicd-sensor` at `6e08deb2221c19a854d8d3be7ce37c659c15bce9`](https://github.com/cicd-sensor/cicd-sensor/tree/6e08deb2221c19a854d8d3be7ce37c659c15bce9)
- License:
  [Apache-2.0 project license](https://github.com/cicd-sensor/cicd-sensor/blob/6e08deb2221c19a854d8d3be7ce37c659c15bce9/LICENSE);
  eBPF components also require their declared dual-license review
- Repository review date: `2026-07-30`
- Related control: `PSB-BUILD-001`

Potential contribution:

- collect runtime process, file, and network evidence from CI jobs;
- help verify attempted boundary violations that static workflow analysis and
  a declared build policy cannot observe.

Disposition and limitations:

- the upstream project describes itself as pre-release and under active
  development, so this repository does not treat its interface or evidence
  schema as stable;
- it is not currently installed or executed, and no workflow example is copied
  into the adopted path;
- adoption requires an immutable release or commit, integrity verification,
  a reviewed privileged eBPF and kernel boundary, evidence redaction and
  retention, synthetic event fixtures, and an explicit `ERROR` when the sensor
  or backend is unavailable;
- runtime telemetry detects and supports investigation; it does not replace
  sandboxing, credential separation, or default-deny egress.

<a id="ref-gov-001"></a>

### REF-GOV-001 — OpenSSF Scorecard

- Status: `adopted-partially`
- Type: open source project security-health evidence tool
- Publisher: OpenSSF
- Live URL: [ossf/scorecard](https://github.com/ossf/scorecard)
- Pinned reference source:
  [`ossf/scorecard` at `64febf8c5229a2a65d09c6b543677b28a51abb09`](https://github.com/ossf/scorecard/tree/64febf8c5229a2a65d09c6b543677b28a51abb09)
- License:
  [Apache-2.0](https://github.com/ossf/scorecard/blob/64febf8c5229a2a65d09c6b543677b28a51abb09/LICENSE)
- Repository review date: `2026-07-30`
- Related guidance:
  - [OpenSSF OSPS Baseline mapping boundary](../frameworks/openssf-osps-baseline/README.md);
  - [framework mapping guidance](FRAMEWORK_MAPPING.md).

Adopted contribution:

- permit individual, current Scorecard check results to be considered as one
  evidence source during repository or supplier assessment;
- keep the aggregate score separate from control pass/fail, OSPS Baseline
  mappings, and compliance claims.

Planned adoption boundary:

- no executable Scorecard integration exists in this repository yet;
- an adapter may be added only after each consumed check is mapped to a
  specific control evidence requirement with source revision, target
  repository, collection time, and freshness;
- unavailable APIs, incomplete checks, stale results, and tool failure must be
  `NOT_CHECKED` or `ERROR`, never a passing aggregate score;
- a score is prioritization input, not proof that a project, dependency, or
  release is secure.

<a id="ref-source-001"></a>

### REF-SOURCE-001 — TruffleHog

- Status: `adopted-partially`
- Type: secret discovery, classification, and credential verification tool
- Publisher: Truffle Security
- Live URL:
  [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
- Pinned reference source:
  [`trufflesecurity/trufflehog` at `ac39a5653be27b1a6613d75e18535764cc7a11cf`](https://github.com/trufflesecurity/trufflehog/tree/ac39a5653be27b1a6613d75e18535764cc7a11cf)
- License:
  [AGPL-3.0 for version 3](https://github.com/trufflesecurity/trufflehog/blob/ac39a5653be27b1a6613d75e18535764cc7a11cf/LICENSE)
- Repository review date: `2026-07-30`
- Related controls:
  - `PSB-SOURCE-003` — organization-operated public-repository current and
    historical exposure assessment;
  - `PSB-SOURCE-002` — explicit non-goal: do not recommend it as a
    developer-local hook.

Adopted contribution:

- document TruffleHog as an organization-operated complementary candidate for
  repository onboarding, scheduled full-history assessment,
  incident-response, and credential-verification use cases;
- require allowlisted network egress, redacted evidence, and a distinct
  execution-error state when live credential verification is enabled.

Disposition and limitations:

- it is not recommended for developer-local hooks or endpoint baselines and is
  not currently installed or executed by this repository;
- adoption requires a unique full-history or credential-verification gap
  relative to the repository-owned scanner and Gitleaks, an immutable and
  integrity-verified executable, license review, and positive, finding, and
  failure fixtures;
- credential verification can contact external providers and affect rate
  limits or monitoring, so it must not run implicitly from an untrusted pull
  request or developer hook;
- public APIs and detector behavior can change; the pinned source snapshot does
  not by itself pin a future executable integration.

## Chat-history reconciliation

The reviewed collaboration history contained:

- nineteen explicit external URLs: the two AI cheat sheets recorded as
  `REF-AI-001` and `REF-AI-002`, three GitHub Actions documentation URLs
  represented by the pinned GitHub guidance registry, and the Advisory
  Database web query recorded with its API as `REF-CICD-001`, plus the six
  security diagnostic and monitoring projects recorded as `REF-CICD-002..004`,
  `REF-BUILD-001`, `REF-GOV-001`, and `REF-SOURCE-001`, plus the six
  practitioner and security-research sources recorded as `REF-CICD-005..010`,
  plus the CI/CD threat taxonomy recorded as `REF-CICD-011`;
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
