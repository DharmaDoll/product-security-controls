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

In particular, the released OWASP Top 10 for Agentic Applications 2026 is
owned by the
[`owasp-agentic-top10` framework registry](../frameworks/owasp-agentic-top10/README.md).
The OWASP AI Agent Security Cheat Sheet remains `REF-AI-002` because it is
implementation guidance; the two sources are intentionally not merged or
duplicated.

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
  - `PSB-DETECT-001` — implemented integrity-verified scanner execution;
  - `PSB-CONTAINER-001` — implemented OCI provenance and workload admission;
  - `PSB-CICD-006` — implemented provider-neutral signed cloud OIDC federation;
  - `PSB-REL-002` — implemented provenance distribution;
  - `PSB-REL-003` — implemented SBOM lifecycle and artifact-bound distribution.

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

<a id="ref-user-005"></a>

### REF-USER-005 — SBOM lifecycle acquisition and centralized management guidance

- Status: `adopted-partially`
- Type: user-supplied narrative guidance
- Provider: repository user
- Provided date: `2026-07-31`
- Original input:
  [SBOM lifecycle guidance](../controls/release-integrity/sbom-binding-publication/docs/user-supplied-sbom-lifecycle-guidance-ja.md)
- External bibliography: not supplied in the original input
- License or redistribution terms: not supplied separately
- Related controls:
  - `PSB-REL-003` — source, build, and deployment observation identity plus
    artifact-bound release SBOM;
  - `PSB-GOV-001` — component-to-build-to-deployment impact lookup;
  - `PSB-REL-004` — implemented supplier SBOM signature trust and quarantine.

Adopted contribution:

- collect separate observations at source, build, and deployment transitions;
- make the artifact-observed build SBOM authoritative for release bytes;
- preserve commit SHA, artifact digest, and deployment ID relationships in a
  centralized catalog;
- use source inventory for early feedback and deployment inventory for active
  impact lookup without overwriting release evidence;
- retain signed supplier SBOM intake as a distinct trust boundary.

Narrowed or deferred contribution:

- runtime observation does not prove a complete inventory of every component
  loaded in process memory;
- CycloneDX 1.7 is the only format implemented by the current E3 adapter;
- supplier signature verification is implemented with a local Ed25519 fixture,
  consumer trust policy, signer-status snapshot, and equivalent negative tests;
- SPDX remains planned until a version-pinned parser and equivalent malformed,
  identity, relationship, and signature negative tests exist.

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
  - `PSB-CICD-006` — implemented exact audience, subject, immutable repository,
    workflow, environment, replay, and bounded cloud credential contract;
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
- the article informs `PSB-CICD-006`; the implemented offline contract does not
  make any provider-specific live federation configuration verified.

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
  - `PSB-CICD-006`, `PSB-DEPS-004`, and `PSB-REL-003`;
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

<a id="ref-cicd-012"></a>

### REF-CICD-012 — NIST SP 800-204D software supply-chain integration guidance

- Status: `reviewed`
- Type: official software supply-chain security integration guidance for
  DevSecOps CI/CD pipelines
- Publisher: National Institute of Standards and Technology (NIST)
- Publication identity: NIST SP 800-204D, final, February 2024
- Official publication page:
  [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final)
- DOI: [10.6028/NIST.SP.800-204D](https://doi.org/10.6028/NIST.SP.800-204D)
- Final PDF:
  [NIST.SP.800-204D.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf)
- Repository review date: `2026-08-04`
- Related controls and plans:
  - `PSB-SOURCE-001` for the developer-environment trust boundary;
  - `PSB-CICD-001..006` for SCM and pipeline dependency, expression,
    permission, untrusted-input, and identity boundaries;
  - `PSB-DEPS-001..004`, `PSB-BUILD-001..003`, and `PSB-REL-001..004` for
    dependency, build, evidence, provenance, and SBOM outcomes;
  - `PSB-IAC-001` and `PSB-CONTAINER-001` for deployment policy and admission.

Adopted planning contribution:

- use the publication as a cross-control integration review for developer
  environment risk, SCM interaction, secure build, repository pull/push,
  evidence-generation integrity, secure commits, and CD/GitOps boundaries;
- reconcile each selected strategy to an existing executable check, an
  explicitly planned control, or a documented gap instead of creating one
  oversized CI/CD control;
- retain the publication's Appendix A relationship to SSDF as supporting
  rationale while continuing to map exact SSDF tasks only through the pinned
  `nist-ssdf` registry;
- verify that artifact, actor, step, repository, and evidence identities stay
  linked across the pipeline rather than treating individually passing tools
  as an integrated secure supply chain.

Disposition and limitations:

- SP 800-204D is guidance, not a new `control.yaml` identifier namespace in
  this repository;
- its scope is cloud-native DevSecOps CI/CD integration and does not replace
  product-specific threat modeling, secure design, or enterprise vulnerability
  management;
- the publication explicitly leaves evolving SBOM and attestation artifact
  specifications to their respective standards, so SLSA, CycloneDX, and SPDX
  identities remain independently versioned;
- a future reconciliation must cite section-level text and executable evidence
  before claiming that a strategy is addressed.

<a id="ref-cicd-013"></a>

### REF-CICD-013 — CIS Software Supply Chain Security Guide and Benchmarks

- Status: `input-required`
- Type: official consensus guide plus provider-specific CIS Benchmark family
- Publisher: Center for Internet Security (CIS); the 2022 guide was developed
  with Aqua Security
- Official guide:
  [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide)
- Guide publication date: `2022-08-31`
- Official benchmark page:
  [CIS Software Supply Chain Security](https://www.cisecurity.org/benchmark/Software-Supply-Chain-Security)
- Versions displayed by the official page on `2026-08-04`:
  - CIS GitHub Benchmark `1.2.0`;
  - CIS GitLab Benchmark `1.0.1`.
- Repository review date: `2026-08-04`
- Required source input before mapping:
  - authorized official PDFs for the selected provider and exact version;
  - SHA-256 for each reviewed PDF;
  - recommendation identifiers, profiles, applicability, and automated/manual
    ownership;
  - license and reuse terms for repository metadata and generated views.
- Related controls and plans:
  - `PSB-SOURCE-002..004`, `PSB-CICD-001..006`, `PSB-DEPS-001..004`,
    `PSB-BUILD-001..003`, and `PSB-REL-001..004`;
  - the planned NIST SP 800-204D cross-control reconciliation.

Potential contribution:

- compare provider-specific repository, branch, identity, workflow, runner,
  dependency, build, and release recommendations with existing atomic checks;
- add only unique, automatable outcomes or explicit organization-owned
  evidence gaps;
- generate separate GitHub and GitLab adoption profiles so a recommendation
  for one platform is never applied to the other by name similarity.

Disposition and limitations:

- the 2022 general Guide and current provider Benchmarks are related but not
  interchangeable sources;
- no CIS requirement is mapped and no benchmark coverage is claimed while the
  authorized versioned PDFs and recommendation inventories are absent;
- the official discovery page is mutable and its displayed latest versions are
  update signals, not immutable evidence;
- third-party mirrors, paraphrased recommendation lists, and product names in
  the general Guide must not be used as framework identifiers.

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

<a id="ref-gov-002"></a>

### REF-GOV-002 — CISA Known Exploited Vulnerabilities Catalog

- Status: `adopted-partially`
- Type: official live vulnerability-exploitation prioritization data source
- Publisher: Cybersecurity and Infrastructure Security Agency (CISA)
- Official catalog:
  [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Machine-readable feeds:
  - [JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json);
  - [CSV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv);
  - [JSON Schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json).
- Source type: continuously updated; no static catalog version
- Repository review date: `2026-08-04`
- Related controls and plans:
  - `PSB-GOV-001` for exact product, component, artifact, and deployment impact
    lookup;
  - `PSB-GOV-003` for implemented product vulnerability triage and response
    priority;
  - `PSB-DETECT-001` and `PSB-DEPS-004` as finding and dependency-change
    sources, not KEV applicability authorities.

Adopted planning contribution:

- make an exact CVE match in a fresh, complete KEV snapshot a priority signal
  for an affected product case;
- retain catalog version metadata, collection time, item count, source digest,
  schema identity, and successful complete retrieval as evidence;
- separate `listed`, `not-listed`, and `catalog-unavailable` states;
- bind any due-date decision to an organization-owned remediation policy rather
  than silently adopting a federal-agency deadline as a universal SLA.

Disposition and limitations:

- absence from KEV does not mean a vulnerability is unexploited, low risk, or
  inapplicable to the product;
- catalog entries identify exploited CVEs but do not prove that a particular
  artifact or deployment is affected; `PSB-GOV-001` supplies that join;
- the live feed is external evidence, so stale, partial, malformed, schema-
  changed, or unavailable retrieval must be `ERROR`, never an empty clean set;
- KEV is a data source and prioritization input, not a compliance framework.

<a id="ref-gov-003"></a>

### REF-GOV-003 — FIRST PSIRT Maturity Document

- Status: `adopted-partially`
- Type: official PSIRT operational capability and maturity guidance
- Publisher: Forum of Incident Response and Security Teams (FIRST)
- Official source:
  [PSIRT Maturity Document](https://www.first.org/standards/frameworks/psirts/psirt_maturity_document)
- Version state: the official page does not declare an independent document
  version; treat it as mutable guidance and record the assessment review date
- Repository review date: `2026-08-04`
- Related plans:
  - `PSB-GOV-003` for the implemented executable vulnerability triage subset;
  - a later organization-owned PSIRT capability profile for maturity levels 1,
    2, and 3.

Adopted planning contribution:

- preserve separate evidence for charter, sponsorship, stakeholders, intake,
  qualification, analysis, remediation, disclosure, product inventory,
  communication, training, and metrics;
- start with the Basic capability outcomes and keep Intermediate and Advanced
  outcomes cumulative and visible as gaps;
- require organization evidence for operational claims instead of treating
  repository fixtures as proof that a PSIRT exists or is mature.

Disposition and limitations:

- the maturity guidance is not a substitute for the more detailed PSIRT
  Services Framework service/function inventory;
- the source itself notes that capability maturity is not the same as capacity
  or an organizational maturity model such as SIM3;
- no maturity level is claimed until a dated organization assessment supplies
  current evidence for every required outcome;
- the mutable source must be snapshotted and integrity-recorded before a
  machine-readable maturity profile is activated.

<a id="ref-gov-004"></a>

### REF-GOV-004 — FIRST PSIRT Services Framework 1.1

- Status: `adopted-partially`
- Type: official PSIRT service, function, and outcome framework
- Publisher: Forum of Incident Response and Security Teams (FIRST)
- Version: `1.1`
- Official source:
  [PSIRT Services Framework 1.1](https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1)
- Repository review date: `2026-08-04`
- Related plans:
  - `PSB-GOV-003` for vulnerability intake, analysis, prioritization,
    remediation ownership, and response evidence;
  - a later PSIRT capability profile for service-area assessment.

Adopted planning contribution:

- use stable service, function, and sub-function identities when building the
  future assessment inventory;
- keep product inventory, stakeholder communication, vulnerability discovery,
  triage, remediation, disclosure, and post-incident improvement evidence
  distinguishable;
- reconcile service outcomes with existing release, SBOM impact, exception,
  and incident-readiness controls before adding new control boundaries.

Disposition and limitations:

- service availability is organization-owned evidence and commonly requires
  `NOT_CHECKED` rather than a repository-generated pass;
- a service-framework relationship is not automatically a control mapping or
  proof of service quality, timeliness, capacity, or maturity;
- the future profile must record which functions are in scope, not applicable,
  externally provided, or unsupported instead of copying all source text.

<a id="ref-gov-005"></a>

### REF-GOV-005 — FIRST CVSS v4.0 Specification

- Status: `adopted-partially`
- Type: official vulnerability technical-severity scoring specification and
  machine-readable vector format
- Publisher: Forum of Incident Response and Security Teams (FIRST)
- Standard version: CVSS `4.0`
- Specification document revision: `1.2`, dated `2024-06-18`
- Official sources:
  - [CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document);
  - [CVSS v4.0 data representations](https://www.first.org/cvss/data-representations);
  - [CVSS v4.0 implementation guide](https://www.first.org/cvss/v4.0/implementation-guide).
- Repository review date: `2026-08-04`
- Related control: `PSB-GOV-003`

Adopted planning contribution:

- validate canonical CVSS 4.0 vector syntax, required Base metrics, ordering,
  duplicate metrics, and stored score/vector consistency;
- preserve Base, Threat, Environmental, and Supplemental metric provenance
  instead of reducing the case to one untraceable numeric value;
- combine technical severity with product applicability, KEV status, asset
  exposure, compensating controls, and organization policy for response
  priority.

Disposition and limitations:

- CVSS measures technical severity and is not by itself a risk score,
  remediation SLA, exploit prediction, or proof of product applicability;
- mutable Threat and Environmental observations require actor, collection
  time, and reassessment evidence;
- implementation must use a reviewed, pinned calculator or independently
  tested algorithm and malformed-vector fixtures; documentation alone cannot
  produce E3 evidence;
- CVSS is not used as a `control.yaml` compliance relationship.

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

<a id="ref-container-001"></a>

### REF-CONTAINER-001 — OWASP Docker Security Cheat Sheet

- Status: `reviewed`
- Type: community container implementation cheat sheet
- Publisher: OWASP Cheat Sheet Series
- Product scope: Docker, with selected Kubernetes examples
- Live URL:
  [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- Pinned source:
  [`Docker_Security_Cheat_Sheet.md` at `cb62ae45198d07302082d4725fc3bdfe24b25dd3`](https://github.com/OWASP/CheatSheetSeries/blob/cb62ae45198d07302082d4725fc3bdfe24b25dd3/cheatsheets/Docker_Security_Cheat_Sheet.md)
- Source commit date: `2026-05-12`
- Reviewed file SHA-256:
  `3442288cd44dda71aed39e82d6abb7d1d6ffb12350ad1a667d8299c2b5488a43`
- License:
  [CC BY-SA 4.0](https://github.com/OWASP/CheatSheetSeries/blob/cb62ae45198d07302082d4725fc3bdfe24b25dd3/LICENSE.md)
- Repository review date: `2026-07-30`
- Related plans:
  - `PSB-CONTAINER-001` — workload runtime baseline and admission;
  - `PSB-CONTAINER-002` — registry transport, authorization, audit, and
    lifecycle;
  - `PSB-CONTAINER-003` — container host and daemon hardening;
  - `PSB-CONTAINER-004` — post-admission runtime threat detection;
  - `PSB-DETECT-001` — image and runtime vulnerability detection;
  - `PSB-CODE-001` — secrets excluded from images;
  - release-integrity controls for signature and provenance evidence.
- Allocation:
  [Container Security Source Allocation](CONTAINER_SECURITY_SOURCE_ALLOCATION.md)

Adopted contribution:

- use its insecure and secure patterns to design tests for non-root execution,
  capability reduction, privilege-escalation prevention, network isolation,
  seccomp or other Linux security modules, resource limits, read-only
  filesystems, and admission enforcement;
- retain host and Docker updates, daemon socket protection, rootless mode,
  logging, secret injection, scanning, and supply-chain guidance under their
  separate control owners;
- treat product commands and Kubernetes snippets as implementation examples,
  not universal acceptance criteria.

Disposition and limitations:

- this cheat sheet is reference guidance, not a framework registry, and its
  rule numbers MUST NOT appear as `control.yaml` framework mappings;
- Docker-specific commands do not prove equivalent Kubernetes, containerd,
  CRI-O, managed-service, host, or cloud enforcement;
- examples may change after the pinned file commit and require semantic review
  before adoption;
- no tool mentioned by the cheat sheet is installed or authorized solely by
  this reference.

<a id="ref-container-002"></a>

### REF-CONTAINER-002 — Kubernetes workload and admission security guidance

- Status: `adopted-partially`
- Type: official platform configuration and admission implementation guidance
- Publisher: Kubernetes project
- Pinned source repository:
  [`kubernetes/website` at `e95679cfa58a843e90bf8575d8b0db548dae452b`](https://github.com/kubernetes/website/tree/e95679cfa58a843e90bf8575d8b0db548dae452b)
- Pinned source files:
  - [Security Context](https://github.com/kubernetes/website/blob/e95679cfa58a843e90bf8575d8b0db548dae452b/content/en/docs/tasks/configure-pod-container/security-context.md)
  - [Network Policies](https://github.com/kubernetes/website/blob/e95679cfa58a843e90bf8575d8b0db548dae452b/content/en/docs/concepts/services-networking/network-policies.md)
  - [Admission Webhook Good Practices](https://github.com/kubernetes/website/blob/e95679cfa58a843e90bf8575d8b0db548dae452b/content/en/docs/concepts/cluster-administration/admission-webhooks-good-practices.md)
- Live documentation:
  - [Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
  - [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
  - [Admission Webhook Good Practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
- Repository review date: `2026-07-30`
- Related control:
  - `PSB-CONTAINER-001` — Kubernetes workload and provenance admission.

Adopted contribution:

- use pod and container security contexts to express non-root execution,
  privilege-escalation denial, read-only filesystems, capability reduction,
  and runtime-default seccomp;
- require a NetworkPolicy that selects the intended workload and establishes
  default-deny ingress and egress before narrower allow policies;
- cover create and update operations, use a bounded timeout, and ensure
  validating enforcement does not turn evaluator failure into an allow;
- prefer built-in CEL admission for self-contained field checks, while
  retaining a narrowly scoped validating webhook adapter when external OCI
  provenance retrieval and cryptographic verification are required.

Disposition and limitations:

- Kubernetes product documentation is reference guidance, not a framework and
  does not create `control.yaml` mappings;
- a NetworkPolicy object has no effect when the selected cluster networking
  implementation does not enforce NetworkPolicy;
- webhook availability, dependency loops, API-version changes, RBAC, and
  upgrade compatibility require live platform evidence and staging tests;
- the pinned documentation source records reviewed semantics but does not pin
  a Kubernetes cluster version or prove that a cluster adopted them.

<a id="ref-container-003"></a>

### REF-CONTAINER-003 — Falco runtime event and health guidance

- Status: `adopted-partially`
- Type: official open-source runtime security product documentation
- Publisher: The Falco Project
- Reviewed release:
  [`falcosecurity/falco` `0.44.0`](https://github.com/falcosecurity/falco/releases/tag/0.44.0)
- Live documentation:
  - [JSON output](https://falco.org/docs/outputs/formatting/#json-output)
  - [Supported rule fields](https://falco.org/docs/reference/rules/supported-fields/)
  - [Metrics](https://falco.org/docs/metrics/)
- Repository review date: `2026-07-31`
- Related controls:
  - `PSB-CONTAINER-004` — Falco JSON adapter, workload identity, rule and
    drop-health verification;
  - `PSB-CONTAINER-003` — implemented provider-neutral host boundary plus
    future live sensor installation, kernel compatibility, and sensor
    hardening.

Adopted contribution:

- consume structured JSON fields instead of parsing human-formatted output;
- require workload, container, and exact image identity in every normalized
  event;
- treat kernel, internal-store, and output-queue drops as observation failure;
- pin the adapter contract and independently review the sensor artifact,
  configuration, and ruleset identity.

Disposition and limitations:

- Falco is a reference adapter, not a mandatory product or framework mapping;
- repository tests use sanitized synthetic events and do not install a
  privileged sensor or download a Falco artifact;
- the release tag pins the reviewed binary release, while live documentation
  can change and must be re-reviewed before an adapter-contract update;
- deployment privilege, driver choice, kernel support, performance, retention,
  and update verification remain live platform responsibilities under
  `PSB-CONTAINER-003`.

<a id="ref-container-004"></a>

### REF-CONTAINER-004 — Sysdig runtime event forwarding and agent health guidance

- Status: `adopted-partially`
- Type: official commercial runtime security product documentation
- Publisher: Sysdig
- Live documentation:
  - [Event forwarding](https://docs.sysdig.com/en/sysdig-secure/event-forwarding/)
  - [Runtime policy events](https://docs.sysdig.com/en/sysdig-secure/runtime-policy-events/)
  - [Sysdig Agent health metrics](https://docs.sysdig.com/en/sysdig-monitor/integrations/integration-library/sysdig-agent-health/)
- Reviewed adapter contract date: `2026-07-31`
- Related controls:
  - `PSB-CONTAINER-004` — Sysdig runtime policy event adapter, agent and
    forwarding-health verification;
  - `PSB-CONTAINER-003` — implemented provider-neutral host boundary plus
    future live agent installation and provider-specific hardening.

Adopted contribution:

- normalize runtime policy event arrays into the provider-neutral runtime
  schema;
- bind event fields to exact workload and image identity supplied at admission;
- verify agent health, connection, license, analyzer drop, and event forwarding
  status independently from a zero-event result;
- test end-to-end alert delivery separately from local detection.

Disposition and limitations:

- Sysdig is a reference adapter, not a mandatory product, purchase
  recommendation, or framework mapping;
- vendor SaaS documentation does not expose an immutable documentation commit,
  so the contract date is review metadata rather than an immutable source pin;
- `13.0.0-fixture` in repository data is synthetic schema input and is not a
  recommended product version;
- tests do not contact vendor APIs, use credentials, or prove subscription,
  deployment, retention, or incident-response configuration.

<a id="ref-deps-001"></a>

### REF-DEPS-001 — Takumi Guard dependency registry proxy

- Status: `adopted-partially`
- Type: package registry proxy product documentation
- Publisher: Flatt Security / Shisho Cloud
- Live URLs:
  - [Takumi Guard documentation](https://shisho.dev/docs/t/guard/)
  - [Quickstart and organization deployment](https://shisho.dev/docs/t/guard/quickstart/)
  - [Go proxy configuration](https://shisho.dev/docs/t/guard/quickstart/golang/)
  - [npm proxy configuration](https://shisho.dev/docs/t/guard/quickstart/npm/)
  - [Limitations](https://shisho.dev/docs/t/guard/limitation/)
- Immutable public documentation snapshot: not identified; retain the live URLs
  and review date, and re-review product behavior before production adoption
- Repository review date: `2026-07-31`
- Related controls:
  - `PSB-DEPS-001` — managed proxy routing and independent release cooldown;
  - `PSB-DEPS-003` — lockfile origin binding to the managed proxy;
  - `PSB-SOURCE-001` — MDM-distributed endpoint configuration and egress
    enforcement.

Adopted contribution:

- package-manager traffic is routed through a managed proxy for
  malicious-package blocking, download tracking, and breach notification;
- npm, pip, Go, and Composer receive centrally distributed client profiles;
- Go `direct` fallbacks and equivalent public-registry bypasses are prohibited;
- read-only install routing is separated from explicit login and publication;
- proxy failure is an error and is not converted to a clean direct install;
- the blocking path is tested only with a harmless provider canary.

Rejected or separate contribution:

- the provider blocklist is not treated as a release-age cooldown because the
  reviewed documentation does not specify the repository's 168-hour
  minimum-age guarantee;
- no global developer setting is silently modified by this repository;
- plaintext proxy credentials, real-malware test installation, and
  developer-optional routing are rejected;
- provider Actions or installers are not adopted without immutable pinning,
  integrity verification, permission review, and offline negative fixtures.

Disposition and limitations:

- Takumi Guard is an implementation example, not a framework mapping or the
  canonical control boundary;
- blocklist coverage cannot establish that every malicious package is blocked;
- local fixtures cannot prove MDM deployment, live provider availability, or
  actual public-registry egress denial.

<a id="ref-deps-002"></a>

### REF-DEPS-002 — GitHub dependency review guidance

- Status: `adopted-partially`
- Type: official source-platform dependency review documentation
- Publisher: GitHub
- Live documentation:
  - [Dependency review concepts](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
  - [Configure the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- Immutable documentation snapshot: not identified; re-review live option and
  event semantics before a production adapter upgrade
- Repository review date: `2026-07-31`
- Related controls:
  - `PSB-DEPS-004` — provider-neutral dependency graph delta and risk decision;
  - `PSB-CICD-001` — immutable Action identity if the GitHub adapter is used;
  - `PSB-CICD-004` and `PSB-CICD-005` — least privilege and untrusted PR
    boundaries.

Adopted contribution:

- compare dependency changes between the pull-request base and head state;
- evaluate introduced vulnerability severity, dependency scope, and license
  policy before merge;
- make the resulting status check required when used as a merge gate.

Extended repository requirements:

- retain direct and transitive package plus edge context;
- bind the decision to exact base/head graph and policy identities;
- review source registry, immutable source commit, provenance, non-author
  approval, and exact expiring exceptions in addition to vulnerability and
  license results;
- treat unavailable, partial, stale, and malformed provider evidence as
  `ERROR`, never as an empty safe diff.

Disposition and limitations:

- GitHub dependency review is an optional adapter, not a framework mapping or
  mandatory product;
- repository tests use synthetic provider-neutral fixtures and do not add or
  execute the Dependency Review Action;
- any future Action integration requires a full commit SHA, minimal
  permissions, safe pull-request context, and provider availability evidence;
- advisory coverage and ecosystem support can be incomplete, and no clean
  result proves that dependency code is non-malicious.

<a id="ref-detect-001"></a>

### REF-DETECT-001 — Trivy release integrity and offline execution guidance

- Status: `adopted-partially`
- Type: official scanner release, integrity-verification documentation, and
  security incident advisory
- Publisher: Aqua Security, with GitHub Advisory Database incident record
- Pinned implementation source:
  [`aquasecurity/trivy` at `8a32853686209a428179bb3a1688802b25691564`](https://github.com/aquasecurity/trivy/tree/8a32853686209a428179bb3a1688802b25691564)
- Pinned release:
  [Trivy v0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0)
- Release state: GitHub API reported `immutable: true` on `2026-07-30`
- Reviewed Linux archive SHA-256:
  `bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea`
- Official documentation:
  - [release signature verification](https://trivy.dev/latest/docs/advanced/signatures/)
  - [air-gapped and offline operation](https://trivy.dev/latest/docs/advanced/air-gap/)
- Supplemental incident record:
  [GHSA-69fq-xp46-6x23](https://github.com/advisories/GHSA-69fq-xp46-6x23)
- Repository review date: `2026-07-30`
- Related control:
  - `PSB-DETECT-001` — integrity-verified scanner execution and sanitized
    fail-closed evidence.

Adopted contribution:

- verify the release asset, publisher checksum file, Sigstore bundle, OIDC
  issuer, and exact release-workflow certificate identity before extraction;
- record the extracted scanner binary digest as an additional local execution
  identity;
- separate explicit network-enabled DB or tool acquisition from ordinary
  offline scan execution;
- disable DB, Java DB, checks-bundle, VEX, version-check, and telemetry network
  updates in the offline runner;
- retain affected release identities as negative fixtures rather than assuming
  a pinned version is safe merely because it is immutable.

Disposition and limitations:

- the official product documentation is implementation guidance, not a
  framework and not a `control.yaml` mapping source;
- a committed verification receipt is only a deterministic fixture;
  production execution requires fresh successful checksum and Sigstore
  verification evidence;
- `cosign` remains a separate bootstrap trust dependency and must be supplied
  through an organization-approved integrity process;
- the latest documentation URLs can change; the implementation source and
  release bytes stay pinned until a reviewed upgrade changes them.

<a id="ref-detect-002"></a>

### REF-DETECT-002 — OWASP DockSec container remediation orchestrator

- Status: `adopted-partially`
- Type: OWASP Lab Project tool and developer-remediation reference
- Publisher: OWASP DockSec project
- Official project page: [OWASP DockSec](https://owasp.org/DockSec/)
- Pinned reviewed source:
  [`OWASP/DockSec` at `4ddcb5285f437c0e84a42c748b0f61f56543e344`](https://github.com/OWASP/DockSec/tree/4ddcb5285f437c0e84a42c748b0f61f56543e344)
- Pinned PyPI release:
  [DockSec 2026.7.5](https://pypi.org/project/docksec/2026.7.5/)
- Reviewed wheel SHA-256:
  `7f8781db7651216556c86c71ab45527bc484801b974ff264fe0ebe7f70a6f5fb`
- PyPI publication state: the reviewed wheel was not uploaded with Trusted
  Publishing
- Reviewed upstream integration files:
  - [`action.yml`](https://github.com/OWASP/DockSec/blob/4ddcb5285f437c0e84a42c748b0f61f56543e344/action.yml)
  - [`Dockerfile`](https://github.com/OWASP/DockSec/blob/4ddcb5285f437c0e84a42c748b0f61f56543e344/Dockerfile)
  - [`entrypoint.sh`](https://github.com/OWASP/DockSec/blob/4ddcb5285f437c0e84a42c748b0f61f56543e344/entrypoint.sh)
  - [`docksec/cli.py`](https://github.com/OWASP/DockSec/blob/4ddcb5285f437c0e84a42c748b0f61f56543e344/docksec/cli.py)
- Repository review date: `2026-07-31`
- Related controls:
  - `PSB-DETECT-001` — pinned optional Dockerfile and Compose remediation
    adapter with an AI-independent fail-closed gate;
  - `PSB-IAC-001` — Golden Path composition consumes the `PSB-DETECT-001`
    adapter without creating a separate security outcome.

Adopted contribution:

- use DockSec only for its documented unique developer-facing value:
  contextual Dockerfile remediation and multi-service Compose correlation;
- retain Trivy as the primary reviewed scanner rather than duplicating
  vulnerability ownership;
- run the authoritative gate with `--scan-only`, `--offline`, `--json`,
  `--no-cache`, and `--fail-on high`;
- normalize upstream status `0` to clean, `1` to finding, and both `2` and `3`
  to project `ERROR`;
- remove LLM provider credentials from the gate process and reject unexpected
  AI output;
- keep AI remediation optional and non-blocking.

Rejected or deferred contribution:

- the upstream GitHub Action is not adopted even at a full commit SHA because
  its reviewed Dockerfile downloads Hadolint through a mutable `latest` URL
  and installs Trivy through `curl | sh`;
- `python -m docksec.setup_external_tools` is not used because every downloaded
  scanner must be pinned and integrity-verified separately;
- `docksec install-skill` is not run because it writes AI-agent instruction
  files that require the independent `PSB-AI-002` review boundary;
- `--no-redact`, AI scores as release decisions, broad baselines, and
  non-expiring ignores are not accepted.

Disposition and limitations:

- DockSec is a tool and reference source, not a framework or a source of
  `control.yaml` requirement identifiers;
- a pinned wheel hash does not establish publisher identity, semantic safety,
  or transitive dependency integrity;
- the committed adapter does not build the production Python environment;
  adopters must provide a reviewed hash-locked environment plus independently
  verified Trivy, Hadolint, and database evidence;
- application-level offline flags do not replace an OS-level network sandbox
  for an untrusted executable;
- AI suggestions can be incomplete or incorrect and require validation against
  the original structured scanner finding and human review.

<a id="ref-rel-001"></a>

### REF-REL-001 — OWASP Dependency-Track SBOM portfolio and analysis platform

- Status: `adopted-partially`
- Type: official OWASP software supply-chain analysis platform, API
  documentation, permission model, and event contract
- Publisher: OWASP Dependency-Track project
- Official project: [Dependency-Track](https://dependencytrack.org/)
- Pinned adapter release:
  [Dependency-Track 4.14.3](https://github.com/DependencyTrack/dependency-track/releases/tag/4.14.3)
- Release state: GitHub reported the `4.14.3` release as immutable on
  `2026-07-31`
- Reviewed API server JAR SHA-256:
  `11a5c85616b745803b5653016d9da2195f2e23ac66fe6a85d2ae2b4661d393a9`
- Official documentation:
  - [CI/CD SBOM publication](https://docs.dependencytrack.org/usage/cicd/)
  - [notifications and BOM processing events](https://docs.dependencytrack.org/integrations/notifications/)
  - [users and permissions](https://docs.dependencytrack.org/administration/users-and-permissions/)
  - [REST API and OpenAPI discovery](https://docs.dependencytrack.org/integrations/rest-api/)
  - [version 5 documentation](https://dependencytrack.github.io/docs/next/)
- Repository review date: `2026-07-31`
- Related controls:
  - `PSB-REL-003` — distinct source/build/deployment observation identities,
    exact artifact-bound CycloneDX publication, least-privilege upload, and
    completed processing receipt verification;
  - `PSB-GOV-001` — exact CVE and component portfolio search linked back to
    SBOM serials, project UUIDs, versions, build records, and response evidence;
  - `PSB-IAC-001` — Golden Path composition of the implemented
    `PSB-REL-003` outcome without duplicating SBOM control ownership.

Adopted contribution:

- use Dependency-Track as an organization SBOM consumer and portfolio index,
  not as the source of release-artifact identity;
- upload to a pre-created exact project UUID and release version with a
  separate `BOM_UPLOAD`-only identity;
- treat the upload token or `BOM_CONSUMED` event as acceptance, not successful
  analysis, and require a bound `BOM_PROCESSED` result;
- map `BOM_PROCESSING_FAILED`, `BOM_VALIDATION_FAILED`, timeout, analyzer
  outage, stale vulnerability data, and incomplete pagination to `ERROR`;
- separate upload identity from read-only incident search using
  `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`;
- normalize provider output to sanitized metadata that excludes API keys, BOM
  bodies, internal endpoints, and unnecessary vulnerability details;
- require exact CVE, component PURL, project UUID and version, SBOM serial, and
  local build-evidence linkage before accepting an impact result.

Rejected or deferred contribution:

- `autoCreate` and `PROJECT_CREATION_UPLOAD` are not part of the normal upload
  path because ambiguous project creation weakens release identity binding;
- broad `SYSTEM_CONFIGURATION`, portfolio mutation, policy-management, or
  vulnerability-analysis permissions are not assigned to upload or read-only
  search jobs;
- the recommended GitHub Action is not adopted without a separate full-SHA,
  internal-download, permission, and credential-flow review;
- Dependency-Track is not treated as a replacement for lockfile integrity,
  local fail-closed scanning, provenance, signature verification, or incident
  evidence;
- version `5.0.3` was the latest major release observed during review, but the
  repository adapter deliberately remains on the reviewed `4.14.3` contract
  because version 5 changes distribution, REST API, migration, and
  notification semantics. Migration requires a separate semantic diff and
  regression evidence.

Disposition and limitations:

- Dependency-Track is an implementation tool and reference, not a framework
  and not a source of `control.yaml` requirement identifiers;
- the committed adapter is offline and verifies normalized fixtures; it does
  not deploy a server, authenticate, upload a production BOM, or prove
  portfolio ACL coverage;
- platform vulnerability results depend on external advisory freshness, PURL,
  CPE, alias, ecosystem, and affected-version quality and can produce false
  positives or false negatives;
- SBOM upload is an untrusted-input boundary and production deployments need
  parser hardening, size limits, current security fixes, isolation, and
  monitoring;
- a processed SBOM and an empty finding set do not prove that the software is
  vulnerability-free.

<a id="ref-rel-002"></a>

### REF-REL-002 — SBOM lifecycle, operational inventory, and interchange guidance

- Status: `adopted-partially`
- Type: official government consumption guidance and open-standard
  documentation
- Publishers: CISA, OWASP CycloneDX, and the SPDX Project
- Official sources:
  - [CISA Recommended Practices for SBOM Consumption](https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_RECOMMENDED_PRACTICES_FOR_SOFTWARE_BILL_OF_MATERIALS_CONSUMPTION-508.pdf)
  - [CISA SBOM Resources Library](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary)
  - [CycloneDX SBOM capability](https://cyclonedx.org/capabilities/sbom/)
  - [CycloneDX Operations BOM capability](https://cyclonedx.org/capabilities/obom/)
  - [CycloneDX 1.7 JSON reference](https://cyclonedx.org/docs/1.7/json/)
  - [SPDX specifications](https://spdx.dev/use/specifications/)
  - [SPDX 3.0.1 specification](https://spdx.dev/wp-content/uploads/sites/31/2024/12/SPDX-3.0.1-1.pdf)
- Repository review date: `2026-07-31`
- Related controls:
  - `PSB-REL-003`;
  - `PSB-GOV-001`;
  - `PSB-REL-004`.

Adopted contribution:

- treat SBOM as machine-readable component and relationship evidence across
  lifecycle use cases rather than a one-time file;
- keep operational environment inventory distinguishable from the software
  release SBOM and link both by exact artifact identity;
- use a portfolio to answer what and where is affected while retaining source
  evidence and explicit completeness;
- keep standardized formats interoperable without claiming support for a
  format that the repository does not parse and test.

Disposition and limitations:

- these sources are references, not framework mappings or compliance claims;
- the current executable adapter remains CycloneDX 1.7 JSON only;
- SPDX 3.1 was observed as a release candidate and is not pinned as an
  implemented production format;
- CISA consumption guidance informs supplier intake, while `PSB-REL-004`
  supplies an E3 local signature, signer-status, exact identity, and quarantine
  boundary; production PKI, transparency, and remote revocation adapters remain
  deployment-specific.

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
- implementation sources selected while delivering and extending
  `PSB-DETECT-001` and the SBOM consumption path, recorded as
  `REF-DETECT-001..002` and `REF-REL-001..002`;
- dependency registry proxy documentation selected for the managed acquisition
  path in `PSB-DEPS-001`, recorded as `REF-DEPS-001`;
- Kubernetes platform guidance selected while delivering
  `PSB-CONTAINER-001`, recorded as `REF-CONTAINER-002`;
- four substantial user-supplied source texts or tables, recorded as
  `REF-USER-001..003` and `REF-USER-005`;
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
