# Sources and Specifications

このdirectoryは、Control、Learning、Engineering Pattern、Implementationの判断根拠を追跡するための
source registryです。旧リポジトリの`docs/SECURITY_GUIDANCE_SOURCES.md`が担っていた役割を継承します。

## 何に使うか

中央recordは「どの外部資料を、どのversionで、どう解釈し、何を採用・除外したか」を答えます。
各Artifact側は、source IDを使って「その資料が、この判断のどこに影響したか」を答えます。

Source recordはControl requirementそのものではなく、組織導入やcomplianceの証拠でもありません。
Framework mappingは[Framework mappings](../mappings/frameworks.yaml)で別に管理します。

## Source roles

| Role | 用途 | 例 |
|---|---|---|
| `normative-specification` | requirementまたは仕様の正確な意味を確認する | NIST SSDF |
| `threat-taxonomy` | 攻撃者のbehaviorやrisk categoryを分類する | MITRE ATT&CK |
| `vendor-guidance-registry` | 製品固有の安全な構成とprovider evidenceを解釈する | GitHub Docs |
| `product-specification` | option、metadata、resolver behaviorを確認する | npm CLI docs |
| `implementation-guidance` | 設計・導入候補を発見し、採否を判断する | Dependency Cooldowns |
| `user-supplied-input` | Repository利用者が提供した原文を追跡する | endpoint hardening guideline |
| `incident-research` | Threat scenarioを具体化する | 公開incident report |

## Usage rules

1. Public repositoryがあるsourceは、可能な限りcommit、tag、digestへ固定する。
2. Live URLしかないsourceは確認日と`re-review-required`を持たせ、固定済みと表現しない。
3. Product documentationをprovider-neutralなControl boundaryへ昇格させない。
4. Community indexは機能発見に使えても、公式な製品仕様の代替にしない。
5. Sourceの推奨を採用しない場合も、Security上重要なら除外理由を残す。
6. Framework IDとの関係はMappingで表し、Source recordをcompliance mappingにしない。
7. ControlやImplementationを変更する際、参照する仕様を削除せず、置換先または非採用理由を残す。

## Pilot source catalog

### Normative specifications and taxonomies

<a id="spec-github-security-guidance"></a>

#### SPEC-GITHUB-SECURITY-GUIDANCE — GitHub Security Guidance registry

- Role: `vendor-guidance-registry`
- Publisher: GitHub
- Exact baseline: `github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8`
- Source commit date: `2026-07-24`
- Registry review date: `2026-07-27`
- Immutable source:
  [github/docs commit](https://github.com/github/docs/commit/b17436de8f10c3e7f6a185d6813bf94bc82d22f8)
- Pilot requirement IDs:
  - `GHSC-SECURE-ACCOUNTS` — account security;
  - `GH-ADMIN-CREDENTIAL-TYPES` — GitHub credential types;
  - `GH-ADMIN-SAML-IAM` — SAML identity and access management;
  - `GH-ADMIN-SCIM-ORGANIZATIONS` — organization SCIM lifecycle.
- Used by: `PSB-SOURCE-004`／`SRC-AUTH-1..6`
- Boundary: GitHub固有の実装根拠であり、GitHub deploymentの安全性やformal complianceを証明しない。

Provider navigation:

- [Best practices for securing accounts](https://docs.github.com/en/code-security/tutorials/implement-supply-chain-best-practices/securing-accounts)
- [GitHub credential types](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types)
- [SAML identity and access management](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on)
- [SCIM for organizations](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-scim-for-organizations)

<a id="spec-nist-ssdf-1-1"></a>

#### SPEC-NIST-SSDF-1.1 — NIST SP 800-218

- Role: `normative-specification`
- Exact publication: NIST SP 800-218, SSDF version `1.1`, 2022
- Official source: [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- Pilot requirement IDs: `PS.3.1`, `PW.4.1`
- Used by: `PSB-SOURCE-004`, `PSB-DEPS-001`
- Boundary: Mappingは特定practiceを支援する関係であり、SSDF準拠を意味しない。

<a id="spec-mitre-attack-v19-1"></a>

#### SPEC-MITRE-ATTACK-v19.1 — MITRE ATT&CK Enterprise

- Role: `threat-taxonomy`
- Exact content version: `v19.1`
- Official source: [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/)
- Pilot technique IDs: `T1078`, `T1552.001`, `T1195.001`
- Used by: `PSB-SOURCE-004`, `PSB-DEPS-001`
- Boundary: Attack behaviorとの関係を示すもので、verification requirementやcomplianceではない。

<a id="spec-openssf-osps-2026-02-19"></a>

#### SPEC-OPENSSF-OSPS-2026.02.19 — OpenSSF OSPS Baseline

- Role: `normative-specification`
- Version／tag: `2026.02.19`／`v2026.02.19`
- Source commit: `e67ae247ebfb2fd758c9d186335e60cad0a74e78`
- Reviewed rendered source SHA-256:
  `54d13befdb1ae4c63b8612acabc1f0d716874be4187d25801d6ba2d6eee98271`
- Pilot requirement ID: `OSPS-AC-01.01`
- Used by: `PSB-SOURCE-004`／`SRC-AUTH-2`
- Boundary: Project maturityまたはOSPS conformanceの判定ではない。

<a id="spec-owasp-agentic-2026"></a>

#### SPEC-OWASP-AGENTIC-2026 — OWASP Top 10 for Agentic Applications

- Role: `threat-taxonomy`
- Exact publication: `OWASP Top 10 for Agentic Applications 2026`
- Publication date: `2025-12-09`
- Pilot category: `ASI03`
- Official source:
  [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Used by: `PSB-SOURCE-004`のGitHub MCP適用時
- Boundary: Agentic risk category全体のcoverageやagentの安全性を意味しない。

### Reviewed guidance retained from the legacy source catalog

<a id="ref-ai-004"></a>

#### REF-AI-004 — GitHub MCP official authentication and governance guidance

- Role: `implementation-guidance`
- Status: `adopted-partially`
- Publisher: GitHub
- Pinned repository baseline: `github/github-mcp-server@3778a41476e31a072430cfee7c5d31c5f72def60`
- Baseline／review date: `2026-08-05`
- License: MIT at the pinned baseline
- Immutable sources:
  - [README](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/README.md)
  - [Policies and governance](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/docs/policies-and-governance.md)
- Live product documentation:
  [Setting up the GitHub MCP Server](https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server)
- Used by: `SRC-AUTH-1`、`SRC-AUTH-3..6`、GitHub Implementation
- Adopted: OAuth-first、bounded PAT fallback、child-process限定delivery、read-only tool exposure。
- Not adopted as proof: IDE secret persistence、live organization policy、binary integrity、runtime authorization。

<a id="ref-user-001"></a>

#### REF-USER-001 — Developer endpoint hardening guideline

- Role: `user-supplied-input`
- Legacy status: `adopted`; Pilot use: `adopted-partially`
- Provided date: `2026-07-28`
- Legacy original:
  `controls/source-protection/developer-endpoint-hardening/docs/user-supplied-endpoint-hardening-guideline-ja.md`
- External bibliography／license: not supplied
- Used by: `SRC-AUTH-2`、`SRC-AUTH-4`
- Adopted: phishing-resistant authentication、protected key／secret storage、short-lived credentialの考え方。
- Boundary: Endpoint hardening全体は`PSB-SOURCE-004`へ統合しない。原文の再配布可否も未確定。

<a id="ref-deps-001"></a>

#### REF-DEPS-001 — Takumi Guard dependency registry proxy

- Role: `implementation-guidance`
- Status: `adopted-partially` as an adjacent pattern
- Publisher: Flatt Security／Shisho Cloud
- Review date: `2026-07-31`
- Immutable documentation snapshot: not identified; `re-review-required`
- Live sources:
  - [Takumi Guard](https://shisho.dev/docs/t/guard/)
  - [Quickstart](https://shisho.dev/docs/t/guard/quickstart/)
  - [npm proxy configuration](https://shisho.dev/docs/t/guard/quickstart/npm/)
  - [Limitations](https://shisho.dev/docs/t/guard/limitation/)
- Used by: `PSB-DEPS-001`の隣接するmanaged proxy option。
- Boundary: Provider blocklistは168時間のrelease-age gateではなく、cooldownの代替にしない。

<a id="ref-deps-004"></a>

#### REF-DEPS-004 — Dependency Cooldowns operational compatibility index

- Role: `implementation-guidance`
- Status: `adopted-partially`
- Publisher: mprpic／Dependency Cooldowns contributors
- License: MIT
- Review date: `2026-08-10`
- Immutable reviewed snapshot: not vendored or executed; `re-review-required`
- Discovery sources:
  - [Dependency Cooldowns](https://cooldowns.dev/)
  - [mprpic/cooldowns](https://github.com/mprpic/cooldowns)
- Official product specifications used to verify candidates:
  - [npm configuration](https://docs.npmjs.com/cli/v11/using-npm/config/)
  - [npm install](https://docs.npmjs.com/cli/install/)
  - [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
  - [uv dependency resolution](https://docs.astral.sh/uv/concepts/resolution/)
  - [uv settings](https://docs.astral.sh/uv/reference/settings/)
  - [pnpm dependency resolution settings](https://pnpm.io/settings/dependency-resolution)
  - [Yarn configuration](https://yarnpkg.com/configuration/yarnrc/)
  - [Yarn security features](https://yarnpkg.com/features/security)
  - [pip install](https://pip.pypa.io/en/stable/cli/pip_install/)
- Used by: `DEP-AGE-1..6`、npm Implementation。
- Adopted: native gate／CI gate／proxyを区別し、設定precedence、missing metadata、bypassを確認する。
- Rejected: helper scriptの実行、global設定の暗黙変更、外部exampleの時間をpolicy baselineとすること。

### Product specifications used by the Pilot

<a id="spec-npm-cli-11"></a>

#### SPEC-NPM-CLI-11 — npm minimum release age behavior

- Role: `product-specification`
- Reviewed implementation floor inherited from the legacy control: npm `11.10.0`
- Configuration surface: `min-release-age`, measured in days
- Official documentation:
  - [npm configuration v11](https://docs.npmjs.com/cli/v11/using-npm/config/)
  - [npm install](https://docs.npmjs.com/cli/install/)
  - [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- Release history used by the legacy review:
  [npm CLI changelog for 11.10.0](https://github.com/npm/cli/blob/latest/CHANGELOG.md#11100-2026-02-11)
- Current state: exact npm source tag／commit is not yet recorded in this Pilot; `re-review-required`。
- Used by: npm Implementation、`DEP-AGE-3..5`。
- Boundary: Unknown-keyの保存や`npm config get`の表示だけではresolver enforcementを証明しない。

<a id="spec-npm-registry-metadata"></a>

#### SPEC-NPM-REGISTRY-METADATA — npm registry package metadata

- Role: `product-specification`
- Official source:
  [npm registry package metadata response](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- Current state: URLはmutable `main`を指すため、production adapter採用前にimmutable sourceへ固定する。
- Used by: `DEP-AGE-1`、`DEP-AGE-2`。
- Boundary: Registry metadataのschemaを参照しても、registry自体の非侵害やtimestamp真正性は証明しない。

<a id="incident-context-retained-for-learning"></a>

### Incident context retained for learning

- `RESEARCH-DEPS-CHECKMARX`:
  [Bitwarden statement on the Checkmarx supply-chain incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- `RESEARCH-DEPS-AXIOS`:
  [Axios npm supply-chain compromise postmortem](https://github.com/axios/axios/issues/10636)

これらはThreat scenarioを具体化する資料です。Cooldownの閾値、製品仕様、ControlへのPass条件は定義しません。

## Pilot traceability

| Artifact | Direct source IDs | Mapping source IDs |
|---|---|---|
| `PSB-SOURCE-004` | `SPEC-GITHUB-SECURITY-GUIDANCE`, `REF-AI-004`, `REF-USER-001` | `SPEC-NIST-SSDF-1.1`, `SPEC-MITRE-ATTACK-v19.1`, `SPEC-OPENSSF-OSPS-2026.02.19`, `SPEC-OWASP-AGENTIC-2026` |
| GitHub source-credential Implementation | `SPEC-GITHUB-SECURITY-GUIDANCE`, `REF-AI-004` | 同上。ただしMCP条件付きmappingを含む |
| `PSB-DEPS-001` | `REF-DEPS-004`, `SPEC-NPM-REGISTRY-METADATA` | `SPEC-NIST-SSDF-1.1`, `SPEC-MITRE-ATTACK-v19.1` |
| npm cooldown Implementation | `SPEC-NPM-CLI-11`, `REF-DEPS-004` | Control mappingを自動継承しない |
| Managed proxy option | `REF-DEPS-001` | Cooldown mappingを自動継承しない |

## Non-pilot migration state

旧`docs/SECURITY_GUIDANCE_SOURCES.md`にある他の`REF-*`は削除または否定していません。このPilotの対象外として
legacy source catalogに残し、対応するControl／Patternを移すときにsource recordごと移行します。
