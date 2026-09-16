# PSB-SOURCE-004: Source access credential lifecycle

さらに具体的に学ぶ：[Learning note](learning.md)

設計する：[Engineering Pattern](../../../../engineering/source-protection/source-access-credential-lifecycle/README.md)

## 問い

Source platformへ到達するcredentialとsessionを、必要な主体、目的、resource、operation、期間へ限定し、
用途終了・異動・退職・端末紛失・漏えい時に、古いauthorityを拒否できるか。

## できてはいけないこと

盗まれた、過剰な、所有者不明の、または不要になったcredentialが、元のtaskを越えてsource、workflow、
release、organization情報へアクセスできる状態を維持してはいけません。

## なぜ重要か

Credentialは単なる秘密文字列ではなく、source platformがoperationを許可するauthorityです。
安全な場所へ保存していても権限が広すぎれば被害範囲は広く、短命でも関連sessionが残れば失効は完了しません。
保管、権限、期間、棚卸し、失効、監査を一つのlifecycleとして扱います。

## 適用範囲

Developerまたはautomationがsource platformへ接続するOAuth grant、access token、PAT、SSH authentication key、
application／workload identityと、それらから作られるsessionに適用します。

次は直接の対象ではありません。

- Developer endpoint全体のpatch、EDR、disk encryption。
- Source platform上のmember、team、repository default全体のgovernance。
- Credential漏えい後のsource、clone、artifactを横断したincident response全体。
- AgentやMCP toolがcredentialを取得した後のtool authorization。

## 必要なSecurity Properties

| ID | 成立すべき状態 |
|---|---|
| `SRC-AUTH-1` | 各authorityをactor、purpose、resource、operation、期限へ明示的に結び付ける |
| `SRC-AUTH-2` | Credentialの発行と機微な変更は、対象riskに適した強いauthenticationを通る |
| `SRC-AUTH-3` | Automationはdeveloper個人の再利用可能credentialではなく、taskに限定したworkload identityを使う |
| `SRC-AUTH-4` | Credentialは保護された場所に保存し、必要なconsumerだけへ配送する |
| `SRC-AUTH-5` | Current inventoryを定期reviewし、lifecycle event後にcredentialと関連sessionを失効して旧authorityの拒否を確認する |
| `SRC-AUTH-6` | 発行、grant変更、利用、失効をownerとresourceへ相関できる |

## 実装判断の羅針盤

1. 最初に「誰が、何へ、何をするか」を決め、credential種別はその後で選ぶ。
2. Humanのinteractive accessとautomation identityを分ける。
3. Credentialの名称ではなく、実際のresource、permission、lifetime、delivery pathを評価する。
4. 自動expiryだけに依存せず、offboarding、role change、loss、exposureを失効triggerにする。
5. Replacement発行やfile削除をrevocationと呼ばず、古いauthorityの拒否を確認する。
6. Audit logをcurrent authorizationの代替にしない。現在のgrantと過去eventを別々に確認する。

Product固有の画面名や設定値はControlへ固定しません。GitHub向けの一案は
[GitHub Implementation](../../../../engineering/source-protection/source-access-credential-lifecycle/implementations/github/README.md)にあります。

## 判定のCalibration

| Observation | このControlの判断 |
|---|---|
| Tokenがkeychainにあるが、全repositoryへのwrite権限を持つ | Fail。Storageだけではauthorityが狭くならない |
| Fine-grained tokenだがowner、repository、期限を確認していない | Passを裏付けない |
| Automationがdeveloper PATを使っている | Fail候補。Humanとworkloadのlifecycleを分離できない |
| 新しいcredentialへ切り替えたが旧credentialをrevokeしていない | Fail。Replacementはrevocationではない |
| Provider APIを取得できない | 安全とは判断できない。Assessmentでは`NOT_CHECKED`または`ERROR` |
| Agentが正しくscopedされたcredentialで危険なwrite toolを呼べる | Credential controlとは隣接するruntime authorizationの問題 |

## 保証しない範囲

このControlは、source platform、IdP、organization owner、認証済みendpoint sessionが侵害されないことを
保証しません。正当に取得済みのcloneや流出済みsourceもrevocationでは回収できません。

## Related artifacts

- [Learning note](learning.md)
- [Engineering Pattern](../../../../engineering/source-protection/source-access-credential-lifecycle/README.md)
- [Credentialは文字列ではなく委任されたauthority](../../../../docs/insights/credential-is-delegated-authority.md)
- [Security効果はEnforcement Pointに宿る](../../../../docs/insights/security-effects-live-at-enforcement-points.md)
- [Pilot mapping](../../../../mappings/pilot.yaml)
- [Framework mappings](../../../../mappings/frameworks.yaml)
- [Sources and Specifications](../../../../sources/README.md)

## 参照仕様とmapping

| Source | Exact version／ID | Relationship |
|---|---|---|
| GitHub Security Guidance | `github/docs@b17436d...`／`GHSC-SECURE-ACCOUNTS`、`GH-ADMIN-CREDENTIAL-TYPES`、`GH-ADMIN-SAML-IAM`、`GH-ADMIN-SCIM-ORGANIZATIONS` | GitHub実装を`supports` |
| MITRE ATT&CK | `v19.1`／`T1078`、`T1552.001` | Valid account abuseとfile内credential露出を`mitigates` |
| NIST SSDF | `1.1 (SP 800-218, 2022)`／`PS.3.1` | Source protectionを`supports` |
| OpenSSF OSPS Baseline | `2026.02.19`／`OSPS-AC-01.01` | 機微操作のMFAを`supports` |
| OWASP Agentic Top 10 | `2026`／`ASI03` | MCP等のagent-mediated accessに限り`mitigates` |

Exact commit、property allocation、rationale、review stateは
[Framework mappings](../../../../mappings/frameworks.yaml)にあります。Mappingは組織導入、完全coverage、
またはformal complianceの主張ではありません。

## Primary references

- [Central source record](../../../../sources/README.md#spec-github-security-guidance)
- [REF-AI-004 GitHub MCP guidance](../../../../sources/README.md#ref-ai-004)
- [REF-USER-001 endpoint hardening input](../../../../sources/README.md#ref-user-001)
- [GitHub: Managing programmatic access to your organization](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization)
- [GitHub: Credential types](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types)
- [GitHub: Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub: Reviewing the audit log for your organization](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
