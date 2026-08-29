# PSB-SOURCE-006: GitHub Organization governance

## このcontrolを一枚で理解する

| 項目 | 内容 |
|---|---|
| セキュリティ上の問題 | Repository単位の保護が正しくても、OrganizationのOwner、member、team、outside collaborator、既定値、Actions、App、security configuration、auditにdriftがあると管理面からsource protectionを迂回できる。 |
| 誰から、または何から守るか | Phished Owner、侵害されたmemberやApp、退職者、放置されたcontractor、誤操作する管理者、IdP同期不良、不完全なAPI収集、audit／alert障害から守る。 |
| 何が対象か | 一つのGitHub Organizationと、それに接続するIdP、全repository、Organization-wide Actions policy、App、security configuration、監査運用。 |
| 何をするか | GitHubとIdPの実設定を下記のminimum baselineへ変更し、各`GHO-001`〜`GHO-010`をcurrent UIまたはread-only APIと実運用結果で確認する。 |
| 成功状態 | 全10 checkがcurrent stateで満たされ、設定者とは別のreviewer、取得時刻、対象、確認結果が記録される。取得不能・partial・staleは`PASS`にしない。 |
| 対象外・残余リスク | Documentation、policy JSON、fixture、verifierのcopyだけではGitHubは安全にならない。GitHub／IdP自体の侵害、repository-local workflow、credential lifecycle、backup、特権変更承認は別controlで扱う。 |

## 最短の導入手順

1. Organization Owner、IdP administrator、repository administrator、CI platform、Securityを決める。
2. GitHub planとenterprise policyで利用できる設定を確認し、変更ticketと二人目のOwnerを用意する。
3. [GitHub adoption runbook](docs/github-adoption-runbook.md)の順に、live settingを`GHO-002`〜`GHO-009`のminimumへ変更する。
4. 同runbookのread-only APIまたはUI確認を実施し、`GHO-001`と`GHO-010`を含めて結果を記録する。
5. 全checkにcurrent evidence、reviewer、次回review日があることをSecurityが確認する。

最小導入にcollector、SaaS App、自動remediationは不要です。組織規模により必要になった場合の案だけを
[automation options](docs/governance-automation-options.md)に分離しています。

## Minimum baseline

詳細なUI path、read-only API、期待結果、plan制約は各checkのリンク先にあります。

| Check | 変更する実設定・運用 | 最小値 | 担当 |
|---|---|---|---|
| [`GHO-001`](docs/github-adoption-runbook.md#gho-001-target-and-evidence) | Organization targetと収集境界 | numeric ID／node IDで対象を固定し、全page、取得時刻、source health、policy digestを記録。24時間以内 | Security |
| [`GHO-002`](docs/github-adoption-runbook.md#gho-002-authentication-and-provisioning) | `Settings > Security > Authentication security`とIdP | 2FAとSAML SSOをrequired、SCIMまたはEMUをhealthy、unlinked identity 0、offboarding 24時間以内 | Organization Owner／IdP administrator |
| [`GHO-003`](docs/github-adoption-runbook.md#gho-003-organization-owners) | `People > Role: Owner` | 2〜3名の記名human、phishing-resistant authentication、90日以内review | Organization Owner／Security |
| [`GHO-004`](docs/github-adoption-runbook.md#gho-004-members-teams-and-outside-collaborators) | `People`、`Teams`、outside collaborator grants | current sponsor、exact repository、最小permission。Outside collaboratorは原則`pull`／`triage`、90日以内expiry／review | Repository administrator |
| [`GHO-005`](docs/github-adoption-runbook.md#gho-005-repository-defaults) | `Settings > Access > Member privileges` | `Base permissions: None`、member repository creation無効、private repository forking無効 | Organization Owner |
| [`GHO-006`](docs/github-adoption-runbook.md#gho-006-github-actions) | `Settings > Actions > General` | selected repositories／selected Actions、full commit SHA、default `GITHUB_TOKEN: read`、PR approval無効、forkへのwrite token／secret無効 | CI platform |
| [`GHO-007`](docs/github-adoption-runbook.md#gho-007-github-apps-and-oauth-apps) | `Settings > Third-party Access`とApp installation policy | 全Appにowner、purpose、selected repositories、最小permission、90日以内review。High-risk writeなし | Security／Organization Owner |
| [`GHO-008`](docs/github-adoption-runbook.md#gho-008-security-configuration-coverage) | `Settings > Security > Advanced Security > Configurations` | 全repositoryへdependency graph、Dependabot alerts、secret scanning、push protectionを適用。Public repositoryの露出判断はPSB-SOURCE-003へ委譲 | Security manager |
| [`GHO-009`](docs/github-adoption-runbook.md#gho-009-audit-drift-and-alerts) | Audit export、daily drift evaluation、alert route | 必須categoryを独立accountへ180日以上保全、gap 0、open drift 0、30日以内alert canary | Security operations |
| [`GHO-010`](docs/github-adoption-runbook.md#gho-010-fail-closed-assessment) | Assessment failure semantics | permission denial、partial、stale、malformed、count mismatch、source errorを`ERROR`。例外で`PASS`へ上書きしない | Security |

## セキュリティ向上の効果はどこから生まれるか

効果は次のlive actionから生まれます。

- GitHubでidentity、Member privileges、Actions、App、security configurationを実際に制限する。
- IdPでassignment、provisioning、offboardingを実際に動かす。
- Owner、member、team、outside collaborator、Appを定期reviewし、不要なgrantを削除する。
- AuditをGitHub Organization Ownerから独立した場所へ保全し、driftとalert deliveryを継続確認する。

`secure/policy.json`は最低値を明示する参照物、`scripts/verify.py`はnormalized evidence contractの回帰検証です。
どちらもprovider settingを変更せず、organization adoptionを証明しません。

## 誰が何をするcontrolなのか

| Role | 作業 |
|---|---|
| Product owner | 対象repositoryと業務上必要なaccessを決める |
| Organization Owner | 2FA、Owner、Member privileges、App installation policyを変更する |
| IdP administrator | SAML／SCIMまたはEMU、group assignment、offboardingを運用する |
| Repository administrator | Teamとoutside collaboratorのexact grant、permission、expiryを管理する |
| CI platform | Organization Actions policyを設定し、必要Actionをreviewする |
| Security manager | App reviewと全repositoryのsecurity configuration coverageを確認する |
| Security operations | Read-only verification、audit retention、drift、alert canaryを運用する |

Development teamはOrganization全体を保守しません。必要なrepository、Action、App accessをexact scopeで申請し、
制限によるbuild failureを担当者へ返します。

## 安全な設定と安全でない設定

| Check | 安全な状態 | 安全でない状態 |
|---|---|---|
| `GHO-001` | Stable Organization ID、全page、24時間以内、全source healthy | login名だけ、最初のpageだけ、last-known-goodをcurrent扱い |
| `GHO-002` | 2FA／SSO required、SCIM／EMU healthy、unlinked 0 | Password-only、SSO optional、退職者がGitHubに残る |
| `GHO-003` | 2〜3名の記名human Owner | shared Owner、過剰Owner、former administrator |
| `GHO-004` | Owned team、exact repository、最小permission、期限付きcollaborator | orphaned team、organization-wide admin、無期限contractor |
| `GHO-005` | `Base permissions: None`、member creation off、private fork off | base `read/write/admin`、memberがrepo作成可、private fork可 |
| `GHO-006` | selected repository／Action、full SHA、token read、fork secret deny | all repository／Action、mutable tag、token write、forkへsecret |
| `GHO-007` | selected repositories、current owner、review済み最小permission | all repositories、owner不明、`administration: write` |
| `GHO-008` | 全repositoryにenforced baseline。Public repositoryはPSB-SOURCE-003のcurrent reviewあり | `not applied`、`failed`、`detached`、unknown repository、未reviewのpublic visibility |
| `GHO-009` | 独立保全、gap 0、daily drift、canary成功 | 同じOwnerが削除可能、export停止、未確認alert route |
| `GHO-010` | 収集不能は`ERROR`、findingは`FAIL` | 欠損をdefault値で補完、collector失敗をclean扱い |

これらはsample JSONの見た目ではなく、live UI／API propertyと運用結果で判定します。

## Live verification

Read-only確認コマンドと、APIでは証明できないIdP／review／retentionのmanual evidenceは
[runbook](docs/github-adoption-runbook.md#verification-result-record)にあります。Production token、user email、
repository名、App secretをrepositoryへcommitしません。

完了記録には最低限、check ID、stable target、取得時刻、確認方法、actual value、期待値、result、
reviewerを含めます。`PASS`はcurrent live stateへだけ使用し、未確認は`NOT_CHECKED`、収集障害は`ERROR`です。

## 補助的なrepository self-test

Maintainerはnormalized policy／snapshot contractのnegative behaviorを次で回帰検証できます。

```bash
make verify-control CONTROL=PSB-SOURCE-006
```

期待する終了status:

| Exit | 意味 |
|---|---|
| `0` | Synthetic secure fixtureがpolicy contractを満たす。Live adoptionは`NOT_CHECKED` |
| `1` | Insecure fixtureまたはweak policyを検出 |
| `2` | Stale、partial、malformed、count mismatch、secret-bearing、adapter failureで評価不能 |

このtestは意図的なunsafe fixture、redaction、fail-closedを検証するため実用的ですが、GitHub設定の確認には
使用しません。Fixtureはproductionへ適用せず、real evidenceとして提出しません。

## 導入完了

次をすべて満たした時だけ導入完了です。

- `GHO-001`〜`GHO-010`を一つずつcurrent live stateで判定した。
- すべてのapplicable checkが`PASS`で、`ERROR`と`NOT_CHECKED`が残っていない。
- Evidenceに収集元、取得時刻、stable target、権限境界、reviewerがある。
- Access／App review、daily posture、30日alert canary、180日audit retentionの運用ownerがいる。
- Plan制約の例外は[PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md)でowned、
  approved、time-boundに管理され、underlying resultを`PASS`へ変えていない。

## 既存controlとの境界

| Control | 所有する責務 |
|---|---|
| [PSB-SOURCE-003](../public-repository-exposure/README.md) | Public repositoryの必要性、内容、履歴、非code面の露出review |
| [PSB-SOURCE-004](../source-access-credential-lifecycle/README.md) | OAuth、PAT、SSH、GitHub App credentialの発行、storage、review、revoke |
| [PSB-SOURCE-005](../repository-destruction-recovery/README.md) | 削除・移管・重要ref破壊制限、独立backup、restore drill |
| PSB-SOURCE-006 | Organization-wide access、既定値、Actions、App、security coverage、monitoring |
| [PSB-CICD-001](../../cicd-security/action-sha-pinning/README.md) | Workflow内のAction revision pinning |
| [PSB-CICD-004](../../cicd-security/actions-least-privilege/README.md) | Workflow／job単位のtoken permission |
| [PSB-CICD-005](../../cicd-security/untrusted-pr-boundary/README.md) | Untrusted PRとcredentialのruntime boundary |
| [PSB-CICD-008](../../cicd-security/privileged-control-plane-change/README.md) | 特権設定変更のapproval、before／after、execution、audit event |
| [PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md) | Narrow、owned、approved、time-boundなsecurity exception |

Public repositoryの内容や露出検出はPSB-SOURCE-003が所有し、このbranchでは同packageを変更しません。

## Recovery and rollback

- Identity変更でlockoutした場合は、事前確認した二人目のOwnerとprovider recovery手順を使う。
- Actions／App制限で処理が止まった場合はexact Action、repository、permissionだけを再reviewし、`all`へ戻さない。
- Collector失敗時はpartial outputを破棄して全件再取得し、古い結果を再timestampしない。
- Hosted settingを戻す場合はsetting単位で影響を確認し、[PSB-CICD-008](../../cicd-security/privileged-control-plane-change/README.md)の承認を得る。
- Repository-local referenceだけを外してもGitHubのlive settingは元に戻らない。

## Frameworkと根拠

Machine-readable mappingは[`control.yaml`](control.yaml)にあります。

- [GitHub security guidance mapping](../../../frameworks/github-security-guidance/README.md)
- [OpenSSF OSPS Baseline mapping](../../../frameworks/openssf-osps-baseline/README.md)
- [MITRE ATT&CK mapping](../../../frameworks/mitre-attack/README.md)
- [REF-CICD-015: DS-202](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-015)
- [REF-CICD-017: Flatt Security](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-017)
- [REF-CICD-018: Allstar](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-018)

Provider固有の設定根拠は、該当するrunbook項目の直下にGitHub公式リンクとして置いています。Mappingは
controlとの関係を示すもので、framework complianceやOrganization全体の安全性を証明しません。

## 制限事項と運用コスト

- SAML／SCIM、security configuration、audit export／retention、一部Actions policyはGitHub planやenterprise
  policyに依存する。利用不能を安全なdefaultとして扱わない。
- APIだけではauthenticator custody、current employment、sponsor、business purpose、独立storage、実際の
  offboarding時間を証明できないため、manual live evidenceが必要。
- Internal repositoryはbase permissionが`None`でもOrganization memberに可視となり得るため、privateと同一視しない。
- Full-length SHA policyはreusable workflowの参照を同じ強さで完全には拘束しない。Workflow単位のcontrolを残す。
- Review、IdP連携、API変更、rate limit、audit storage、alert routingの継続運用コストがある。
- Audit eventが0件、fixtureが`PASS`、dashboardがgreenという事実だけでは安全性を証明しない。
