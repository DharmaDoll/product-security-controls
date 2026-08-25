# PSB-SOURCE-006: GitHub Organizationのaccess、既定値、Actions、App、監査driftを継続管理する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Repositoryごとの設定が安全でも、GitHub Organizationに過剰なOwner、放置されたmember・team・outside
collaborator・App、危険なrepository既定値、広いActions policy、security configurationの適用漏れ、
監査停止があると、新しいrepositoryや管理面からsource protectionを迂回できる。

### 誰から、または何から守るか

Phished Organization Owner、侵害されたmemberやthird-party App、退職者、放置されたcontractor、
誤操作する管理者、不完全なSAML／SCIM連携、partial GitHub API、audit exporterやalert receiverの障害、
安全基準を弱めるlocal exceptionから守る。

### 何が対象か

一つのGitHub Organizationについて、identity連携、Owner、member、team、outside collaborator、
Organizationのrepository既定値、Actions policy、GitHub／OAuth App、全repositoryのsecurity
configuration、audit export、posture drift、alert deliveryを対象とする。

### 何をするか

Read-only provider adapterからstable ID、完全pagination、source healthを持つsecret-free snapshotを作り、
repository-owned policyのSHA-256へbindする。Access・既定値・Actions・App・repository coverage・monitoringを
検証し、弱いpolicy、未管理例外、不完全・stale・malformed・secret-bearing evidenceをfail closedにする。

### 成功状態

24時間以内の完全なsnapshotで、SSO／provisioning、2～3名の記名Owner、90日以内のaccess review、
deny-orientedなOrganization defaults、selectedかつfull-SHAのActions、限定App、全repositoryのsecurity
coverage、独立保全されたauditとdrift／alertの健全性が確認される。検証不能は`PASS`にならない。

### 対象外・残余リスク

E3 fixtureはGitHubやIdPへ接続せず設定変更も行わないため、live Organizationへの導入を証明しない。
Credential lifecycleは`PSB-SOURCE-004`、source破壊とbackupは`PSB-SOURCE-005`、特権変更の承認連鎖は
`PSB-CICD-008`、漏洩後rotationは`PSB-GOV-004`が所有する。GitHubまたはIdP自体の侵害も残る。

## なぜOrganization単位のcontrolが必要か

Repository-local workflow、ruleset、scannerは、そのrepositoryが既にinventoryへ入り、期待する
Organization policyの下で運用されていることを前提にします。次の状態は個別repositoryだけでは十分に
確認できません。

- Organization Ownerやoutside collaboratorが誰で、現在も必要か;
- member／teamのgrantがどのrepositoryへ届くか;
- 新しいrepositoryがどのbase permission、visibility、fork policyで作られるか;
- OrganizationのActions policyがどのrepositoryとActionを許すか;
- GitHub App／OAuth Appがどのresourceとpermissionを保持するか;
- security configurationが完全なrepository inventoryへ届いているか;
- hosted settingのdriftをauditとalertで継続検知できるか。

このcontrolは、これらを一つのsecret-free relationship snapshotとして評価します。GitHub UIの
checkboxを列挙するだけではなく、inventory completeness、stable identity、freshness、policy identity、
error stateを検証対象にします。

## 既存controlとの境界

| Control | 所有する責務 |
|---|---|
| `PSB-SOURCE-003` | Public repository、Git history、非code面の露出検出とcredential-first remediation |
| `PSB-SOURCE-004` | OAuth、PAT、SSH、GitHub App credentialの発行、storage、review、revoke |
| `PSB-SOURCE-005` | Critical repositoryの削除・移管・重要ref破壊制限、独立backup、restore drill |
| `PSB-SOURCE-006` | Organization-wide access関係、既定値、Actions、App、repository security coverage、継続monitoring |
| `PSB-CICD-008` | 特権設定変更のactor、session、before／after、approval、execution、audit eventの結合 |
| `PSB-GOV-002` | Narrow、owned、approved、time-boundなsecurity exception |

`PSB-SOURCE-006`は`PSB-CICD-008`の変更イベントを再実装しません。現在のOrganization postureと完全な
対象集合を確認し、設定変更の正当性や承認はそのcontrolへ引き渡します。

## 安全な例と安全でない例

[`secure/policy.json`](secure/policy.json)は次のfloorを固定します。

- Snapshot、access review、outside collaborator、App review、alert testの期限;
- SSO、2FA、SAML／SCIMまたはEnterprise Managed Users、24時間以内offboarding;
- 2～3名の記名human Ownerとphishing-resistant authentication;
- `none`のbase permission、member repository作成とprivate forkのdeny;
- selected repository／selected Action、full SHA、read-only `GITHUB_TOKEN`、fork credential deny;
- selected repositoryだけのApp、high-risk Organization／Actions write deny;
- dependency graph、Dependabot alerts、secret scanning、push protection;
- 180日以上のaudit retention、独立security account、必須event category、alert test;
- local exception禁止と`PSB-GOV-002`への一本化。

[`secure/organization-snapshot.json`](secure/organization-snapshot.json)はreal user、repository、App、
tokenを含まないsynthetic snapshotです。Stable numeric ID、count、freshness、policy digest、healthを持ちます。

[`insecure/organization-snapshot.json`](insecure/organization-snapshot.json)は意図的に危険です。4名のOwner、
shared account、manual provisioning、admin contractor／team、全repository・全Action、write token、fork secret、
all-repository App、security feature欠落、短いaudit retention、open drift、恒久local exceptionを隔離して
示します。Live Organizationへ適用する設定ではありません。

## 最短の導入手順

### 前提条件とtrust assumption

- Organization Owner、IdP管理者、repository管理者、security reviewerを識別し、同一人物だけで完結させない;
- GitHub plan、SAML／SCIMまたはEnterprise Managed Users、Actions policy、security configuration、audit APIの
  利用可否を確認する;
- Provider adapterはread-only GitHub Appまたはfine-grained tokenを使い、secret値をsnapshotへ出さない;
- Organization、member、team、repository、Appにはrename後も追跡できるstable provider IDを使う;
- Pagination、rate limit、API version、schema change、permission denialを`ERROR`として返す;
- Fixture PASSをlive Organizationの`PASS`へ昇格しない。

### コピーするファイル

最低限、次をadopter repositoryのreview対象directoryへコピーまたは参照します。

```text
secure/policy.json
scripts/verify.py
```

`secure/organization-snapshot.json`はcontract例です。Production evidenceとしてコピーしてはいけません。

### 明示的なrepository-local activation

Repository rootで、既存directoryを上書きしないことを確認してから実行します。

```bash
test ! -e .security/github-organization-governance
mkdir -p .security/github-organization-governance
cp controls/source-protection/github-organization-governance/secure/policy.json \
  .security/github-organization-governance/policy.json
cp controls/source-protection/github-organization-governance/scripts/verify.py \
  .security/github-organization-governance/verify.py
```

このactivationはGitHub、Git、shell、IDEのglobal設定を変更しません。既存pathがある場合は停止し、
merge内容をadopterがreviewします。

### Live snapshot contract

導入先のread-only collectorは、fixtureと同じschemaで次を正規化します。

1. Organizationのlogin、numeric database ID、node ID、2FA／SSO／provisioning状態;
2. 完全なmember、Owner、team、outside collaboratorとrepository grant;
3. Organization Member privilegesとrepository creation／private fork既定値;
4. Organization Actions policyとexact selected repository IDs;
5. Installed GitHub App、authorized OAuth App、owner、repository selection、permission;
6. 全repositoryとsecurity configuration／feature state;
7. Audit coverage、retention、export、sequence、drift、alert test;
8. Collector health、完全pagination、observed time、exact policy file bytesのSHA-256。

Collectorにwrite permissionを与えず、write APIや自動remediationをverification processへ混ぜません。
GitHub APIを取得できない項目は推測せず`ERROR`またはorganization-owned external evidenceにします。

### Harmless positive self-test

```bash
python3 controls/source-protection/github-organization-governance/scripts/verify.py \
  --policy controls/source-protection/github-organization-governance/secure/policy.json \
  --snapshot controls/source-protection/github-organization-governance/secure/organization-snapshot.json \
  --evaluation-time 2026-08-26T12:00:00Z
```

終了statusは`0`で、`PASS GHO-001`から`PASS GHO-010`と、live enforcementが
`NOT_CHECKED`であることを表示します。

### Harmless negative self-test

```bash
python3 controls/source-protection/github-organization-governance/scripts/verify.py \
  --policy controls/source-protection/github-organization-governance/secure/policy.json \
  --snapshot controls/source-protection/github-organization-governance/insecure/organization-snapshot.json \
  --evaluation-time 2026-08-26T12:00:00Z
```

終了statusは`1`です。Fixtureしか読まないため、GitHubの設定、member、repository、Appは変更しません。

## 検証

Canonical commandは次です。

```bash
make verify-control CONTROL=PSB-SOURCE-006
```

| Exit | 意味 |
|---|---|
| `0` | Policyとsynthetic snapshot contractが成立。Live adoptionは引き続き`NOT_CHECKED` |
| `1` | 危険なidentity、access、default、Actions、App、repository coverage、monitoring、またはweak policyを検出 |
| `2` | Missing、stale、partial、malformed、count mismatch、secret-bearing、adapter errorで検証不能 |

Negative testsは、unsafe hosted settings、weak policy、local exception、stale snapshot、partial pagination、
count mismatch、adapter error、malformed JSON、secret-bearing evidenceを区別します。Secret-bearing fixtureの値を
error outputへ複製しません。

## 導入後のCI／server-side enforcement

Local verifierだけではhosted settingを強制しません。導入先は次を別途維持します。

1. GitHub／Enterprise／IdP側で2FA、SSO、provisioning、Owner、Member privilegesを強制する;
2. Organization Actions policyとsecurity configurationをserver-sideで適用する;
3. Read-only collectorを少なくとも日次実行し、snapshotを24時間以内に保つ;
4. Driftをblocking findingまたはaccountable alertへ送り、alert receiverを30日以内ごとに無害なcanaryで試す;
5. AuditをGitHub Organization Ownerが削除できないsecurity accountへexportする;
6. 例外はlocal JSONへ埋めず、`PSB-GOV-002`でexact control／check／target、owner、approver、expiryを持たせる;
7. 特権設定の是正変更は`PSB-CICD-008`のapprovalとaudit chainを使う。

## よくある失敗と復旧

- `ERROR ... stale`: Collector schedule、queue、clock、API accessを修復し、freshな全件収集をやり直す。古い
  snapshotをmanualで再timestampしない;
- `ERROR ... pagination`: Rate limitとcursor処理を修復し、partial outputを破棄して最初から収集する;
- Count mismatch: API surface間のeventual consistencyを確認し、同じobservation windowで再収集する;
- SAML／SCIMが利用できない: SSOを無言でoptionalにせず、plan制約、manual offboarding、短いreview、owner、
  expiryを`PSB-GOV-002`で明示する;
- Actionsを制限してworkflowが止まった: 必要なActionのexact sourceとfull commit SHAをreviewしてallowlistへ
  追加し、`all`へ戻さない;
- App permission不足: 必要なoperationだけをreviewして追加し、`administration: write`や全repository grantを
  temporary workaroundにしない;
- Audit alertが届かない: Receiverとroutingを修復し、同じharmless canaryが届くまでmonitoringをcleanにしない。

## Rollback

Repository-local activationを戻す場合は、review後にコピーした
`.security/github-organization-governance/`だけを削除し、CI参照を外します。この操作はGitHub hosted settingを
戻しません。Hosted settingのrollbackは、current impactを確認し、`PSB-CICD-008`のreview済み変更として
setting単位で行います。広いOwner、`Actions: all`、write default token、fork secret、all-repository Appを
一括復活させてはいけません。

## 運用コスト

- GitHub planとAPI surfaceごとのcollector保守、pagination、rate limit、schema change対応;
- IdP／SCIMとGitHub stable IDのjoin、offboarding遅延の調査;
- Owner、team、outside collaborator、Appの90日以内review;
- Repository inventoryとsecurity configuration coverageの差分是正;
- Audit storage、retention、alert receiver、canary、incident routingの運用;
- Business上必要なpublic repository、admin team、App write permissionのexact exception review。

## Frameworkと参考資料

Machine-readable mappingsは[`control.yaml`](control.yaml)にあります。

- `github-security-guidance`はGitHub Docs commit
  `b17436de8f10c3e7f6a185d6813bf94bc82d22f8`へpinされ、Organization Actions、SAML、SCIM、audit、
  credential type、secure account／code pagesを参照する;
- OpenSSF OSPS Baseline `2026.02.19`はcollaborator permissionとCI least privilegeのsupporting mapping;
- MITRE ATT&CK `v19.1`のValid AccountsとAccount Manipulationはattack behavior mappingであり、complianceではない;
- `REF-CICD-015` DS-202はpipeline asset inventory、separation of duties、audit、repository protectionの
  tool-independent design inputとして使う;
- `REF-CICD-017`のFlatt Security資料は日本語のoperational contextに限定し、current GitHub仕様やframework
  mappingの根拠にはしない;
- `REF-CICD-018` Allstarはorganization-scale monitoringの比較対象だが、このcontrolはinstall、authorize、
  execute、自動remediationを行わない。

これらのmappingやfixture PASSはGitHub Security、OpenSSF、MITREへのcomplianceやOrganization全体の安全性を
証明しません。

## 制限事項

- Normalized snapshot contractはGitHub REST／GraphQL／Enterprise APIのlive collectorそのものではない;
- GitHub planによりSAML／SCIM、full-SHA policy、security configuration、audit retentionの利用可否が異なる;
- Provider eventの遅延とeventual consistencyにより、一時的なcount mismatchが起こり得るがcleanへfallbackしない;
- Metadata-only evidenceは実際のauthenticator custody、IdP policy、App hosting、audit backend integrityを証明しない;
- Public repositoryが必要な場合、visibilityだけで拒否せず`PSB-SOURCE-003`のcurrent reviewを要求する;
- Required security featureが有効でもscanner rule、license、coverage、response processの品質までは証明しない;
- Audit eventが0件でも不正操作がなかったことを証明しない;
- Organization-wide posture PASSでもrepository-local code、workflow、ruleset、branch、release、buildは各controlで
  独立検証する必要がある。
