# GitHub Organization governance adoption runbook

このrunbookは`PSB-SOURCE-006`の正式な最小実装です。対象はGitHub.com／GitHub Enterprise Cloudの一つの
Organizationです。GitHub Enterprise ServerではUI、API version、plan差分を確認し、同じrequired stateを
満たしてください。

このfile、policy、verifierをcopyするだけではsecurity効果は発生しません。効果はGitHubとIdPのlive settingを
変更し、access review、audit retention、drift detection、alert deliveryを運用することから生まれます。

## Prerequisites

- 対象Organizationのlogin、numeric database ID、node IDを記録できる。
- Organization Owner、IdP administrator、repository administrator、CI platform、Securityを特定する。
- 設定者と最終reviewerを同一人物だけで完結させない。
- 二人目のOwner、IdP recovery、変更ticket、setting単位のrollback ownerを用意する。
- GitHub planとenterprise policyでSAML／SCIMまたはEMU、Actions policy、security configuration、
  audit API／exportの利用可否を確認する。
- `gh`をread-only確認に使う場合、approved credentialで`gh auth status`が成功する。

API例は2026-08-29時点のGitHub REST API version `2026-03-10`を明示します。Credentialは表示、引数化、
repositoryへの保存をしません。例はGETだけで、GitHub設定を変更しません。

```bash
export TARGET_GITHUB_ORG="example-organization"
gh auth status
gh api -H "X-GitHub-Api-Version: 2026-03-10" "/orgs/$TARGET_GITHUB_ORG"
```

最初のGETが失敗した場合は権限を推測で増やさず、必要なread permissionをendpointの公式資料で確認します。
Fine-grained tokenまたはread-only GitHub Appを選び、write permissionをverificationへ与えません。

## Change safety

1. Ticketへstable Organization ID、setting、before value、実施者、reviewer、rollback ownerを記録する。
2. 2FA／SAMLで影響を受けるmember、outside collaborator、billing manager、botを確認する。
3. SAML enforcement前にtest sign-in、recovery code、二人目のOwner、IdP障害時手順を試す。
4. OAuth restriction、Actions restriction、security configurationはinventory取得後に小さい対象から変更する。
5. 変更後に同じ画面またはread-only APIでactual valueを読み返す。

Lockout回避のためにOwnerを恒久追加する、Actionsを`all`へ戻す、Appへbroad writeを与える、security
configurationをdetachすることはrollbackではありません。

## GHO-001: target and evidence

| 項目 | 内容 |
|---|---|
| 対象 | 一つのGitHub Organizationと、評価に使う全provider source |
| 担当 | Security |
| UI／API | Organization URL、`GET /orgs/{org}`、全件取得する各inventory endpoint |
| Minimum | numeric `id`と`node_id`で対象を固定し、全page、取得時刻、API version、source health、policy digestを記録。24時間以内 |
| Unsafe | login名だけ、最初のpageだけ、source errorを無視、古いsnapshotをcurrent扱い |
| Security impact | 対象やpageが欠けると、後続checkが見ていないprincipal、repository、Appを安全と誤判定する |

Read-only確認:

```bash
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG" --jq '{login,id,node_id}'
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/repos?per_page=100" --jq '.[].id'
shasum -a 256 secure/policy.json
```

Expectedは対象のstable IDがticketと一致し、`gh api --paginate`がexit `0`で全件を返し、取得時刻が24時間以内、
policy digestがreview対象fileと一致することです。Linuxでは`shasum -a 256`の代わりに`sha256sum`を使えます。
Repository数、member数、App数は別surfaceとも照合します。Permission denial、rate limit、page欠落、count
mismatchは`ERROR`です。

公式資料:

- [Get an organization](https://docs.github.com/en/rest/orgs/orgs#get-an-organization)
- [Using pagination in the REST API](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)
- [About API versioning](https://docs.github.com/en/rest/about-the-rest-api/api-versions)

## GHO-002: authentication and provisioning

| 項目 | 内容 |
|---|---|
| 対象 | Organization authenticationとauthoritative IdP lifecycle |
| 担当 | Organization Owner／IdP administrator |
| UI／API | `Settings > Security > Authentication security`、IdP SAML／SCIM console、`GET /orgs/{org}` |
| Minimum | 2FA required、利用可能ならsecure 2FA methods、SAML SSO required、SCIMまたはEMU healthy、unlinked identity 0、offboarding 24時間以内 |
| Unsafe | 2FA／SSO optional、manual provisioningだけ、退職者がGitHubに残る |
| Security impact | Password-onlyまたはIdPと切れたvalid accountがsource accessを保持する |

設定順:

1. `Require two-factor authentication for everyone in your organization`を有効にする。
2. 利用可能なら`Only allow secure two-factor methods`を有効にする。
3. SAMLをtestしてから`Require SAML SSO authentication`を有効にする。
4. SCIMまたはEMUでassignmentとmembershipを同期し、unlinked identityを0にする。
5. 無害なtest identityをIdPで無効化し、GitHub access喪失までが24時間以内であることを記録する。

Read-only補助確認:

```bash
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG" --jq '{two_factor_requirement_enabled}'
```

Expectedは`two_factor_requirement_enabled: true`です。ただし、このfieldだけではSAML enforcement、secure
authenticator、SCIM health、offboarding時間を証明しないため、GitHub UI、IdP health、offboarding resultを
別々にreviewします。PlanでSAML／SCIMを利用できない場合は`PASS`にせず、
[PSB-GOV-002](../../../governance-operations/time-bound-security-exceptions/README.md)へ期限付き例外を記録します。

公式資料:

- [Requiring two-factor authentication](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [Enabling and testing SAML single sign-on](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/enabling-and-testing-saml-single-sign-on-for-your-organization)
- [About SCIM for organizations](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-scim-for-organizations)

## GHO-003: Organization Owners

| 項目 | 内容 |
|---|---|
| 対象 | Organization Ownerとbreak-glass administration |
| 担当 | Organization Ownerが変更し、Securityが独立review |
| UI／API | `People > Role: Owner`、`GET /orgs/{org}/members?role=admin` |
| Minimum | 2〜3名、記名human、current employment、phishing-resistant authentication、90日以内review |
| Unsafe | shared Owner、service identityのOwner、4名以上、former administrator、弱いauthentication |
| Security impact | Ownerはmembership、App、Actions、repository、security settingを横断して変更できる |

Read-only確認:

```bash
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/members?role=admin&per_page=100" +  --jq '.[] | {id,node_id,login}'
```

Expectedは2〜3件で、各IDがHR／IdP上のcurrent humanと一致します。GitHub APIはcurrent employment、
authenticator type、review decisionを返さないため、それらはIdP evidenceとdated reviewで確認します。
Sharedまたはorphaned Ownerは削除し、緊急用accessは記名、保管、利用監査を別途持たせます。

公式資料:

- [Roles in an organization](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization)
- [REST API endpoints for organization members](https://docs.github.com/en/rest/orgs/members)

## GHO-004: members, teams, and outside collaborators

| 項目 | 内容 |
|---|---|
| 対象 | Member、team、outside collaboratorからrepositoryへのgrant |
| 担当 | Repository administrator |
| UI／API | `People`、`Teams`、outside collaborator view、members／teams／outside-collaborators endpoints |
| Minimum | current affiliation、current sponsor、owned non-admin team、exact repository、最小permission、90日以内review。Outside collaboratorは原則`pull`／`triage`かつ90日以内expiry |
| Unsafe | orphaned team、former worker、全repository admin、owner不明、無期限contractor |
| Security impact | Ownerを減らしてもordinary grantやteam経由のvalid accessは残る |

Read-only inventory:

```bash
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/members?per_page=100" --jq '.[] | {id,node_id,login}'
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/teams?per_page=100" --jq '.[] | {id,node_id,slug}'
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/outside_collaborators?per_page=100" +  --jq '.[] | {id,node_id,login}'
```

Expectedは全principalとteamがcurrent owner／sponsorを持ち、repository grantがexact scopeへresolveし、期限切れ、
unknown、admin相当のoutside collaboratorが0であることです。Effective repository roleだけではteamかdirect
grantかを判別できない場合があるため、People／Team UIとaccess review記録を併用します。

公式資料:

- [Managing outside collaborators](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators)
- [Repository roles for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization)
- [REST API endpoints for outside collaborators](https://docs.github.com/en/rest/orgs/outside-collaborators)

## GHO-005: repository defaults

| 項目 | 内容 |
|---|---|
| 対象 | Organizationのrepository defaultとmember creation／fork authority |
| 担当 | Organization Owner |
| UI／API | `Settings > Access > Member privileges`、`GET /orgs/{org}` |
| Minimum | `Base permissions: None`、member repository creation disabled、public／private／internal creation disabled、private repository forking disabled |
| Unsafe | base `Read`／`Write`／`Admin`、member repository creation enabled、private fork enabled |
| Security impact | 新規repositoryがreview前にambient access、意図しないvisibility、private forkを持つ |

GitHub UIで次を設定します。

1. `Base permissions`を`None`にする。
2. `Repository creation`でmemberによるrepository作成を無効にする。
3. Public、private、利用可能な場合はinternal repository作成がすべて無効であることを確認する。
4. `Repository forking`で`Allow forking of private repositories`を無効にする。

Current settingのread-only確認:

```bash
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG" +  --jq '{
    default_repository_permission,
    members_can_create_repositories,
    members_can_create_public_repositories,
    members_can_create_private_repositories,
    members_can_create_internal_repositories,
    members_can_fork_private_repositories
  }'
```

Expectedは`default_repository_permission`が`none`、全booleanが`false`です。Plan上存在しないfieldは
推測せず、UIのcurrent valueとAPI response schemaを記録します。Internal repositoryはOrganization memberへ
readableとなり得るため、private相当として扱いません。既存forkはsetting変更だけで消えないため別途inventoryを
reviewします。

公式資料:

- [Setting base permissions](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization)
- [Restricting repository creation](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization)
- [Managing the forking policy](https://docs.github.com/en/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization)
- [REST API endpoints for organizations](https://docs.github.com/en/rest/orgs/orgs)

## GHO-006: GitHub Actions

| 項目 | 内容 |
|---|---|
| 対象 | Organization Actions enablement、allowlist、token defaults、fork workflow |
| 担当 | CI platform |
| UI／API | `Settings > Actions > General`、Organization Actions permissions endpoints |
| Minimum | selected repositories、selected Actions／reusable workflows、full-length SHA required、default token `read`、PR approval disabled、forkへwrite token／secret disabled |
| Unsafe | all repositories、all Actions、mutable reference、default `write`、workflow PR approval、fork credential delivery |
| Security impact | Repository-local reviewをOrganization policyの広いruntime／token trustが迂回する |

UIでminimumを設定した後、次をread-onlyで確認します。

```bash
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/actions/permissions"
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/actions/permissions/repositories?per_page=100"
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/actions/permissions/selected-actions"
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/actions/permissions/workflow"
gh api -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/actions/permissions/fork-pr-workflows-private-repos"
```

Expectedはenabled repository集合がapproved inventoryと完全一致し、allowed action policyがselected、
`sha_pinning_required: true`、`default_workflow_permissions: read`、
`can_approve_pull_request_reviews: false`、`send_write_tokens_to_workflows: false`、
`send_secrets_and_variables: false`です。Enterpriseが上位で管理する場合はOrganization値とeffective policyを
両方記録します。

Full-length SHA requirementだけではreusable workflow参照を完全に拘束しません。Workflow内は
[PSB-CICD-001](../../../cicd-security/action-sha-pinning/README.md)、
[PSB-CICD-004](../../../cicd-security/actions-least-privilege/README.md)、
[PSB-CICD-005](../../../cicd-security/untrusted-pr-boundary/README.md)で検証します。

公式資料:

- [Disabling or limiting GitHub Actions](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization)
- [REST API endpoints for GitHub Actions permissions](https://docs.github.com/en/rest/actions/permissions)

## GHO-007: GitHub Apps and OAuth Apps

| 項目 | 内容 |
|---|---|
| 対象 | Installed GitHub Appとauthorized OAuth App |
| 担当 | Organization Owner／Security |
| UI／API | `Settings > Access > Member privileges`、`Settings > Third-party Access`、`GET /orgs/{org}/installations` |
| Minimum | Installation requestをOwner reviewへ限定し、全Appにcurrent owner、purpose、selected repositories、最小permission、90日以内review。High-risk writeなし |
| Unsafe | memberが自由にinstall、all repositories、owner不明、stale review、Actions／administration／members／workflow write |
| Security impact | Appはhuman access reviewと独立した永続identityとしてsourceやcontrol planeへ到達する |

1. Member privilegesでrepository administratorによる無審査installationを無効にする。
2. Third-party AccessでGitHub AppとOAuth Appを全件reviewする。
3. 各Appをcurrent human owner、purpose、selected repository ID、permission、review dateへ結ぶ。
4. `actions`、`administration`、`members`、`organization_administration`、`workflows`のwriteをbaselineで
   許可しない。
5. OAuth App access restrictionsを有効化する前に既存authorization、SSH key、webhookへの影響をreviewする。

Read-only inventory:

```bash
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/installations?per_page=100"
```

ExpectedはUIとAPIのinstallation件数が一致し、各installationがselected repositoriesです。Authorized OAuth
App、business owner、review dateはこのendpointだけでは揃わないため、Third-party Access UIとgovernance
registerを併用します。Permission不足をall-repositoryまたはadmin writeで回避しません。

公式資料:

- [Reviewing installed integrations](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-your-organizations-installed-integrations)
- [Limiting App access requests and installations](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [Enabling OAuth App access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/enabling-oauth-app-access-restrictions-for-your-organization)
- [REST API endpoints for organizations](https://docs.github.com/en/rest/orgs/orgs#list-app-installations-for-an-organization)

## GHO-008: security configuration coverage

| 項目 | 内容 |
|---|---|
| 対象 | Organizationのcomplete repository inventoryとcode security configuration |
| 担当 | Security manager |
| UI／API | `Settings > Security > Advanced Security > Configurations`、code-security configuration endpoints |
| Minimum | 全repositoryへenforced configurationを適用し、dependency graph、Dependabot alerts、secret scanning、push protectionをenabled。Public repositoryはPSB-SOURCE-003のcurrent reviewへ接続 |
| Unsafe | `not applied`、`failed`、`detached`、unreviewed override、unknown repository、未reviewのpublic visibility |
| Security impact | 新規・移管・除外repositoryがsecret／dependency detectionの外に残る |

1. Review済みconfigurationで4 featureをenabledにする。
2. New repositoryへのdefaultを設定する。
3. `Repositories` viewの対象集合をcomplete repository inventoryと突合する。
4. `not applied`、`failed`、`detached`、unknownを0にする。
5. Public repositoryは[PSB-SOURCE-003](../../public-repository-exposure/README.md)のcurrent reviewへ接続する。

Read-only確認:

```bash
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/code-security/configurations?per_page=100"
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/repos?per_page=100" --jq '.[] | {id,node_id,name,visibility}'
```

Expectedはrequired configurationの`enforcement`が`enforced`で、4 featureが`enabled`、全repositoryが
configurationへ関連付くことです。Configuration一覧だけではcoverageを証明しないため、associated repositories
endpointまたはUIのRepositories viewで全repositoryを照合します。Planでfeatureを利用できない場合はfeature単位の
`NOT_CHECKED`／`FAIL`と期限付き例外を残します。

公式資料:

- [Configuring security features in your organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security)
- [Applying a custom security configuration](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/establish-complete-coverage/apply-custom-configuration)
- [REST API endpoints for code security configurations](https://docs.github.com/en/rest/code-security/configurations)

## GHO-009: audit, drift, and alerts

| 項目 | 内容 |
|---|---|
| 対象 | Organization audit log、independent retention、posture drift、alert delivery |
| 担当 | Security operations |
| UI／API | `Settings > Archive > Logs > Audit log`、`GET /orgs/{org}/audit-log`、approved SIEM／storage |
| Minimum | Membership、App、visibility、Actions、ruleset、Organization settingを独立accountへ180日以上保全。Sequence gap 0、daily drift、open drift 0、30日以内canary |
| Unsafe | UI閲覧だけ、同じOwnerが全証跡を削除可能、export停止、gap無視、未試験alert route |
| Security impact | 不正な管理変更がpoint-in-time review後に残り、検知も追跡もできない |

Read-only spot check:

```bash
gh api --paginate -H "X-GitHub-Api-Version: 2026-03-10" +  "/orgs/$TARGET_GITHUB_ORG/audit-log?per_page=100"
```

ExpectedはAPI取得が成功し、required categoryがexport対象で、exporterのlast successとsequenceがcurrent、
independent storageのretentionが180日以上、daily posture resultにopen driftがなく、30日以内のharmless canaryが
accountable receiverへ届いていることです。Audit eventが0件でも安全性は証明できません。Planがstreamingや
長期retentionを提供しない場合はapproved independent pull、短いcollection interval、例外を設計します。

公式資料:

- [Reviewing the audit log](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
- [Audit log events](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [REST API endpoints for organizations](https://docs.github.com/en/rest/orgs/orgs#get-the-audit-log-for-an-organization)

## GHO-010: fail-closed assessment

| 項目 | 内容 |
|---|---|
| 対象 | Live verification、collector、normalized assessment、exception handling |
| 担当 | Security |
| UI／API | 全read-only verification source、collector job result、assessment result |
| Minimum | Missing、permission denial、partial pagination、stale、malformed、count mismatch、source errorは`ERROR`。Unsafe stateは`FAIL`。Exceptionはunderlying resultを変更しない |
| Unsafe | Missing fieldをsecure defaultで補う、last-known-goodをcurrent扱い、collector failureをgreen、`secure: true`を信頼 |
| Security impact | Verification boundaryの障害が全checkの意味を消し、危険なOrganizationをcleanと報告する |

実環境ではcollectorの失敗run、permission denial、rate limit、page count、last success、alert routingをreviewします。
障害を意図的にproductionへ起こす必要はありません。次のrepository self-testはfail-closed contractだけを安全に
確認します。

```bash
make verify-control CONTROL=PSB-SOURCE-006
```

Expectedはsecure synthetic fixtureがexit `0`、unsafe／weak policyがexit `1`、stale、partial、malformed、
count mismatch、secret-bearing、adapter failureがexit `2`です。出力はsecret fixture値を複製しません。
これはlive adoptionの`PASS`ではなく、maintainer regressionです。

## Verification result record

Real evidenceをrepositoryへcommitしません。組織のapproved evidence systemに一check一行で記録します。

| Field | 内容 |
|---|---|
| `check_id` | `GHO-001`〜`GHO-010`の一つ |
| `target` | Organization numeric ID／node ID |
| `observed_at` | UTCの取得時刻 |
| `source` | GitHub UI path、API endpoint、IdP、job、storage、canary |
| `authority` | 使用したread-only permissionまたはmanual reviewer role |
| `actual` | Secretや不要なpersonal dataを除くcurrent value |
| `required` | このrunbookのminimum |
| `result` | `PASS`、`FAIL`、`NOT_CHECKED`、`ERROR` |
| `reviewer` | 設定者とは別の記名reviewer |
| `next_review` | Access／Appは90日以内、alert canaryは30日以内、postureは24時間以内 |

Synthetic fixture、手書きの`secure: true`、README screenshotだけをevidenceにしません。

## Completion checklist

| Check | 導入完了条件 |
|---|---|
| `GHO-001` | Stable target、全件、freshness、source health、policy digestを確認 |
| `GHO-002` | 2FA／SSO、provisioning、unlinked identity、offboarding resultを確認 |
| `GHO-003` | Owner 2〜3名を一人ずつcurrent identity／auth／reviewへ照合 |
| `GHO-004` | Member、team、outside collaboratorのowner／scope／permission／expiryを照合 |
| `GHO-005` | Member privilegesの6 propertyがminimumと一致 |
| `GHO-006` | Actionsのrepository、Action、SHA、token、PR、fork settingがminimumと一致 |
| `GHO-007` | GitHub App／OAuth Appの全件、owner、repository、permission、reviewを照合 |
| `GHO-008` | Complete repository inventoryとconfiguration coverageが一致 |
| `GHO-009` | Audit coverage、retention、independent boundary、drift、canaryを確認 |
| `GHO-010` | Live collection failureがcleanにならず、補助negative testも成功 |

全applicable checkがcurrent `PASS`で、`ERROR`／`NOT_CHECKED`がなく、運用ownerと次回review日がある時だけ
導入完了です。Exceptionはunderlying resultを`PASS`へ書き換えません。

## Recovery and rollback

- 2FA／SAML変更でaccessを失った場合は、二人目のOwnerと事前確認したprovider recovery手順を使う。
- Actions制限でworkflowが止まった場合は、必要なexact Action／reusable workflowだけをreviewしてallowlistへ
  追加し、`all`へ戻さない。
- Appが停止した場合は、必要なexact repository／permissionだけを再承認する。
- Security configurationで問題が出た場合は対象repositoryとfeature単位で調査し、全体をdetachしない。
- Collector失敗時はpartial outputを破棄して全件再収集し、古いsnapshotを再timestampしない。
- Alert failure時はreceiverを修復し、同じharmless canaryが届くまでmonitoringをcleanにしない。
- Hosted settingのrollbackはsetting単位のimpactと
  [PSB-CICD-008](../../../cicd-security/privileged-control-plane-change/README.md)の独立承認を必要とする。

## Optional repository-local reference

Normalized assessmentを採用する組織だけが、既存pathを上書きしないことを確認して次をcopyします。

```bash
test ! -e .security/github-organization-governance
mkdir -p .security/github-organization-governance
cp controls/source-protection/github-organization-governance/secure/policy.json +  .security/github-organization-governance/policy.json
cp controls/source-protection/github-organization-governance/scripts/verify.py +  .security/github-organization-governance/verify.py
```

この操作はGitHub、IdP、Git、shell、IDE、OSを変更しません。Existing pathがあれば停止し、adopterが差分を
reviewします。このoptional integrationを外してもhosted settingは元に戻りません。
