# PSB-SOURCE-004 GitHub最短導入runbook

## このrunbookの位置付け

このrunbookが`PSB-SOURCE-004`の主実装です。GitHub／IdPの実設定とcredential lifecycle運用を
変更し、current stateと専用test scopeの拒否結果を確認します。Repository内のJSONをcopyする
だけではsecurity stateは変わりません。

対象はGitHub.com／GitHub Enterprise Cloudです。GitHub Enterprise Server、GitLab、Bitbucketは
対象providerの機能とversionをreviewした別profileを必要とします。

## 1. 実施者

| Role | このrunbookで行うこと |
|---|---|
| Product owner | 対象repositoryと必要accessを承認する |
| Organization owner | GitHub organization policyを変更する |
| IdP administrator | SSO、phishing-resistant authentication、membership lifecycleを設定する |
| Repository administrator | App／PATのrepositoryとpermissionを限定する |
| Platform／SRE | Automation identityとconsumer migrationを実施する |
| Developer | Approved interactive authenticationとprotected storageを使用する |
| Security | Pre-change impact、current state、exception、drillをreviewする |
| Incident response | Exposure時の失効と影響調査をownerとして実施する |

Organization ownerが自分の変更を唯一のsecurity reviewerとして承認しないでください。

## 2. 開始前の確認

### 2.1 対象scope

次を組織内の承認済みsystem of recordへ記録します。このrepositoryへ実organization名やuser情報を
commitしません。

- GitHub enterprise／organizationのstable IDと表示名。
- Product-critical repositoryのstable ID。
- Member、outside collaborator、service account、automation actor。
- OAuth App、GitHub App、fine-grained／classic PAT、SSH／deploy key。
- GitHub MCP利用の有無と対象IDE。
- Credentialを利用するCI、bot、local tool、package／release consumer。

Inventoryにcredential値、authorization header、private key、recovery codeを入れません。

### 2.2 Pre-change impact

設定変更前に次を確認します。

- 2FA未準拠のmember、billing manager、outside collaborator、bot account。
- Organization dataへ到達するOAuth Appと、そのreauthorization owner。
- GitHub App installationとrepository／permission。
- Classic PATとfine-grained PATのconsumer、expiration、migration owner。
- SSH／deploy keyとautomation consumer。
- 少なくとも2名のorganization ownerと、承認済みrecovery method。

2FA要求は非準拠outside collaboratorのaccessへ影響します。OAuth App access restrictionの初回有効化も
既存Appや一部SSH accessを停止させ得ます。通知、change window、recovery ownerなしに実施しません。

### 2.3 Test scope

次を用意します。

- Production sourceを含まない専用private test repositoryを2つ。
  - `allowed-test`: readを許可する。
  - `unselected-test`: credential scopeから外す。
- 一つのcredential class専用のtest identity／credential。
- `allowed-test`でだけ使用するunique inert Git ref／operation marker。
- Test credentialとtest repositoryを削除できる独立admin。

## 3. Authentication securityを設定する

実施者: Organization owner／IdP administrator。Reviewer: Security。

1. GitHubで対象organizationを開く。
2. `Settings`を開く。
3. `Security`セクションの`Authentication security`を開く。
4. `Require two-factor authentication for everyone in your organization`を選択する。
5. 利用できる場合、`Only allow secure two-factor methods`も選択し、SMSを除外する。
6. 影響対象を再確認して`Save`／`Confirm`する。
7. Enterprise／IdPを使用する場合は、SAML SSOとmembership lifecycleを接続する。

GitHubの`secure two-factor methods`にはauthenticator app等も含まれるため、この設定だけを
phishing-resistantの証明にしません。Sensitive source accessにはpasskey／security keyをIdP／enterprise
policyまたはreview可能なorganization policyで要求します。

成功状態:

- 全member／outside collaboratorに2FAが要求される。
- SMS-only accessが許可されない。
- Passkey／security keyのrequired stateをIdP／enterprise evidenceで確認できる。
- Removed／blocked userをaudit eventと事前inventoryへ相関できる。

## 4. Personal access token policyを設定する

実施者: Organization owner。Reviewer: Security。

### 4.1 Classic PAT

1. Organization `Settings`を開く。
2. `Personal access tokens`配下の`Settings`を開く。
3. `Tokens (classic)` tabを選ぶ。
4. Organization resourceへのclassic PAT accessを`Restrict access`にする。
5. 既存consumerを確認して`Save`する。

Classic PAT approvalという仕組みに依存しません。GitHubのorganization approval対象は
fine-grained PATであり、classic PATはrestrictしない限りorganizationへ到達し得ます。

### 4.2 Fine-grained PAT

Fine-grained PATを完全に禁止できる場合はrestrictします。利用が必要な場合だけ次を設定します。

1. `Fine-grained tokens` tabを選ぶ。
2. Access policyを必要なfine-grained PATだけが利用できる状態にする。
3. `Require approval of fine-grained personal access tokens`で`Require administrator approval`を選ぶ。
4. `Set maximum lifetimes for personal access tokens`を`90 days`以下にする。
5. `Pending requests`でowner、repository、permission、expiration、purposeをreviewする。
6. Exact taskに必要なrequestだけをapproveし、broad／unowned requestをdenyする。

Organization owner自身が作成するfine-grained PATはapprovalが不要となるprovider挙動があるため、
owner tokenも別のsecurity reviewerがinventory上で確認します。

成功状態:

- Classic PATはorganization resourceへ到達しない。
- Active fine-grained PATはownerが1つ、explicit repository、minimum permission、90日以下である。
- Broad scopeは`PSB-GOV-002`のcurrent exceptionなしに存在しない。
- Lifetime policyによるblockを失効と誤認せず、旧tokenを明示的にrevokeできる。

## 5. OAuth AppとGitHub Appを制限する

実施者: Organization owner。Reviewer: Security。

### 5.1 OAuth App

1. Organization `Settings`を開く。
2. `Third-party Access`の`OAuth app policy`を開く。
3. 現在許可されているAppとconsumerをpre-change inventoryへ照合する。
4. `Restrict third-party application access`を有効にする。
5. Business owner、purpose、必要scopeが確認できたAppだけをapprove／reauthorizeする。
6. 未使用またはowner不在のApp accessをdenyする。

初回有効化は既存OAuth Appと一部SSH accessへ影響し得ます。停止後に全Appを無条件で再許可せず、
inventoryにある必要対象だけを戻します。

### 5.2 GitHub App installation

1. Organization `Settings`を開く。
2. `Access`の`Member privileges`を開く。
3. `GitHub Apps`でrepository administratorによる直接installationを許可せず、organization ownerの
   request／review経路へ寄せる。
4. `Third-party Access`の`GitHub Apps`でinstalled Appを一件ずつ開く。
5. `Repository access`を`Only select repositories`相当にする。
6. `Permissions`をtaskに必要なread／write operationだけへ限定する。
7. Owner不在または未使用Appはsuspend後に影響を確認し、不要ならuninstallする。

App request自体を無効にするかはorganization sizeとreview capacityで決めます。Request flowを
無効にしてdeveloperがbroad PATへ逃げないよう、承認経路とresponse ownerを先に用意します。

成功状態:

- App installationにorganization owner reviewがある。
- `All repositories`や不要なorganization permissionがない。
- App ID、installation ID、repository selection、permission、owner、review dateがinventoryにある。

## 6. Automationをuser tokenから移行する

実施者: Platform／SREとrepository administrator。Reviewer: Security。

1. Developer OAuth／PATを使うautomation consumerを一つ選ぶ。
2. 専用GitHub Appまたは同等のshort-lived workload identityを用意する。
3. Installationを必要repositoryだけへ限定する。
4. Installation tokenをjob開始時に生成し、job終了後に破棄する。
5. Tokenをapproved secret deliveryからexact consumerへ渡す。
6. Test scopeでread／writeの必要operationを確認する。
7. Consumerを切り替え、旧developer tokenをprovider側でrevokeする。
8. 旧tokenが拒否されることを確認する。

GitHub App installation tokenは短命でも、App installationがall repositories／broad permissionsなら
blast radiusは大きいままです。Token lifetimeとApp grantを別々にreviewします。

成功状態:

- Automation inventoryにdeveloper OAuth／PATがない。
- App installationとtokenがexact repository／permissionへ限定される。
- Old authority denialを確認できる。

## 7. Developer credentialを保護する

実施者: Developer。Reviewer: Securityまたはendpoint owner。

- Interactive Git／CLIはorganization-approved OAuthまたはhardware-backed SSHを優先する。
- PATが不可避ならfine-grained、task専用、explicit repository、minimum permission、90日以下にする。
- OAuth／PATはOS keychainまたはapproved secret managerへ保存する。
- `.env`、shell profile、IDE JSON literal、Git remote URL、shell historyへcredential値を置かない。
- SSH authentication keyは可能な範囲でnon-exportable、hardware-backed、user verification付きにする。
- SSH authenticationとcommit signingのkey用途をinventoryで区別する。

Endpoint storageとhardware custodyはGitHub APIから証明できません。Sanitized endpoint reviewを
`PSB-SOURCE-001`のhost boundaryと組み合わせ、未確認なら`NOT_CHECKED`とします。

## 8. GitHub MCPを使用する場合

MCPを使わない場合、このsectionはreviewed `N/A`です。

1. [`../secure/github-mcp-oauth.json`](../secure/github-mcp-oauth.json)のremote OAuthを第一選択にする。
2. Local MCPがmemory-only OAuthを提供する場合もPATより優先する。
3. PATが不可避な場合だけ、[`../secure/github-mcp-auth-policy.json`](../secure/github-mcp-auth-policy.json)
   のbounded fallbackを使用する。
4. PATはMCP専用、fine-grained、explicit repository、read-only、90日以下にする。
5. IDE設定には`${input:github_token}`等のprotected referenceだけを置く。
6. Secretをexact MCP childへだけ解決し、IDE parent／shell全体へexportしない。
7. MCP artifactは`PSB-AI-002`、read-only toolset／write approvalは`PSB-AI-004`で別に強制する。

`password: true`は表示maskにすぎない可能性があります。OS keychain保管とchild-only deliveryを
live endpointで確認できない限り`SCL-015`は`NOT_CHECKED`です。

## 9. Quarterly reviewを運用する

実施者: Securityと各credential owner。Cadence: 90日以内。

各credentialについて次を確認します。

- Ownerが在籍し、現在のroleと一致する。
- Purposeとconsumerが存在する。
- Repositoryとpermissionが現在のtaskに必要である。
- Last useが説明でき、unused credentialはrevoke候補である。
- Expirationがpolicy内である。
- OAuth／App／SSO authorizationがcurrentである。
- Exceptionがactiveで、expiryとremediation ownerがある。

Inventory sourceがpartial、pagination incomplete、stale、unreadableの場合、reviewを完了にしません。

## 10. Revocation triggerを運用する

実施者: Incident response／identity owner。Approver: Security。

Trigger:

- Offboarding。
- Role／team／repository ownership change。
- Device lossまたはendpoint compromise。
- Credential exposureまたは疑い。
- Owner不在、purpose消滅、長期未使用。
- Broad permission、期限違反、invalid exceptionの発見。

処理順序:

1. 対象credential ID、owner、consumer、repository scopeを特定する。
2. Provider側でOAuth grant、PAT、SSH key、App credential／installationをrevoke／suspendする。
3. 関連sessionとdownstream credentialを無効化する。
4. 必要consumerを新しいbounded identityへ移す。
5. Old credentialで以前の許可操作が拒否されることを確認する。
6. Sanitized audit evidenceから利用と影響repositoryを調査する。
7. Exposure sourceを除去し、`PSB-SOURCE-003`と`PSB-GOV-004`へ必要なresponseを接続する。

File削除、Git history rewrite、replacement発行、自然expiryだけでrevocation完了としません。

## 11. Live verification

### 11.1 Test record

Credential値を含めず次を記録します。

- Control／check ID。
- Test repositoryのsanitized stable reference。
- Credential classとsanitized provider ID。
- Test actor role。
- Started／completed timestamp。
- Operation classとresult code。
- Reviewerとresult (`PASS`／`FAIL`／`NOT_CHECKED`／`ERROR`)。

### 11.2 Test sequence

1. Allowed test repositoryのreadを実行し、成功とaudit相関を確認する。
2. 明示的に未付与のpermissionを必要とするinert operationを試し、`403`等の拒否を確認する。
   Read-only profileではunique test refの作成を使用できる。
3. Unselected test repositoryをreadし、`403`／`404`の拒否を確認する。
4. Test credentialをprovider側でrevokeする。
5. Allowed readを再実行し、`401`／`403`／`404`の拒否を確認する。

HTTPのread-only profileでは、`POST /repos/{owner}/{allowed-test}/git/refs`にdefault branchのcommitと
uniqueな`refs/heads/psb-source-004-denial-<date>`を指定すると、`Contents: write`がないことを具体的に
確認できます。期待結果は`403`／`404`で、`201`は`FAIL`です。Tokenをrequest例やlogへ埋め込まず、
approved secret deliveryからtest client processへ渡します。

Write-capable automationはapproved writeをpositiveとし、別の未付与permissionをnegativeに選びます。
Unexpected operationが成功した場合は`FAIL`です。独立adminがtest changeを削除しpermissionを修正します。
Error、timeout、rate limit、untrusted outputを拒否成功として扱いません。

## 12. Evidence checklist

導入完了時に、組織のprivate evidence systemで次を参照できる状態にします。

- Current 2FA／SSO／phishing-resistant authentication policy。
- Classic／fine-grained PAT policyとactive grant review。
- Approved OAuth Appとinstalled GitHub App review。
- Credential／consumer inventoryとquarterly review date。
- Approved storage／SSH enrollment review。
- Audit coverage、retention、representative lifecycle event。
- Revocation drillとold-authority denial。
- Active exceptionとexpiry、またはexceptionなしの確認。

Policy文書やfixture outputだけをcurrent provider stateの代わりにしません。

## 13. Common failureとrecovery

| Failure | Recovery |
|---|---|
| 2FA変更でoutside collaboratorがremoved | Secure 2FA準拠後にowner reviewして再招待する |
| PAT policyでconsumerが停止 | Bounded fine-grained PATまたはGitHub Appへ移し旧tokenをrevokeする |
| OAuth restrictionでapproved Appが停止 | Inventoryとownerを確認し必要Appだけreauthorizeする |
| App migrationでpermission不足 | Exact missing operationだけをreviewして追加する |
| Audit APIがplan対象外 | UI／approved exportでmanual reviewしAPI checkは`NOT_CHECKED` |
| Evidence collection failure | `ERROR`として再収集し、clean扱いしない |
| Unexpected write succeeded | `FAIL`、test change cleanup、permission是正、再試験 |

## 14. Rollback

- Organization policyを一括scriptで戻さない。
- 変更前state、影響actor、security reviewer、rollback reasonを確認する。
- Classic PAT、unrestricted OAuth、all-repository Appを黙って再許可しない。
- Service continuityが必要なら、exact actor／repository／permission／期限のtemporary pathを作り、
  `PSB-GOV-002` exceptionへ登録する。
- Credential migrationはconsumer単位で戻し、old credentialを無期限に残さない。

## 15. References

- [GitHub personal access token policy](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
- [Managing fine-grained PAT requests](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/managing-requests-for-personal-access-tokens-in-your-organization)
- [OAuth App access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [GitHub App request and installation restrictions](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [Reviewing installed GitHub Apps](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-github-apps-installed-in-your-organization)
- [Requiring organization 2FA](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub REST API: Git references](https://docs.github.com/en/rest/git/refs)
