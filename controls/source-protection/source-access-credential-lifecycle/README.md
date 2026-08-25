# PSB-SOURCE-004: Source access credential lifecycle

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHub OAuth token、PAT、SSH key、App credentialが長寿命・過剰権限・平文保管・未棚卸しだと、単一credential theftがsource改変や組織侵害へ拡大する。

### 誰から、または何から守るか

Phishing、malware、悪意あるtool、local access、漏洩credentialの再利用、owner不在、rotation・revocation失敗から守る。

### 何が対象か

Developerとautomationのsource-platform credential、OAuth・PAT・SSH・GitHub App、IDEからGitHub MCPへのsecret delivery、scope、repository access、保管、期限、利用証跡、incident response。

### 何をするか

GitHub／IdPの認証・PAT・OAuth／App設定を安全側へ変更し、automationを短命identityへ分離する。Credentialをowner・purpose・exact scope・保管・期限へbindし、棚卸し、失効、監査を運用する。

### 成功状態

Current GitHub／IdP設定と完全なinventoryがbaselineを満たし、専用test scopeでexpected allow、未付与permission／scope拒否、失効後の旧authority拒否を確認できる。未確認項目は`NOT_CHECKED`のまま残る。

### 対象外・残余リスク

Fixture verifierはlive設定や導入を証明しない。Identity provider、developer endpoint、GitHub control plane自体の侵害、取得済みcloneやsourceの回収は対象外である。

## 導入

### セキュリティ向上の効果はどこから生まれるか

このcontrolの効果は、repository内のJSONをcopyすることではなく、次の実設定と運用から生まれます。

- GitHub／IdPで2FA、phishing-resistant authentication、PAT、OAuth／GitHub App policyを強制する。
- Developer user credentialをautomationから除き、GitHub App等の短命identityへ移す。
- Active credentialをowner、purpose、repository、permission、expirationと結び付けてreviewする。
- Offboarding、role change、device loss、exposure、長期未使用時にcredentialと関連sessionを失効する。
- Credential lifecycleと利用eventを保持し、影響repositoryへ相関できるようにする。

`secure/*.json`とverifierはreference baselineの説明とregression testです。それだけではlive GitHub
accessは変わらず、organization adoptionの証明にもなりません。

### 誰が何をするcontrolなのか

| Role | 作業 |
|---|---|
| Product owner | 対象repository、必要なaccess、automation consumerを確定する |
| Organization owner／IdP administrator | 2FA／SSO、PAT、OAuth／GitHub App、membership policyを変更する |
| Repository administrator | App／PATのrepositoryとpermissionを限定し、user tokenをautomationから除く |
| Platform／SRE | 短命automation identityとapproved secret deliveryを構築する |
| Developer | Approved OAuth／hardware-backed SSHを使用し、PAT fallbackをprotected storeへ置く |
| Security | Inventory、exception、audit coverage、revocation drillを独立reviewする |
| Incident response | Exposure等でgrant、token、key、sessionを失効し影響を確認する |

### 前提条件とtrust assumptions

- GitHub organization、対象repository、credential class、automation consumerを列挙できること。
- Organization ownerとsecurity reviewerを分離できること。
- 利用中のGitHub plan、SAML／SCIM、IdP、MCP有無を把握していること。
- 管理設定変更前にmember、outside collaborator、OAuth／GitHub App、PAT、SSHへの影響をreviewすること。
- Positive／negative test用にproductionから分離したtest repositoryと専用test credentialを用意できること。

### Copyまたは参照するfile

| 用途 | File |
|---|---|
| 実設定と運用 | [`docs/github-adoption-runbook.md`](docs/github-adoption-runbook.md) |
| General reference baseline | [`secure/credential-policy.json`](secure/credential-policy.json) |
| GitHub MCP OAuth | [`secure/github-mcp-oauth.json`](secure/github-mcp-oauth.json) |
| GitHub MCP PAT fallback | [`secure/github-mcp-auth-policy.json`](secure/github-mcp-auth-policy.json)と[`secure/github-mcp-pat-fallback.json`](secure/github-mcp-pat-fallback.json) |
| 将来のread-only監査 | [`docs/read-only-audit-options.md`](docs/read-only-audit-options.md) |

### 最短の導入手順

詳細とrecoveryは[GitHub adoption runbook](docs/github-adoption-runbook.md)を使います。

1. **Inventory**: 対象repository、member、App、OAuth、PAT、SSH、automation consumerとownerを記録する。
2. **Authentication**: Organization Settingsの`Authentication security`で2FAを必須にし、利用可能なら
   `Only allow secure two-factor methods`を有効にしてSMSを除外する。Passkey／security key要件は
   IdP／enterprise policyで別に強制・確認する。
3. **PAT**: `Personal access tokens`でclassic PAT accessをrestrictする。Fine-grained PATが必要なら
   administrator approval、explicit repository、minimum permission、maximum lifetime 90日以下にする。
4. **OAuth／App**: `OAuth app policy`でorganization access restrictionsを使用する。GitHub App installationを
   owner reviewへ寄せ、installed Appを`Only select repositories`相当とminimum permissionにする。
5. **Automation**: Developer OAuth／PAT consumerをGitHub App installation token等へ移し、旧credentialを失効する。
6. **Storage**: TokenをOS keychain／approved secret manager、SSH keyを可能ならhardware-backed keyへ移す。
7. **Operations**: 90日以内のinventory review、event-driven revocation、audit review、expiring exceptionを開始する。
8. **Verify**: 専用test scopeでexpected allow、ungranted permission拒否、選択外repository拒否、失効後拒否を確認する。

### 安全なself-test

一つのcredential classずつ、専用test repositoryだけで実行します。実値をcommand history、log、
repository evidenceへ残しません。

| Test | 操作 | 期待状態 |
|---|---|---|
| Positive | 許可されたtest repositoryでprofile上のallowed operationを行う | 成功し、audit eventへ相関できる |
| Negative: permission | 明示的に未付与のpermissionを必要とするinert operationを試す | `403`等で拒否され、変更がない |
| Negative: scope | 選択外test repositoryをread | `403`または`404`で拒否される |
| Revocation | 専用credentialを失効して同じreadを再試行 | `401`／`403`／`404`で旧authorityが拒否される |

Read-only profileでは、専用test repositoryへのunique test ref作成をpermission negativeにできます。
Write-capable automationは正当なwriteをpositiveとし、別の未付与permissionを選びます。操作が予期せず
成功した場合は`FAIL`として独立adminがtest changeを除去し、permissionを是正します。

### 期待する結果と状態

Live adoptionは次の状態で判定します。

- `PASS`: Current settingまたは実拒否結果がrequired stateを証明した。
- `FAIL`: Current stateまたは実試験がunsafe stateを示した。
- `NOT_CHECKED`: Plan、authority、endpoint、evidenceがなく確認していない。
- `ERROR`: Collection、authentication、pagination、parse、freshness等に失敗した。
- Reviewed `N/A`: 対象credential classまたはMCPを使用していない。

Reference implementationは次で確認できます。

```bash
make verify-control CONTROL=PSB-SOURCE-004
```

Exit statusは`0=reference accepted`、`1=security finding`、`2=input／evidence error`です。

### よくある失敗とrecovery

- 2FA有効化でoutside collaboratorが外れた: compliantな2FA設定後にreviewして再招待する。
- PAT lifetime policyで既存tokenが拒否された: consumerを新しいbounded credentialへ移し、旧tokenを明示失効する。
- OAuth restrictionでApp／SSH accessが止まった: pre-change inventoryにあるapproved対象だけをreauthorizeする。
- GitHub App migrationでautomationが停止した: App repository／permissionとconsumer設定を修正する。
  Broad user PATを無期限に復活させない。
- API／audit evidenceを取得できない: `PASS`にせず`NOT_CHECKED`または`ERROR`にする。

### Server-side enforcementとrollback

Developer-local設定だけでは完了しません。GitHub／IdP側のpolicy、App grant、PAT approval、audit、
membership lifecycleを必ず維持します。Provider settingは一括自動rollbackせず、変更前stateと影響対象を
reviewして設定単位で戻します。Rollbackでclassic PAT、unrestricted OAuth App、broad GitHub Appを
黙って再許可しません。緊急経路は`PSB-GOV-002`のnarrow、owned、expiring exceptionを使います。

### 導入完了条件

- Scope内のcredentialとconsumerにowner、purpose、resource、permission、review、expiration／revocation stateがある。
- GitHub／IdPのcurrent settingがbaselineを満たす。
- Developer tokenをautomationが使用していない。
- Expected allow、ungranted-permission denial、scope denial、revocation denialが専用test scopeで確認済みである。
- Audit eventをownerとtargetへ相関できる。
- 未確認項目とresidual riskが`NOT_CHECKED`として残り、fixture `PASS`をlive adoptionに使用していない。

### Read-only監査を追加する場合

今すぐcollectorを導入する必要はありません。Fine-grained PAT、installed GitHub Apps、SAML credential
authorization、audit logの一部はGitHub API／exportでread-only確認できます。一方、IdP policy、
keychain保管、IDE child-only delivery、SSH hardware custodyは別sourceが必要です。確認可能なfield、
plan／permission制約、future collectorのfail-closed要件は
[`docs/read-only-audit-options.md`](docs/read-only-audit-options.md)にまとめています。

## Security problem

GitHub OAuth tokens, personal access tokens (PATs), SSH keys, and GitHub App
credentials can authorize source access, workflow changes, release operations,
and organization data access. Attackers target developers because one reusable
credential can turn endpoint compromise or phishing into organization-wide
source and software-supply-chain impact.

The token prefix identifies the credential mechanism, not its safety:

- `gho_...` is an OAuth access token, including tokens issued for GitHub CLI;
- `ghp_...` is a classic PAT;
- `github_pat_...` is a fine-grained PAT;
- SSH authentication uses a private key rather than an HTTP token.

OAuth tokens and PATs are different credential types, but both require
least-privilege authorization, protected storage, bounded lifetime, inventory,
review, revocation, and audit. A token must not be called "safe" merely because
it was created by `gh`.

## Threat actor, action, and target

- A phisher, infostealer, malicious extension, dependency, or local user steals
  a cached developer credential.
- An over-broad token grants access to repositories, workflows, organization
  data, or releases beyond the developer's immediate task.
- An abandoned token or SSH key remains usable after role change, offboarding,
  device loss, or an incident.
- A malicious IDE extension, child process, or prompt-injected MCP tool obtains
  a PAT from an ambient IDE or shell environment and reuses its GitHub access.
- The target is the source-platform identity boundary: user OAuth grants, PATs,
  SSH keys, GitHub Apps, credential storage, and organization authorization.

The objective is to prevent one developer credential from becoming durable,
unbounded organization access. Endpoint hardening remains in `PSB-SOURCE-001`;
CI/CD workload federation remains a separate control boundary.

## Secure and insecure examples

- `secure/credential-policy.json` is a metadata-only policy that prefers
  short-lived or installation-scoped mechanisms, limits PATs, protects local
  storage, and requires review and revocation.
- `insecure/credential-policy.json` deliberately permits classic PATs,
  unrestricted resources, plaintext storage, indefinite lifetime, and missing
  review or audit controls.
- `secure/github-mcp-*.json` demonstrates OAuth-first GitHub MCP authentication
  and a metadata-only fine-grained PAT fallback delivered only to an exact
  read-only MCP child process.
- `insecure/github-mcp-*.json` deliberately hardcodes a token placeholder,
  launches a floating image, enables every toolset, and has no lifecycle owner.

The fixtures contain no token, private key, username, repository name, or
production evidence. They are not applied to GitHub or the host, and their
success is not organization adoption evidence.

## Authentication selection

Use the narrowest mechanism that fits the actor:

1. For automation, prefer a GitHub App installation token or another
   short-lived workload identity with explicit repository permissions.
2. For interactive developer Git access, use an organization-approved
   authentication flow such as GitHub CLI OAuth or hardware-protected SSH,
   combined with phishing-resistant MFA, SSO authorization, bounded grants,
   and secure credential storage.
3. If a PAT is unavoidable, prefer a fine-grained PAT restricted to the
   required owner, repositories, permissions, and expiration.
4. Treat classic PATs and broad scopes such as `repo` or `workflow` as
   exception paths requiring documented need, owner, approval, and expiry.

Fine-grained does not automatically mean least privilege. Resource owner,
repository selection, permission set, duration, and organization approval must
all be reviewed.

## GitHub MCPを開発者IDEで使う場合

環境変数はsecret storeではなく、secretを必要なprocessへ渡す配送手段です。PATを
`.bashrc`、`.zshrc`、`.env`、IDE JSON、Git remote URLへ保存したり、PATを持つ親shellから
IDE全体を起動したりすると、別extensionや子processへGitHub authorityが広がります。

このcontrolは次の順序を強制します。

1. GitHub.comの対応IDEでは公式remote MCPのOAuthを第一選択にする。
2. Local MCPでOAuthを利用できる場合も、user管理PATよりmemory-only OAuthを優先する。
3. PATが不可避な組合せだけ、GitHub MCP専用fine-grained PATを発行する。
4. PATはownerを1つ、repositoryを明示選択、permissionをread-only最小限、期限を90日以下に
   し、Organization approvalとSSO policyへ接続する。
5. PATはOS keychainまたは承認済みsecret managerへ置き、IDE設定には
   `${input:github_token}`という参照だけを記録する。
6. `GITHUB_PERSONAL_ACCESS_TOKEN`はexact MCP child processへだけ解決し、IDE parentや
   全shell環境へexportしない。
7. MCPは既定でread-onlyとし、`context,repos,pull_requests`だけを公開する。Write用途は
   別profileとし、`PSB-AI-004`のexact tool authorizationと人間の承認を通す。

OAuthの最小構成は[`secure/github-mcp-oauth.json`](secure/github-mcp-oauth.json)です。
PAT fallbackの[`secure/github-mcp-pat-fallback.json`](secure/github-mcp-pat-fallback.json)は
credential値を含まず、管理配布したexact commandへsecret参照だけを渡します。
`password: true`は表示maskにすぎない可能性があるため、実際のIDEが入力をOS keychain等へ
保存し、MCP childだけへ渡すことをlive endpoint evidenceで確認するまでは
`NOT_CHECKED`です。

Control境界は次のとおりです。

| Control | GitHub MCPに対する責務 |
|---|---|
| `PSB-SOURCE-004` | OAuth／PAT選択、PAT権限・期限・秘密保管・rotation・revoke・audit。 |
| `PSB-AI-002` | 公式MCP serverのcanonical source、immutable artifact、semantic review、revocation。 |
| `PSB-AI-004` | Exact MCP command／URL、read-only toolset、write approval、runtime inventoryとaudit。 |

## Verification

From the repository root:

```bash
make verify-control CONTROL=PSB-SOURCE-004
```

The reference verifier:

- accepts the secure metadata fixture;
- rejects the insecure fixture with one finding for every atomic requirement;
- reports malformed or unreadable input as `ERROR` with exit code `2`;
- never reads or prints an actual credential.
- accepts the OAuth-first and bounded PAT-fallback GitHub MCP fixtures;
- rejects hardcoded ambient broad and mutable GitHub MCP configuration;
- treats malformed or credential-bearing MCP evidence as `ERROR` with exit
  code `2`, never as a clean configuration.

Production adoption follows the runbook and requires current organization token
policy, OAuth and App grants, SSH inventory, audit records, protected-storage
review, access review, and a sanitized revocation exercise. Missing live
evidence remains `NOT_CHECKED`.

## Incident response

When exposure is suspected:

1. revoke the OAuth grant, PAT, SSH key, or App credential first;
2. invalidate related sessions and rotate downstream credentials;
3. preserve sanitized audit evidence and determine repositories and operations
   reached with the credential;
4. remove exposed values from source, logs, artifacts, caches, and history;
5. review forks and previously cloned copies;
6. close the lifecycle gap that allowed excessive privilege or persistence.

Deleting a token from a file or rewriting Git history does not revoke it.

## Limitations and operational cost

The repository verifier validates reference metadata; it cannot enumerate or
revoke live GitHub credentials. GitHub organization and enterprise settings, SSO,
audit-log retention, and token approval capabilities vary by plan and platform
configuration. OAuth grants may be broader or longer-lived than desired even
when local storage is protected. SSH commit signing and SSH authentication are
different uses and must be governed separately.

The exact managed command in the PAT sample is an organization deployment
contract, not proof that the installed GitHub MCP binary is authentic. Bind it
to a reviewed immutable artifact through `PSB-AI-002`. IDEs differ in secret
input persistence and environment inheritance, so a static `${input:...}`
reference cannot prove OS-keychain storage or child-only delivery. Live
adoption remains `NOT_CHECKED` until endpoint evidence confirms both.

Short lifetimes, hardware keys, approval workflows, and recurring access
reviews add developer and administrator effort. Break-glass access must remain
narrow, monitored, and time-bound. Framework mappings in `control.yaml` are
supporting relationships, not a compliance claim.

## References

- [実装仕様書](docs/implementation-spec.md)
- [実装計画書](docs/implementation-plan.md)
- [GitHub adoption runbook](docs/github-adoption-runbook.md)
- [Read-only audit options](docs/read-only-audit-options.md)
- [GitHub personal access token policy](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
- [GitHub OAuth App access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [GitHub App request and installation restrictions](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [GitHub organization 2FA requirements](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub MCP Server setup](https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server)
- [GitHub MCP Server README pinned at `3778a41476e31a072430cfee7c5d31c5f72def60`](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/README.md)
- [GitHub MCP policies and governance pinned at `3778a41476e31a072430cfee7c5d31c5f72def60`](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/docs/policies-and-governance.md)
- [REF-AI-004 GitHub MCP official authentication guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-004)
