# GitHub implementation: Source access credential lifecycle

Pattern：[Source access credential lifecycle](../../README.md)

Control：[PSB-SOURCE-004](../../../../../controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/README.md)

## Status

Migration Pilotです。旧ProjectのGitHub guidanceを再配置したもので、採用時にはGitHub plan、API、画面、
IdP構成を公式documentationで再確認してください。Sampleやこの文書の存在は導入証拠ではありません。

## 対象

- GitHub.comまたはGitHub Enterprise Cloudのorganizationとrepository。
- OAuth grant、fine-grained／classic PAT、SSH authentication key、GitHub App。
- Developer access、repository automation、GitHubへ接続するdeveloper tool。

## 先に決めること

| Decision | Owner |
|---|---|
| 対象organization、repository、business-critical operation | Product owner |
| Human authentication、SSO、joiner／mover／leaver | Organization／IdP owner |
| PAT、OAuth App、GitHub App policy | Organization owner、Security |
| Automation identityとconsumer | Repository admin、Platform |
| Endpoint storageとtoolへのdelivery | Endpoint owner、Developer |
| Review cadence、revocation objective、incident handoff | Security、Incident response |

## Recommended adoption sequence

### 1. Current authorityを棚卸しする

Credential値を収集せず、class、sanitized ID、owner、purpose、repository selection、permission、
created／last-used／expiry、review stateを記録します。APIやUIで取得できない範囲は未確認として残します。

### 2. Human authenticationを強化する

Organizationのauthentication policyをIdPと接続し、source accessとcredential変更に適したMFAを要求します。
設定変更前に、memberとoutside collaboratorへの影響、recovery owner、再登録手順を確認します。

### 3. Programmatic accessを制限する

- Classic PATを通常経路にしない。
- Fine-grained PATが必要なら、owner、selected repositories、permissions、expiryをreviewする。
- OAuth AppとGitHub Appをorganization ownerのreview対象にする。
- App installationごとにrepository selectionとpermissionを確認する。

### 4. AutomationからHuman credentialを除く

Developer PATやOAuth tokenを使用するbot／CIを、GitHub App installation token等の短命identityへ移します。
Consumerの移行後、旧credentialを明示的にrevokeします。

### 5. Storageとdeliveryを分ける

PATやtokenをshell profile、dotenv、Git remote URL、repository、IDE JSON literalへ保存しません。
Approved keychainまたはsecret managerから、必要なprocessだけへ短時間配送します。

### 6. Expected allowとdenialを確認する

Productionから分離したtest repositoryとtest identityで、次を確認します。

- 許可したreadまたはwriteだけが成功する。
- 未付与operationが副作用なしで拒否される。
- Selected repository外へのaccessが拒否される。
- Test credentialのrevocation後、同じoperationが拒否される。

Timeout、API failure、権限不足で試験できない状態は、拒否成功として扱いません。

### 7. Reviewとrevocationを運用する

Offboarding、role change、device loss、exposure、owner不在、用途終了、長期未使用をtriggerにします。
Replacement発行、file削除、自然expiryだけで完了とせず、旧authorityの拒否まで確認します。

## GitHub-connected developer tools

ToolがOAuthを安全に利用できる場合は、user-managed PATを日常的に作らない構成を優先します。
PAT fallbackが不可避なら、tool専用、selected repositories、read-onlyの必要permission、bounded expiryとし、
親IDEやunrelated child processへ値を広げません。

Credential scopeだけでtool actionを認可しません。Write actionやhigh-impact operationは別のruntime
authorization boundaryで制御します。

## Failure handling

- Authentication policy変更で利用者が停止した場合、安全要件を満たす再登録を行う。
- App permission不足は必要operationだけを追加し、全repository／broad writeへ戻さない。
- Evidence sourceを取得できない場合、安全と推測せずAssessment上で未確認またはerrorにする。
- Emergency accessはactor、resource、operation、期限、別承認者を限定する。

## Official references

- [Versioned GitHub Security Guidance source record](../../../../../sources/README.md#spec-github-security-guidance)
- [REF-AI-004 GitHub MCP source record](../../../../../sources/README.md#ref-ai-004)
- [GitHub credential types](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types)
- [Managing programmatic access to your organization](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization)
- [Setting a personal access token policy for your organization](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
- [OAuth App access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [Limiting OAuth App and GitHub App requests and installations](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [Reviewing GitHub Apps installed in your organization](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-github-apps-installed-in-your-organization)
- [Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [Reviewing the audit log for your organization](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
- [Setting up the GitHub MCP Server](https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server)
- [Pinned GitHub MCP README](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/README.md)
- [Pinned GitHub MCP policies and governance](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/docs/policies-and-governance.md)
