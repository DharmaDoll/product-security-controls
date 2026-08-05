# PSB-SOURCE-004: Source access credential lifecycle

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | GitHub OAuth token、PAT、SSH key、App credentialが長寿命・過剰権限・平文保管・未棚卸しだと、単一credential theftがsource改変や組織侵害へ拡大する。 |
| 誰から、または何から守るか | Phishing、malware、悪意あるtool、local access、漏洩credentialの再利用、owner不在、rotation・revocation失敗から守る。 |
| 何が対象か | Developerとautomationのsource-platform credential、OAuth・PAT・SSH・GitHub App、IDEからGitHub MCPへのsecret delivery、scope、repository access、保管、期限、利用証跡、incident response。 |
| 何をするか | Automationは短命installation token、GitHub MCPはOAuthを優先し、PAT fallbackをpurpose・owner・exact scope・秘密ストア・MCP子process・期限へbindして棚卸し、rotation、revokeを検証する。 |
| 成功状態 | Credential classごとの最小権限・短寿命・hardwareまたはsecret-manager保護・利用monitoringに加え、GitHub MCPが既定read-onlyになり、orphan・stale・broad・平文・malformed recordは拒否される。 |
| 対象外・残余リスク | Verifierはlive GitHub credentialを列挙・失効・実権限testせず、identity provider、developer endpoint、GitHub control plane自体の侵害を防がない。 |

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
production evidence. They are not applied to GitHub or the host.

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

The verifier:

- accepts the secure metadata fixture;
- rejects the insecure fixture with one finding for every atomic requirement;
- reports malformed or unreadable input as `ERROR` with exit code `2`;
- never reads or prints an actual credential.
- accepts the OAuth-first and bounded PAT-fallback GitHub MCP fixtures;
- rejects hardcoded ambient broad and mutable GitHub MCP configuration;
- treats malformed or credential-bearing MCP evidence as `ERROR` with exit
  code `2`, never as a clean configuration.

Production adoption requires external evidence such as organization token
policy, OAuth application grants, SSH-key inventory, audit-log records,
credential-helper configuration, access review, and a sanitized revocation
exercise.

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

This control validates declared policy metadata; it cannot enumerate or revoke
live GitHub credentials. GitHub organization and enterprise settings, SSO,
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

- [GitHub MCP Server setup](https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server)
- [GitHub MCP Server README pinned at `3778a41476e31a072430cfee7c5d31c5f72def60`](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/README.md)
- [GitHub MCP policies and governance pinned at `3778a41476e31a072430cfee7c5d31c5f72def60`](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/docs/policies-and-governance.md)
- [REF-AI-004 GitHub MCP official authentication guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-004)
