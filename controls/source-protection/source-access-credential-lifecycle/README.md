# PSB-SOURCE-004: Source access credential lifecycle

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | GitHub OAuth token、PAT、SSH key、App credentialが長寿命・過剰権限・平文保管・未棚卸しだと、単一credential theftがsource改変や組織侵害へ拡大する。 |
| 誰から、または何から守るか | Phishing、malware、悪意あるtool、local access、漏洩credentialの再利用、owner不在、rotation・revocation失敗から守る。 |
| 何が対象か | Developerとautomationのsource-platform credential、OAuth・PAT・SSH・GitHub App、scope、repository access、保管、期限、利用証跡、incident response。 |
| 何をするか | Automationは短命installation tokenやworkload identityを優先し、credentialをpurpose・owner・exact scope・保管・期限へbindして棚卸し、rotation、revokeを検証する。 |
| 成功状態 | Credential classごとの最小権限・短寿命・hardwareまたはsecret-manager保護・利用monitoringが満たされ、orphan・stale・broad・malformed recordは拒否される。 |
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

Short lifetimes, hardware keys, approval workflows, and recurring access
reviews add developer and administrator effort. Break-glass access must remain
narrow, monitored, and time-bound. Framework mappings in `control.yaml` are
supporting relationships, not a compliance claim.
