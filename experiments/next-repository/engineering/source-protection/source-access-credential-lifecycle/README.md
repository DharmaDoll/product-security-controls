# ENG-SOURCE-001: Source access credential lifecycle

対応するControl：[PSB-SOURCE-004](../../../controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/README.md)

## Summary

Human、automation、developer toolへsource platformのauthorityを与えるとき、credentialの選択だけでなく、
発行、配送、利用、棚卸し、失効、監査までを一つのlifecycleとして設計します。

## Use case

- DeveloperがGit client、CLI、IDEからsourceを読み書きする。
- CI、bot、release serviceがrepositoryへアクセスする。
- MCP serverやdeveloper toolが利用者に代わってsource metadataを読む。
- Offboarding、role change、device loss、incident後にauthorityを止める。

## Scope and assumptions

対象はsource platformへ提示されるHumanまたはworkload credentialと派生sessionです。
Endpoint全体の防御、source changeの内容review、agent tool authorization、source platform自体の侵害は隣接問題です。

Source platformとIdPが、resource、operation、lifetime、revocationを強制できることを前提とします。

## Assets and trust boundaries

主なAssetはsource、workflow、release設定、repository metadata、それらを操作するauthorityです。

```text
Human / workload
       |
       v
approved authentication and credential issuance
       |
       v
protected store -> exact consumer process
       |
       v
source-platform authorization -> repository operation
       |
       v
current inventory / audit / revocation
```

次の境界を別々に確認します。

1. Identity proofからcredential issuance。
2. Protected storageからconsumerへの配送。
3. Credentialからsource resource／operationへのauthorization。
4. Lifecycle eventからcredential／session revocation。

## Threat and abuse paths

| Threat | Abuse path | Impact |
|---|---|---|
| Credential theft | Plaintext file、parent environment、malicious extensionから取得 | Sourceの読取・変更、workflow悪用 |
| Overprivilege | 一つのtask用credentialが全repository／writeへ到達 | Blast radius拡大 |
| Identity confusion | Automationがdeveloper accountを共有 | Owner、目的、失効条件が曖昧になる |
| Lifecycle drift | Offboardingや用途終了後もgrant／sessionが残る | 長期persistence |
| Audit gap | Current grantとeventを相関できない | Detectionとcontainmentの遅延 |

## Security invariants

- Humanとautomationのauthorityを同じ長期credentialへ集約しない。
- Credentialをactor、purpose、resource、operation、expiryへ結び付ける。
- Protected storeから必要なconsumerだけへ配送する。
- Lifecycle event後はcredentialと関連sessionを無効化し、旧authorityを拒否する。
- Credential値を記録せずにcurrent authorityと重要eventを調査できる。

## Architecture decisions

### Humanかworkloadか

Interactive accessには組織承認済みのHuman authenticationを使います。AutomationにはHuman tokenを再利用せず、
対象resourceとtaskへ限定できるapplicationまたはworkload identityを使います。

### Scopeをどこで狭めるか

Credential発行時だけでなく、source platform側のrepository selectionとoperation permissionで強制します。
Tool側のallow-listはdefense in depthであり、provider authorizationの代替にしません。

### Storageとdeliveryを分ける

Keychainやsecret managerは保管場所です。Environment variableやprocess inputは配送経路です。
安全なstoreから取り出した値でも、parent process全体へ渡せばambient authorityになります。

### Expiryとrevocationを分ける

Expiryは最長存続時間を制限します。Revocationはincidentやlifecycle eventを受け、期限前でもauthorityを止めます。
両方を持たせます。

## Implementation selection

| Situation | Recommended direction |
|---|---|
| Developer interactive Git | SSO／MFAへ結び付いたapproved OAuth、またはhardware-backed SSH等 |
| Repository automation | Installation／repository／permissionに限定した短命application identity |
| Developer tool／MCP | OAuthを優先し、fallback credentialはtool専用・resource限定・短命にする |
| Emergency operation | 通常grantを恒久拡大せず、別承認と期限を持つbreak-glass path |

製品名だけで安全性を決めず、実際のgrantとdelivery pathを比較します。

## What to verify

設計reviewでは少なくとも次を観測します。

- Current inventoryがHuman、automation、App、key、grant、sessionの対象scopeを表す。
- Expected operationは成功し、未付与operationと対象外resourceは拒否される。
- Lifecycle event後に旧credentialと派生sessionが拒否される。
- Audit eventをsanitized credential identity、actor、resource、operationへ相関できる。
- Provider／IdP／endpointの未確認領域をsampleで補完していない。

具体的なtest harnessはplatform ImplementationまたはAssessmentが所有します。

## Operations and response

Owner不在、用途終了、長期未使用、role change、offboarding、device loss、exposureをreview／revocation triggerにします。
Incident時はreplacement発行より先に旧authorityをcontainし、source、workflow、releaseへの利用履歴を調べます。

## Residual risk

Source platformやIdPのcontrol plane compromise、認証済みendpoint sessionの乗っ取り、既にcloneされたsourceは残ります。

## Implementations

- [GitHub](implementations/github/README.md)

## Related insights

- [Credentialは文字列ではなく委任されたauthority](../../../docs/insights/credential-is-delegated-authority.md)
- [Security効果はEnforcement Pointに宿る](../../../docs/insights/security-effects-live-at-enforcement-points.md)

## Sources

- [GitHub Security Guidance baseline](../../../sources/README.md#spec-github-security-guidance)
- [REF-AI-004 GitHub MCP guidance](../../../sources/README.md#ref-ai-004)
- [REF-USER-001 endpoint hardening input](../../../sources/README.md#ref-user-001)
