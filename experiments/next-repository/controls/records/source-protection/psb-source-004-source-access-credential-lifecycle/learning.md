# Source access credential lifecycle — Learning Note

[Control Record](README.md)

## この文書の目的

Credentialを「漏らしてはいけない文字列」とだけ捉えず、source platform上のauthorityとして設計するための教材です。
特定のGitHub画面や一つのtoken種別を覚えることは目的ではありません。

## 1. 具体Scenario

DeveloperがIDE extensionからsource repositoryを読むため、長期PATを設定しています。PATはshell profileへ
exportされ、IDE本体とすべてのchild processが読み取れます。対象は一つのrepositoryですが、tokenは複数repositoryへの
write権限を持ち、有効期限もありません。

悪意あるextensionまたは侵害されたtoolが環境変数を読み取ると、攻撃は次のように進みます。

```text
malicious extension
      |
      v
parent processからPATを取得
      |
      v
source platformが有効なcredentialとして受理
      |
      +--> unrelated repositoryを読む
      +--> sourceやworkflowを変更する
      +--> developerが気付くまで再利用する
```

問題はPATという名称ではありません。一つのcredentialが、必要以上のresource、operation、期間、consumerへ
authorityを広げていることです。

## 2. 用語

### Identity

誰または何がrequestしているかを表す主体です。Human account、application、workloadなどがあります。

### Credential

Source platformがIdentityまたはauthorityを確認するために受け入れるtoken、key、grant等です。

### Authority

実際に許可されるoperationの範囲です。Credentialを保護する理由は、文字列そのものではなくauthorityを奪われないためです。

### Session

Credentialやauthenticationから派生し、一定期間requestを許可する状態です。元のcredentialだけを削除しても、
既存sessionが使える場合があります。

### Revocation

古いauthorityを無効にし、同じrequestが拒否される状態へ変えることです。新credentialの発行やfile削除とは異なります。

## 3. Threat Model

想定する相手は、phishing adversary、infostealer、malicious extension、侵害されたdeveloper tool、
元の役割を失った利用者です。Source platformのcontrol plane全体を支配しているとは仮定しません。

守る対象はsource、workflow、release設定、repository metadataと、それらを変更できるauthorityです。

主なtrust boundaryは次の三つです。

1. Endpoint上のstorageからconsumer processへの配送。
2. Consumerからsource platformへのauthenticationとauthorization。
3. HR／IdP／incident eventからprovider側revocationへの連携。

## 4. Security Invariant

> 一つのcredentialが盗まれても、攻撃者は元のactor、purpose、resource、operation、期間を越えた
> source authorityを取得できず、lifecycle event後は古いauthorityを再利用できない。

完全なcredential theft防止を前提にせず、盗難時のblast radiusとpersistenceを制限します。

## 5. 直感をCalibrationする

### 「Fine-grainedなら安全」ではない

Fine-grainedという種類でも、全repository、write permission、長い期限を選べば広いauthorityになります。
Labelではなく実grantを見ます。

### 「Keychainに入れたから安全」ではない

Protected storageはcopyを減らしますが、正規processが不要なresourceへアクセスできるならoverprivilegeは残ります。

### 「短命tokenだからrevocation不要」ではない

短命性はpersistenceを制限しますが、incident中に有効なsessionやrefresh pathが残る可能性があります。

### 「新しいtokenへrotationしたから完了」ではない

旧credentialと関連sessionが拒否されるまで、replacementは新しいauthorityを追加しただけです。

## 6. 設計判断

Actorごとに必要なaccessを分けます。

| Actor | 優先する考え方 |
|---|---|
| Developer | 組織承認済みinteractive authentication、保護されたstorage、必要resourceだけのgrant |
| Automation | Human credentialを再利用せず、resourceとtaskに限定した短命workload identity |
| Emergency operator | 通常権限を恒久拡大せず、狭く監視された期限付き経路 |
| Agent／tool | Credential scopeに加え、toolとparameterのruntime authorizationを別境界で強制 |

## 7. Control境界

このControlへPassしても、endpoint malware、malicious source change、unsafe tool invocation、source platform
control plane compromiseまで安全になるわけではありません。逆に、endpointが十分にhardenedでも、provider側に
orphaned credentialが残ればこのControlは成立しません。

## 8. 持ち帰る問い

- 現在利用可能なsource authorityを、credential値を見ずに一覧化できるか。
- AutomationがHuman accountへ依存していないか。
- Credentialを保管している場所と、実際に受け取るprocessを区別できるか。
- Offboardingやlossから、関連sessionの拒否まで追跡できるか。
- Audit eventをcurrent grantと取り違えていないか。

## Related insight

- [Credentialは文字列ではなく委任されたauthority](../../../../docs/insights/credential-is-delegated-authority.md)
- [Security効果はEnforcement Pointに宿る](../../../../docs/insights/security-effects-live-at-enforcement-points.md)

## Sources

- [GitHub Security Guidance baseline](../../../../sources/README.md#spec-github-security-guidance)
- [REF-AI-004 GitHub MCP guidance](../../../../sources/README.md#ref-ai-004)
- [REF-USER-001 endpoint hardening input](../../../../sources/README.md#ref-user-001)
