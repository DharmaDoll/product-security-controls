# PSB-AI-009: Rogue agentを独立停止し安全な状態へ復旧する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Goalを逸脱・侵害されたagentが停止命令を無視できる、または停止後に古いkey・session・approvalを再利用できると、tool操作、model利用、memory汚染、agent間伝播が継続し、拙速な復旧で再侵害する。 |
| 誰から、または何から守るか | Prompt injectionやsupply-chain compromiseを受けたagent、誤った自律判断、侵害operator、retry automation、agent自身へ依存したkill switch、control-plane・collector・署名検証障害から守る。 |
| 何が対象か | Agent/session identity、model・tool・delegation・memory authority、agent key、approval、進行中action、incident evidence、fallback runbook、復旧用identityとread-only canary。 |
| 何をするか | Model・agent・repository・extensionから独立したcontrol planeで、署名付き停止命令をexact agent/sessionへ適用する。全authorityを失効し、不確実なactionを隔離し、model非依存fallbackを使い、二者承認後に新しいidentityで段階復旧する。 |
| 成功状態 | 検知から60秒以内に新規model/tool/delegation/memory操作が止まり、旧authorityが無効化される。証跡保全とfallback試験後、旧key/sessionのreplayが拒否され、独立した二者署名により新sessionのread-only canaryだけが再開する。 |
| 対象外・残余リスク | Synthetic fixtureはlive provider、gateway、key custody、credential revocation、process kill、SIEM、incident teamの実運用を証明しない。外部side effectのrollback、full-authority復旧、原因となったmodelの安全性、組織PSIRT成熟度は別途必要である。 |

## セキュリティ上の問題

Agentが侵害・誤作動したと判断した後も、そのagentへ「停止してください」とpromptで依頼するだけでは
containmentになりません。Agent自身、読み込んだrepository、侵害されたextension、または同じmodelが
停止判断と実行を支配していると、攻撃者は停止条件を書き換えられます。

また、processだけを終了しても次のauthorityが残れば、再起動やreplayで同じ侵害が続きます。

- model accessとtool grant;
- agent signing keyとsession authority;
- 未消費approvalとdelegation nonce;
- memory write authority;
- pending actionと結果不明のside effect。

このcontrolは「止める」だけでなく、証跡を壊さずに隔離し、限定fallbackを試験し、新しいidentityへ
段階的に復旧するまでを一つのstate machineとして扱います。

```text
DETECTED
  -> CONTAINMENT_AUTHORIZED
  -> CONTAINED
  -> QUARANTINED
  -> RECOVERY_PENDING
  -> RECOVERED_READ_ONLY
```

## 誰から何を守るか

主な攻撃者・失敗源は次のとおりです。

- Prompt/document injectionやpoisoned memoryでgoalを逸脱したagent;
- 悪意あるSkill、MCP server、plugin、model/tool adapter;
- 未承認delegationやapproval replayを繰り返す侵害済みagent;
- Agent自身が停止処理を実行するagent-local kill switch;
- Timeoutを未実行と誤認して自動retryするworkflow;
- 原因・旧authority・negative testを確認せず復旧するoperator;
- 収集欠損、署名検証不能、制御面停止を「異常なし」と扱う運用。

保護対象はsourceやdeployment等の外部side effect、developer/cloud authority、他agentとtenant、
incident evidence、および安全に再開できる復旧経路です。

## Control境界

| Control | 所有する境界 |
|---|---|
| `PSB-AI-006` | Typed action、exact request identity、single dispatch、unknown outcome quarantine。 |
| `PSB-AI-007` | Resource・anomaly signal、warning restriction、single-session circuit breaker、alert receipt。 |
| `PSB-AI-008` | Agent間identity・delegation・budget ceiling、replay、one-hop停止。 |
| `PSB-AI-009` | 独立した停止authority、全権限失効、incident quarantine、fallback、復旧前提、二者承認、read-only再開。 |
| `PSB-GOV-001` | SBOM/build/artifact/deploymentを使うsoftware supply-chain incident影響検索とdry-run runbook。 |

AI-009はAI-006／007／008のexact policy IDとSHA-256を固定します。これらの意味が変われば、古い
incident fixtureは`ERROR`となり再reviewが必要です。AI assetとdeployment identityが整うまでは、
live incident workflowとGOV-001の接続を`NOT_CHECKED`のままにします。

## 安全な実装

### 独立control planeと検知

[`secure/policy.json`](secure/policy.json)は停止・復旧planeがagent process、model output、repository
content、extension runtimeから独立し、agentやrepositoryから無効化できないことを要求します。

[`secure/trigger-evidence.json`](secure/trigger-evidence.json)は次のsanitized signalを結合します。

- AI-007の`approval-replay`、open circuit breaker、verified alert receipt;
- AI-008の`invalid-delegation-attempt`とdownstream未dispatch。

Signalは停止理由であり、modelへ渡すpromptやtool contentは保存しません。

### 署名付きcontainment

[`secure/containment-command.json`](secure/containment-command.json)はincident commanderが署名した
5分間有効なexact agent/session命令です。Wildcard tenant、agent、sessionは許可しません。
Verifierはrepositoryにあるpublic keyだけを使用してEd25519署名を検査します。Fixture署名用の
private keyはrepositoryへ保持しません。

命令適用後、60秒以内に次を同時に止めます。

- 新規model call;
- tool dispatch;
- agent間delegation;
- memory write;
- 対象agent process。

Agent key、approval receipt、delegation nonce、model access、session authority、tool accessも個別に
失効します。Process停止だけでauthorityを残す状態は合格しません。

### Quarantineとfallback

`pending-action`と`unknown-outcome`は自動retryせずquarantineし、cleanupより先にmetadata-onlyの
evidence snapshotを保全します。外部処理の成否が不明な場合はAI-006のreconciliationを使います。

Fallbackは最大15分の`operator-runbook-read-only`です。Agent process、model、tool dispatch、
mutationを使わず、incident status、runbook、保全済みevidenceのreadだけを許可します。この経路も
実際にexerciseされていなければ復旧条件を満たしません。

### 復旧

[`secure/recovery-authorization.json`](secure/recovery-authorization.json)はincident commanderと
security reviewerの異なる二者が同じpayloadへ署名します。次を満たすまで発行できません。

- Root causeがreview済み;
- 旧agent keyと旧session authorityが無効;
- clean runtime revision、新agent ID、新key、新sessionを使用;
- 旧session、key、approval、delegationのreplay negative testがすべてdeny;
- evidence保全とfallback exerciseが完了。

復旧は最大5分のauthorizationで新sessionをread-only canaryとして起動します。旧authorityを戻さず、
full-authorityへ自動昇格しません。Fixtureの最終状態は`RECOVERED_READ_ONLY`です。

## 危険な実装

`insecure/`は実serviceへ接続しないinert fixtureで、次を再現します。

- Agent自身が無効化できるrepository-local hookをkill switchとする;
- 改ざん済み署名、wildcard scope、2時間有効な停止命令を受理する;
- Model、tool、delegation、memory、agent processを動かし続ける;
- Key、access grant、session authorityを失効しない;
- Unknown outcomeを自動retryし、snapshotより先にcleanupする;
- Agent/modelを使うfull-authority fallbackを実行する;
- Root causeなし、旧key・旧sessionのまま、negative testをskipする;
- 同一operatorだけで復旧し、canaryなしでfull authorityを自動復元する;
- Synthetic fixtureからlive adoptionを`ADOPTED`と過大主張する。

これらは既知のunsafe behaviorとして`FAIL`です。Policy/trust/public key改ざん、malformed、collector／
evaluator／crypto verifier障害、sensitive evidence混入は判断不能なので`ERROR`です。

## 検証

Repository rootから実行します。

```bash
make verify-control CONTROL=PSB-AI-009
```

Verifierを直接実行する場合:

```bash
python3 controls/ai-development-security/rogue-agent-containment-recovery/scripts/verify.py \
  --repository-root . \
  --policy controls/ai-development-security/rogue-agent-containment-recovery/secure/policy.json \
  --trigger controls/ai-development-security/rogue-agent-containment-recovery/secure/trigger-evidence.json \
  --containment-command controls/ai-development-security/rogue-agent-containment-recovery/secure/containment-command.json \
  --recovery-authorization controls/ai-development-security/rogue-agent-containment-recovery/secure/recovery-authorization.json \
  --evidence controls/ai-development-security/rogue-agent-containment-recovery/secure/incident-evidence.json
```

終了コードは`0=accepted`、`1=known unsafe behavior`、`2=evidence／dependency／evaluator error`です。
署名が不正な命令は`FAIL`、public keyやcrypto verifierを利用できない状態は`ERROR`になります。

## 期待する出力

```text
PASS PSB-AI-009/RRC-001 control plane and cross-control contracts are independent and immutable
PASS PSB-AI-009/RRC-002 trigger evidence is attributable complete fresh and policy-bound
...
PASS PSB-AI-009/RRC-011 evidence is ordered sanitized and live enforcement remains NOT_CHECKED
ACCEPTED rogue-agent containment and recovery evidence; live enforcement NOT_CHECKED
```

## Production統合

1. Agent runtimeとは別のsecurity control planeとbreak-glass accessを用意する。
2. Operator identityをphishing-resistant MFAとhardware-backed keyへbindし、役割ごとのauthorityを分ける。
3. AI-007 alertとAI-008 delegation rejectionをexact tenant／agent／sessionへ正規化する。
4. Model gateway、tool broker、delegation ledger、memory store、identity providerへ同じincident scopeをfan-outする。
5. 停止適用をacknowledgementではなく、各enforcement pointのnegative requestで検証する。
6. Pending／unknown actionをAI-006 request identityへ結び、自動retryを止める。
7. Evidenceを保全してからcleanupし、raw prompt、credential、tool contentはincident bundleへ複製しない。
8. Model非依存のread-only fallbackを定期演習する。
9. Root cause、key/session rotation、replay test、二者署名後にread-only canaryだけを許可する。
10. Full-authority復旧はcanaryと追加review後の別decisionとし、このfixtureから自動化しない。

## 運用上の注意と制限

- Kill switchの管理APIとagent toolが同じcredentialを共有しないようにする。
- Control plane outageを「agent正常」とみなさず、new session・model・tool dispatchをfail closedにする。
- Broad tenant killは可用性影響が大きい。通常命令はexact agent/session、tenant-wide操作は別break-glass手順にする。
- Revocation完了はAPI受付ではなく、旧authorityを使ったnegative requestで確認する。
- Evidence snapshotは必要最小限のidentity、decision、digest、timestampだけにする。
- Fallbackがmodelや同じextensionを使えば同時侵害となるため、operator-owned手順を別経路で保持する。
- Read-only canaryでもmodel入力へ機密情報を送らない。AI application gatewayとdata egressは別controlである。
- Started external side effectのtransaction rollbackはapplication固有であり、このcontrolは自動実行しない。
- Fixtureのpublic keyはproduction operator key custody、rotation、revocationを証明しない。

## Framework mappingと参考資料

行単位mappingは`control.yaml`が正本です。

- OWASP Top 10 for Agentic Applications 2026 `ASI10 Rogue Agents`へ、独立停止、権限失効、
  quarantine、復旧前提、二者承認、段階再開を直接mappingする;
- `ASI08 Cascading Failures`へ、連鎖遮断、unknown action隔離、bounded fallback、replay denialを
  限定的にmappingする;
- MITRE ATLAS `AML.M0024`へsanitized trigger、state transition、audit evidenceをsupportとしてmappingする;
- `AML.M0028`へtool authority失効とread-only canaryを、`AML.M0032`へagentから独立したcontrol planeを
  mitigation/supportとしてmappingする。

これらはriskやmitigationとの関連を示すだけで、OWASP category全体のcoverage、live incident readiness、
formal complianceを意味しません。

- [REF-AI-002 OWASP AI Agent Security Cheat Sheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)
- [REF-AI-003 AwesomeProductSecurity portfolio view](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-003)
- [OWASP Agentic Top 10 registry](../../../frameworks/owasp-agentic-top10/README.md)
- [MITRE ATLAS registry](../../../frameworks/mitre-atlas/README.md)
