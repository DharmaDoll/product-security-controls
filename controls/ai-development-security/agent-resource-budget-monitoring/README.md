# PSB-AI-007: Agent resource budget monitoring

## このcontrolを一枚で理解する

### セキュリティ上の問題

AI agentは停止条件が弱いとtoken・cost・時間・tool call・retry・recursionを消費し続け、denial-of-wallet、外部service負荷、重複side effect、長時間の権限保持を引き起こす。ログが欠けた状態を「利用なし」と扱うことも危険である。

### 誰から、または何から守るか

resource-intensiveな依頼を送る攻撃者、prompt injection、暴走・loopするagent、障害時のretry storm、recursive workflow、侵害されたtool、usage collector・alert pipeline・circuit breakerの故障から守る。

### 何が対象か

1 agent sessionのinput/output/total token、整数micro-unit cost、wall-clock duration、tool call、高影響操作、retry、recursion、security anomaly、breaker decision、alert receipt。

### 何をするか

session単位のhard budgetと80% warningをmodel外のpolicyで判定し、warning時はread-onlyへ制限、上限超過またはanomaly時は新規model callとside effectをblockする。sanitized telemetryとalert deliveryも検証する。

### 成功状態

正常sessionだけが継続し、warningはside effectを停止、上限超過・unknown tool連発・approval replayはcircuit breakerを開く。必要alertが120秒以内に届き、収集欠損やevaluator障害は`ERROR`になる。

### 対象外・残余リスク

fixtureはproviderのbilling、tokenizer、gateway、backend、alert receiverのlive enforcementを証明しない。予算値は例であり、事業SLOや契約上限ではない。multi-agent全体予算、kill-switch後の復旧、model品質・安全性は別controlで扱う。

## セキュリティ上の問題

AI agentは1回のrequestで終わらず、model call、tool call、retry、子taskを繰り返します。
各操作が単独では許可されていても、累積量が無制限なら次の問題が発生します。

- tokenやAPI costを消費し続けるdenial-of-wallet;
- retry stormやtool loopによる外部serviceの負荷と重複side effect;
- 長時間sessionによるcredential・approval・context exposureの拡大;
- recursionが深くなり、停止理由や責任主体を追跡できなくなる;
- unknown tool denialやapproval replayの連発を単なる失敗として見逃す。

modelに「使いすぎたら止まる」と指示するだけでは、攻撃されたmodel自身が停止判定を
持つことになります。このcontrolは、provider-neutralなusage evidenceをmodel外で評価し、
circuit breakerへ強制decisionを渡します。

## 誰から何を守るか

主な攻撃者・失敗源は次のとおりです。

- 大量推論や長いagent chainを誘発する外部入力・prompt injection;
- termination conditionを満たせず同じ処理を反復するagent;
- timeoutを受けて無制限にretryするautomation;
- unknown toolや消費済みapprovalを繰り返し試す侵害済みagent;
- token、cost、event sequenceを欠落させるcollector障害;
- breakerを適用せずalertを抑止するgatewayや監視pipelineの設定不備。

保護対象はAI利用予算だけでなく、外部serviceのavailability、sourceやdeploymentへの
side effect、session内で使われるdeveloper authorityです。

## 実装

### Budget policy

`secure/policy.json`は説明用のsynthetic baselineとして次を設定します。

| Resource | Hard limit |
|---|---:|
| Input token | 20,000 |
| Output token | 8,000 |
| Total token | 28,000 |
| Cost | 500,000 USD micro-units |
| Duration | 900秒 |
| Tool call | 20回 |
| High-impact action | 1回 |
| Retry | 3回 |
| Recursion depth | 4 |

costはfloating-pointではなく通貨付きinteger micro-unitで比較します。丸め誤差や通貨混在で
上限判定が変わることを避けるためです。これらの値はrepository fixture専用で、production
の適正値を意味しません。

80%へ達したsessionは`restrict / read-only`となり、side effectを止めながら安全な要約や
終了処理を許可します。hard limit超過またはsecurity anomalyは`block / none`となり、
新規model callとside effectを止めます。すでに開始済みのremote transactionは
`PSB-AI-004`と`PSB-AI-006`のidempotency／reconciliation境界で処理します。

### Telemetryとanomaly

このcontrolは`PSB-AI-004`のfleet telemetry policyをSHA-256とpolicy identityで固定し、
Claude CodeとCodexの両provider classを要求します。そのmetadata-only contractへ、
session resource集計値と次のanomaly countを追加します。

- unknown tool denialが2回以上;
- approval replayが1回以上;
- hook failureが1回以上。

anomaly thresholdはmodelの判断ではなくpolicyから導出します。prompt、tool arguments、
target、credential、tool outputはevidenceへ保存しません。

### Test scenarios

| Session | 期待結果 |
|---|---|
| `SESSION-NORMAL` | budget内で`continue` |
| `SESSION-WARNING` | 80%到達でread-onlyへ`restrict` |
| `SESSION-TOKEN-LIMIT` | input/output/total token超過で`block` |
| `SESSION-COST-LIMIT` | cost超過で`block` |
| `SESSION-DURATION-LIMIT` | 15分超過で`block` |
| `SESSION-TOOL-LIMIT` | tool、高影響操作、retry、recursion超過で`block` |
| `SESSION-ANOMALY` | unknown tool denialとapproval replayで`block` |

安全例ではrestrict/blockの6 sessionsすべてに、120秒以内のverified alert receiptが
あります。危険例は同じ観測値をすべて`continue`として扱い、alertを`suppressed`にする
inert overlayです。外部APIやmodelは呼びません。

## 検証

repository rootで実行します。

```bash
make verify-control CONTROL=PSB-AI-007
```

直接実行する場合:

```bash
python3 controls/ai-development-security/agent-resource-budget-monitoring/scripts/verify.py \
  --repository-root . \
  --control-root controls/ai-development-security/agent-resource-budget-monitoring \
  --policy controls/ai-development-security/agent-resource-budget-monitoring/secure/policy.json \
  --evidence controls/ai-development-security/agent-resource-budget-monitoring/secure/session-evidence.json
```

期待結果は`expected-results/`へ固定しています。

- 安全例: 11 checksが`PASS`、live enforcementは`NOT_CHECKED`;
- 危険例: resourceとanomalyの7 checksおよびbreaker／alertが`FAIL`;
- binding改ざん、sequence gap、収集失敗、evaluator失敗、malformed、sensitive evidenceは
  exit code 2の`ERROR`。

## 導入ガイド

1. provider usage API、gateway、tool brokerからsession ID付きの累積counterを取得する。
2. token、cost、duration、tool、retry、recursionのownerとhard limitをservice tierごとに決める。
3. costは通貨と整数最小単位を固定し、unknown priceやcurrency mismatchを`ERROR`にする。
4. warningでは新しいhigh-impact actionを止め、安全なread／summary／shutdownだけを許可する。
5. hard limitとsecurity anomalyはmodel外のgatewayで新規model callとside effectを拒否する。
6. breaker適用とalert receiptを同じsession／policy revisionへ結び付ける。
7. telemetry gap、collector outage、unknown tokenizer、billing delayをzero usageとして扱わない。
8. organization-owned live evidenceを収集するまでassessmentは`NOT_CHECKED`にする。

## 運用上の注意

- hard limitは通常処理のp95/p99、abuse case、service SLO、provider quota、費用責任者を基にreviewする;
- token countはprovider/model/tokenizer versionに依存するため、collector identityを保持する;
- billing確定が遅れるproviderではgateway-side estimateと請求実績を別fieldとして扱う;
- retryは同一attemptのtransport retryと、人が承認した新しいbusiness retryを区別する;
- recursion depthはsingle-agent task stackに限定し、multi-agent delegationは別controlで評価する;
- breakerを解除するには原因、session、actor、policy revisionを確認し、新しい承認を要求する;
- alert量が多くてもthresholdを無条件に緩めず、false positiveと見逃しを別々に測定する。

## 制約と残余リスク

- aggregated fixtureは個々のprovider usage recordやinvoiceの真正性を証明しない;
- AI-004 policyのSHA-256 bindingはlive event署名やcollector key custodyの代替ではない;
- warning直前の並行requestにより一時的に上限を超えるため、production counterはatomic reservationを必要とする;
- circuit breakerは開始済みremote side effectをrollbackせず、AI-006のoutcome reconciliationが必要である;
- safe summaryを許可すると追加tokenを消費するため、独立したtermination reserveが必要になる場合がある;
- multi-agent aggregate budget、cross-session budget、tenant quota、provider outage、kill-switch後のrecoveryは範囲外;
- resource budget通過はmodel outputの正確性、安全性、complianceを証明しない。

## Framework mapping

行単位mappingは`control.yaml`が正本です。MITRE ATLASはattack behaviorとmitigationの
関連、OWASP Agentic Top 10はcoarse risk relationshipであり、完全coverageやcompliance
を意味しません。

- MITRE ATLAS `AML.T0034.002` Agentic Resource Consumption;
- MITRE ATLAS `AML.T0029` Denial of AI Service;
- MITRE ATLAS `AML.M0024` AI Telemetry Logging;
- OWASP Top 10 for Agentic Applications 2026 `ASI08` Cascading Failures。

## 関連controlと参考資料

- `PSB-AI-004`: provider runtime telemetry、hook failure、approval replay、gateway decisionを提供する;
- `PSB-AI-006`: exact action identity、single dispatch、uncertain outcome reconciliationを提供する;
- [`REF-AI-002`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002): resource-abuseとmonitoring設計の参考資料;
- [`REF-AI-003`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-003): AI運用、KPI、kill-switchを含むportfolio-level参考資料。
