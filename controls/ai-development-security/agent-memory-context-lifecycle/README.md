# PSB-AI-005: Agent memory・context・data lifecycleを制御する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Agentが文書やtool outputをmemoryへ保存すると、untrusted instructionやcredentialが元のtrust情報を失ったまま後続sessionへ再注入され、goal hijack、情報漏えい、context枯渇を継続させる可能性がある。 |
| 誰から、または何から守るか | Memory poisoningを仕込むcontent提供者、侵害tool、別user／session／task、過剰な保存を行うagent、cleanup／collector／evaluator障害、誤ったdata classificationから守る。 |
| 何が対象か | Memory write candidate、payloadとprovenance、classification、user／session／task scope、TTL、active store、retrieval decision、expired payload、deletion tombstone。 |
| 何をするか | 保存前にexact payload、source trust、classification、size、TTL、scopeを検査し、read時にも全scopeを再認可する。期限切れpayloadを削除し、contentを含まないtombstoneだけを残す。 |
| 成功状態 | 承認summaryだけがactiveとなり、poisoned・credential-class・oversized writeが拒否される。Exact scopeだけがreadでき、cross-scopeとtombstoneはdeny、期限切れpayloadは5分以内に消える。証跡不能は`ERROR`となる。 |
| 対象外・残余リスク | Local fixtureはhosted providerのmemory、backup、cache、replica、vector index、encryption、residency、管理者access、実削除を証明しない。これらはlive evidenceが得られるまで`NOT_CHECKED`である。 |

## セキュリティ上の問題

PSB-AI-003が現在のtaskでprompt injectionを拒否しても、その内容が「便利な記憶」として
保存されれば、次のsessionで元のsourceや警告なしに再利用されます。Memoryは単なるcacheでは
なく、後続のagent判断へ影響するinstruction supply chainです。

このcontrolはmemory lifecycleを次の連続したdecisionとして扱います。

```text
source → classify → write decision → active store → retrieval authorization
       → expiry → payload deletion → sanitized tombstone
```

Write時だけscopeを付けても、read時にmemory IDだけで返せば隔離は成立しません。また、expiry
flagだけを立ててもpayloadが残っていれば削除ではありません。

## 誰から何を守るか

- Tool outputやdocumentへ遅延実行用のinstructionを埋める攻撃者;
- Credential、production data、raw promptをmemoryへ保存するagentやdeveloper;
- 別user、別session、別taskから既知memory IDを指定するrequest;
- 大量contextを保存してrankingやtoken budgetを占有する入力;
- TTL後もpayload、backup、indexを残すcleanup failure;
- Missing lifecycle evidenceを「active memoryなし」と解釈する運用。

保護対象はagentの将来goal、developerとcustomer data、tenant／session／task isolation、context
capacity、およびmemoryの削除可能性です。

## Control境界

| Control | 所有する境界 |
|---|---|
| `PSB-AI-003` | Prompt／document／tool output injectionのsource scenarioと現在taskのgoal preservation。 |
| `PSB-AI-004` | Agent processのfilesystem、network、credential、tool、audit enforcement。 |
| `PSB-AI-005` | Contextをmemoryへ保存・取得・期限切れ・削除するdata lifecycleとscope。 |
| `PSB-SOURCE-004` | GitHub token、PAT、SSH、App credentialそのもののlifecycle。 |

AI-005はaudit log retentionを扱うAI-004と異なり、agentへ再注入されるmemory payloadを対象に
します。[`secure/policy.json`](secure/policy.json)はPSB-AI-003 corpusをexact SHA-256へ固定し、
そのtool-output scenarioをpoisoned write fixtureとして再利用します。

## 安全な実装

[`secure/candidate-writes.json`](secure/candidate-writes.json)には4候補があります。

| Candidate | 条件 | 期待decision |
|---|---|---|
| `MEM-CAND-001` | User-approved、internal、81 bytes、24時間、exact scope | `allow` |
| `MEM-CAND-002` | PSB-AI-003 tool output由来のuntrusted data | `deny: untrusted-source` |
| `MEM-CAND-003` | Credential-class synthetic placeholder | `deny: classification-prohibited` |
| `MEM-CAND-004` | 157 bytes、policy上限128 bytes | `deny: payload-too-large` |

Verifierは申告sizeを信じず、payload fileを直接読みSHA-256とbyte数を計算します。Active storeは
allowとなった候補と、memory ID、payload digest、classification、source、user、session、
task、作成時刻、expiryの全項目で一致しなければなりません。

### Retrieval

5件のread fixtureで次を検査します。

- exact `USER-A / SESSION-A / TASK-A`だけがdigestを取得できる;
- userだけ、sessionだけ、taskだけを変えたrequestはすべてdeny;
- tombstoneとなった`MEM-OLD-001`は同じscopeでもdeny;
- deny responseはpayload digestやcontentを返さない。

### Expiryとdeletion

`MEM-OLD-001`はexpiryから60秒後に削除済みで、policyの5分grace内です。TombstoneにはID、
payload digest、scope、expiry、deletion time、reasonだけを残し、指定payload pathが存在しない
ことを検査します。

## 危険な実装

[`insecure/lifecycle-evidence.json`](insecure/lifecycle-evidence.json)は次を再現します。

- Untrusted、credential-class、oversized候補をすべてallowしてactive storeへ保存;
- 別user、別session、別taskへactive payload digestを返す;
- Expired recordのdeletionをpendingのままにする;
- Tombstoned memoryを再取得可能にする。

これらは11件の`FAIL`です。一方、payload改ざん、PSB-AI-003 binding不一致、collection／
evaluator失敗、機微field混入は判定材料を信頼できないため`ERROR`です。

## 実行方法

```bash
make verify-control CONTROL=PSB-AI-005
```

直接実行する場合:

```bash
python3 controls/ai-development-security/agent-memory-context-lifecycle/scripts/verify.py \
  --repository-root . \
  --control-root controls/ai-development-security/agent-memory-context-lifecycle \
  --policy controls/ai-development-security/agent-memory-context-lifecycle/secure/policy.json \
  --candidates controls/ai-development-security/agent-memory-context-lifecycle/secure/candidate-writes.json \
  --evidence controls/ai-development-security/agent-memory-context-lifecycle/secure/lifecycle-evidence.json
```

終了コードは`0=fixture contractを満たす`、`1=確認済みpolicy violation`、`2=証跡を信頼して
判定できない`です。Collector failureを空の安全なmemory storeとして扱いません。

## 期待する出力

```text
PASS 4 candidate writes were derived from classification trust size scope and retention policy
PASS untrusted PSB-AI-003 content credential-class data and oversized context were denied before persistence
PASS 1 active memory record preserves exact payload provenance user session task scope and expiry
PASS 5 retrieval cases enforce exact scope and deny tombstoned memory without returning payload data
PASS 1 expired memory tombstone proves bounded deletion and payload absence
PASS lifecycle evidence is complete sanitized and distinguishes policy findings from evaluator ERROR
PASS synthetic fixture validates the lifecycle contract; live provider memory enforcement is NOT_CHECKED
```

## Production統合

1. Providerと自社memory storeの全write経路をinventoryする。
2. Source provenance、data classification、user／session／task scopeをwrite前に必須化する。
3. Payload byte、record数、TTLをpolicy service側で計算し、agent申告値を信用しない。
4. Readごとに全scope、expiry、tombstone、request identityを再評価する。
5. Primary store、vector index、cache、replica、backupの削除SLAを分けて証跡化する。
6. Metadata-only auditをsecurity sinkへ送り、contentやembeddingをlogへ複製しない。
7. Live cross-user／session／task negative testとdeletion verificationを定期実行する。
8. Provider APIで観測できない項目は`NOT_CHECKED`のままrisk ownerへ割り当てる。

## 運用上の注意と制限

- Collaboration memoryを導入する場合、scopeをwildcard化せず別の共有resourceとauthorizationを定義する。
- Content scannerやclassification modelの失敗をallowへ変換しない。
- Encryptionは必要ですが、保存不要なcredentialを暗号化して長期保持する理由にはならない。
- Deletionはprimary databaseだけでなくcache、index、backup、provider retentionを確認する。
- Digestはcontent identityであり、攻撃者がpolicyとrecordを同時変更できる場合の真正性を保証しない。
- Provider memory feature、model version、retention仕様が変わればfixtureとlive evidenceを再評価する。

## Framework mappingと参照資料

- MITRE ATLAS `AML.T0080.000 Memory`: Durable memory poisoningに対し、source-aware write、
  isolation、retrieval、expiry、deletionでmitigateする。
- MITRE ATLAS `AML.T0080.001 Thread`: Session／task間のcontext propagationをexact scopeで抑える。
- MITRE ATLAS `AML.M0031 Memory Hardening`: lifecycle checksを具体化する関係として`supports`する。
- OWASP Agentic Top 10 `ASI06 Memory and Context Poisoning`: このcontrolの直接risk mapping。
- [OWASP Agentic Top 10 registry](../../../frameworks/owasp-agentic-top10/README.md)
- [MITRE ATLAS registry](../../../frameworks/mitre-atlas/README.md)
- [REF-AI-002 OWASP AI Agent Security Cheat Sheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)

Mappingはattack behaviorとrisk categoryの関係であり、live provider、formal compliance、
memory securityの完全coverageを意味しません。
