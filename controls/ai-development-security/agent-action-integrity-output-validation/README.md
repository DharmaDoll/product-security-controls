# PSB-AI-006: Agent action integrity and output validation

## このcontrolを一枚で理解する

### セキュリティ上の問題

AI agentのmodel出力はもっともらしくても信頼できる命令ではない。free-form出力、承認後に変わったtarget／parameter、不正なtool結果、timeout後の無条件retryを実行すると、未承認操作、誤対象への変更、二重実行、偽の成功判定につながる。

### 誰から、または何から守るか

prompt injectionを仕込む攻撃者、侵害されたmodel・tool・gateway、承認と実行の間で値を変える競合、malformed response、network timeout、agentまたは実装者の誤ったretry処理から守る。

### 何が対象か

model proposal、typed tool call、policy decision、PSB-AI-004 authorization receipt、execution envelope、idempotency identity、tool result、reconciliation state、監査証跡。

### 何をするか

model出力をstrict schemaで検証してcanonical request digestを作り、独立policy・高影響操作の承認・実行・結果を同じdigestとresource identityへ束縛する。replayを拒否し、実行結果が不明なら隔離して照合する。

### 成功状態

schema不正とscope逸脱は実行前にdenyされ、許可された操作だけがexact target／parameterで1回dispatchされる。結果はaction固有schemaとrequest identityが一致し、unknown outcomeは承認を戻さず自動retryしない。検証不能は`ERROR`となる。

### 対象外・残余リスク

deterministic fixtureはlive agent、MCP gateway、外部service、backend idempotency storeの実 enforcementを証明しない。承認者が正確だが有害な操作を承認するリスク、tool自体の悪意、application authorization、rollbackの安全性は別途扱う。

## セキュリティ上の問題

modelが生成したJSONやtool callは、認可済み命令ではなくuntrusted proposalです。
「JSONとしてparseできた」「人が一度Approveした」「toolがsuccessを返した」という個別の
事実だけでは、同じ操作が実行されたことを証明できません。

特に次の境界でidentityが切れると危険です。

```text
untrusted model proposal
          ↓ strict schema + canonicalization
normalized request digest
          ↓ independent policy + PSB-AI-004 authorization
bound decision
          ↓ exact digest + idempotency identity
execution envelope
          ↓ strict result schema + request/resource binding
trusted result or quarantine/reconcile
```

このcontrolは、上の変換とidentity continuityを所有します。OS sandbox、credential denial、
human approvalの署名・期限・single-use enforcementそのものは`PSB-AI-004`を再実装せず、
そのauthorization receiptをexact request digestへ束縛して利用します。

## 誰から何を守るか

主な攻撃者・失敗源は次のとおりです。

- prompt injectionやpoisoned contextによりfree-form操作を出力させる攻撃者;
- model proposalをpolicy decisionとして扱う誤ったagent実装;
- decision後にtargetやparameterを差し替えるcompromised adapterやrace;
- stale、別request用、再利用済みのauthorization receipt;
- malformed、別resource用、または攻撃者が生成したtool result;
- timeoutを「未実行」とみなし、同じside effectを自動retryする処理。

保護対象はsource publicationなどの外部side effect、その承認identity、実行対象、tool結果を
利用する後続decisionです。

## 実装

### Strict proposalと独立policy

`secure/proposals.json`は次の4 scenariosを持ちます。

| Scenario | 入力 | 期待結果 |
|---|---|---|
| `ACT-T001` | review済みdocs search | policy-onlyでallow |
| `ACT-T002` | pull request作成 | PSB-AI-004のbound authorization付きでallow |
| `ACT-T003` | unknown fieldを含むfree-form proposal | `schema-invalid`でdeny |
| `ACT-T004` | wildcard targetへのsource publication | `scope-violation`でdeny |

proposalはexact fields、action固有parameter type、byte limit、exact value、target allowlist、
freshnessを検証します。unknown fieldを無視して実行可能なsubsetだけを拾うことはしません。
正規化後のJSONからSHA-256を計算し、decision以降はmodel出力そのものを参照しません。

### Authorizationとexecution binding

read-only操作はreview済みpolicyだけで許可できます。high-impactなsource publicationは、
`PSB-AI-004`が発行・検証した次の属性を持つreceiptが必要です。

- exact request digest;
- exact AI-004 runtime-policy digest;
- 有効期間が最大300秒で、評価時点に有効;
- `single_use: true`かつdispatch前に`consumed: true`。

execution envelopeはproposal、decisionと同じrequest digest、target、parameter digestを持ち、
attempt 1だけを許可します。2回目のdispatchは同じidempotency identityでdenyされます。

### Output validationとunknown outcome

結果はaction固有schema、execution ID、request digest、resource identityへ束縛します。
成功結果に想定外fieldや型があれば後続処理へ渡しません。

外部side effectのtimeoutは「失敗」でも「未実行」でもありません。`unknown`として隔離し、
authenticated outcome lookupなどで照合します。元のauthorizationを復活させず、自動retryも
行いません。これは二重pull requestや二重deploymentを防ぐための安全側の状態です。

## 危険例と安全例

`insecure/execution-evidence.json`は実際の外部操作を行わないinert fixtureです。次の既知の
危険動作を含みます。

- unknown-field proposalとwildcard targetをmodel要求だけでallow;
- 別request digestのauthorizationを受理;
- decision後にexecution targetを変更;
- dispatchをattempt 2として再実行し、replayもallow;
- action固有ではないfree-form result schemaを信頼;
- unknown resultで自動retryし、消費済みauthorizationを復活。

`secure/execution-evidence.json`では、不正proposalを実行せず、許可した2操作だけをexact
identityでdispatchします。pull request fixtureの結果は意図的に`unknown`とし、正常な
reconciliation boundaryを検証します。どちらもproduction serviceへ接続しません。

## 検証

repository rootで実行します。

```bash
make verify-control CONTROL=PSB-AI-006
```

直接実行する場合は次のとおりです。

```bash
python3 controls/ai-development-security/agent-action-integrity-output-validation/scripts/verify.py \
  --repository-root . \
  --policy controls/ai-development-security/agent-action-integrity-output-validation/secure/policy.json \
  --proposals controls/ai-development-security/agent-action-integrity-output-validation/secure/proposals.json \
  --evidence controls/ai-development-security/agent-action-integrity-output-validation/secure/execution-evidence.json
```

期待結果は`expected-results/`に固定しています。

- 安全なfixtureは10 checksを`PASS`にし、live enforcementを`NOT_CHECKED`とする;
- 既知の危険動作は該当checkを`FAIL`にし、終了コード1を返す;
- proposal／binding改ざん、収集失敗、evaluator失敗、malformed／sensitive evidenceは
  `ERROR`として終了コード2を返し、cleanへ変換しない。

## 導入ガイド

1. model providerのtool-call outputを直接実行せず、provider-neutral proposal schemaへ変換する。
2. JSON Schema等でrequired fields、unknown fields、型、長さ、enum、resource scopeをstrict検証する。
3. canonicalizationを1か所に実装し、policy decision、approval UI、gateway、backendで同じdigestを利用する。
4. high-impact actionは`PSB-AI-004`のparameter-bound authorizationを取得し、dispatch前にatomicにconsumeする。
5. backendでidempotency keyとrequest digestを一対一に記録し、同じkeyへの別digestをconflictとして拒否する。
6. tool responseをaction固有schemaとresource identityで検証してから、後続agent contextへ渡す。
7. timeout／connection lossはunknownへ移し、status lookupとoperator reconciliationが完了するまで自動retryしない。
8. adopted gateway、provider、backendのlive evidenceを別途収集し、fixture結果で代用しない。

## 運用上の注意

- schema versionとpolicy revisionの更新はsecurity-sensitive changeとしてreviewする;
- canonicalization implementationは言語間でtest vectorを共有し、Unicodeやnumber表現差を確認する;
- idempotency recordのretentionは外部serviceが同じrequestを再受理し得る期間以上にする;
- output validation失敗を空結果や成功へ変換せず、`ERROR`またはquarantineとして監視する;
- raw model output、prompt、tool arguments、credential、result bodyをcontrol evidenceへ保存しない;
- HITL回数を増やすのではなく、high-impactだけをexact parametersで1回承認する。

## 制約と残余リスク

- fixtureのauthorization receiptはsynthetic metadataであり、署名検証とatomic ledgerは`PSB-AI-004`の責務である;
- SHA-256 bindingは、policyとartifactを同時に書き換えられる攻撃者に対するauthenticated commitmentではない;
- backend側がidempotencyを実装しなければ、gatewayだけでnetwork ambiguityによる二重side effectを完全には防げない;
- strict schemaはschema内で意味的に有害だが形式上正しい値を自動的に見抜かない;
- humanが正しいparametersを見てなお有害な操作を承認するriskと、説明による誘導の評価は残る;
- application固有authorization、business invariant、transaction、rollback、compensating actionは各application controlが所有する;
- live provider adapter、MCP gateway、external serviceの採用状態は`NOT_CHECKED`である。

## Framework mapping

行単位mappingは`control.yaml`を正本とします。MITRE ATLASはattacker behaviorとmitigationの
関連を、OWASP Agentic Top 10はcoarse risk relationshipを表すだけで、complianceや完全な
agent security coverageを意味しません。

- MITRE ATLAS `AML.T0053` AI Agent Tool Invocation;
- MITRE ATLAS `AML.M0028` AI Agent Tools Permissions Configuration;
- MITRE ATLAS `AML.M0033` Input and Output Validation for AI Agent Components;
- OWASP Top 10 for Agentic Applications 2026 `ASI02`, `ASI05`, `ASI09`。

## 関連control

- `PSB-AI-002`: 実行可能なMCP／extension dependency identityを管理する;
- `PSB-AI-003`: proposalを誘導するprompt／document injection scenarioを検証する;
- `PSB-AI-004`: sandbox、tool permission、署名付きsingle-use approval、side-effect reconciliationを強制する;
- `PSB-AI-005`: proposalへ影響するmemoryのwrite、scope、retentionを管理する。
