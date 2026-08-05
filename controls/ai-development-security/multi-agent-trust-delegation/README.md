# PSB-AI-008: Multi-agent trust and delegation

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Agent間messageを単なるmodel contextとして信頼すると、偽装sender、権限増幅、cross-tenant data移送、budget増幅、replay、再委譲により、一体のagent侵害がagent chain全体へ伝播する。 |
| 誰から、または何から守るか | Goal-hijacked／侵害済みagent、偽装agent、改ざんされたmessage transport、stale/replayed delegation、過剰なorchestrator設定、collector・crypto verifier障害から守る。 |
| 何が対象か | Orchestratorとworker/reviewer agentのidentity・public key、parent request、delegation envelope、capability、tenant・resource・data classification、resource budget、replay state、isolated runtime、signed response。 |
| 何をするか | Agent間delegationとresponseをEd25519署名し、exact sender/recipient edge、parent request、権限・data・budget ceiling、TTL・nonce・sequence・hopをmodel外で検証してから専用contextで実行する。 |
| 成功状態 | 正当な1-hop review delegationだけが許可され、署名偽造、権限・tenant・budget逸脱、replay、onward delegation、ambient credential、response差替えは遮断され、評価不能は`ERROR`になる。 |
| 対象外・残余リスク | Synthetic public-key fixtureはlive agent identity、transport、key custody、atomic replay ledger、process isolation、model provider、multi-hop recoveryを証明しない。Live enforcementは`NOT_CHECKED`である。 |

## セキュリティ上の問題

Agent AがAgent Bへ「このtaskを実行して」と送るmessageは、MCP tool callとも、人間のapproval
とも異なるtrust boundaryです。Message本文がもっともらしくても、sender identity、parent task、
recipient、権限上限、data scope、resource budget、freshnessを独立検証できなければ、低権限agentが
高権限agentをconfused deputyとして利用できます。

このcontrolは、自然言語messageではなく次の署名付き契約をdelegation単位にします。

```text
parent request digest + sender + recipient + tenant + task + purpose
+ capabilities + resource scope + classification + budget
+ issued/expiry + nonce + sequence + hop + onward-delegation flag
```

## 誰から何を守るか

- Prompt injectionを受けたorchestratorがworkerへ未保有のwrite権限を渡す;
- Attackerがagent名だけを偽装し、署名のないdelegationを投入する;
- Internal dataを別tenantまたはclearance不足agentへ送る;
- Child agentごとにtokenやtool-call予算を作り直し、親budgetを増幅する;
- Valid delegationまたはresponseを再送し、同じ処理を繰り返す;
- Reviewerが別agentへ再委譲し、責任と権限のchainを伸ばす;
- Shared contextやambient credentialにより、delegated scope外へ到達する;
- Collector、trust manifest、crypto verifierの障害をcleanとして扱う。

対象はagent間のcommunicationとdelegationです。Single-agent tool authorityは`PSB-AI-004`、
actionとresult integrityは`PSB-AI-006`、single-session resource ceilingは`PSB-AI-007`が所有します。

## 安全な実装

[`secure/delegation-envelope.json`](secure/delegation-envelope.json)はorchestratorからreviewerへの
1-hop delegationです。署名検証用public keyだけをrepositoryへ置き、fixture作成用private keyは
保持しません。

安全なdelegationは次を満たします。

- Exact AI-006 parent request digest、session、tenantへbindする;
- Trust manifestのactive sender keyによるEd25519署名を検証する;
- Senderからrecipientへのedgeと`review-diff` purposeが登録済みである;
- Capabilityは`repository.read`と`review.comment.propose`だけである;
- Repository、ref、`src/` path、`internal` classificationを超えない;
- Delegated budgetはAI-007へ接続したedge ceiling以下で、responseの実消費はdelegation以下である;
- TTLは5分、sequenceは単調増加、nonceは未消費、hopは1で再委譲不可である;
- Recipientは専用context、ambient credentialなしで実行する;
- Responseもrecipientが署名し、元delegation digestとAI-006 result schemaへbindする。

PolicyはAI-004、AI-006、AI-007のexact policy IDとSHA-256を検証するため、依存controlの意味が
変わった場合は自動的に`ERROR`になります。

## 危険な実装

[`insecure/delegation-envelope.json`](insecure/delegation-envelope.json)は、署名後のpayloadを
変更し、未承認`deployment.write`、別repository/ref/path、`confidential` data、過大budget、
stale TTL、replayed sequence/nonce、hop 2、onward delegationを含みます。

[`insecure/execution-evidence.json`](insecure/execution-evidence.json)は別tenantのshared contextで
ambient credentialを保持したまま処理を続け、response replayとlive adoptionを過大主張します。
これはisolated fixtureであり、実serviceやcredentialへ接続しません。

## 導入方法

1. Agent identityをdisplay nameではなく組織発行IDと署名keyへbindする。
2. Orchestrator、worker、reviewerごとのrole、tenant、clearance、maximum capabilityを登録する。
3. 許可するsender→recipient edgeをpurpose、resource、classification、budget単位で定義する。
4. Parent requestを`PSB-AI-006`のcanonical digestとauthorizationへbindする。
5. Child budgetを`PSB-AI-007`の親budgetからatomicにreserveし、childごとに新規予算を発行しない。
6. Delegation dispatch前にsignature、edge、ceiling、TTL、nonce、sequence、hopを検査する。
7. Recipientを専用identity/contextで起動し、親のcredential、memory、filesystem、networkを継承させない。
8. Responseにも署名させ、delegation digest、sender/recipient、schema、budget usageを検証する。
9. Replay ledger、key revocation、collector、crypto verifierが利用不能ならdispatchを止める。
10. Live pilotでforgery、replay、cross-tenant、budget exhaustion、recipient停止をfault injectionする。

## 検証

Repository rootから実行します。

```bash
make verify-control CONTROL=PSB-AI-008
```

直接実行する場合:

```bash
python3 controls/ai-development-security/multi-agent-trust-delegation/scripts/verify.py \
  --repository-root . \
  --policy controls/ai-development-security/multi-agent-trust-delegation/secure/policy.json \
  --delegation controls/ai-development-security/multi-agent-trust-delegation/secure/delegation-envelope.json \
  --response controls/ai-development-security/multi-agent-trust-delegation/secure/response-envelope.json \
  --evidence controls/ai-development-security/multi-agent-trust-delegation/secure/execution-evidence.json
```

Exit codeは`0=accepted`、`1=known unsafe behavior`、`2=evidenceまたはevaluator error`です。
Invalid signatureは安全でないdelegationとして`FAIL`、key/trust manifest/cross-control binding/
crypto verifierが利用不能なら判定不能として`ERROR`です。

## 期待する出力

```text
PASS PSB-AI-008/MAD-001 trust manifest and AI-004/006/007 bindings are exact
PASS PSB-AI-008/MAD-002 delegation and response signatures authenticate exact agent identities
...
PASS PSB-AI-008/MAD-011 evidence is complete sanitized and live adoption remains NOT_CHECKED
ACCEPTED multi-agent delegation evidence; live enforcement NOT_CHECKED
```

## 運用上の注意と制限

- Public key fixtureとprecomputed signatureはverifier test用で、production key enrollmentやcustodyを
  証明しません。Private fixture keyはrepositoryへ保存していません。
- Static JSON replay stateはatomic consumptionを証明しません。Productionではsender/key単位の
  transactional nonce・sequence ledgerが必要です。
- 予算比較はdelegation時の数値contractです。並行childへのatomic reservation、返却、provider billing、
  cross-session/tenant aggregateはlive evidenceが必要です。
- `src/**`はfixture内の正規化済みscopeです。Symlink、alternate ref、case folding、URL alias等は
  gatewayでcanonicalizeしてから比較します。
- One-hop reviewだけを実装しており、multi-hop workflow、dynamic agent discovery、consensus、quorum、
  failover、rollback、kill-switch recoveryは対象外です。
- Agent isolation、credential非継承、message transport authenticity、response deliveryはstatic evidenceで
  強制できないため、adoptionは`NOT_CHECKED`のままです。
- OWASP Agentic Top 10とMITRE ATLAS mappingはrisk/behavior relationshipであり、complete coverageや
  complianceを意味しません。

## References

- [REF-AI-002 OWASP AI Agent Security Cheat Sheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)
- [OWASP Top 10 for Agentic Applications 2026](../../../frameworks/owasp-agentic-top10/README.md)
- [MITRE ATLAS registry](../../../frameworks/mitre-atlas/README.md)
