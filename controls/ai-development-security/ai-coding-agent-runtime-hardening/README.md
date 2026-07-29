# PSB-AI-004: AI coding agent runtime hardening

## セキュリティ上の問題

Claude CodeやCodexのようなcoding agentは、source codeを読むだけでなく、shell、
filesystem、Git、networkを操作できます。悪意あるrepository文書、tool出力、
compromised extension、またはagent自身の判断ミスがあると、developerと同じ権限で
credentialを読み、sourceを公開し、policyを変更できる可能性があります。

「このファイルの指示を無視するな」のようなprompt上の注意は、processの権限境界では
ありません。このcontrolは、provider-neutralな結果要件を、Claude CodeとCodexの
managed configurationへ変換し、同じ検査で比較します。

## 誰から何を守るか

主な攻撃者・失敗源は次のとおりです。

- indirect prompt injectionを含む悪意あるrepository、issue、documentation、Web内容;
- compromised MCP、plugin、Skill、hook、またはtool;
- stolen developer identityを使う外部攻撃者;
- scopeを誤解したcoding agentまたは誤った承認をするdeveloper;
- dangerous bypassやrepository-local設定を追加するconfiguration drift。

保護対象は、product source、Git history、`.agents`、`.codex`などのagent policy、
developer credential、host、外部serviceへ送信されるdataです。

## 実装済みスライス

### Runtime adapter

`policy/runtime-policy.json`を正本とし、両providerで次の7結果を検証します。

| Check | 必要な結果 | Claude Code adapter | Codex adapter |
| --- | --- | --- | --- |
| `AAR-001` | isolationを強制しfail closed | native sandboxと`failIfUnavailable` | managed permission profile |
| `AAR-002` | writeはworkspaceだけ | sandbox deny-write | `:workspace`を継承したmanaged filesystem profile |
| `AAR-003` | synthetic credentialをdeny | `denyRead`とpermission deny | filesystem `deny` |
| `AAR-004` | network default deny | strict empty allowlist | network-disabled profile |
| `AAR-005` | `git push`はhuman approval | managed `ask` rule | managed restrictive prefix rule |
| `AAR-006` | bypassを選択不能にする | bypassとunsandboxed escapeをdisable | full-accessと`never`をallowlistから除外 |
| `AAR-007` | repositoryが権限を広げられない | managed-only permission/domain rules | managed requirementsとprofile allowlist |

実在credentialは使用しません。`.psb-fixtures/credentials`はpath文字列だけの
synthetic fixtureです。

### High-impact action approval gate

第2スライスは、provider固有のpromptに加えて、実行直前に呼び出す
`scripts/verify-approval.py`を提供します。次の操作classをdefault-deny policyへ
登録しています。

- dependency installation;
- source commit、publication、history rewrite;
- package publication;
- database mutation;
- infrastructure changeとcloud administration;
- deploymentとrollback。

gateは次の4結果を検査します。

| Check | 必要な結果 |
| --- | --- |
| `AAR-008` | toolとoperationがreview済みhigh-impact classへ一意に分類される |
| `AAR-009` | actor、agent、class、tool、operation、target、normalized parameters、policy version、request digestが一致し、approverがactorと異なる |
| `AAR-010` | approvalが実行時点で有効かつ最大300秒 |
| `AAR-011` | approval IDとrequest digestが未使用でissuerがtrusted、validator unavailableは`ERROR` |

targetまたはparameterを承認後に変えるとcanonical request digestとfield比較の両方が
不一致になります。console evidenceにはtargetやparameterの内容を出しません。

### Extension capabilityと低頻度HITL

第3スライスは、MCP、Skill、plugin、browserなどを同じcapability boundaryとして
扱います。`extension_capabilities` policyは、synthetic MCP serverをURLの完全一致で
識別し、serverごとに利用できるtoolを限定します。Skillはinstructionだけを提供し、
direct tool authorityを持ちません。unreviewed plugin installation、browser control、
computer useはこのsliceでは無効です。

HITLは次の基準にしました。

| 操作 | HITL | 条件 |
| --- | ---: | --- |
| review済みread-only | 0回 | exact serverとexact tool |
| 可逆な低リスク更新 | 0回 | exact resource、1 KiB以下、idempotency key必須 |
| source公開などhigh-impact | 1回 | 第2スライスのbound approval gate |
| destructive、unknown、policy不明 | 0回 | promptではなくdenyまたは`ERROR` |

「確認を減らす」ためにbypassを許すのではありません。自動化してよい条件を機械判定し、
人へ確認すべき操作だけを1回に集約します。

### Managed PreToolUse enforcement

第4スライスは、offline capability判定を実際のtool-call境界へ接続する
`scripts/pretool-gate.py`を追加します。Claude CodeとCodexの
`PreToolUse` JSONを`mcp__<server>__<tool>`と`tool_input`へ正規化し、次をtool実行前に
検査します。

- serverとtoolがreview済みinventoryに完全一致すること;
- bounded writeのresourceが完全一致すること;
- bodyがUTF-8で1 KiB以下であること;
- 空でない128文字以下のidempotency keyがあること;
- destructiveまたはunknown toolでないこと。

managed matcherは`^mcp__.*$`なので、未知toolも検査を迂回せずdefault denyへ到達します。
readと条件内のbounded writeは追加確認なしで`allow`、違反は`deny`です。malformed input、
policy missing、engine unavailableはexit `2`でblockします。

command hookのprocess起動失敗やtimeoutは、gateが明示的に返すexit `2`と同じ保証があるとは
限りません。そのためbounded writeをnative allowlistへ直接置かず、hookが明示的に
`allow`を返した時だけpromptをskipします。hook process自体が応答しなければnative
permission promptへfallbackし、silent auto-executionにはしません。厳密なfail closedが
必要なproductionでは、supervised local policy serviceまたはMCP gatewayでも同じ判定を
強制します。

2026-07-29に確認したCodex仕様では`PreToolUse`の`ask`は未対応で、返すとhook failure後に
tool callが継続します。そのためprovider固有の`ask`を承認境界にせず、第5スライスの
provider-neutralな署名済みapprovalを両providerで検証します。

### Authenticated approvalとatomic single use

第5スライスは、high-impact tool callを次の順序で処理します。

1. managed actor identityとprovider/session identityを取得する;
2. MCP引数をtool、operation、target、parametersへcanonicalizeする;
3. exact request digestと同名の署名済みapprovalだけをinboxから選ぶ;
4. active key ID、issuer、algorithm、有効期間、public-key SHA-256を照合する;
5. OpenSSL 3でcanonical approvalのRSA PKCS#1 v1.5 SHA-256署名を検証する;
6. actor、agent、target、parameters、policy revision、TTLを再検査する;
7. approval IDとrequest digestをSQLiteの`BEGIN IMMEDIATE` transactionで一意に記録する;
8. commit後にだけprovider native JSONで`allow`を返す。

これがhigh-impact操作に対する1回のHITLです。署名済みapprovalを発行する外部UIで人が
exact requestを確認し、hook成功後に追加のnative promptは出しません。approval missing、
署名不正、期限切れ、binding不一致、replayは`deny`です。actor、trust、OpenSSL、ledgerの
検査不能はexit `2`でblockします。

SQLite transactionは2つの並行hookが同じapprovalを同時に見るraceを防ぎ、1つだけが
`allow`を取得します。ただしexternal MCP side effectとSQLite commitを単一transactionには
できません。commit後にtoolが失敗した場合、approvalは安全側に消費済みとなり、新しい
approvalと同じidempotency keyによるreconciliationが必要です。

### Installed runtime inventoryとredacted audit

第6スライスは、managed設定の「インストールさせない」という意図だけでなく、endpointで
実際に有効なextensionを検査します。Claude CodeとCodexのmanaged inventory snapshotは、
次の項目を`policy/runtime-policy.json`のreview済み集合と完全一致で照合します。

- extension IDとkind（MCP、Skill、plugin）;
- `PSB-AI-002`が管理するdependency record ID;
- MCP transportと完全一致URL;
- Skillがdirect tool authorityを持たないこと;
- snapshotがcompleteで、managed collector由来かつ1時間以内であること;
- plugin installationが無効で、未知・欠落extensionがないこと。

「collector unavailable」を空のinventoryとして扱うと、検査失敗がcleanに見えます。
そのためincomplete/unavailable/malformedは`ERROR`、staleや実状態のdriftは`FAIL`です。

managed `PreToolUse`はprovider responseを返す前に、`allow`、`deny`、`error`を固定schemaの
JSON Linesへappendします。記録するのはprovider、policy revision、tool ID、reason codeと、
SHA-256化したsession/request/approval referenceだけです。prompt、transcript、
tool argument、target、body、tool output、credential、signatureは記録しません。

audit directoryは絶対パス・非symlink・mode `0700`、fileは`O_NOFOLLOW`・mode `0600`、
append lock、size上限、`fsync`を要求します。would-be allowを記録できない場合はprovider
allow JSONを返さずexit `2`でblockします。local logは14日保持のreference stateとし、
組織のsecurity logへexportしてrotationします。

Codexのnative OTelは補完的な別surfaceです。公式仕様上、prompt contentは
`log_user_prompt = false`でredactできますが、tool resultなどのevent coverageとdata
handlingは別途reviewが必要です。このcontrolのcontent-free hook auditをnative OTelや
Compliance APIの完全な代替とはみなしません。

## 安全でない例と安全な例

`insecure/`は、sandbox無効、host-wide write、credential read、unrestricted
network、approvalなしのpush、dangerous bypassを意図的に含む隔離fixtureです。
実際の設定へ配置しないでください。

`secure/`は2026-07-29に確認した公式documentationを基準とするreference
configurationです。

- Claude Codeはmanaged settingsでsandboxをfail closedにし、
  `allowManagedPermissionRulesOnly`と`allowManagedDomainsOnly`を使います。
- Codexは0.138.0以降のmanaged permission profilesを使用し、admin-enforced
  `requirements.toml`で許可profileとapproval policyを限定します。
- `secure/approval/`はbound、short-lived、single-use approvalのsynthetic evidenceです。
- `secure/approval-runtime/`はmanaged actor、digest-pinned public trust root、
  provider別request、署名済みapprovalのfixtureです。issuer private keyは含みません。
- `secure/capabilities/`はread、bounded write、high-impactのHITL回数fixtureです。
- `secure/runtime-assessment/`はprovider別installed inventory、audit storage state、
  content-freeなallow/deny/error eventのfixtureです。
- Claude Codeはmanaged URL allowlistとexact MCP permission rule、Codexはmanaged
  identity requirement、`enabled_tools`、`writes` modeを使います。
- 両providerはmanaged-only `PreToolUse`から同じgateを呼びます。設定内の
  `/opt/psb-ai-004`と`/var/lib/psb-ai-004`はMDM等で配布するsample absolute pathです。
- `insecure/approval/approval.json`はwildcard、self-approval、24時間TTL、untrusted
  issuerを意図的に含みます。
- `insecure/approval-runtime/forged-envelope.json`は署名を1 byte相当変更した
  isolated negative fixtureです。
- `insecure/runtime-assessment/`はunreviewed installed plugin、kind/dependency record
  confusion、raw tool input leakage、world-writable storage、過剰保持を隔離しています。

これらは組織固有path、必要なdestination、管理配布経路をreviewするためのsampleです。
testはglobal setting、user setting、hookを変更しません。

## 統合方法

1. `policy/runtime-policy.json`の結果要件を組織のthreat modelと照合します。
2. 対象clientがsampleのminimum versionを満たすことを確認します。
3. `secure/claude/managed-settings.json`はClaude Codeのmanaged settings配布経路、
   `secure/codex/requirements.toml`はCodexのsystemまたはenterprise managed
   requirementsとして試験的に配布します。
4. repository layerには`secure/*/repository-*`相当のrestrictive設定だけを置きます。
5. pilot端末でactive setting sourceと実際のdeny/prompt動作を確認し、CODEOWNERと
   security review後に展開します。
6. provider adapterがnative commandやtool callを正規化し、policyのtool、
   operation、target、parametersへ変換する境界を実装します。
7. human approval serviceはcanonical request全体を表示し、認証済みapproverから
   short-lived evidenceを発行して、endpointには署名済みenvelopeだけを配送します。
   issuer private keyをdeveloper endpointへ配布しません。
8. actor state、approval inbox、trust manifest、public key、ledger directoryを
   root/admin ownershipと最小permissionで管理し、repositoryから書けないようにします。
9. `pretool-gate.py`はside effect直前に署名、binding、TTLを検証し、SQLiteへ
   single-use consumptionをcommitできた場合だけexact actionをallowします。
10. productionではexternal side effectにもidempotency keyを渡し、commit後のtool failureを
    reconciliationして、同じapprovalを復活させず新しい承認でretryします。
11. MCP server identityはdisplay nameではなくexact URLまたはexact commandで管理し、
    tool追加をcapability changeとしてreviewします。
12. read-onlyとbounded reversible writeは自動化し、high-impactだけをapproval gateへ
    routeします。unknownまたはdestructive toolを追加promptで救済しません。
13. reviewed `pretool-gate.py`、policy、engine state、approval modulesをsampleの
    absolute pathへ管理配布し、
    file owner、permission、digestをfleet側で検証します。
14. native product側のbounded writeを`auto`にする前に、pilot clientでallow、deny、
    exit `2`、hook process timeout、high-impact promptを実動確認します。このsampleは
    native prompt fallbackを残しており、static fixtureだけを理由にproductionの恒久的な
    native allowへ移行しません。
15. MDM等のrepository外collectorで各providerのactive extension snapshotを取得し、
    `dependency_record_id`を`PSB-AI-002`のreview recordへ接続します。収集不能を空配列に
    変換しません。
16. `/var/log/psb-ai-004`を管理owner・mode `0700`で作成し、audit fileのrotation、
    organization security logへのexport、access role、14日以内のlocal retention、
    export failure alertを実装します。
17. Codex OTelなどのnative telemetryを併用する場合も、prompt contentを明示的に無効化し、
    tool argument/outputをsensitive dataとしてcollector側でredactします。network-off
    profileからcollectorへ送る場合は、そのdestinationだけを別のreview済みegressとして
    設計します。

sample fileをそのままdeveloperのglobal設定へcopyすることや、testから自動install
することはありません。Claude Codeのarray設定はscope間でmergeされるため、単に
managed fileの優先順位が高いだけでは`allowWrite`の追加を防げません。managed-only
lockとrepository configuration reviewを併用します。

## 検証方法

repository rootで実行します。

```bash
make verify-control CONTROL=PSB-AI-004
```

offline verifierは製品を起動せず、次を決定的に検査します。

- secure Claude Code/Codex adapterの14結果がすべて`PASS`;
- insecure adapterが14件の`FAIL`、exit `1`;
- repository-downgradeがfinding、exit `1`;
- malformed、unsupported baseline、evaluator failureが`ERROR`、exit `2`;
- secure high-impact approvalの4結果がすべて`PASS`;
- broad、expired、replay、target/parameter改変、unclassifiedが`FAIL`、exit `1`;
- validator unavailableとmalformed approvalが`ERROR`、exit `2`;
- exact MCP adapter、read、bounded write、high-impact HITL policyが`PASS`;
- destructive、unknown、effect mismatch、target broadening、過剰/不足HITLが`FAIL`;
- capability engine unavailableとmalformed invocationが`ERROR`;
- provider-shaped `PreToolUse`でread/bounded writeがallowされ、wrong resource、
  oversized body、missing idempotency、destructive、unknownがdenyされること;
- policyまたはengine unavailableとmalformed hook inputがexit `2`でblockされること;
- signed approvalの署名、exact binding、TTL、public-key digestが有効なこと;
- malformed envelope、untrusted key、forged signature、expired、target変更、
  missing verifierがallowにならないこと;
- high-impact toolの未知の追加引数がbindingから脱落せず、exit `2`でblockされること;
- sequential replayと2つのconcurrent consumerのうち1つだけがconsumeできること;
- corrupt ledgerが`ERROR`となり、Claude CodeとCodexが有効な1 approvalだけをallowすること;
- recent completeな両provider inventoryがreview済みextension集合と完全一致すること;
- unreviewed plugin、kind/dependency confusion、stale snapshotが`FAIL`になること;
- unavailable/malformed inventoryとunavailable audit stateが`ERROR`になること;
- actual managed hookがallow/deny/errorを固定fieldで記録し、raw request contentを
  含まないこと;
- broad permission、過剰保持、missing decision、unexpected content fieldが`FAIL`に
  なり、missing directoryまたはsymlink audit sinkがexit `2`でblockされること;
- evidenceにcredential値やprivate destinationが含まれないこと。

exit codeは次の意味です。

| Exit | 意味 |
| --- | --- |
| `0` | 全providerの全結果がpolicyを満たした |
| `1` | policy違反を検出した |
| `2` | parse、version、file、またはevaluator errorで検査を完了できなかった |

`ERROR`をclean resultとして扱ってはいけません。

## 期待される出力

secure profileは各providerに同じcheck IDを出し、最後に次を表示します。

```text
RESULT PASS profile=secure checks=14 failures=0
```

secure approval gateは次を表示します。

```text
RESULT PASS request_id=REQ-FIXTURE-001 approval_id=APR-FIXTURE-001 checks=4 failures=0
```

read-only invocationでは確認回数が0として表示されます。

```text
RESULT PASS invocation=INV-FIXTURE-READ extension=docs_reader tool=search expected_hitl=0 checks=3 failures=0
```

managed hookのroutine allowはprovider native JSONとして次を返します。

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"PSB-AI-004 allowed an invocation matching the reviewed capability."}}
```

signed high-impact approvalはissuer authenticationとsingle-use commit後に次を返します。

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"PSB-AI-004 authenticated and consumed one exact bound approval."}}
```

runtime inventoryとaudit evidenceは次を表示します。

```text
PASS PSB-AI-004/AAR-018 provider=claude-code installed runtime inventory exactly matches reviewed extensions
PASS PSB-AI-004/AAR-018 provider=codex installed runtime inventory exactly matches reviewed extensions
PASS PSB-AI-004/AAR-019 audit decisions are complete redacted access-controlled and retention-bound
RESULT PASS profile=secure checks=3 failures=0
```

検査不能時はallow JSONを返さず、sanitized stderrとexit `2`で停止します。

完全なdeterministic outputは`expected-results/`にあります。出力するのはpolicy ID、
provider、check ID、decision reasonだけで、command argumentやcredential値は
記録しません。

## 運用上の注意

- networkが必要なtaskは、default denyを解除するのではなく、providerごとのmanaged
  allowlistへreview済みdestinationを追加し、local/private/metadata/socketを分けて
  testします。
- approval fatigueを避けるため、read-only操作とside effectを区別します。ただし
  source publication、dependency install、deploymentなどの高影響操作を包括的に
  allowしてはいけません。
- action adapterはcommand stringをそのままapproval対象にせず、tool、operation、
  target、parameterへ正規化します。正規化不能または複数classへ一致する場合は
  policy errorとして実行を止めます。
- SHA-256 request digestはbinding用、RSA signatureはissuer authenticity用です。
  productionではissuer private keyをHSM/KMS等でendpointから分離し、approver認証、
  key rotation、revocation、trust-root更新を運用します。
- permission rule、hook、command prefixはdefense in depthです。shell indirectionや
  product parserの変更に備え、OS sandbox、managed endpoint、CI、server-side
  protectionを維持します。
- active product binaryでのruntime assessmentはこのstatic fixtureとは別のevidence
  です。設定を配布しただけでadopted状態や完全なAI securityを主張できません。
- low-risk自動更新のscope、size、idempotency条件を緩める場合は、新しいrisk classとして
  reviewし、既存の自動許可を暗黙に拡張しません。
- Claude CodeとCodexではhigh-impact routingのnative hook機能が同一ではありません。
  providerが未対応と明記する`ask`を互換性目的で返さず、両providerとも同じ外部署名済み
  approvalを検証してから`allow`します。
- hook設定はscriptを配布しません。MDM等はabsolute pathへのimmutableまたは
  integrity-verifiedな配置、root/admin ownership、更新、rollbackを別途実装します。
- explicit exit `2`以外のhook process faultはstatic testだけでfail-closedを証明できない
  ため、bounded writeにはnative prompt fallbackを残します。prompt fallbackも許容できない
  操作はMCP gateway側でdeny-by-defaultにします。
- inventory collectorはrepositoryやagentから書けない管理境界で実行し、snapshot時刻、
  complete/unavailable state、provider versionを保持します。display nameだけの一致を
  review済みextension identityとして扱いません。
- hook auditはpre-execution decision evidenceです。toolのserver-side outcome、native
  product event、workspace audit、SIEM ingestionを同じeventとして混同せず、
  session/request referenceで必要最小限にcorrelateします。
- audit size ceiling到達やexport/rotation停止はagentをblockし得るため、容量監視と
  break-glassではなく安全なrotation手順を運用します。

## 制限と残余リスク

このprototypeは、actual clientが設定とhookをloadした証明、production fleet collector、
private networkとmetadata serviceの詳細allowlist、production issuer key custody、
consumptionとexternal side effectのatomicity、shell indirection、実MCP serverのruntime
annotation検証をまだ実装していません。synthetic snapshot verifierは過去にinstall済みの
plugin driftを検出しますが、deployed endpointでcollectorが真正かつcompleteに走った証明や
PSB-AI-002のsource digest reviewを代替しません。compromised client binary、
sandbox vulnerability、endpoint administrator、developerの誤承認も残余リスクです。
managed hook sampleはtarget・size・idempotencyとsigned approvalをtool-call時に検査し、
SQLiteでsingle-use consumptionをcommitしますが、fleet配布、active client assessment、
managed path ownership、OpenSSL binary integrityのlive evidenceは含みません。SQLiteと
external MCPを同じtransactionにできないため、commit後failureはapprovalをburnし、
idempotent reconciliationと新しい承認を要求します。

hook auditはpre-execution decisionだけを記録し、external toolの成功・失敗を証明しません。
Codex OTel、Claude Codeやworkspace固有のaudit、Compliance API、server-side logsはcoverage、
redaction、retention、identityが異なる別証跡です。reference audit stateはdeployed owner、
rotation、export、SIEM ingestion、alertの稼働を証明しません。

MITRE ATLAS mappingは関連するattack behaviorとの対応であり、compliance requirement
でもAI security coverageの証明でもありません。

## 再開方法

実装段階と未実装範囲は
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md)に残します。途中で停止した
場合はそのphase checklistから再開し、chat historyだけを状態管理に使いません。

## References

- [Claude Code settings](https://code.claude.com/docs/en/settings)
- [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing)
- [Claude Code permissions](https://code.claude.com/docs/en/permissions)
- [Claude Code managed settings](https://code.claude.com/docs/en/server-managed-settings)
- [Claude Code managed MCP](https://code.claude.com/docs/en/managed-mcp)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Codex sandbox and approvals](https://learn.chatgpt.com/docs/agent-approvals-security)
- [Codex permissions](https://learn.chatgpt.com/docs/permissions)
- [Codex managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
- [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp)
- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Codex monitoring and telemetry](https://learn.chatgpt.com/docs/agent-approvals-security#monitoring-and-telemetry)
- [Codex plugin controls](https://learn.chatgpt.com/docs/enterprise/apps-and-connectors)
- [REF-AI-001 Claude Code Hardening Cheatsheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-001)
- [REF-AI-002 OWASP AI Agent Security Cheat Sheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)

The cheat sheets are reviewed design inputs, not framework mappings or
automatic compliance requirements.
