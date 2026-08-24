# PSB-CONTAINER-004: Workload-bound container runtime threat detection

## このcontrolを一枚で理解する

### セキュリティ上の問題

Admission時に安全だったcontainerでも、脆弱性悪用、悪意ある依存関係、侵害後の操作により、実行中にshell起動、重要file変更、権限昇格、runtime socket操作、不審通信、resource濫用が発生し得る。

### 誰から、または何から守るか

Applicationへ侵入した外部攻撃者、悪意あるまたは侵害されたdependency・image、内部不正、誤操作、sensor停止、event drop、通知経路障害から守る。

### 何が対象か

Admit済みcontainer workload、exact image digest、process・file・privilege・runtime境界・network・resource event、Falco/Sysdig adapter、sensor health、alert delivery、response handoff。

### 何をするか

Falco JSONまたはSysdig runtime policy eventを共通schemaへ正規化し、admission時のworkload/image identityへ結び、6種類の挙動、rule完全性、sequence、drop、sensor状態、通知到達性を検証する。

### 成功状態

Review済みruleが全て有効で、sensorと通知経路が正常、event欠落がなく、検知eventが正確なworkloadへ結び付く。違反は`DETECTED`、観測不能は`ERROR`となり、破壊的responseは独立承認なしに実行されない。

### 対象外・残余リスク

Fixtureはlive clusterへのsensor導入、kernel telemetry完全性、実際のSOC応答を証明しない。未知の攻撃、rule回避、誤検知、sensorのhost侵害、暗号化通信内容は残余リスクである。

## 何を守るcontrolか

`PSB-CONTAINER-001`はworkloadを実行する前の状態を検証します。このcontrolは、
その後に発生する挙動を継続観測します。想定するのは、許可済みapplicationの
脆弱性が悪用された場合や、review後に初めて悪性挙動を示すdependencyが含まれて
いた場合です。

| 誰／何から | 対象 | 攻撃・失敗 | このcontrolが行うこと |
|---|---|---|---|
| applicationへ侵入した攻撃者 | container process | interactive shellや未承認processを起動する | process ruleを検知しexact workloadへ結び付ける |
| 悪意あるcodeまたは侵害済みprocess | filesystem | executable、configuration、credential pathを書き換える | protected-file writeを検知する |
| container escapeを狙う攻撃者 | capability・namespace・runtime API | privilegeを追加しruntime socketを操作する | privilegeとruntime-boundaryを別々に検知する |
| compromised workload | network | 未承認destinationへ通信しC2やexfiltrationを試みる | network ruleで検知する |
| faultyまたはmalicious process | node resource | fork、CPU、memoryを異常消費する | resource ruleで検知する |
| sensor・forwarder・receiver障害 | telemetry chain | event 0件を安全と誤判定する | health、sequence、drop、deliveryを検証し`ERROR`にする |

## まず実行するコマンド

```bash
make verify-control CONTROL=PSB-CONTAINER-004
```

検証はnetwork、cluster、kernel access、vendor credentialを使用しません。Falcoと
Sysdigのsanitized synthetic fixtureをofflineで評価します。

| 終了コード | 意味 | 運用上の扱い |
|---:|---|---|
| `0` | 観測chainが正常で、対象batchにruntime eventなし | `CLEAN` |
| `1` | runtime behaviorまたはresponse policyの違反を検知 | incident triageへ引き渡す |
| `2` | sensor、drop、sequence、通知、schema、identityを評価不能 | **cleanとみなさず観測障害として対応する** |

## 12のatomic check

| Check | 確認内容 |
|---|---|
| `RTD-001` | provider adapter、sensor release、config、rulesetのreview済みidentity |
| `RTD-002` | runtime eventとadmission時のworkload・exact image digestの結合 |
| `RTD-003` | unexpected process／shell |
| `RTD-004` | protected file write |
| `RTD-005` | privilege、capability、namespace変更 |
| `RTD-006` | runtime socketまたはsensitive mount access |
| `RTD-007` | denied listener／network destination |
| `RTD-008` | abnormal process／resource consumption |
| `RTD-009` | sensor health、rule inventory、sequence、event／output drop |
| `RTD-010` | authenticated alert receiverへの到達 |
| `RTD-011` | authorization-bound responseとevidence保全 |
| `RTD-012` | raw commandやpayloadを除外したsanitized evidence |

担当、確認方法、期待証跡、行単位framework mappingは`control.yaml`から生成される
spreadsheetへ自動展開されます。

## Secure example

[`secure/runtime-policy.json`](secure/runtime-policy.json)は、二つのprovider
adapterに共通するreview済みrule category、最大signal age、alert receiver、
evidence fieldを定義します。

- Falco: JSON outputの`output_fields`から必要なidentityとrule metadataだけを取得
- Sysdig: event forwardingのruntime policy JSONから同じfieldだけを取得

[`secure/falco-health.json`](secure/falco-health.json)と
[`secure/sysdig-health.json`](secure/sysdig-health.json)は、sensorが動作している
ことだけでなく、次を証明するsynthetic health snapshotです。

- expected sensor release、artifact、config、ruleset identity
- required rule inventoryの完全一致
- event batch countと連続sequence
- kernel／analyzer event dropとoutput dropが0
- provider／forwarder connectionが正常

`sensor_release: 13.0.0-fixture`を含む値はschemaを試験するsynthetic valueであり、
Sysdig製品versionの推奨やpinではありません。実運用adapterは、組織がreviewした
releaseとartifact digestをpolicyへ記録してください。

## Insecure example

`insecure/`は**テスト専用であり、本番へ投入してはいけません**。
FalcoとSysdigのfixtureは、同じ6種類の挙動をprovider固有schemaで表現します。
raw output／descriptionにはevidenceへ出してはいけないsynthetic command markerも
含め、normalizerがこれを破棄することをテストします。

別のnegative fixtureでは、次の状態を検証します。

- Falco kernel event drop
- Sysdig agent／forwarder disconnect
- malformed provider event
- receiverへのalert delivery failure
- 独立承認なしのautomatic kill／delete response

検知eventは終了コード`1`、観測chainの破損は終了コード`2`です。どちらも
event 0件のclean結果とは区別されます。

## 実環境への統合

1. `PSB-CONTAINER-003`に従い、Falco、Sysdig Agent、または同等sensorをhost／nodeへ
   review済みかつversion固定した方法で導入する。
2. `PSB-CONTAINER-001`のadmission evidenceからcluster、namespace、workload、
   Pod UID、full container ID、exact image digest、policy versionを引き継ぐ。
3. provider eventへstable rule ID、category、monotonic sequenceとidentity fieldsを
   追加する。
4. eventを[`scripts/normalize.py`](scripts/normalize.py)でprovider-neutral schemaへ
   変換する。raw command、arguments、file content、network payloadは転送しない。
5. sensor health、enabled rule inventory、drop counter、forwarder状態をevent batchと
   同じ観測windowで取得する。
6. owned receiverへauthenticated test eventを送り、delivery結果を記録する。
7. [`scripts/verify.py`](scripts/verify.py)の`0`、`1`、`2`をそれぞれclean、
   detection、telemetry errorとして扱う。
8. responseはincidentを作成し、isolationやcredential revocationを独立承認へ
   引き渡す。fixtureだけを根拠に自動kill／deleteしない。

実運用adapterはvendor API credentialをeventやevidenceへ含めてはいけません。
credential取得、rotation、rate limit、pagination、retryはadapter側の責任です。

## FalcoとSysdigの位置付け

このcontrolが要求するのは、provider名ではなく次のcapabilityです。

- workload-bound runtime behavior event
- review済みrule inventory
- event count／sequenceとdrop counter
- sensor／forwarder health
- alert delivery確認

Falcoはopen sourceのruntime security engineとしてJSON outputとmetricsを提供します。
Sysdig Secureはruntime policy event forwardingとagent healthを提供します。本controlは
両者の代表的schema adapterを実装していますが、製品比較や購入判断、live installerは
含めません。同じcapability contractを満たす別製品もadapter追加で利用できます。

## Operational notes

- まずaudit／dry-runでbaselineを取り、expected process、file、network destinationを
  workloadごとに絞る。globalなbroad ignoreは追加しない。
- rule変更はconfig／ruleset digestを更新し、canary nodeで性能と誤検知を確認する。
- drop counterが1以上、rule不足、signal stale、forwarder切断、receiver失敗のいずれも
  security telemetry incidentとしてownerへ通知する。
- event volume、CPU、memory、kernel compatibility、retention costをSLOとして監視する。
- full command line、environment、file content、packet payloadはsecretや個人情報を
  含み得るため、既定の証跡から除外する。
- severityだけで自動的な破壊操作を決めない。workload identity、asset criticality、
  corroborating evidenceを確認する。
- sensorを攻撃対象から分離し、least privilege、read-only configuration、
  authenticated transport、restricted egressを適用する。

## Responsibility boundaries

- image／SBOM vulnerability scanning: `PSB-DETECT-001`
- workload admission: `PSB-CONTAINER-001`
- registry lifecycle: `PSB-CONTAINER-002`
- host、kernel、container daemon、sensor installation hardening: `PSB-CONTAINER-003`
- post-admission behavior、sensor health、alert delivery: `PSB-CONTAINER-004`
- incident ownership、exception、retention: governance controls

`PSB-CONTAINER-003`が未実装でも、このprovider-neutral evaluation contractはofflineで
検証できます。ただし、live adoptionはhost側sensor導入と防御を完了するまで証明
されません。

## Limitations

- synthetic fixture成功はlive sensor deploymentやkernel visibilityを証明しません。
- Falco／Sysdigの全event schema、rule、deployment optionを網羅しません。
- sensor artifact digestはfixtureであり、downloaded binaryの真正性確認例ではありません。
- encrypted network payloadの内容やapplication-level semantic abuseは検知しません。
- rule未定義の未知挙動、kernel-level evasion、sensor host compromiseは残余リスクです。
- automatic isolation、process kill、credential revocationは実装せず、承認付きhandoffだけを
  検証します。
- NIST SP 800-190 mappingは該当要求との関係を示し、準拠や全体coverageを主張しません。

## References

- [Falco JSON output](https://falco.org/docs/outputs/formatting/#json-output)
- [Falco metrics](https://falco.org/docs/metrics/)
- [Falco supported fields](https://falco.org/docs/reference/rules/supported-fields/)
- [Sysdig event forwarding](https://docs.sysdig.com/en/sysdig-secure/event-forwarding/)
- [Sysdig runtime policy events](https://docs.sysdig.com/en/sysdig-secure/runtime-policy-events/)
- [Sysdig agent health metrics](https://docs.sysdig.com/en/sysdig-monitor/integrations/integration-library/sysdig-agent-health/)
- [`REF-CONTAINER-003` Falco runtime guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-container-003)
- [`REF-CONTAINER-004` Sysdig runtime guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-container-004)
