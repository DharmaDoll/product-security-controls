# PSB-CONTAINER-002: Container registry security

## このcontrolを一枚で理解する

### セキュリティ上の問題

Registryが平文通信、広い権限、長寿命credential、mutable release、監査欠落、無期限のstale imageを許すと、正しいbuild後でもimageの窃取・差し替え・再利用が起きる。

### 誰から、または何から守るか

外部攻撃者、network attacker、盗まれたdeveloper credential、over-privileged CI identity、compromised publisher、registry／audit／lifecycle service障害から守る。

### 何が対象か

Private／release container registryのendpoint、repository、actor、pull／push／delete／admin権限、release tagとdigest、audit record、image lifecycle inventory。

### 何をするか

TLSとexact trust anchor、default-denyのrepository/action scope、短寿命identity、protected reference immutability、attributable audit、期限付きの非deployable lifecycleを検証する。

### 成功状態

7 checksのpolicyと証跡が一致し、anonymous／cross-repository write、release置換、unaudited action、stale deployable imageを拒否し、証跡異常は`ERROR`になる。

### 対象外・残余リスク

Fixtureはlive registry enforcementを証明せず、imageの脆弱性・malware、署名・provenance、workload admission、registry可用性をこのcontrol単独では保証しない。

## 何を守るcontrolか

Buildで正しいimageを生成しても、registryまでの通信が盗聴される、publisherが
別repositoryへpushできる、release tagが後から上書きされる、または古いimageが
deploy可能なまま残れば、consumerが受け取るものは変わります。このcontrolは
「registryへ置いてから利用境界へ渡すまで」の運用状態を検証します。

| 誰／何から | 対象 | 攻撃・失敗 | このcontrolが行うこと |
|---|---|---|---|
| network attacker／偽registry | endpointとcredential | HTTP、弱いTLS、曖昧なmirrorへ接続する | HTTPS、TLS 1.2以上、exact hostとtrust anchorを要求する |
| stolen identity／broad CI role | repositoryと操作 | anonymous write、cross-repository push、不要なdelete／adminを行う | exact actor・repository・actionとdefault denyを評価する |
| long-lived robot credential | release publisher | job終了後もcredentialをreplayする | `PSB-CICD-006`由来の短寿命receiptと非保存状態を確認する |
| compromised publisher／admin | release reference | 既存tagを別digestへ置換する、protected digestを削除する | protected tagの一対一bindingとdelete denyを検証する |
| insider／collector障害 | audit trail | sensitive pullやmutationのactor・対象を追跡できない | operationとredacted audit recordを一対一で照合する |
| stale image／lifecycle drift | image inventory | 古い・revoked imageが無期限にdeploy可能になる | state transition、非deployable状態、quarantine／removal期限を検証する |
| API／collector outage | 全checkの外部証跡 | 欠落を「eventなし」と誤認する | health、complete、freshnessを先に検証し`ERROR`でfail closedにする |

## まず実行するコマンド

```bash
make verify-control CONTROL=PSB-CONTAINER-002
```

通常検証はnetwork、cloud credential、live registryを使いません。syntheticな
provider-neutral policyと正規化済み証跡を、固定したevaluation timeで評価します。

| 終了コード | 意味 | 運用上の扱い |
|---:|---|---|
| `0` | 全checkを評価し、違反なし | policy採用候補 |
| `1` | transport、権限、mutation、audit、lifecycleに違反あり | registry設定または対象imageを修正する |
| `2` | malformed、stale、incomplete、unavailableな証跡 | **cleanと扱わず、評価を停止する** |

## 7つのatomic check

| Check | 確認内容 | 主担当 |
|---|---|---|
| `REG-001` | TLS-only endpointとexact trusted registry identity | CI／platform |
| `REG-002` | repository・action単位のleast privilegeとdefault deny | CI／platform |
| `REG-003` | `PSB-CICD-006`由来の短寿命identityとstored credential禁止 | CI／platform |
| `REG-004` | protected release tagの上書きとdigest削除の禁止 | release manager |
| `REG-005` | sensitive read、write、adminのattributable audit | security |
| `REG-006` | active／deprecated／quarantined／removed lifecycle | shared |
| `REG-007` | registry API、authorization、audit、lifecycle証跡のhealth | security |

各行のthreat actor、failure scenario、必要性、担当、確認方法、証跡、framework
mappingは`control.yaml`から生成されるchecklistにも残ります。

## 安全例と危険例

`secure/`は次を表します。

- `https://registry.example.invalid`とreview済みCA SHA-256だけを信頼する。
- exact actorへexact repositoryの必要なactionだけを与え、default denyにする。
- release publisherは10分で失効する`PSB-CICD-006` receiptを使い、credentialを保存しない。
- `release-` tagは最初のdigestから変更できず、protected digestを削除できない。
- sensitive pullと全write／admin attemptをrequest ID単位で監査する。
- stale imageを非deployableなdeprecated／quarantined状態へ移し、removal期限を持つ。

`insecure/`は平文endpoint、wildcard grant、anonymous／cross-repository write、
24時間credential、stored credential、release overwrite、監査欠落、deployableな
stale imageを意図的に含みます。productionへ適用してはいけません。

## Fixture間のbinding

```text
policy.json
   |-- endpoint / role / mutation / audit / lifecycle requirements
   |
identity.json -------- exact actor / repository / actions / audience / TTL
operations.json ------ request / actor / repository / digest / tag / outcome
   |                         |
   |                         +---- audit.json one-to-one correlation
   |
   +------------------------------ protected tag history

inventory.json ------- lifecycle state / deployability / deadlines
evidence-health.json - source health / completeness / freshness
```

Verifierは入力の`PASS`文字列を集計しません。policyからauthorization decisionを
再計算し、operationとauditをexact fieldで照合し、tag historyとlifecycle deadlineを
再評価します。

## 導入方法

Provider adapterは、AWS ECR、Artifact Registry、ACR、GHCR、またはOCI
Distribution固有のAPIを次の正規化境界へ変換します。

1. endpoint、TLS、trusted registry identityを取得する。
2. actor、repository、actionのeffective authorizationを列挙する。
3. `PSB-CICD-006`で検証済みのexchange receiptを、registry actorへ結び付ける。
4. protected tagのpush／delete historyと現在digestを取得する。
5. sensitive readとwrite／admin attemptのauditを完全paginationで収集する。
6. digest単位のstate、age、deployability、deadline、decision sourceを取得する。
7. 各sourceの取得health、完全性、観測時刻を別manifestに記録する。

Adapterがpagination、schema、権限、API応答を確認できない場合、空配列を返しては
いけません。`evidence-health.json`を非`ok`にし、評価を`ERROR`へ送ります。

## 他controlとの境界

- `PSB-CICD-006`: OIDC tokenの署名、claim、audience、replayとcloud exchangeを検証する。
  このcontrolはその正規化receiptをregistry roleへbindする。
- `PSB-REL-001`／`PSB-REL-002`: artifact signature、provenance authenticity、
  publicationを担当する。registry retentionはSLSA達成証拠へ自動昇格しない。
- `PSB-DETECT-001`: image vulnerability／secret scanを実行する。scanner failureは
  quarantine成功ではなく`ERROR`である。
- `PSB-CONTAINER-001`: exact digestをworkload admissionで許可または拒否する。
  registryでquarantineしただけではlive deploymentの停止を証明しない。

## Expected output

成功時の先頭は次の形式です。

```text
PASS PSB-CONTAINER-002 registry policy accepted
PASS REG-001 TLS-only trusted registry identity verified
```

Policy違反は`FAIL REG-xxx ...`、証跡の取得・形式・freshness異常は次のように
別状態になります。

```text
ERROR PSB-CONTAINER-002 registry evaluation unavailable: audit evidence is incomplete
```

Outputはcredential値、token、secret、private keyを含みません。

## 運用上の注意

- Break-glass deleteを導入する場合も、通常roleへ混ぜず、single-use approval、
  独立承認、期限、exact digest、監査、復旧／incident手順を別policyで定義します。
- Public anonymous pullは公開repositoryごとに明示レビューします。anonymous push、
  delete、adminを許可する理由にはなりません。
- Retentionは「消す」だけでなく、legal hold、provenance／SBOM保持、rollback期間、
  incident evidence保存との競合を組織policyで解決します。
- Audit collector自身のcredentialはleast privilegeにし、write pathから独立させます。
- Lifecycle automationは最初にnon-deployable化し、削除前にowner通知とgrace periodを
  設けると、availabilityとsecurityのtrade-offを管理しやすくなります。

## Framework mapping

- NIST SP 800-190 September 2017 `4.2.1`: insecure registry connection対策。
- NIST SP 800-190 September 2017 `4.2.2`: stale image lifecycle対策。
- NIST SP 800-190 September 2017 `4.2.3`: registry authentication／authorization対策。

これは該当countermeasureへのreviewed relationshipであり、NIST準拠やcontainer
security全体の完全coverageを意味しません。SLSA Build requirementはproducer、
build platform、provenance、consumerのcontrolに残し、このregistry運用状態へ
重複mappingしません。CIS Docker Benchmark mappingはauthorized v1.8.0 sourceの
reviewまで追加しません。

## 参考資料

- [NIST SP 800-190 registry](../../../frameworks/nist-sp-800-190/README.md)
- [Container Security Source Allocation](../../../docs/CONTAINER_SECURITY_SOURCE_ALLOCATION.md)
- [OWASP Docker Security Cheat Sheet allocation](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-container-001)
- [PSB-CICD-006](../../cicd-security/audience-bound-oidc-federation/README.md)
- [PSB-CONTAINER-001](../container-admission-baseline/README.md)

## Limitations

- Offline E3 fixtureはlive provider enforcement、API authorization、collector identityを証明しません。
- Provider固有adapterとcryptographic collector authenticationは次のsliceです。
- Vulnerability／malware scan、signature／provenance、admission、backup／DRは別controlまたは組織証跡です。
- Quarantineとdeploy停止のend-to-end bindingにはlive registryとorchestrator双方のevidenceが必要です。
