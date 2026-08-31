# PSB-DETECT-003: 外部attack surfaceを発見し所有inventoryへ照合する

公開DNS、Certificate Transparency、HTTPS metadataを攻撃者と同じoutside-in視点で観測し、
組織が承認したasset inventoryとの差から未知asset、想定外公開、delegation drift、再出現を
検出するcontrolです。侵入試験や脆弱性exploitではなく、External Attack Surface Management
（EASM）のdiscovery／ownership reconciliation境界を提供します。

## このcontrolを一枚で理解する

### セキュリティ上の問題

内部inventoryにないsubdomain、staging、管理画面、退役漏れ、委託SaaSが外部公開されると、
攻撃者がSecurity teamより先に発見できます。既知assetでもowner、公開可否、service、CNAME先の
変更や期限切れを外部状態と照合しなければ、個別のscanner対象へ入らないまま残ります。

### 誰から、または何から守るか

DNS、証明書、公開service metadataを収集して標的を選ぶ外部攻撃者、shadow ITや廃止失敗を
生む開発・運用変更、partial／stale／failed collectorを「変化なし」と誤認する監視運用から
守ります。

### 何が対象か

Ownershipを確認したdomain root、その配下のhostname、公開DNS、Certificate Transparencyの
name observation、owned nameに対するport 443のHTTPS metadata、承認済みasset inventoryと
継続finding stateが対象です。

### 何をするか

三つの外部観測sourceを完全性、health、freshness、immutable window ID付きで正規化し、各candidateを
stable asset ID、owner、environment、`owned-name`／`delegated-service`、期待公開状態、期待service、
review期限へ照合します。未知、想定外、期限切れ、delegation drift、remediation後の再出現を別状態で
出力します。

### 成功状態

設定した全sourceが正常完了し、観測assetがcurrent inventoryと公開policyへ結び付き、未知・違反・
再出現がfindingになります。Source欠落、staleness、scope mismatch、sensitive evidenceは`ERROR`となり、
0 findingsへ変換されません。

### 対象外・残余リスク

Internet全体の網羅、未知root、任意IP／port scan、wordlist探索、login試行、credential validation、
脆弱性probe、exploit、第三者shared infrastructureは対象外です。Fixtureの`PASS`はlive EASM導入、
脆弱性不存在、過去に一度も露出しなかったことを証明しません。

## 最短の導入方法

### 前提とtrust assumption

- Securityがdomain ownership、外部providerへ送信可能なseed、scan許可scopeを確認する。
- Asset inventoryがstable ID、owner、environment、公開可否、service、review期限を出力できる。
- CT、public DNS、HTTPS metadata adapterがsource healthと完全性を別fieldで出力できる。
- 実hostname、provider record、finding stateはaccess-controlledなsecurity repositoryへ置く。
- Runnerの現在時刻、network egress、provider利用規約、rate limitはadopterが管理する。

### Copyするfile

最小構成では次をprivate security repositoryへcopyします。

```text
secure/policy.json
secure/inventory.json
secure/observations.json
secure/state.json
scripts/verify.py
```

`example.invalid`とsynthetic IDを実組織のreview済み値へ置換します。既存fileを自動上書きする
installerはありません。Collectorはこのpackageに含まれないため、各組織のprovider adapterが
同じsanitized contractを生成します。

### 明示的なactivation

Reference fixtureを確認します。

```bash
make verify-control CONTROL=PSB-DETECT-003
```

Copy後の単体実行例です。

```bash
python3 scripts/verify.py \
  --policy secure/policy.json \
  --inventory secure/inventory.json \
  --observations secure/observations.json \
  --state secure/state.json
```

Live運用ではcollector完了後に同じverifierをtrusted scheduleから実行し、exit `1`をreview queue、
exit `2`をmonitoring failureとして別々に通知します。Fixtureをcopyしただけでは外部監視は開始されません。

### 無害なpositive／negative self-test

`secure/`は二つの承認済みHTTPS assetを表します。一つはowned infrastructure、もう一つはexact CNAMEへ
委譲したSaaSです。`insecure/`は次を含むsyntheticな`.invalid` fixtureです。

- private想定なのにpublic DNS／HTTPSで観測された管理asset;
- inventoryにないstaging asset;
- remediation後に同じfingerprintで再出現した旧管理asset。

Testはさらにunhealthy／stale source、第三者domain、scope mismatch、期限切れreview、CNAME drift、
sensitive banner、login試行を許すpolicyを拒否します。実network、credential、provider-valid domainは
使用しません。

## 実装contract

```text
verified owned roots              approved current inventory
          |                                  |
          v                                  v
CT / public DNS / HTTPS metadata ---> strict reconciler
          |                                  |
          |                                  +--> known expected assets
          |                                  +--> NEW_UNATTRIBUTED
          |                                  +--> FINDING
          |                                  +--> REAPPEARED
          +--> source health ----------------+--> ERROR
```

### Policy

`secure/policy.json`は次を固定します。

- Domain rootのstable ID、owner、ownership evidence、review期限;
- 最大24時間のinventory／observation age;
- CT、public DNS、HTTPS metadataの完全なsource set;
- `owned-name`と`delegated-service`の区別;
- DNSとowned nameのport 443 HTTPS metadataだけを許すvalidation boundary;
- login、vulnerability probe、third-party IP scanの禁止;
- reappearanceとexternal reobservationを必要とするstate policy;
- output allow-listとsensitive field deny-list。

Reference verifierはpolicyの`as_of`をdeterministic fixture時刻として使用します。Live adapterではtrusted
current timeからpolicy／evidenceを生成し、古い`as_of`を使い回さないでください。

### Inventory

`secure/inventory.json`は「内部から見て存在すべき状態」です。Assetごとに次を必須にします。

- `asset_id`、hostname、root ID;
- `owner`、`environment`;
- `owned-name`または`delegated-service`;
- delegated serviceの場合はexact CNAME target;
- `expected_public`と期待HTTPS service;
- review時刻と最大90日のexpiry。

`status: COMPLETE`でないinventory、duplicate asset、unknown owner、古いexportは`ERROR`または
policy findingです。Inventoryにない観測assetを自動で承認済みに追加しません。

### Observation

`secure/observations.json`は「外部から観測できた状態」です。Raw provider responseを保存せず、
hostname、root ID、source、signal kind、digest形式のrecord ID、DNS target class、HTTPS protocol／port／
TLS／status classだけを保持します。

IP address、banner、body、header、credential、email、snippet、tokenはverification evidenceへ入れません。
実調査でraw evidenceが必要な場合も、別のaccess-controlled evidence storeに最小期間だけ保持します。

### Attribution

自社hostnameがCDNやSaaSを指していても、そのIPやprovider全体は自社所有ではありません。

| Class | 意味 | Active validation |
|---|---|---|
| `owned-name` | Organizationが管理するdomain配下のname | Owned nameへのDNS／HTTPS metadataのみ |
| `delegated-service` | Owned nameからexact third-party serviceへ委譲 | Owned nameとexact CNAME driftだけを確認 |
| `shared-infrastructure` | CDN／SaaS／shared hostingのaddress | Addressを新しいscan scopeへ展開しない |

この分離により、attacker viewを維持しながら第三者への無許可scanを防ぎます。

### Stateとresult semantics

Stateはscope ID、hashed hostname fingerprint、first／last seen、owner、reason class、`open`／
`remediated`だけを保持します。Remediated entryにはexternal reobservation evidence IDとclosure時刻が必要です。

| Exit | State | 意味 |
|---:|---|---|
| `0` | `PASS` | Exact complete observation setがinventory／policyと一致 |
| `1` | `FINDING` | Known assetの想定外公開、service、期限、delegation drift |
| `1` | `NEW_UNATTRIBUTED` | 初めて観測したinventory外asset |
| `1` | `UNATTRIBUTED` | 未所有のまま継続観測されるasset |
| `1` | `REAPPEARED` | Remediation済みfingerprintの再出現 |
| `2` | `ERROR` | Input、scope、source、freshness、schema、sensitive evidenceの問題 |

`PASS`は設定済みrootとsourceのその時点の結果だけを表します。「attack surfaceなし」ではありません。

## Expected output

Secure fixture:

```text
PASS scope=external-surface@sha256:1111111111111111111111111111111111111111111111111111111111111111 observed=2 known=2 findings=0
```

Insecure fixture:

```text
FINDING asset=AST-ADMIN-001 reason=unexpected-public-exposure
REAPPEARED fingerprint=3970e1d5597dc88bfa9a331117e816ff9fa9f5b2c10b92699abe7d8daaa3219d reason=previously-remediated-asset-observed
NEW_UNATTRIBUTED fingerprint=8836b1dd93519ab3ca64103b5cf18feae0f093b8a109fd362ded4c465f62fc75 reason=asset-not-in-approved-inventory
REJECTED findings=3 known=0 observed=3
```

Outputはstable asset IDまたはhashed fingerprintだけを使い、hostnameやraw observationをconsoleへ出しません。

## Findingの運用

1. `NEW_UNATTRIBUTED`にasset ownerとbusiness purposeを割り当てる。
2. 意図した公開ならinventoryへstable ID、owner、environment、service、期限を追加する。
3. 不要な公開ならDNS、service、certificate issuance pathを修正する。
4. Credential exposureが疑われる場合は内容を転記せず`PSB-GOV-004`へhandoffする。
5. Risk acceptanceが必要ならexact control／check／targetを`PSB-GOV-002`へ結ぶ。
6. 外部から再観測してclosure evidenceを作り、以後の再出現を`REAPPEARED`にする。

FindingがCVEを持つ場合だけでなく、unknown ownerやpolicy driftでも対応対象です。Hostnameやcertificateへの
出現だけで脆弱性、subdomain takeover、incidentを自動確定しません。

## 他controlとの境界

| Control | 所有する境界 |
|---|---|
| `PSB-SOURCE-003` | Public code、Issue、PR、Gist、Web indexからのdomain／endpoint／credential周辺OSINT。将来このcontrolへの任意discovery inputにできる。 |
| `PSB-IAC-001` | Approved IaC、resolved plan、provider enforcement、drift。期待inventoryのproducer候補。 |
| `PSB-DETECT-001` | 既知targetに対するintegrity-verified vulnerability／misconfiguration scan。EASM discoveryを代替しない。 |
| `PSB-SOURCE-006` | GitHub Organizationのidentity、repository、App、Actions、audit posture。Internet service inventoryではない。 |
| `PSB-GOV-002` | Exactで期限付きのsecurity exception。EASM local stateは例外contractを再実装しない。 |
| `PSB-GOV-004` | Public exposureでcredentialが疑われた後のcontainment、rotation、old-authority denial。 |

## CI／server-side enforcement

Production adoptionでは次がrepository fixtureとは別に必要です。

- Root ownership、inventory、collector source setの完全性を組織systemから生成する;
- Scheduleとnetwork egressをreviewし、provider failureを監視する;
- Raw observation、state、notificationをprivate storeへ置く;
- Exit `1`と`2`を別queue／SLOへ送り、finding countでcollector healthを上書きしない;
- Review backlog、unknown owner age、reappearance、source freshnessを運用metricにする;
- Provider adapterのschema変更とcoverage limitを定期reviewする。

Live collector、inventory、notification、review、remediation evidenceがなければ組織導入状態は
`NOT_CHECKED`です。

## Failure recoveryとrollback

- `ERROR`時は最後のsuccessful stateをcleanとして更新せず、source／inventory／scopeを復旧して再実行する。
- Collector schema変更時はraw responseをverifierへ直接渡さず、normalizerをreviewしてfixtureを追加する。
- State破損時はaccess-controlled backupからscope IDを確認して復旧し、観測を0件から開始しない。
- Rollbackはscheduleを停止し、collector credentialをrevokeし、copyしたconfig／scriptをadopter-owned reviewで削除する。
- State削除は再出現検知履歴を失うため、retentionとexportを確認してから実施する。

Global Git、shell、IDE、DNS、cloud resourceをこのreference implementationが変更することはありません。

## Framework mapping

- MITRE ATT&CK v19.1 `T1590.001 Domain Properties`: verified rootとdomain asset reconciliation。
- MITRE ATT&CK v19.1 `T1590.002 DNS`: public DNS observationとasset attribution。
- MITRE ATT&CK v19.1 `T1596.003 Digital Certificates`: CT name discoveryの照合。
- NIST SSDF 1.1 `RV.1.1`: vulnerability／security issueを識別・確認するための情報収集を支持。

ATT&CK mappingは攻撃者のreconnaissance behaviorに関連する検出境界であり、compliance requirementや
全attack surface coverageではありません。`T1595 Active Scanning`は初期sliceにactive port／vulnerability
scanがないためmappingしていません。

## 残余リスクと運用cost

- Domain seed自体が漏れていれば未知brand、買収domain、IP-only assetは見つからない。
- CTとpassive DNSはprovider coverage、履歴、rate limitに依存する。
- Wildcard certificate、CDN、shared hostingはasset attributionのfalse positiveを増やす。
- HTTPS metadataは認証・認可・content・software安全性を検証しない。
- DNSやserviceを消してもCT履歴、search cache、screenshotには残り得る。
- Live運用にはasset owner triage、false-positive review、provider adapter保守、通知SLOが必要になる。
- 大規模domain portfolioではstate store、pagination、case managementをこの小さなreference外で実装する必要がある。

## 参照

- [`PSB-SOURCE-003`](../../source-protection/public-repository-exposure/README.md)
- [`MITRE ATT&CK registry`](../../../frameworks/mitre-attack/README.md)
- [`NIST SSDF registry`](../../../frameworks/nist-ssdf/README.md)
- [`Threat model`](../../../docs/THREAT_MODEL.md)
