# PSB-REL-003: SBOM lifecycle observationsをrelease artifactへ結び付ける

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Source-only、別artifact向け、不完全、未処理のSBOMがrelease evidenceとして扱われると、脆弱性影響調査で誤ったcomponent inventoryを信頼する。 |
| 誰から、または何から守るか | 誤ったgenerator・build automation・release operator、artifact差替え、incomplete graph、Dependency-Track処理・analyzer・parser障害から守る。 |
| 何が対象か | Source・Build・Deployment CycloneDX observation、release artifact、SBOMとmanifest digest、component graph、publication、Dependency-Track projectとreceipt。 |
| 何をするか | 三つのobservationを別identity・authorityで関連付け、Build SBOMをexact artifactへbindしてimmutable公開し、least-privilege upload後の処理完了まで検証する。 |
| 成功状態 | CycloneDX 1.7 identity・exact PURL・完全graph・artifact binding・publication・`BOM_PROCESSED`・lifecycle linkが一致し、failureはcleanにならない。 |
| 対象外・残余リスク | Fixtureは実generator・release API・object storage・Dependency-Trackを実行せず、SBOMの存在はcomponent omissionや脆弱性なしを証明しない。 |

## Goal

Release artifactごとに完全なCycloneDX SBOMを生成し、artifactとSBOM双方の
SHA-256、release version、component graphを一対一で結び付けます。SBOMは
immutableなrelease locationへ同時公開し、Dependency-Trackへleast-privilegeで
登録した後、非同期処理が完了したことまで確認します。

同時に、SBOMを1回だけ生成するのではなく、次の3つの観測を別documentとして
一元catalogへ関連付けます。

| Observation | Trigger | Subject | Authority |
| --- | --- | --- | --- |
| Source | pull requestまたはpush | immutable commit SHAとdeclared dependency | early feedback only |
| Build | artifact生成直後 | 実artifactのSHA-256とbuild時に観測したcomponent | release authoritative |
| Deployment | deploy時と継続refresh | deployment IDと実際に配置したartifact SHA-256 | operational observation |

3つを同じserialへ上書きしません。Source observationは「導入意図を早く検出する」
ためには有用ですが、OS package、bundle、static link、build時downloadを含むrelease
artifactの証明には使いません。Build observationをexact released bytesへ結び付ける
既存の`SBM-002`がrelease inventoryのauthoritative boundaryです。

Deployment observationは、どのartifactがどのenvironmentへ配置されたかと、
collectorが観測できたoperational stateを表します。「実行中memory上の全componentを
完全に観測した」とは仮定しません。この区別により、早期feedback、release evidence、
稼働影響検索を混ぜずに積み上げられます。

このcontrolが防ぐのは「SBOMファイルがどこかにある」だけの状態です。攻撃者、
誤ったbuild automation、またはrelease operatorのミスにより、別artifact向け、
transitive dependency欠落、古いproject version向け、未処理、または解析不能な
SBOMが正常なrelease evidenceとして扱われるfailure scenarioを対象にします。

## Insecure implementation

`insecure/`は次の問題を同時に示します。

- source treeだけから作られ、release artifact digestと一致しないSBOM
- exact PURL、transitive component、dependency relationship、complete composition
  の欠落
- mutable HTTP location、短いretention、SBOM requirementのdowngrade
- Dependency-Trackの`autoCreate`、mutable version、broad API permission、
  literal API key、plaintext transport
- upload受付を分析完了とみなし、処理失敗やtimeoutをcleanとして扱うpolicy
- 誤ったproject UUID、SBOM digest、serial、secret-bearing receipt
- lifecycleで1つのserialを上書きし、source-only SBOMをrelease authorityにする
- branch名、`latest` deployment、誤ったartifactを使うidentity graph
- lifecycle collector失敗をcleanな一元inventoryとして扱う

## Secure implementation

`secure/`は次を実装したsynthetic fixtureです。

1. Release artifactの実byte列からSHA-256を計算する。
2. CycloneDX 1.7 root componentのhashへ同じdigestを記録する。
3. Directとtransitive componentをexact PURLで記録し、dependency graphと
   `aggregate: complete`を検証する。
4. Artifact digest、SBOM digest、serial number、公開時刻、immutable location、
   retention、no-downgrade stateをrelease manifestへ記録する。
5. 事前作成したDependency-Track project UUIDとexact versionへ、
   `BOM_UPLOAD`だけを持つCI identityで送信する。
6. API受付tokenを成功とせず、`BOM_PROCESSED` receiptをartifact-bound manifestへ
   照合する。
7. `BOM_PROCESSING_FAILED`、`BOM_VALIDATION_FAILED`、timeout、解析dataの停止・
   陳腐化、parse failureを`ERROR`として終了する。
8. Source、Build、Deployment observationを別serialで保存し、commit SHA →
   artifact SHA-256 → deployment IDをgraphとして照合する。
9. 各observationのtrigger、completeness、authorityを固定し、source／runtime viewが
   release-authoritative Build SBOMを上書きしない。

Fixtureは実APIへ接続しません。Dependency-Track API、webhookまたはread-only API
から取得した結果を`psb-dependency-track-receipt/1.0`へ正規化するproduction
adapterを組織側で用意します。ReceiptにはAPI key、SBOM本文、内部URL、脆弱性詳細を
含めず、照合に必要なmetadataだけを残します。

## Dependency-Track integration boundary

このreference adapterはDependency-Track `4.14.3`のdocumented API permissionと
notification eventを対象とし、official releaseのAPI server JAR SHA-256をfixtureで
固定しています。Dependency-Track 5系はAPI、distribution、notification schemaに
breaking changeがあるため、`latest`へ置換しません。5系へ移行するときはOpenAPI、
permission、upload、event、migration semanticsを再レビューし、同じnegative testを
通してからpolicy versionを更新します。

CIではDependency-Track用のthird-party GitHub Actionを無条件に採用しません。
採用する場合はfull commit SHA、内部download、permissions、credential forwardingを
別途レビューします。Provider-neutralなHTTPS clientを使う場合も、endpoint allowlist、
TLS、timeout、response size、log redactionを強制します。

## Verification

```bash
make verify-control CONTROL=PSB-REL-003
```

| 終了コード | 意味 |
| --- | --- |
| `0` | SBOM、release binding、公開policy、Dependency-Track処理証跡が一致 |
| `1` | SBOM、manifest、project binding、permissionまたはreceiptのpolicy違反 |
| `2` | parse不能、Dependency-Track処理・検証失敗、timeout、解析data unavailable／stale |

Fixtureの`PASS`はproduction releaseやDependency-Track deploymentの準拠を証明しません。
Live environmentでは、exact release、project、API identity、OpenAPI version、通知配送、
analyzer health、vulnerability data freshnessのorganization-owned evidenceが必要です。

## Format and supplier boundary

標準formatの相互運用性は重要ですが、このE3 adapterが実際にparseし、negative testを
持つのはCycloneDX 1.7 JSONです。SPDXも有力な標準ですが、version-pinned parser、
identity／relationship／completenessの同等contract、malformed input testを追加する
までは「対応済み」と表示しません。

Supplierやplatform teamから入手するSBOMはuntrusted inputです。調達で署名付きSBOMを
要求する場合も、署名があるだけでは採用しません。想定product、version、artifact
digest、signer identity、timestamp、失効状態、schemaを検証し、不一致または検証不能を
quarantineする独立controlが必要です。このcontrolはproducer-owned release artifactの
SBOMを対象とし、supplier署名検証済みとは主張しません。

User-supplied guidanceの原文と、このrepositoryでauthorityを分離した解釈は
[`docs/user-supplied-sbom-lifecycle-guidance-ja.md`](docs/user-supplied-sbom-lifecycle-guidance-ja.md)
に保存しています。

## Operational notes

- API keyはsecret managerから注入し、upload jobだけに渡します。
- Upload用identityとportfolio調査用identityは分離します。
- Projectは事前作成し、product identityとrelease versionをUUIDへ関連付けます。
- SBOMはuntrusted inputとしてsize制限とschema validationを行います。
- Analyzerやmirrorの停止中に「脆弱性なし」と判断してはいけません。
- Portfolio、component、脆弱性、license dataは機密情報としてaccessとretentionを
  制限します。
- 一元catalogはobservationを上書きせず、commit、artifact、deploymentのimmutable
  relationshipを保持します。
- Source observationのfindingはPR feedbackに使用し、release artifact inventoryの
  substituteにはしません。
- VEXやsuppressionはSBOMの事実を変更しません。判断にはowner、理由、scope、期限、
  再評価を必要とします。

## Limitations

- Fixtureは実package managerやSBOM generatorを実行せず、lockfileとの一致は
  `PSB-DEPS-003`および将来のecosystem adapterが担当します。
- SBOMの完全性はdeclared graphとfixture expectationsの範囲であり、runtime download、
  vendoring、plugin、statically linked componentを自動発見しません。
- Dependency-Trackの脆弱性照合はdata source、PURL品質、alias、CPE、version rangeの
  品質に依存し、false positive／false negativeが残ります。
- このcontrolはSLSA Build Level 2 requirementではなく、SLSA provenanceを置き換え
  ません。
- SBOMはsoftwareが脆弱性を含まないことやformal complianceを証明しません。

## References

- [CycloneDX 1.7 JSON Reference](https://cyclonedx.org/docs/1.7/json/)
- [CycloneDX SBOM capability](https://cyclonedx.org/capabilities/sbom/)
- [CycloneDX Operations BOM capability](https://cyclonedx.org/capabilities/obom/)
- [SPDX specifications](https://spdx.dev/use/specifications/)
- [CISA SBOM Resources Library](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary)
- [Dependency-Track CI/CD integration](https://docs.dependencytrack.org/usage/cicd/)
- [Dependency-Track notifications](https://docs.dependencytrack.org/integrations/notifications/)
- [Dependency-Track users and permissions](https://docs.dependencytrack.org/administration/users-and-permissions/)
- [Dependency-Track REST API](https://docs.dependencytrack.org/integrations/rest-api/)
