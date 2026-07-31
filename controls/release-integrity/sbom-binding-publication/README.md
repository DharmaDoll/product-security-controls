# PSB-REL-003: release artifactへSBOMを結び付けて公開・処理確認する

## Goal

Release artifactごとに完全なCycloneDX SBOMを生成し、artifactとSBOM双方の
SHA-256、release version、component graphを一対一で結び付けます。SBOMは
immutableなrelease locationへ同時公開し、Dependency-Trackへleast-privilegeで
登録した後、非同期処理が完了したことまで確認します。

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

## Operational notes

- API keyはsecret managerから注入し、upload jobだけに渡します。
- Upload用identityとportfolio調査用identityは分離します。
- Projectは事前作成し、product identityとrelease versionをUUIDへ関連付けます。
- SBOMはuntrusted inputとしてsize制限とschema validationを行います。
- Analyzerやmirrorの停止中に「脆弱性なし」と判断してはいけません。
- Portfolio、component、脆弱性、license dataは機密情報としてaccessとretentionを
  制限します。
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
- [Dependency-Track CI/CD integration](https://docs.dependencytrack.org/usage/cicd/)
- [Dependency-Track notifications](https://docs.dependencytrack.org/integrations/notifications/)
- [Dependency-Track users and permissions](https://docs.dependencytrack.org/administration/users-and-permissions/)
- [Dependency-Track REST API](https://docs.dependencytrack.org/integrations/rest-api/)
