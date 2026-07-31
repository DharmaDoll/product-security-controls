# PSB-REL-004: supplier SBOMを検証してからportfolioへ受け入れる

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Supplier SBOMを存在や署名だけで信頼すると、正しく署名された別製品・別artifactや失効signerのinventoryが通常portfolioへ混入する。 |
| 誰から、または何から守るか | 外部forger、transfer channel compromise、誤ったsupplier release job、未知・期限切れ・失効signer、status source・crypto verifier障害から守る。 |
| 何が対象か | Supplier artifact、CycloneDX SBOM、signed envelope、detached signature、consumer trust root、signer status snapshot、portfolio upload identity。 |
| 何をするか | 署名とkey digest、supplier・product・version、artifact・SBOM digest、serial・root identity、signer lifecycleを照合し、least-privilege import前に判定する。 |
| 成功状態 | 全期待値を検証した入力だけが`ACCEPTED_FOR_PORTFOLIO_IMPORT`となり、不正・不一致は`QUARANTINE`、検証基盤障害は`ERROR`として通常importをblockする。 |
| 対象外・残余リスク | Fixtureは完全なCycloneDX schema、production PKI・OCSP・CRL・transparencyを再現せず、正規supplier signerやbuild自体の侵害、SBOM omissionを検出できない場合がある。 |

## Goal

supplierやplatform teamから受領したSBOMを、単に「ファイルが存在する」だけで
信頼しません。署名済みenvelope、supplier／製品／version、実artifactとSBOMの
SHA-256、CycloneDX identity、署名者の有効期間と現在の失効状態をconsumer-owned
policyへ照合し、成功した入力だけをportfolio import候補にします。

## 想定する攻撃と失敗

対象は外部supplierのSBOM、対応するrelease artifact、署名、受入policy、
signer status source、portfolio upload identityです。

- 攻撃者または誤ったrelease jobが、正しい署名付きSBOMを別製品へ付け替える。
- 失効済み・期限切れ・未知のsupplier signerが過去の信頼を再利用する。
- 不正なSBOMが通常inventoryへ入り、後の脆弱性影響調査を誤らせる。
- signer status sourceや暗号検証器が停止したのに、受入成功として扱われる。
- supplier upload identityがproject作成やpolicy変更まで行い、侵害範囲を広げる。
- 証跡へsupplierのcomponent inventoryや鍵素材を複製してしまう。

署名の妥当性は「誰かがそのenvelopeを署名した」ことしか示しません。そのため、
署名されたproduct identityと実byte列をconsumerの期待値へ別途結び付けます。

## Runnable implementation

安全なfixtureは次を含みます。

- synthetic supplier artifactとCycloneDX 1.7 SBOM
- product、artifact digest、SBOM digest、serialを結ぶsigned envelope
- test-only Ed25519公開鍵とdetached signature
- consumer-owned intake policy
- signer identity、有効期間、失効状態を持つstatus snapshot
- portfolio projectを固定した`BOM_UPLOAD`専用import policy

秘密鍵はrepositoryへ収録していません。公開鍵と署名はsynthetic fixture専用で、
実環境のtrust rootには使用できません。

insecure fixtureは署名自体が有効でも、別製品identity、失効済みsigner、
過剰権限、automatic import、過剰なevidence保存を含むため隔離されます。

## 判定状態

| 状態 | 意味 | portfolioへの動作 |
|---|---|---|
| `ACCEPTED_FOR_PORTFOLIO_IMPORT` | 全期待値を検証できた | 固定済みprojectへの次工程を許可 |
| `QUARANTINE` | supplier入力が未署名、不正、不一致、未知、期限切れ、失効 | 通常portfolioへ入れずreview queueへ送る |
| `ERROR` | policy、失効情報、暗号検証器を信頼できる状態で評価できない | fail closedで停止し、運用障害として通知 |

`QUARANTINE`は「脆弱性なし」ではありません。`ERROR`もclean resultでは
ありません。どちらも通常importを許可しません。

## Insecure and secure examples

安全でない受入policy:

```json
{
  "auto_import": true,
  "portfolio_project_id": "*",
  "allowed_permissions": [
    "BOM_UPLOAD",
    "PROJECT_CREATION_UPLOAD",
    "SYSTEM_CONFIGURATION"
  ]
}
```

安全な受入policy:

```json
{
  "auto_import": false,
  "portfolio_project_id": "9c32beea-216c-4c7e-a340-0b3172b6c27d",
  "allowed_permissions": ["BOM_UPLOAD"],
  "may_create_project": false,
  "may_modify_policy": false
}
```

insecure fixtureはテストデータであり、deployまたは実supplier受入へ使用しません。

## 検証

```bash
make verify-control CONTROL=PSB-REL-004
```

検証器の終了コードは次のとおりです。

- `0`: `ACCEPTED_FOR_PORTFOLIO_IMPORT`
- `1`: `QUARANTINE`
- `2`: `ERROR`

negative testは、署名済み別製品、SBOM byte改ざん、未署名、malformed input、
unsupported format、未知・期限切れ・失効済みsigner、古い・取得不能のstatus
snapshot、OpenSSL実行不能を含みます。

成功時の期待出力:

```text
PASS supplier signature identity schema and signer status verified
RESULT ACCEPTED_FOR_PORTFOLIO_IMPORT
```

出力はcheck IDと判定理由だけを残し、component一覧、SBOM body、公開鍵本文、
署名本文を証跡へ出しません。

## Integration

1. 調達またはsupplier onboardingでsupplier ID、製品、signer identity、
   trust root、失効確認方法、rotation手順を登録します。
2. 受領したartifact、SBOM、signed envelope、signatureを隔離領域へ置きます。
3. immutableなartifact bytesに対して本control相当の検証を実行します。
4. `ACCEPTED_FOR_PORTFOLIO_IMPORT`だけをpre-created projectへ送ります。
5. import後のSBOM processingとvulnerability data freshnessは
   `PSB-REL-003`のfail-closed adapterで確認します。
6. signer status sourceの障害はsupplier content violationと分けて運用通知します。

`--as-of`はテスト再現性のため明示しています。production adapterでは信頼できる
UTC clockを使用し、実行時刻の上書きを一般利用者へ許可しません。

## Control boundary

- `PSB-REL-001`はrelease artifactとSLSA provenanceのconsumer verificationを
  所有します。SBOMのproduct schemaやportfolio quarantineは所有しません。
- `PSB-REL-003`は自組織が生成するSource／Build／Deployment SBOMと
  Dependency-Track処理完了を所有します。supplier authenticityは所有しません。
- `PSB-REL-004`は外部SBOMが通常portfolioへ入る前のtrust boundaryを所有します。

SBOM署名はSLSA Build level要件ではなく、SLSA level達成を証明しません。

## Operational notes

- trust rootとrevocation sourceはsupplier upload channelから分離して管理します。
- key rotationでは旧新keyの重複期間を限定し、product scopeを明示します。
- quarantine領域はretention、access control、削除手順を定義します。
- supplier confidential inventoryをsecurity evidenceや一般CI logへ複製しません。
- productionではcertificate chain、timestamp authority、transparency serviceなど、
  supplierの署名方式に合う検証adapterをversion pinして追加します。
- scannerやcrypto toolの実行失敗を署名成功として扱ってはいけません。

## Limitations and residual risk

- fixtureのCycloneDX確認はこのcontrolが必要とする構造profileであり、
  CycloneDX公式JSON Schema全体のvalidatorではありません。
- checked-in公開鍵はPKI chain、OCSP、CRL、keyless identity、
  transparency logを再現しません。
- status snapshotはsyntheticです。productionではsource authenticityと取得失敗を
  独立して検証する必要があります。
- 正規supplier signerやsupplier build自体の侵害は検出できない場合があります。
- 署名済みSBOMもcomponent omissionや誤ったdependency relationshipを含み得ます。
- 現在のadapterはCycloneDX 1.7のみです。SPDXはversion-pinned parserと同等の
  malformed、identity、relationship、signature negative testが必要です。
- 受入成功は製品、supplier、SBOM、frameworkへのformal complianceを意味しません。

## References

- [CycloneDX 1.7 JSON Reference](https://cyclonedx.org/docs/1.7/json/)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [`REF-REL-002`: SBOM lifecycle and interchange guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-rel-002)
- [`REF-USER-005`: reviewed user-supplied SBOM lifecycle guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-user-005)
