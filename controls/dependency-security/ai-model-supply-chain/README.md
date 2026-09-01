# PSB-DEPS-005: AI model・datasetを実行前に検証して隔離する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Model名や「scan済み」という表示だけを信頼すると、mutable revision、別byte、unsafe serialization、未承認dataset、別modelの検査結果がtraining・evaluation・servingへ入る。

### 誰から、または何から守るか

悪意ある／侵害されたmodel・dataset publisher、registryやtransfer pathの改ざん、失効signer、custom loader、誤ったrelease job、signer status・crypto verifier障害から守る。

### 何が対象か

Model weight artifact、dataset、loader、取得manifest、CycloneDX ML-BOM、inspection attestation、signer status、deployment handoff。

### 何をするか

HTTPS sourceとfull revision、実byteのSHA-256、非実行形式、bounded static inspection、model-data-loader graph、署名とsigner lifecycle、dataset authorization、handoffを一つのexact identityへ照合する。

### 成功状態

Model codeを一度もimport／deserializeせず全9 checkが通り、exact staging handoffだけが`ACCEPTED_FOR_STAGING`となる。不一致は`QUARANTINE`、検証不能は`ERROR`になる。

### 対象外・残余リスク

Live modelの精度・bias・privacy・backdoor不存在、dataset consent実在、production HSM／registry／scanner、RAG index、AI TEVV、runtime sandboxは証明しない。

## まず理解する基本的な対応作業（案1）

中央serviceの有無にかかわらず、このcontrolの本質は次の作業です。案1として各teamが
手作業やrepository-local jobで始める場合も、この順序を省略しません。

1. Product ownerとdata ownerが、model／datasetの用途、owner、license、data利用許可を決める。
2. Model名や`latest`ではなく、HTTPS source、version、full revisionを取得要求へ固定する。
3. 取得物をtraining／evaluation／servingから分離したquarantineへ置き、まだloadしない。
4. Quarantine内の実byteからSHA-256を計算し、取得manifestと照合する。
5. Pickle、custom loader、`trust_remote_code=true`を拒否し、pinned Safetensors loaderだけを許可する。
6. Modelをimport／deserializeせず、size、header、dtype、shape、offsetをbounded parserで検査する。
7. Model、dataset、loader、利用applicationのexact relationshipをCycloneDX ML-BOMへ記録する。
8. 検査材料と結果をorganization-owned signerで署名し、signerのscope、expiry、revocationを確認する。
9. 全checkが通ったexact digestだけをtrusted staging namespaceへ昇格し、consumerがdigestを再照合する。
10. Findingは`QUARANTINE`、検証基盤障害は`ERROR`として停止し、どちらもcleanとして扱わない。

案1は最初のmodelを安全に扱う理解と緊急導入には有効です。一方、teamごとにdownload
credential、policy、scanner、signer、昇格手順を持つと、更新漏れと直接downloadによる
bypassが増えます。そのため本実装は、この同じ10作業を一か所で強制する案3を基本形に
します。

## 基本実装: 中央Model Intake Control Plane（案3）

セキュリティ向上は、このdirectoryをcopyした事実ではなく、実環境で次を変更することから
生まれます。

- Training／evaluation／servingから外部model registryへの直接取得権限とegressを外す。
- 中央intake serviceだけに外部取得とquarantine書込を許可する。
- `quarantine`と`trusted`を別namespace・別権限にし、consumerは`trusted@sha256`だけをreadする。
- Request、manifest、artifact、dataset、ML-BOM、attestation、handoffをquarantineへsnapshotし、
  verifierが`ACCEPTED_FOR_STAGING`を返したexact bytesだけを昇格してdigestをreadbackする。
- `QUARANTINE`または`ERROR`ではtrusted namespaceを変更しない。

[中央intake worker](scripts/intake_worker.py)はこの状態遷移をone-shotで実行し、
[service policy](secure/service-policy.json)はconsumer-owned policyとverifierをSHA-256で
pinします。[安全な要求例](secure/intake-request.json)と
[危険な要求例](insecure/intake-request.json)は同じinterfaceを使います。Local実装は
filesystem namespaceを使う安全なreference adapterであり、live OCI registry、IAM、KMS、
network isolationの設定済みを証明しません。

担当は次のように分けます。

- Product owner: modelの用途、対象environment、acceptance boundaryを承認する。
- Data owner: datasetのlicense、purpose、personal-data／consent evidenceを承認する。
- Platform／SRE: 中央service、network、quarantine／trusted namespace、runtime read権限を構築する。
- Security: policy、scanner、signer scope、例外、実環境negative testをreviewする。
- Development team: 外部から直接loadせず、trusted digestだけをstagingでconsumeする。
- Organization owner: IAMとKMS key policyを承認し、開発者によるtrusted直接pushを禁止する。

具体的なcopy対象、Amazon ECRを使う最小設定例、IAM matrix、live verification、rollback、
framework／guide一覧は
[中央Model Intake Control Plane導入ガイド](docs/CENTRAL_INTAKE_ADOPTION.md)にまとめています。

## 最短のlocal導入と自己テスト

PrerequisiteはPython 3.10以上、OpenSSL、Bashです。Modelやdatasetのcodeは実行せず、外部
networkにも接続しません。

```bash
make verify-control CONTROL=PSB-DEPS-005
```

中央状態遷移だけを直接確認する場合:

```bash
bash controls/dependency-security/ai-model-supply-chain/tests/test-central-intake.sh
```

成功時はexit `0`で`RESULT PROMOTED sha256:...`、危険な要求はexit `1`で
`RESULT QUARANTINE`、OpenSSL等の検証基盤障害はexit `2`で`RESULT ERROR`になります。
どちらのnegative pathもtrusted artifactを書きません。

## Goal

AI modelは通常のlibrary dependencyと同じく外部から取得するartifactですが、追加の
危険があります。model weightがpickle等の実行可能serializationであれば「modelを
読む」操作がcode executionになります。また、modelとdataset、fine-tuning、loader、
deploy先の関係が失われると、後から影響範囲を調べられません。

このcontrolは、modelを実行する前の隔離領域で次を一つのbundleとして検証します。

1. modelとdatasetのimmutable source、full revision、exact bytes;
2. CycloneDX 1.7 ML-BOMのapplication → model → dataset／loader関係;
3. Safetensors限定、remote code禁止、pinned loader;
4. modelをimportしないSafetensors header／tensor layout検査;
5. exact materialsとinspector digestを結ぶEd25519署名とsigner status;
6. dataset license、use authorization、personal-data declaration;
7. accepted bundleだけを許すexact deployment handoff。

## 想定する攻撃と失敗

- Publisherまたはregistry侵害により、`latest`やbranchがreview後に別modelへ動く。
- `.pkl`、`.pt`、custom loader、`trust_remote_code=true`が取得時にcodeを実行する。
- Clean receiptが別model／dataset／ML-BOMから再利用される。
- 正しいmodel hashに、異なるdataset名やloader relationshipが付けられる。
- 未知license、未承認用途、personal dataを含むdatasetがtrainingへ入る。
- Quarantine済みmodelに`decision: ACCEPTED`を書くだけでdeploymentへ渡す。
- Signer status、OpenSSL、trusted policyが使えないのにcleanとして扱う。
- 証跡へproprietary weights、dataset rows、signatureやkeyを複製する。

Hashは「同じbyteである」ことを示しますが、「安全にloadできる」「そのdatasetを
使ってよい」「そのinspectionが信頼できる」ことは示しません。このため、identity、
format、provenance、authorization、signature、handoffを別々のatomic checkとして
検証します。

## Runnable implementation

安全なfixtureは次を含みます。

- 1 tensor／124 bytesのsynthetic Safetensorsをbase64 transportしたartifact;
- personal dataを含まない1行のsynthetic dataset;
- model、dataset、Safetensors loaderを結ぶCycloneDX 1.7 ML-BOM;
- model、acquisition manifest、ML-BOM、dataset、inspector digestを結ぶ署名済み
  intake attestation;
- test-only Ed25519公開鍵とcurrent signer status;
- exact `staging` handoff。

Repositoryにprivate keyはありません。公開鍵とprecomputed signatureはfixture専用で、
production trust rootには使用できません。

危険例の`inert-unsafe-model.pkl.b64`は、実pickleやpayloadではありません。
`INERT ... NOT A PICKLE`という無害な文字列を、危険なpickle取得要求のmetadataと
組み合わせています。したがってnegative testはunsafe policy decisionを再現しますが、
malicious codeを収録・実行しません。

## Insecure and secure examples

安全でない取得要求:

```json
{
  "model": {
    "version": "latest",
    "source_revision": "main",
    "serialization": "pickle",
    "trust_remote_code": true
  },
  "loader": {
    "name": "custom-loader",
    "version": "latest",
    "inspection_mode": "execute-import"
  }
}
```

安全な取得要求:

```json
{
  "model": {
    "version": "1.0.0",
    "source_revision": "1111111111111111111111111111111111111111",
    "serialization": "safetensors",
    "sha256": "df0c00870b43005f873ec026757af59db1956218773b4ee401df32a9536c1aed",
    "trust_remote_code": false
  },
  "loader": {
    "name": "safetensors",
    "version": "0.8.0",
    "source_commit": "a406ca3e7a90598be0cd05a50069cb9bf5ef6ba6",
    "dependency_control": "PSB-DEPS-003",
    "inspection_mode": "non-executing-static-header"
  }
}
```

`secure/`は参照contract、`insecure/`は隔離されたnegative fixtureです。どちらも
実model registryやproduction deploymentへ接続しません。

## 判定状態

| 状態 | 意味 | 次工程 |
|---|---|---|
| `ACCEPTED_FOR_STAGING` | 全identity、format、structure、signature、dataset、handoffを検証できた | exact digestのstaging評価候補にできる |
| `QUARANTINE` | model bundleにmutable identity、不一致、unsafe format、finding、失効、handoff違反がある | 通常registry／training／servingへ渡さずreview queueへ隔離 |
| `ERROR` | trusted policy、signer status、crypto verifierを信頼できる状態で評価できない | fail closedで停止し、content findingと分けて運用通知 |

`QUARANTINE`も`ERROR`も「脆弱性なし」「安全なmodel」を意味しません。

## 検証

```bash
make verify-control CONTROL=PSB-DEPS-005
```

終了コード:

- `0`: `ACCEPTED_FOR_STAGING`;
- `1`: `QUARANTINE`;
- `2`: `ERROR`。

Negative testは、valid signatureを保持したunsafe bundle、mutable source、pickle、
remote code、custom loader、未知license、personal-data declaration、ML-BOM mismatch、
artifact／attestation改ざん、malformed input、sensitive evidence、stale／unavailable
signer status、OpenSSL実行不能を含みます。

期待される成功出力:

```text
PASS AMS-004 bounded safetensors structure verified without model execution
PASS AMS-008 verification dependencies available and current
RESULT ACCEPTED_FOR_STAGING
```

出力はcheck IDと判定理由だけです。weight bytes、tensor values、dataset rows、
signature、key本文、credentialは出しません。

## Integration

1. Model registry、dataset registry、publisher、signer、loaderのownerを登録する。
2. Modelとdatasetを直接runtimeへ渡さず、networkとcredentialを限定した隔離領域へ
   exact revisionで取得する。
3. 取得直後にraw bytesのdigestを計算し、modelをimportせずformat／header／layoutと
   別scannerの結果を検証する。
4. CycloneDX 1.7 ML-BOMへapplication、model、dataset、loader、fine-tuning等の
   exact relationshipを記録する。本fixtureはmodel、dataset、loaderの最小subset。
5. Organization-owned inspector identityでexact materialsと結果を署名し、status
   sourceでsigner scope、expiry、revocationを確認する。
6. 全checkが通ったbundleだけにimmutable handoffを作り、staging consumerがdigestを
   再照合する。Model loaderのpackage取得は`PSB-DEPS-003`へ渡す。
7. TEVV、red-team、quality、privacy評価は別release gateで実行し、このcontrolの
   `ACCEPTED_FOR_STAGING`だけをproduction release判断にしない。

`--as-of`はfixture再現用です。Production adapterはtrusted UTC clockを使い、bundle
publisherが評価時刻を上書きできないようにします。

## Control boundary

- `PSB-DEPS-003`はloader package、lockfile、download artifactのintegrityを所有する。
- `PSB-REL-003`はsoftware release SBOMとsource／build／deployment observationを
  所有する。本controlはAI model・dataset semanticsを持つML-BOM intakeを所有する。
- `PSB-REL-004`はsupplier software SBOMの署名とportfolio quarantineを所有する。
  本controlはmodel bytesの非実行inspectionとAI dependency handoffを追加する。
- RAG corpusのsource authorization、tenant／classification isolation、index deletion、
  retrieval provenance、poisoning testは後続の独立controlとする。
- Model behaviorのTEVV／adversarial release gateは`detection-verification`の後続
  controlとする。
- Runtime sandbox、model serving egress、application data policyは本control外。

## Operational notes

- Productionではmodel registry download client、scanner、Safetensors library、
  signature verifierをversion／digest pinし、update時にnegative corpusを再実行する。
- Safetensorsはembedded Python object executionを避けますが、parser、framework、
  downstream kernel、tensor shape、memory consumptionを自動的に安全にはしません。
- Quarantine storageにはsize、retention、access、egress、deletion、incident holdを
  定義し、通常model registryとnamespaceを分離します。
- Dataset authorizationはdata ownerが発行し、license、consent、purpose、residency、
  deletion、personal-data classificationをproduction evidenceで補います。
- ML-BOMはmodel releaseごとにimmutable serialを持たせ、同じserialへsource、build、
  deploy観測を上書きしません。
- Scannerやsignature verifierのfailureは、finding zeroとして保存しません。

## Limitations and residual risk

- Parserは本controlに必要なSafetensors／CycloneDX fieldsを検証するstructural profileで、
  公式schemaやlibrary全体の代替ではありません。
- Synthetic fixtureはlive modelのaccuracy、bias、privacy、robustness、alignment、
  backdoor不存在を証明しません。
- 正規publisher、registry、scanner、signerが侵害されれば、整合した悪性bundleが
  作られる可能性があります。
- Static structureとmalware scanでsemantic weight poisoningや全payloadを検出できるとは
  限りません。
- Dataset license、consent、use authorizationの実在はorganization-owned evidenceが
  必要で、fixtureの文字列だけでは保証しません。
- Test keyはHSM、certificate chain、transparency、timestamp、production revocationを
  再現しません。
- このmappingはMITRE ATLAS、SSDF、CycloneDXまたは製品へのformal complianceを
  意味しません。

## References

- [CycloneDX 1.7 ML-BOM capabilities](https://www.cyclonedx.org/capabilities/mlbom/)
- [CycloneDX 1.7 specification at the reviewed commit](https://github.com/CycloneDX/specification/tree/4b3f59453366e27c8073fd24e98bf21ef8892c8e)
- [Safetensors 0.8.0 format and security rationale](https://github.com/safetensors/safetensors/tree/a406ca3e7a90598be0cd05a50069cb9bf5ef6ba6)
- [PyTorch serialization security and `weights_only`](https://docs.pytorch.org/docs/stable/notes/serialization.html)
- [NIST SSDF 1.1 / SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATLAS 2026.05 reviewed data release](https://github.com/mitre-atlas/atlas-data/blob/da9ebf9b66e6902ad97c267e2a20af0bd996a60f/dist/v6/ATLAS-2026.05.yaml)
- [OWASP AISVS 1.0 model lifecycle requirements](https://github.com/OWASP/AISVS/blob/78775233666a2022dcfb82037e5e029116955c00/1.0/en/0x10-C03-Model-Lifecycle-Management.md)
- [OWASP AISVS 1.0 infrastructure requirements](https://github.com/OWASP/AISVS/blob/78775233666a2022dcfb82037e5e029116955c00/1.0/en/0x10-C04-Infrastructure.md)
- [OWASP AISVS 1.0 supply-chain requirements](https://github.com/OWASP/AISVS/blob/78775233666a2022dcfb82037e5e029116955c00/1.0/en/0x10-C06-Supply-Chain.md)
- [`REF-DEPS-003`: AI model artifact and ML-BOM safety guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-deps-003)
