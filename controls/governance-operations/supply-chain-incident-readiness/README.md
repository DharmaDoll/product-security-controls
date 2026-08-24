# PSB-GOV-001: build artifactと稼働deploymentのincident影響を即時特定する

## このcontrolを一枚で理解する

### セキュリティ上の問題

汚染dependency発覚時にrepository、build、artifact、credential、稼働deploymentを逆引きできないと、影響判定・containment・clean rebuildが遅れる。

### 誰から、または何から守るか

Supply-chain compromise、incomplete・stale SBOM、誤ったartifact identity、Dependency-Track outage、不完全pagination、危険な自動responseから守る。

### 何が対象か

CycloneDX inventory、build evidence、artifact digest、provenance、credential identifier、Dependency-Track response、deployment inventory、incident runbook。

### 何をするか

Exact package・version・PURL・CVEからbuildとartifactを逆引きし、digestでactive deploymentへ結び、承認を要するsanitized dry-run response planを生成する。

### 成功状態

完全でfreshなinventoryから影響対象または該当なしを証跡付きで判定でき、検索・parser・pagination・analyzer障害は該当なしとせずERRORになる。

### 対象外・残余リスク

SBOMにないcomponent、runtime download、ephemeral workload、未観測deploymentはfalse negativeとなり得て、fixtureは実credential失効やproduction responseを実行しない。

## Goal

汚染が疑われるpackage名とexact versionを入力すると、集中管理したSBOMから影響する
repository、build、artifact、credential identifier、証跡を逆引きし、containment、
credential失効、clean rebuild、通知のrunbookをdry-runで生成できる状態にします。
さらにbuild recordのexact artifact digestをactive deploymentへ関連付け、
「どのenvironmentでそのbyte列が稼働しているか」を影響結果へ含めます。

## 実装

- CycloneDX 1.7 JSON SBOM inventory
- SBOM serial numberとbuild recordの関連付け
- build、artifact digest、provenance、log digest、credential identifierの記録
- repository-owned incident runbook
- package／version exact matchによる影響検索
- Dependency-Trackのexact component PURL／CVE portfolio query結果と、local SBOM
  serial、project UUID／version、build recordの相互照合
- 全page取得、inventory freshness、analyzer health、query failureを検証する
  read-only adapter contract
- external actionを実行しないdry-run plan
- immutable deployment ID、environment、observation time、exact artifact digestの
  build recordへの関連付け

fixtureのpackage、repository、artifact、credential identifierはすべてsyntheticです。
実token、個人情報、production dataは含みません。

## 検証と実行

```bash
make verify-control CONTROL=PSB-GOV-001
```

直接検索する場合:

```bash
python3 controls/governance-operations/supply-chain-incident-readiness/scripts/respond.py \
  --package compromised-lib \
  --version 4.2.0 \
  --inventory-dir controls/governance-operations/supply-chain-incident-readiness/secure/inventory \
  --records controls/governance-operations/supply-chain-incident-readiness/secure/build-records.json \
  --runbook controls/governance-operations/supply-chain-incident-readiness/secure/runbook.json \
  --dry-run
```

Dependency-Trackのportfolio全体からCVEとexact componentを検索し、repository-owned
evidenceへ照合する場合:

```bash
python3 controls/governance-operations/supply-chain-incident-readiness/scripts/respond.py \
  --package compromised-lib \
  --version 4.2.0 \
  --inventory-dir controls/governance-operations/supply-chain-incident-readiness/secure/inventory \
  --records controls/governance-operations/supply-chain-incident-readiness/secure/build-records.json \
  --runbook controls/governance-operations/supply-chain-incident-readiness/secure/runbook.json \
  --dependency-track-policy controls/governance-operations/supply-chain-incident-readiness/secure/dependency-track-policy.json \
  --dependency-track-response controls/governance-operations/supply-chain-incident-readiness/secure/dependency-track-response.json \
  --vulnerability-id CVE-2026-4242 \
  --dry-run
```

Fixtureはnetworkへ接続せず、Dependency-Track API結果を
`psb-dependency-track-impact-response/1.0`へ正規化して検証します。Production
adapterは全pageを取得し、query、snapshot時刻、analysis health、project UUID、
project version、SBOM serial、component PURL、vulnerability IDだけを出力します。
API key、SBOM本文、脆弱性の非公開detail、内部endpointは証跡へ含めません。

Upload用の`BOM_UPLOAD` identityとは分離し、調査adapterには
`VIEW_PORTFOLIO`と`VIEW_VULNERABILITY`だけを割り当てます。不完全pagination、
API outage、stale inventory、analyzer failure、query mismatchは「該当なし」ではなく
終了コード`2`です。

Deployment inventoryも同じfail-closed原則で扱います。Image名や`latest` tagだけでは
artifact identityになりません。SBOMに結び付いたbuild recordとdeployment collectorの
artifact digestが一致しない場合、稼働影響は検証不能です。Fixtureはactive deployment
relationshipを検証しますが、process memory上にloadされたすべてのlibrary、ephemeral
workload、runtime downloadを完全に観測したとは主張しません。

| 終了コード | 意味 |
| --- | --- |
| `0` | inventory検証成功、該当なし |
| `1` | 影響対象を検出、またはrunbook policy違反 |
| `2` | SBOM／record欠落、parse不能、検証器失敗 |

「該当なし」と「inventoryを検索できなかった」を区別します。

## 必須runbook

1. 証跡、SBOM、provenance、build logを保全
2. 影響workflowとartifact配布を停止
3. 関連credentialを失効
4. 影響artifactとcacheをquarantine
5. reviewed safe versionへpin
6. clean environmentでrebuild
7. stakeholderへ通知

すべてownerとmanual approvalを持ちます。このreferenceは常にdry-runで、外部systemを
変更しません。production自動化では各actionを個別の承認境界に接続してください。

## 制限事項

- SBOMが古い、不完全、未収集なら影響範囲を見落とす
- package alias、vendoring、静的link、runtime downloadには追加identifierが必要
- package名とversionの一致は侵害を証明せず、調査対象を抽出するだけ
- credential identifierは失効対象を示すだけで、実際のsecret値を保存しない
- containmentや失効は可用性へ影響するため自動実行しない
- SBOM scanner、inventory、record storeの失敗をcleanと扱ってはいけない
- Dependency-Trackのportfolio access範囲が狭い、pageが欠落する、project ACLが
  不完全、またはvulnerability dataが古い場合はfalse negativeが生じる
- Dependency-Track 4.14.3 fixtureを5系へ移行する場合、breaking API、
  distribution、permission、notification semanticsを再レビューする
- deployment collectorのcluster coverage、freshness、ephemeral workload coverageが
  不完全なら稼働影響のfalse negativeが残る

## 公式リファレンス

- [CycloneDX 1.7 JSON Reference](https://cyclonedx.org/docs/1.7/json/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Dependency-Track REST API](https://docs.dependencytrack.org/integrations/rest-api/)
- [Dependency-Track users and permissions](https://docs.dependencytrack.org/administration/users-and-permissions/)
