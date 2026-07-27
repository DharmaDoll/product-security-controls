# PSB-GOV-001: supply-chain incidentの影響範囲と対応planを即時生成する

## Goal

汚染が疑われるpackage名とexact versionを入力すると、集中管理したSBOMから影響する
repository、build、artifact、credential identifier、証跡を逆引きし、containment、
credential失効、clean rebuild、通知のrunbookをdry-runで生成できる状態にします。

## 実装

- CycloneDX 1.7 JSON SBOM inventory
- SBOM serial numberとbuild recordの関連付け
- build、artifact digest、provenance、log digest、credential identifierの記録
- repository-owned incident runbook
- package／version exact matchによる影響検索
- external actionを実行しないdry-run plan

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

## 公式リファレンス

- [CycloneDX 1.7 JSON Reference](https://cyclonedx.org/docs/1.7/json/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
