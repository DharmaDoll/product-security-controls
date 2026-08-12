# Application vulnerability assessment checklist import

## 目的と現在の状態

組織が既に持つアプリケーション脆弱性診断checklistを、原文・source ID・versionを失わず、
行単位の担当、確認方法、証跡、control disposition、framework mappingへ変換します。

これはcontrolではなく、`PSB-CODE-001..`を既存診断項目と重複なく設計するための
data-model／generation prerequisiteです。現在、実sourceは未提供です。したがってcanonical
generationは空profileを作らず、次へ`INPUT_REQUIRED`を出力します。

```text
generated/checklists/profiles/application-vulnerability-assessment/status.json
```

## Trust boundary

Source CSV／XLSXとreconciliation CSVはuntrusted inputとして扱います。Importerは次を行います。

- Manifest、source、reconciliationのexact SHA-256を検証する;
- Source title、owner、version、review date、sheet、column semanticsを必須にする;
- UTF-8 CSVまたはbounded XLSXだけをread-onlyで解析する;
- Duplicate ID、unknown column、blank row、formula-like cell、XLSX formula、macro、external
  link、unsafe ZIP path、oversized inputを拒否する;
- Missing sourceを0件のclean checklistとして扱わない;
- Organization-only rowのIDをdigest化し、原文・atomic wording・mappingをpublic outputへ出さない;
- Framework mappingをrepository registryのexact version／identifierへ照合する;
- Import errorではprofileを生成せず、CLIをexit code `2`にする。

Importerはsource workbookを変更せず、hookをinstallせず、組織の診断結果や回答を収集しません。

## Source manifest

Manifestは
[`application-checklist-source-manifest.schema.json`](../schemas/application-checklist-source-manifest.schema.json)
に従います。

```json
{
  "schema": "psb-application-checklist-source/v1.0",
  "source": {
    "title": "Organization application assessment",
    "owner": "product-security",
    "version": "2026.08",
    "review_date": "2026-08-06"
  },
  "input": {
    "path": "assessment.xlsx",
    "format": "xlsx",
    "sheet": "Checklist",
    "sha256": "<64 lowercase hex characters>"
  },
  "columns": {
    "source_id": "Check ID",
    "wording": "Question",
    "category": "Category",
    "publication": "Publication"
  },
  "reconciliation": {
    "path": "reconciliation.csv",
    "format": "csv",
    "sha256": "<64 lowercase hex characters>"
  }
}
```

CSV inputでは`sheet`を`CSV`にします。Source columnsはmanifestに宣言した4列だけを許可します。
`publication`は`public`または`organization-only`です。

## Reconciliation CSV

Reconciliation CSVの列は固定です。

| Column | 意味 |
|---|---|
| `source_id` | Original source row ID。必ずsourceに存在する。 |
| `atomic_id` | Split後も一意なstable ID。 |
| `atomic_wording` | 一つだけ判定可能な要求。 |
| `disposition` | `implemented`、`planned`、`duplicate`、`out-of-scope`、`mapping-review-required`。 |
| `control_ids` | Semicolon区切りのowner／planned control ID。 |
| `responsible_role` | Control metadataと同じrole vocabulary。 |
| `verification_method` | 実行または確認方法。 |
| `expected_evidence` | 必要な証跡。実際の証跡値は書かない。 |
| `framework_mappings` | Exact registry mapping。 |
| `notes` | Split理由、重複、対象外理由等。 |

Compound source rowは複数reconciliation rowへ分けます。生成物の`Relationship`は
`split-from`になり、単一rowは`same-as-source`になります。すべてのsource rowに最低一つの
reconciliationが必要です。

Framework mappingは次の5 fieldをpipeで区切り、複数mappingをsemicolonで区切ります。

```text
owasp-asvs|5.0.0|v5.0.0-13.3.1|supports|high
```

Versionはregistryの`mapping_version`と完全一致し、relationshipとconfidenceもcontrol mappingと
同じ語彙を使います。Mappingがまだreviewされていない行は空欄とし、dispositionを
`mapping-review-required`にします。Mapping欄を埋めただけでcomplianceを主張しません。

## 実行方法

Repository外に置いたprivate sourceをimportする例:

```bash
make import-application-checklist \
  APPLICATION_CHECKLIST_MANIFEST=/absolute/path/to/source-manifest.json \
  APPLICATION_CHECKLIST_OUTPUT=/absolute/path/to/generated-profile
```

成功時はexit code `0`で次を生成します。

```text
generated-profile/
├── status.json
├── profile.csv
├── reconciliation.csv
└── application-vulnerability-assessment.xlsx
```

`profile.csv`とExcelの`Application Profile`はpublic atomic rowsだけを含みます。
`reconciliation.csv`はpublic rowsと、内容を出さないorganization-only placeholderを含みます。
Excelはheader freezeとauto-filterを持ちます。実際の回答、判定、証跡URLはこの生成物へ書かず、
access-controlledなassessment copyへ記録します。

Canonical repository generationは次を探します。

```text
inputs/application-vulnerability-assessment/source-manifest.json
```

未提供の現在は`make generate`が成功しつつ`INPUT_REQUIRED`を残します。これはimport完了ではなく、
必要入力が明示されている状態です。

## Synthetic verification

[`tests/fixtures/application-checklist-import/secure`](../tests/fixtures/application-checklist-import/secure)
は公開可能な架空sourceです。次を検証します。

- CSVとXLSXが同じ3 public atomic rowsを生成する;
- Compound rowがone-to-manyでtraceableにsplitされる;
- Exact OWASP ASVS mappingが行単位で残る;
- Organization-only wordingがJSON、CSV、XLSXへ出ない;
- 二回生成したCSV／XLSX／statusがbyte-for-byte一致する;
- Duplicate ID、unknown column、source version欠落、formula、malformed XLSX、mapping version
  mismatch、reconciliation欠落が`ERROR`になる。

Synthetic fixtureの成功は、組織sourceの取込、診断内容の妥当性、PSB-CODE control実装、ASVS
coverage、またはアプリケーションの安全性を証明しません。
