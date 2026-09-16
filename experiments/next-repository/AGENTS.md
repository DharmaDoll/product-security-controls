# AGENTS.md

## Mission

ここはProduct Security Engineeringの意思決定を支援するKnowledge Baseである。
文章量、実装数、test数を増やすことではなく、読者がSecurity outcomeと実装判断を理解できることを優先する。

作業前に`README.md`、`PRINCIPLES.md`、`docs/ARTIFACT_MODEL.md`、
`docs/CONTENT_QUALITY.md`、`docs/SOURCE_POLICY.md`を読むこと。

## Artifact boundaries

- `controls/`: 何を満たすべきか。製品固有手順やfixtureを正本にしない。
- `engineering/`: 繰り返す設計問題をどう安全に解くか。
- `engineering/**/implementations/`: 製品・platform・言語固有の設定、code、test。
- `docs/learning/`およびcontrol-local `learning.md`: 一つのテーマを具体Scenarioから理解する教材。
- `docs/insights/`: 複数領域へ持ち運べるRepository独自の洞察。
- `assessments/`: 組織導入とcurrent evidenceの判定方法。
- `mappings/`: 独立して成立したArtifact間の関係。
- `sources/`: 参照仕様、一次資料、guidance、user inputのversion、採否、限界。

同じ本文を複数Artifactへ複製しない。別Artifactの詳細が必要なら正本へlinkする。

## Writing rules

1. 最初に読者、問い、守るAsset、threat actorまたはfailure sourceを決める。
2. 攻撃成立条件、越えるtrust boundary、影響を具体的に書く。
3. Security InvariantとEnforcement Pointをplain languageで示す。
4. 一つの具体Scenarioから始め、固有製品に依存しない原則へ抽象化する。
5. `dangerous`、`secure`、`best practice`だけで理由を済ませない。
6. ControlへのPassとsystem全体の安全性を同一視しない。
7. 既存の隣接Artifactと境界が重なる場合、統合せず違いを説明する。
8. 読者が次の判断をできない長文は、Learning、Insight、Pattern、Implementationへ分割する。

## AI-driven writing rules

- Templateの全sectionを機械的に埋めない。
- 空のLearning、Insight、Implementation、Assessmentを作らない。
- 一つのgeneric paragraphを複数Controlへ展開しない。
- Sourceにない具体値、製品挙動、coverage、evidenceを補完しない。
- AI生成内容はRepository interpretationであり、source確認前に事実として扱わない。
- 大量生成より、少数のArtifactをend-to-endで読み直し、役割重複を除く。

## Implementation and verification

- Control recordへtestを置かない。
- Testは対象Implementationが実在し、観測可能なSecurity Propertyがある場合だけ追加する。
- Insecure exampleは比較による学習価値がある場合だけ、隔離して作る。
- SaaS設定や組織運用は、架空のfixtureで`PASS`にせず、具体GuidanceまたはAssessmentへ置く。
- Failure、timeout、missing input、partial collectionをclean resultへ変換しない。
- Secret、private identifier、production dataをtest、log、evidenceへ入れない。

## Sources and mappings

- Primary sourceを優先し、version、revision、確認日を記録する。
- Normative、Research、Repository interpretation、Derived insightを区別する。
- Control本文から詳細を分離しても、参照仕様を省略しない。Source recordを残し、Security Propertyまたは
  Implementationからsource IDで到達できるようにする。
- Mappingは別Artifactとして作り、ControlやPatternの意味をmappingから逆算しない。
- Compliance、complete coverage、organization adoptionを根拠なく主張しない。

## Definition of done

新しいArtifactは、その種類に応じて次を満たす。

- Control: 問い、直接のfail、適用範囲、Security Property、境界が明確。
- Learning: Scenario、用語、abuse path、誤解、判断のcalibrationが単独で理解できる。
- Pattern: Architecture、選択肢、control placement、trade-off、失敗経路が実装判断に使える。
- Implementation: 対象version、変更箇所、前提、確認方法、制限が明確。
- Insight: 複数Artifactへ再利用でき、単一Controlの言い換えではない。
- Mapping: 両endpointが独立して存在し、relationshipとrationaleが説明できる。
- Source: role、publisher、exact versionまたは確認日、利用箇所、採否、限界が説明できる。

数合わせのfileがないこと、local linkが解決すること、旧Artifactとの関係が
`docs/MIGRATION.md`へ記録されていることも確認する。
