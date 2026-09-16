# Principles

## 1. 読者の判断を成果にする

このリポジトリの成果はファイル数や自動テスト数ではありません。読者が、保護対象、脅威、
必要なSecurity Property、実装の選択肢、残るriskを説明し、自分の環境で次の行動を選べることです。

## 2. Security outcomeをtoolより先に置く

GitHub、npm、Trivy、Falco等は実装または観測手段です。Control名や上位taxonomyをtool名に従属させません。

## 3. ControlとImplementationを分ける

Controlは「何を満たすべきか」を定義します。Implementationは特定のplatform、言語、製品で
「どう実現するか」を示します。一つのControlに複数Implementationが対応してよく、
一つのEngineering Patternが複数Controlを支援しても構いません。

## 4. Security効果はEnforcement Pointから生まれる

README、policy sample、fixture、scanner outputが存在するだけではsystemを保護しません。
誰のauthorityが、どのoperationを、どの境界で許可・拒否するかを示します。

## 5. Guidance-firstを正式な成果物として認める

設計、SaaS設定、組織運用、責任分界など、repository内のcodeで実効性を再現できない領域では、
具体的で検証可能なGuidanceが正しい成果物です。形式的なscriptを追加して自動化率を上げません。

## 6. Testは証明できる対象にだけ所属させる

TestはControlの存在ではなく、特定Implementationの性質を検証します。READMEの文字列、
自己申告の`PASS`、架空のproduction evidenceを検査するtestは作りません。

## 7. 不明をcleanへ変換しない

判定不能、取得失敗、部分的な観測、古い情報は、安全な状態ではありません。必要に応じて
`NOT_CHECKED`、`INCOMPLETE`、`ERROR`を区別し、`PASS`へ補完しません。

## 8. 学習過程と横断的洞察を保存する

Learningは一つのControlや設計問題を具体Scenarioから理解するために使います。Insightは複数領域へ
持ち運べるMental Modelを保存します。どちらもNormative requirementや適合証拠の代替ではありません。

## 9. Sourceと解釈を混ぜない

Normative、Research、Primary source、Repository interpretation、Derived insightを区別します。
外部sourceは固定versionまたは確認日を持ち、変更可能な情報は再確認します。
Controlを簡潔にするために、判断根拠となる仕様を削除してはいけません。Source recordへ分離し、
ControlのSecurity Property、Mapping、Implementationからsource IDで追跡できるようにします。

## 10. Mappingは意味を定義しない

Framework、Control、Pattern、Threatのmappingは、独立して理解したArtifact間の関係評価です。
Mappingがあることを、準拠、導入済み、完全な対策の証明にしません。

## 11. Artifactを数合わせで作らない

空のdirectory、placeholder、同じ説明の複製、形式的なsecure／insecure pairを禁止します。
内容がなければArtifactを作らず、gapまたは未着手として見える形で残します。

## 12. 実装可能性と利用可能性を両立する

Guidanceだけで終わらせず、実装時に必要な選択肢、責任者、境界、失敗しやすい点を示します。
一方で、全Controlへ製品固有の最短手順を強制しません。

## 継承するSecurity invariants

- Real secret、credential、personal data、malware、production dataを保存しない。
- Third-party GitHub Actionsはimmutable full commit SHAを使う。
- Downloadするtoolやartifactはversionとintegrityを検証する。
- Untrusted PRへprivileged credentialを渡さない。
- Security exceptionは狭く、owner、理由、期限を持つ。
- Scannerやcollectorの失敗をclean resultにしない。
- Framework mappingからformal complianceを推論しない。
- AI Agent、Skill、MCP、Plugin、外部promptを未確認の依存関係として扱う。
