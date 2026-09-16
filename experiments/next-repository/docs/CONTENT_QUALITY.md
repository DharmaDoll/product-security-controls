# Content Quality

## 有用な文書の判定

Artifactを追加する前に、対象読者が読み終えた後で何を判断できるようになるかを一文で説明します。
説明できなければ作成しません。

## Control Record

- 一つのSecurity outcomeに焦点を当てる。
- Threat actorまたはfailure source、attack path、impacted assetを具体化する。
- Pass候補、直接fail、証拠不足、隣接Controlのfailを混同しない。
- 製品固有例をControlの唯一の実現方法にしない。
- 「導入する」「適切に設定する」だけで終わらせず、守るPropertyを示す。

## Learning Note

- 一つの具体Scenarioを最後まで追ってから抽象化する。
- 用語をScenario内のActor、Data、Actionへ結び付ける。
- よくある直感的な誤りと、なぜ誤りかを残す。
- Rawな会話log、挨拶、機械的な言い直しを保存しない。
- Control本文の複製にしない。

## Engineering Pattern

- Architectureの選択肢とtrade-offを示す。
- どの境界でSecurity decisionを強制するかを示す。
- Threatとmitigationを別catalogへ分断しない。
- 一製品の画面操作だけで一般Patternを定義しない。
- Control mappingからPatternを逆生成しない。

## Implementation

- 対象platformとsupported versionを明示する。
- 変更するfile、setting、serviceと、実効性が生まれる場所を示す。
- Testは実際に観測できるPropertyだけを検査する。
- Sampleをproduction adoption evidenceと表現しない。
- Unsupportedなplatformを埋め草として列挙しない。

## 禁止するFiller

- README文字列だけを確認するtest。
- `secure: true`を受理するだけのverifier。
- 同一paragraphのControl間copy。
- Sourceの単なる要約をInsightと呼ぶこと。
- 空の`secure/`、`insecure/`、`tests/`、`expected-results/`。
- 「TBD」を隠すための一般論。

## Review questions

1. 最初の画面で「何を問うArtifactか」が分かるか。
2. Security効果が生まれるEnforcement Pointを特定できるか。
3. 読者が実装方式を選ぶ材料があるか。
4. 別Artifactと重複していないか。
5. Sourceの事実とRepositoryの解釈が区別されているか。
6. 自動化できないことを、形式的な自動化で隠していないか。
