# Artifact Model

## なぜ分けるのか

Control、教材、Architecture、製品固有設定、test、組織証跡は、更新理由も読者も異なります。
一つのpackageへ集約すると、抽象的な保証が製品versionに引きずられ、実装手順が説明文へ埋もれます。

## Artifactの役割

| Artifact | 答える問い | 主な読者 | 必須内容 | 持たせないもの |
|---|---|---|---|---|
| Control Record | 何を満たすべきか | Product Security、Architect | 問い、直接fail、適用範囲、Security Property、境界 | 製品固有のcopy手順、fixture test |
| Learning Note | なぜそう考えるか | 学習者、Reviewer | Scenario、用語、abuse path、誤解、calibration | 適合判定、production evidence |
| Engineering Pattern | どう設計するか | Developer、Architect、Platform | trust boundary、推奨構造、選択肢、trade-off | 一つのframework要件への従属 |
| Implementation | 特定技術でどう実現するか | Developer、Operator | 対象version、設定・code、確認、制限 | Control全体の保証主張 |
| Insight | 他分野でも使える見方は何か | 全読者 | Mental Model、具体例、適用方法、限界 | 単一Controlの要約 |
| Assessment | 導入済みと何で判断するか | Assessor、Control owner | scope、current observation、判定状態 | Sampleの成功によるadoption推論 |
| Mapping | Artifact間にどんな関係があるか | Product Security、Governance | endpoints、relationship、rationale、review state | endpoint自体の定義 |
| Source Record | 何を根拠に判断したか | Author、Reviewer | role、publisher、version、採否、利用箇所、限界 | Control requirement、compliance claim |

## 関係

```text
Threat / failure / assurance source
                 |
                 v
           Control Record
                 |
        optional explanation
                 v
            Learning Note

System / incident / recurring design problem
                 |
                 v
        Engineering Pattern
                 |
          platform choice
                 v
          Implementation

Control Record <---- reviewed Mapping ----> Engineering Pattern
       |
       +---- Assessment observes adoption

Learning and implementation work
       |
       +---- reusable synthesis ----> Insight

Source Record ---- informs ----> Control / Learning / Pattern / Implementation
       |
       +---- versioned basis ----> Mapping
```

## Controlのminimum contract

Control READMEは次だけを必須とします。

1. `問い`。
2. `できてはいけないこと`。
3. `適用範囲`と`非適用`。
4. 必要なSecurity Property。
5. 実装判断の羅針盤。
6. Controlが直接保証しない範囲。
7. 関連するLearning、Pattern、Sourceへのlink。

「最短導入」「secure／insecure」「expected output」「evidence table」「rollback」は必須にしません。
必要なら、それぞれImplementationまたはAssessmentへ置きます。

## 独立性

- LearningがなくてもControlは成立する。
- 対応Implementationがなくても、有用なassurance objectiveならControlは成立する。
- Control mappingがなくてもEngineering Patternは成立する。
- Testがなくても、実装不能な抽象資料ではなく、具体的な判断を可能にするGuidanceなら価値がある。
- Mappingやfixtureがなくてもgapを隠さない。
