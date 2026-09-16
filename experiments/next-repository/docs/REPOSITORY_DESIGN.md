# Repository Design

## 二つの独立したView

### Controls view

`controls/`は「何を満たすべきか」を扱います。Controlはtoolや一つの実装方式に依存せず、
Security outcomeを診断する軸です。

### Engineering view

`engineering/`は「どのように失敗し、どう設計すべきか」を扱います。Patternはframework inventoryから
機械的に作らず、system、incident、trust boundary、繰り返す設計問題から発見します。

### Derived mappings

MappingはControlとPatternを独立に理解した後で作ります。Mappingの存在をArtifact maturityや
組織導入の条件にしません。

## Domainの選び方

Directoryは、外部frameworkの章構造やtool名ではなく、読者が問題を探す場所に合わせます。
Cross-cuttingな関係はcopyせず、linkとmappingで表現します。

Pilotでは現行domain名を継承しますが、最終taxonomyとして確定はしません。

## Control Recordの長さ

行数を機械的に制限しませんが、一度の読書で境界と実装判断をつかめることを目標にします。
具体Scenarioの詳細、Q&A、製品別screen名、command、test matrixが必要になった時点で別Artifactへ分けます。

## Engineering Patternの構成

Patternは必要な範囲で次を含みます。

```text
Use case
  -> scope and assumptions
  -> assets and trust boundaries
  -> threat / abuse path
  -> security invariants
  -> recommended architecture and control placement
  -> implementation options and trade-offs
  -> what to observe
  -> residual risk
```

製品固有の値やcommandは`implementations/<platform>/`へ置きます。

## Generated content

人が読む本文を大量生成しません。生成対象は索引、reverse mapping、link checkなど、正本を複製せず
探索性または整合性を改善するものに限定します。生成物が正本にならないよう明示します。
