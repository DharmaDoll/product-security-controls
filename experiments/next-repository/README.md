# Product Security Engineering Field Guide — virtual repository

このdirectoryは、次期リポジトリの情報設計を実物で評価するための仮想ルートです。
独立したGit repositoryではなく、現行リポジトリの生成処理やcontrol catalogからも参照されません。

## Mission

Product Security担当者と開発者が、実装またはレビューしようとしている分野について、
次の判断をできる知識基盤を作ります。

- 何を守るべきか、何が起きてはいけないか。
- どのSecurity Propertyを、どの境界で強制すべきか。
- 複数の実装方式から、自分の環境に合うものをどう選ぶか。
- ある対策が保証する範囲と、保証しない範囲はどこか。
- さらに深く学ぶ場合、どの一次資料、Learning、Insightを読むべきか。

コードや設定例の数ではなく、設計と実装の判断を誤らないための「羅針盤」を主成果とします。

## 入口を二つに分ける

### Product Security担当者

1. [Control catalog](controls/README.md)から、満たすべきSecurity outcomeを選ぶ。
2. Control recordで適用範囲、Security Property、境界を確認する。
3. 必要なら[Learning guide](docs/learning/README.md)と
   [Cross-cutting insights](docs/insights/README.md)で理解を深める。
4. 実装方針は対応するEngineering Patternで検討する。
5. 判断根拠のversionと採否は[Sources and Specifications](sources/README.md)で確認する。

### 開発者・Platform担当者

1. [Engineering](engineering/README.md)から、解こうとしている設計問題を選ぶ。
2. Patternで推奨Architecture、選択肢、trade-offを確認する。
3. 利用技術に対応するImplementationがあれば、そこだけを採用・検証する。

ControlとEngineering Patternは別々に成立します。両者の関係は
[Mappings](mappings/README.md)で後から評価します。

## Artifact structure

```text
.
├── README.md
├── AGENTS.md
├── PRINCIPLES.md
├── controls/       # 何を満たすべきか
├── engineering/    # どう安全に設計・実装するか
├── docs/
│   ├── learning/   # 一つのテーマを具体的に理解する
│   └── insights/   # 複数領域へ持ち運べる洞察
├── assessments/    # 組織導入をどう判定するか
├── mappings/       # 独立したArtifact間の関係
└── sources/        # 仕様、一次資料、guidance、採否とversion
```

役割の詳細は[Artifact Model](docs/ARTIFACT_MODEL.md)、設計判断は
[Repository Design](docs/REPOSITORY_DESIGN.md)を参照してください。

## Pilot scope

現在は次の二つだけを再構成しています。

| Domain | Control | Pilotで確認すること |
|---|---|---|
| Source Protection | [PSB-SOURCE-004](controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/README.md) | Guidance中心のcontrolからLearning、Pattern、GitHub固有手順を分離できるか |
| Dependency Security | [PSB-DEPS-001](controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/README.md) | 抽象的なcooldownの保証とnpm固有実装を分離できるか |

旧Artifactとの関係と、意図的に移植しなかったものは
[Migration Ledger](docs/MIGRATION.md)に記録します。
Pilotが参照する仕様とguidanceは
[Sources and Specifications](sources/README.md)へ移行し、exact versionを
[Framework mappings](mappings/frameworks.yaml)から追跡できます。

## このPilotで行わないこと

- 現行control catalog、schema、generatorの変更。
- 52 controlsの一括変換。
- fixtureの成功を組織導入の証拠とすること。
- 空のLearning、Implementation、Assessmentを数合わせで作ること。
- 新しいframework準拠または完全なrisk coverageの主張。参照仕様と既存mappingは省略せず、
  version付きで保持した上で移行review中として扱う。
