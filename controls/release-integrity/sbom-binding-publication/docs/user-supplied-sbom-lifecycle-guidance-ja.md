# User-supplied SBOM lifecycle guidance

## Provenance

- Source: user-supplied collaboration text
- Received: 2026-07-31
- Bibliographic sources: not supplied with the text
- Treatment: design input, not a framework mapping or compliance source

## Original guidance (formatting normalized)

SBOM（ソフトウェア部品表）を取得・生成する最適なタイミングは、単一のフェーズに
依存するのではなく、「成果物が生成または変化するすべてのフェーズ」で取得し、
それらを一元管理基盤で紐付けることが最も効果的です。

### 1. SBOM取得の3つの主要なタイミング

#### 開発フェーズ（Source SBOM）

- タイミング: `git push`やプルリクエスト（PR）の作成時
- 対象: `package-lock.json`、`go.mod`、`requirements.txt`などの依存関係定義
  ファイル
- 効果: 開発者が意図して導入したライブラリを特定し、コードベースに「いつ」
  脆弱性が混入したかを追跡できる

#### ビルド・パッケージングフェーズ（Build SBOM） ※最も重要

- タイミング: コンテナイメージのビルド直後（`docker build`後）
- 対象: OSパッケージ、インストールされたバイナリ、ランタイム環境に含まれる
  コンポーネント
- 効果: ビルドプロセスは、ソースコード、依存関係、成果物が交差する唯一の
  タイミングであり、最も正確なSBOMを生成できる。OSレベルの脆弱性や、
  ビルド時にのみ混入するリスクを把握するために不可欠

#### デプロイ・運用フェーズ（Runtime SBOM）

- タイミング: Kubernetes等の実行環境へデプロイされた時、および稼働中
- 対象: 実際にメモリ上で動作しているコンポーネント
- 効果: 「どのリポジトリから来たイメージが、どの環境で動いているか」という
  実態を把握し、Log4jのようなゼロデイ脆弱性発生時に、影響を受ける稼働資産を
  即座に特定できる

### 2. 一元管理における運用

- CycloneDXまたはSPDXなどの標準formatを採用する
- SBOMをGit commit SHAへ紐付ける
- project／service、component、vulnerabilityの関係をgraphとして管理し、
  componentから影響serviceを逆引きする

### 3. Stakeholder別の取得・活用

- third-party productの調達時にsupplierへ署名付きSBOMを要求し、管理台帳へ取り込む
- platform teamが共通base image等のSBOMを生成・署名し、service teamが検証して
  利用するGolden Pathを提供する

結論として、一元管理を成功させるには、ビルドフェーズでの自動生成を核としつつ、
開発から運用までの各ポイントでSBOMを「積み上げ」、それらをリポジトリやイメージの
メタデータとして一元管理基盤に集約し続けるプロセスを構築することが最も効果的です。

## Repository interpretation

このrepositoryでは、source、build、deploymentの各観測を同じSBOMで上書きしません。
Source SBOMは早期feedback、Build SBOMはexact release artifactに対するauthoritative
inventory、deployment／operations inventoryは実際のartifact配置と追加観測を示す
別documentとして扱います。実行中memoryの完全性は自動的に仮定しません。

Supplier署名付きSBOMの受入れは、署名者identity、対象product／version／digest、
失効、timestamp、schema、quarantineを検証する独立したcontrolが必要です。現在の
`PSB-REL-003` fixtureの成功をsupplier署名検証済みとは扱いません。
