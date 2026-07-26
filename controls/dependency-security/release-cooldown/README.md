# PSB-DEPS-001: 依存パッケージのrelease cooldown

## セキュリティ上の問題

公開直後の依存パッケージを自動的に採用すると、maintainer accountの侵害、
悪意あるrelease、package takeoverなどが発生した直後の、検知や削除がまだ
追いついていないversionを開発端末やbuild環境で実行する可能性があります。

release cooldownは、公開から一定時間が経過していないversionを通常のdependency
updateから除外し、registry、利用者、security communityによる検知のための
観測時間を確保します。

このreference policyでは、通常の最小待機時間を7日（168時間）とします。
7日は標準が保証する安全値ではなく、このcontrolの運用baselineです。

## 適用範囲

cooldownは開発端末だけの設定にはしません。repository-owned policyと同じ検証器を
次の場所で共有します。

- 開発端末で新しいdependency versionをresolveまたはupdateするとき
- pull requestでmanifestやlockfileが変更されたとき
- CIでdependency updateを検証するとき
- buildでlockfile外のversionが新しくresolveされていないことを確認するとき

既にレビューされ、integrityが固定されたlockfileからの再現installでは、
毎回新しいversionをresolveしません。通常installはfrozen／locked modeを使い、
cooldown判定はdependency update時とlockfile review時に行います。

Git hooksは、manifest／lockfile変更時に検証コマンドの実行を促す補助には使えますが、
package managerによるresolveそのものの強制境界にはしません。

## 脅威と失敗シナリオ

主な失敗シナリオは`DEPENDENCY-NEW-RELEASE-COMPROMISE`です。

1. 攻撃者がpackage maintainerまたはregistry accountを侵害する
2. 悪意あるversionを公開する
3. 開発端末や自動updateが公開直後のversionをresolveする
4. install script、build plugin、compiler pluginなどが開発者権限やCI権限で実行される

cooldownは公開直後の自動採用を遅らせますが、悪意あるversionそのものを安全化する
ものではありません。

## 実装例

### 安全な例

`secure/`には次を含みます。

- `cooldown-policy.json`
  - 最小168時間
  - HTTPS registry allowlist
  - artifact integrity必須
  - 最大72時間の時限例外
- `lockfile.json`
  - exact package version
  - exact registry
  - `sha256` integrity
  - ローカルartifact fixture
- `registry-metadata.json`
  - versionごとの公開日時とintegrity
- `artifacts/`
  - checksum検証用のsynthetic artifact

安全なfixtureには、公開から7日以上経過した通常dependencyと、緊急security fixを
想定した、owner・理由・承認者・開始時刻・失効時刻付きのexact version例外が
含まれます。

### 安全でない例

`insecure/`は次の問題を明示します。

- cooldownが0時間
- allowlist外registry
- integrity欠落
- 公開から24時間しか経過していないversion

fixtureで使用するpackage名、registry、artifactはすべてsyntheticです。

## 検証方法

```bash
make verify-control CONTROL=PSB-DEPS-001
```

直接実行する場合は、評価時刻を明示します。

```bash
python3 controls/dependency-security/release-cooldown/scripts/verify.py \
  --policy controls/dependency-security/release-cooldown/secure/cooldown-policy.json \
  --lockfile controls/dependency-security/release-cooldown/secure/lockfile.json \
  --metadata controls/dependency-security/release-cooldown/secure/registry-metadata.json \
  --as-of 2026-07-27T00:00:00Z
```

終了コードは次のとおりです。

| 終了コード | 意味 |
| --- | --- |
| `0` | cooldown、registry、integrity、例外policyを満たす |
| `1` | policy違反を検出 |
| `2` | metadata欠落、JSON破損、artifact読取失敗などで検証不能 |

registry metadataの取得やscanner実行に失敗した場合は、cleanな結果として扱いません。

## 例外

緊急security updateまで7日待つことで、既知脆弱性への露出が長引く場合があります。
そのため例外は許可しますが、次をすべて必須とします。

- exact package名
- exact version
- owner
- 具体的なjustification
- approver
- `created_at`
- `expires_at`
- policyで定めた最大期間以内

wildcard、package全体、期限なし、未使用の例外は許可しません。例外はcooldownだけを
迂回し、registry allowlistやartifact integrity検証は迂回しません。

## 開発端末での推奨運用

1. 通常installはcommitted lockfileのfrozen／locked modeを使用する
2. dependency updateはrepository-owned commandまたはreviewed automationに限定する
3. update時にregistry metadata snapshotとartifact integrityを検証する
4. manifestとlockfileを同じreview単位にする
5. install scriptやbuild pluginが実行される前に検証を完了する
6. package manager cacheをcooldownの迂回手段として扱わない
7. endpoint側のnetwork、credential、sandbox policyも独立して適用する

`PSB-SOURCE-001`のdeveloper endpoint hardeningは、dependency resolveをこのcontrolへ
委譲します。cooldownのロジックをendpoint policyやGit hookへ重複実装しません。

## 制限事項

cooldownでは次を防止できません。

- 待機期間を過ぎたmalicious package
- 長期間潜伏するbackdoor
- typosquattingやdependency confusionそのもの
- compromised lockfileまたはregistry metadata
- 既に採用済みversionで後から判明した脆弱性
- internal registryやpackage manager clientの侵害

このreference verifierは、与えられたmetadata snapshotを検査しますが、そのmetadataが
本物のregistryから取得されたことや署名済みであることは証明しません。production
integrationでは、許可したregistryからHTTPSで取得し、取得失敗をblockし、可能なら
署名・provenance・透明性情報を検証する必要があります。

cooldownはlockfile、hash／integrity、dependency review、SCA、registry制限、
install script制御と組み合わせる必要があります。
