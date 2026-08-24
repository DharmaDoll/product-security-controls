# PSB-DEPS-003: lockfileと取得artifactの完全性を強制する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Manifest、lockfile、registry、取得artifactが一致しなければ、review済みdependency graphと実build inputが異なるものへ差し替わる。

### 誰から、または何から守るか

Lockfile改変、未承認registry、version range、cacheまたはartifact差替え、暗黙lockfile更新、proxy fallbackから守る。

### 何が対象か

Dependency manifest、lockfile、exact version、managed registry origin、download artifact hash、package-manager frozen install、検証器。

### 何をするか

Manifestとfrozen lockfileの集合・version・originを照合し、実artifact SHA-256をlock recordへ検証して、CI中の再解決・書換え・public fallbackを拒否する。

### 成功状態

Dependency名とexact versionが完全一致し、managed proxy由来のartifact hashがlockfileと一致し、missing・tampered・parse不能な入力は停止する。

### 対象外・残余リスク

正しいhashはpackageが安全・脆弱性なしであることを証明せず、意味的なdependency妥当性、license、既知脆弱性は別controlが必要である。

## Goal

CIとbuildでlockfile外のdependency解決および暗黙のlockfile書換えを禁止し、
manifest、lockfile、registry、exact version、artifact integrityの一致を検証します。

## 脅威と失敗シナリオ

`DEPENDENCY-LOCKFILE-INTEGRITY-BYPASS`では、攻撃者または誤設定がlockfileを
書き換える、未承認registryへ向ける、version rangeを残す、またはartifactを差し替える
ことで、reviewされたdependency graphと実際のbuild inputを乖離させます。
public registryへのdirect fallbackも、`PSB-DEPS-001`で定めたmanaged proxyの検査と
取得履歴を迂回するため拒否します。

## 実装

このreferenceはpackage-manager非依存の正規化fixtureを使います。

- `manifest.json`: direct dependencyのexact version
- `lockfile.json`: frozen flag、manifest SHA-256、registry、artifact SHA-256
- `policy.json`: managed HTTPS proxy、direct fallback拒否、proxy障害時`ERROR`、
  runtime credential injection、許可hash algorithm、frozen必須
- `artifacts/`: network downloadを行わないsynthetic package artifact

実環境では同じ不変条件を次へ変換します。

| Ecosystem | Locked install |
| --- | --- |
| npm | `npm ci` |
| pnpm | `pnpm install --frozen-lockfile` |
| Bun | `bun install --frozen-lockfile` |
| Python | lock toolのfrozen syncと`pip --require-hashes` |

検証器は、manifestとlockfileのdependency集合が完全一致し、versionがexactであり、
registryがcredentialなしHTTPS managed proxyのallowlistに入り、実artifactのSHA-256が
lockfileと一致することを確認します。lockfileのorigin固定はclientのnetwork強制を
代替しないため、`PSB-DEPS-001`のMDM／CI profileとegress denyも適用します。

## 検証

```bash
make verify-control CONTROL=PSB-DEPS-003
```

終了コードは`0=適合`、`1=policy違反`、`2=入力欠落・parse不能・読取失敗`です。

negative testは、非frozen install、manifest hash不一致、version range、未承認registry、
direct fallback、clean-on-outage、embedded credential、integrity欠落、artifact改ざん、
JSON破損を検証します。

## 運用上の注意

- manifestとlockfileは同一PRでreviewする
- dependency update以外のCIではlockfile生成を禁止する
- cache hitでもartifact integrity検証を省略しない
- URL/VCS/local path dependencyは、commitとartifact hashを固定する別profileが必要
- scannerまたはlockfile parserの失敗をcleanと扱わない
- proxy障害時にpublic registryへfallbackせず、`ERROR`として止める

## 制限事項

- 正しいhashはartifactが安全であることを証明しない
- compromised registryが配布前から悪性artifactを提供した場合は検出できない
- transitive graphの意味的妥当性、license、既知脆弱性は別controlが必要
- 実package manager固有lockfile parserへのintegrationが必要
