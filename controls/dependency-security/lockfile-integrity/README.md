# PSB-DEPS-003: lockfileと取得artifactの完全性を強制する

## Goal

CIとbuildでlockfile外のdependency解決および暗黙のlockfile書換えを禁止し、
manifest、lockfile、registry、exact version、artifact integrityの一致を検証します。

## 脅威と失敗シナリオ

`DEPENDENCY-LOCKFILE-INTEGRITY-BYPASS`では、攻撃者または誤設定がlockfileを
書き換える、未承認registryへ向ける、version rangeを残す、またはartifactを差し替える
ことで、reviewされたdependency graphと実際のbuild inputを乖離させます。

## 実装

このreferenceはpackage-manager非依存の正規化fixtureを使います。

- `manifest.json`: direct dependencyのexact version
- `lockfile.json`: frozen flag、manifest SHA-256、registry、artifact SHA-256
- `policy.json`: HTTPS registry allowlist、許可hash algorithm、frozen必須
- `artifacts/`: network downloadを行わないsynthetic package artifact

実環境では同じ不変条件を次へ変換します。

| Ecosystem | Locked install |
| --- | --- |
| npm | `npm ci` |
| pnpm | `pnpm install --frozen-lockfile` |
| Bun | `bun install --frozen-lockfile` |
| Python | lock toolのfrozen syncと`pip --require-hashes` |

検証器は、manifestとlockfileのdependency集合が完全一致し、versionがexactであり、
registryがcredentialなしHTTPS originのallowlistに入り、実artifactのSHA-256が
lockfileと一致することを確認します。

## 検証

```bash
make verify-control CONTROL=PSB-DEPS-003
```

終了コードは`0=適合`、`1=policy違反`、`2=入力欠落・parse不能・読取失敗`です。

negative testは、非frozen install、manifest hash不一致、version range、未承認registry、
integrity欠落、artifact改ざん、JSON破損を検証します。

## 運用上の注意

- manifestとlockfileは同一PRでreviewする
- dependency update以外のCIではlockfile生成を禁止する
- cache hitでもartifact integrity検証を省略しない
- URL/VCS/local path dependencyは、commitとartifact hashを固定する別profileが必要
- scannerまたはlockfile parserの失敗をcleanと扱わない

## 制限事項

- 正しいhashはartifactが安全であることを証明しない
- compromised registryが配布前から悪性artifactを提供した場合は検出できない
- transitive graphの意味的妥当性、license、既知脆弱性は別controlが必要
- 実package manager固有lockfile parserへのintegrationが必要
