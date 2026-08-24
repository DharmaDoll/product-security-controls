# PSB-DEPS-002: install時の任意コード実行をdefault denyにする

## このcontrolを一枚で理解する

### セキュリティ上の問題

Package install時のlifecycle scriptやsource buildは、dependencyを利用する前にdeveloper端末やCIの権限で任意codeを実行できる。

### 誰から、または何から守るか

侵害・偽装されたpackage、悪意あるmaintainer、typosquatting、source distribution fallback、広すぎるまたは期限切れ例外から守る。

### 何が対象か

npm・pnpm・Bun・pip等のdependency install、lifecycle script、build backend、source distribution、repository-owned policy、例外。

### 何をするか

Install-time executionをdefault denyにし、必要なpackage・script・versionだけをowner・理由・期限付きで承認し、hash固定wheel等の非実行経路を優先する。

### 成功状態

未承認scriptとsource buildが実行されず、例外はexactかつ有効期限内で、missing・malformed policyやverifier failureはfail closedとなる。

### 対象外・残余リスク

Install後のimport、test、compiler plugin、application runtimeでの悪性code実行や、承認済みscript自体の安全性は保証しない。

## セキュリティ上の問題

依存パッケージのinstallは、単なるファイル展開とは限りません。Node.js系の
`preinstall`、`install`、`postinstall`や、Python source distributionのbuild backendは、
開発者端末またはCI runnerの権限でコードを実行できます。侵害されたpackage、
typosquatting、dependency confusionなどを取得した場合、installしただけでcredentialや
source codeの窃取、外部通信、build outputの改ざんにつながります。

このcontrolは、依存packageのinstall-time code executionをdefault denyにし、必要な
例外だけをexact package version、owner、別のapprover、理由、期限で管理します。

## 対象と前提

- 対象domain: `dependency-security`
- control ID: `PSB-DEPS-002`
- 対象: 開発端末、pull request CI、build環境
- fixtureはsyntheticであり、packageのdownloadやscript実行は行わない
- package managerとlockfileは別途immutable versionに固定する
- repository-owned設定を使い、global user設定には依存しない

## 脅威と失敗シナリオ

主な失敗シナリオは`DEPENDENCY-INSTALL-SCRIPT-EXECUTION`です。

1. 攻撃者がdependencyまたはそのpublish accountを侵害する
2. lifecycle scriptやsource build backendにpayloadを追加する
3. 開発者またはCIが通常のinstall commandを実行する
4. install処理がcredentialを持つprocessとしてpayloadを実行する

失敗しやすい運用は、warningだけで継続する、package名だけを無期限に許可する、
`--trust-all`相当を使う、wheelがない場合に自動でsdistへfallbackすることです。

## 安全な実装

`secure/`は4つのprofileを検証します。

| Ecosystem | Repository-owned enforcement |
| --- | --- |
| npm | `.npmrc`の`ignore-scripts=true`で全dependency lifecycle scriptを停止 |
| pnpm 11 | `strictDepBuilds: true`、`dangerouslyAllowAllBuilds: false`、exact versionの`allowBuilds` |
| Bun | `bunfig.toml`の`install.ignoreScripts=true`でprojectとdependencyのscriptを停止 |
| pip | `--only-binary=:all:`、`--require-hashes`、exact pin、SHA-256 hash |

pnpmの`native-fixture@1.2.3`は、native buildが不可欠なdependencyを想定したsynthetic
例です。`install-execution-policy.json`の時限承認と一致する場合だけ許可されます。
拒否entryは明示できますが、許可entry以外はdefault denyです。
承認期間のreference上限は30日（720時間）です。安全性を保証する期間ではなく、
承認の棚卸しを強制する運用baselineであり、version変更時は期間内でも再reviewします。

npmやBunでscriptが本当に必要な場合は、全停止を弱める前に次を行います。

1. lifecycle scriptと配布artifactをsemantic reviewする
2. exact resolved versionとintegrityを固定する
3. credentialと外向きnetworkを持たない隔離build jobで実行する
4. outputだけを後段へ渡し、通常の開発shellやdeploy jobでは実行しない
5. owner・別承認者・理由・期限付きの例外としてreviewする

package manager固有allowlistを採用する場合も、name-only、range、wildcard、一括承認を
禁止し、同じ例外台帳との照合を追加してください。

## 安全でない実装

`insecure/`は次を含みます。

- npm lifecycle scriptを有効化
- pnpmのfail-open設定とversion rangeによる許可
- Bunのscript実行許可
- pipのsdist fallback、未固定version、hashなし
- ownerとapproverが同一で期限切れの例外

実際の悪性scriptや実在packageは含みません。

## 検証方法

```bash
make verify-control CONTROL=PSB-DEPS-002
```

直接実行する場合:

```bash
python3 controls/dependency-security/install-script-execution/scripts/verify.py \
  --policy controls/dependency-security/install-script-execution/secure/install-execution-policy.json \
  --profile-dir controls/dependency-security/install-script-execution/secure \
  --as-of 2026-07-27T00:00:00Z
```

| 終了コード | 意味 |
| --- | --- |
| `0` | 4 profileと例外台帳がbaselineを満たす |
| `1` | script許可、sdist fallback、broad／expired例外などのpolicy違反 |
| `2` | 設定欠落、JSON／TOML破損、読取失敗などで検証不能 |

検証器や設定parseの失敗をcleanな結果として扱いません。

## 開発端末での推奨運用

- global設定を自動変更せず、repository-owned設定をcommitする
- package managerのversionを固定し、lockfileのfrozen modeを使う
- dependency update PRでこのcontrolと`PSB-DEPS-001`を実行する
- install processへcloud credential、npm publish token、SSH agentを渡さない
- install中の外向き通信をregistryなど必要最小限に制限し、telemetryを残す
- 許可したbuild scriptはversion更新ごとに再reviewする
- Git hookは補助とし、CI／build側でも同じpolicyを強制する

## 制限事項と残余risk

- wheelにも悪性のruntime codeは含められるため、wheel-onlyはpackageを安全にしない
- lifecycle scriptを止めても、import、test、compiler plugin、application起動時の実行は残る
- npmやBunの全停止ではnative moduleなどが動かず、隔離buildまたは例外設計が必要になる
- pnpm 10と11では設定名が異なる。このreferenceはpnpm 11の`allowBuilds`を対象にする
- package manager自体、registry、lockfile、binary artifactの侵害は別controlが必要である
- build isolation、network egress、provenance、signature、SBOM、SCAを併用する必要がある

## 参照した公式仕様

- [npm CLI 11.18.0: npm-install-scripts](https://docs.npmjs.com/cli/v11/commands/npm-install-scripts/):
  install script approvalとversion pin
- [pnpm 11.x settings](https://pnpm.io/settings):
  `strictDepBuilds`、`allowBuilds`、`dangerouslyAllowAllBuilds`
- [Bun lifecycle scripts](https://bun.com/docs/guides/install/trusted)と
  [bunfig.toml](https://bun.com/docs/runtime/bunfig):
  `trustedDependencies`、`install.ignoreScripts`
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)と
  [requirements file format](https://pip.pypa.io/en/stable/reference/requirements-file-format/):
  wheel-only、hash checking mode

仕様は更新されるため、package manager major version更新時に設定名とdefaultを
再確認してください。
