# PSB-DEPS-003: native lockfileと取得artifactの完全性を強制する

## このcontrolを一枚で理解する

### セキュリティ上の問題

通常installがmanifestから依存関係を再解決したりlockfileを書き換えたりすると、reviewしたgraphとbuildへ入るgraphが一致しない。さらに、名前とversionが同じでも取得bytesがlockfileのintegrityと異なれば、cacheや配布artifactの差替えを見逃す。

### 誰から、または何から守るか

未reviewのmanifest変更、package managerの暗黙再解決、registry・cache・mirror上のartifact差替え、欠落または壊れたlockfileを成功扱いするCIから守る。

### 何が対象か

JavaScriptの`package.json`とnative lockfile、Pythonの`pyproject.toml`／完全hash付き`requirements.lock`とnative lockfile、lockfileが記録するdirect・transitive dependencyおよび取得artifactである。

### 何をするか

native package managerのimmutable installを使い、manifestとlockfileの鮮度、direct／transitive graph、取得artifactのintegrityを検証する。npmは追加preflightで全外部artifact recordの強いSRIも確認し、pipは全requirementのhashとwheel-onlyを強制する。

### 成功状態

review済みlockfileが変更されずにinstallでき、manifest drift、hash欠落、別bytes、lockfile欠落、runtime欠落が非zeroで停止する。検証不能はclean resultではなく`ERROR`になる。

### 対象外・残余リスク

Lockfileは推移的依存を安全に選ぶものではない。resolverが選んだ推移的graphとartifact identityを記録するだけであり、malicious package、既知脆弱性、install script、公開直後の危険、review済みlockfile自体の悪意、registry originやnetwork egressは別controlが必要である。

## 最短の導入手順

### 前提とtrust assumption

- macOSまたはLinux、Bash、対象ecosystemのnative runtimeを使う。
- package manager自体を信頼済み経路から導入する。pnpmとuvはこのcontrolに記録したversionへ固定する。
- manifestとlockfileを同じPRでreviewし、通常CIではlockfileを生成しない。
- dependency installが必要とするnetworkとregistry authenticationは採用側が設定する。このcontrolはregistry allowlistやegress制御を代替しない。

### JavaScript: npm

次のdirectoryをrepositoryへコピーする。

- [`secure/javascript/npm/install-locked.sh`](secure/javascript/npm/install-locked.sh)
- [`secure/javascript/npm/verify-package-lock.mjs`](secure/javascript/npm/verify-package-lock.mjs)

Activationと通常CIのinstallは同じ一行でよい。

```bash
bash path/to/npm/install-locked.sh .
```

このwrapperは`package-lock.json` v2／v3の全外部artifact recordにSHA-256／384／512 SRIがあることをpreflightし、`npm ci --package-lock=true --ignore-scripts --no-audit --no-fund`を実行する。成功時はexit `0`、policy違反は`1`、入力またはruntime不備は`2`である。

### JavaScript: pnpm

次のdirectoryをrepositoryへコピーする。

- [`secure/javascript/pnpm/install-locked.sh`](secure/javascript/pnpm/install-locked.sh)
- [`secure/javascript/pnpm/PNPM_VERSION`](secure/javascript/pnpm/PNPM_VERSION)
- [`secure/javascript/pnpm/RUNTIME.md`](secure/javascript/pnpm/RUNTIME.md)

承認済みのpnpm `11.25.0` binaryを明示して実行する。

```bash
PSB_PNPM=/approved/path/to/pnpm \
  bash path/to/pnpm/install-locked.sh .
```

Offline cacheを準備済みなら、`PSB_PNPM_OFFLINE=1`とrepository-localな`PSB_PNPM_STORE_DIR`も指定できる。wrapperはversion一致を検査し、`install --frozen-lockfile --ignore-scripts`を実行する。

### Python: pip

[`secure/python/pip/install-locked.sh`](secure/python/pip/install-locked.sh)をコピーし、全direct／transitive requirementを`==`と`--hash=sha256:...`で固定した`requirements.lock`を用意する。

```bash
python3 -m venv .venv
PSB_PYTHON="$PWD/.venv/bin/python" \
  bash path/to/pip/install-locked.sh .
```

wrapperは専用virtual environmentを必須とし、`pip install --require-hashes --only-binary=:all:`と`pip check`を実行する。Source distributionを許可するprojectは、build isolation・build dependency・provenanceを別途設計し、wheel-only flagを黙って外さない。

### Python: uv project

[`secure/python/uv/`](secure/python/uv/)をコピーする。標準profileはmanifest freshnessを検査する`--locked`を使う。Runtimeの取得元、SHA-256、attestation手順は[`RUNTIME.md`](secure/python/uv/RUNTIME.md)に固定する。

```bash
PSB_UV=/approved/path/to/uv \
  bash path/to/uv/install-locked.sh .
```

Wheel-only projectでは次を使う。

```bash
PSB_UV=/approved/path/to/uv \
  bash path/to/uv/install-locked-wheel-only.sh .
```

固定`requirements.lock`をuvで同期する場合は、virtual environmentのPythonを指定する。

```bash
PSB_UV=/approved/path/to/uv \
PSB_PYTHON="$PWD/.venv/bin/python" \
  bash path/to/uv/sync-hashed-requirements.sh .
```

uv projectで`--frozen`をこのcontrolの代わりに使ってはいけない。`--frozen`はlockfileを更新しない一方、`pyproject.toml`との鮮度確認を省く。ここではstale manifestを拒否する`uv sync --locked`を使う。

## このcontrolがしてくれること

Lockfile生成時はresolverがdirect dependencyから推移的依存を解決し、選ばれた完全graphと取得元／hashをnative lockfileへ記録する。通常install時にこのcontrolが行うのは再解決ではなく、次の固定と照合である。

1. manifestがreview済みlockfileと一致し、再生成が不要であることを確認する。
2. lockfileに記録されたdirect／transitive graphをnative package managerへそのままinstallさせる。
3. package managerのintegrity検証で取得bytesがlock recordと一致することを確認する。
4. lockfileの暗黙更新、hash不一致、検証runtime不在を失敗として止める。

Graphを更新するPRだけは通常installと分離し、package managerの明示的なlock／update commandでlockfileを生成して差分をreviewする。

| Ecosystem | Reviewするupdate | 通常CI／build |
| --- | --- | --- |
| npm | `npm install`または対象を絞った`npm update` | [`npm ci`](https://docs.npmjs.com/cli/commands/npm-ci/)とnpm wrapper |
| pnpm | `pnpm update <package>`または明示的`pnpm install` | [`pnpm install --frozen-lockfile`](https://pnpm.io/cli/install)とpnpm wrapper |
| pip | compile tool等で全graphのhash付き`requirements.lock`を再生成 | [`pip --require-hashes`](https://pip.pypa.io/en/stable/topics/secure-installs/) wrapper |
| uv | `uv lock --upgrade-package <package>`等 | [`uv sync --locked`](https://docs.astral.sh/uv/concepts/projects/sync/) wrapper |

### Secure／insecure behaviorの差

| Ecosystem | Insecure example | Secure example | 観測する差 |
| --- | --- | --- | --- |
| npm | [`npm install`を通常CIで実行](insecure/javascript/npm/install-mutable.sh) | [`npm ci` wrapper](secure/javascript/npm/install-locked.sh) | Insecure pathはmanifest driftに合わせてlockを書き換える。Secure pathは書き換えず拒否する |
| uv | [`uv sync --frozen`](insecure/python/uv/install-frozen-without-freshness.sh) | [`uv sync --locked` wrapper](secure/python/uv/install-locked.sh) | Insecure pathはstale manifestを許す。Secure pathはfreshness mismatchを拒否する |

Insecure exampleは説明とisolated negative test専用であり、default activationやCI sampleから参照しない。

## Lockfileの限界と組み合わせるcontrol

Lockfileは「推移的依存を解決してくれない」のではなく、resolverが一度解決した推移的graphを固定する。したがって、固定された推移的dependencyがmalicious／vulnerable／obsoleteなら、その危険も忠実に再現する。また、ecosystemやsource形式によってはhashが無いrecord、platformごとのinstall差、mutable VCS reference、build時に取得される別dependencyが残る。

| Lockfileだけでは解決しないこと | 組み合わせる実装 |
| --- | --- |
| malicious package、既知脆弱性、license | [PSB-DETECT-001: integrity-verified scanner](../../detection-verification/integrity-verified-scanner/README.md)とdependency review |
| 公開直後のdependency compromise | [PSB-DEPS-001: release cooldown](../release-cooldown/README.md) |
| install／lifecycle scriptによるcode execution | [PSB-DEPS-002: install script execution](../install-script-execution/README.md) |
| lockfile diffへ紛れた不審なgraph変更 | [PSB-DEPS-004: dependency change review](../dependency-change-review/README.md) |
| package manager runtimeやrelease artifactの真正性 | [PSB-REL-001: signature/provenance verification](../../release-integrity/signature-provenance-verification/README.md) |
| registry origin、dependency confusion、public fallback、egress | [Supply-chain principlesのpackage source boundary](../../../docs/SUPPLY_CHAIN_PRINCIPLES.md) |
| native addon、source build、build dependency | build isolation、pinned toolchain、provenance verificationを別途実施 |

## JavaScript profile一覧

| Profile | 状態 | 提供内容 | 採用時の要点 |
| --- | --- | --- | --- |
| npm | native test済み | Wrapperとpackage-lock preflight | `npm ci`、scripts無効、全外部artifactの強いSRI |
| pnpm | pinned runtimeでnative test済み | Wrapper、version pin、runtime digest | pnpm `11.25.0`、`--frozen-lockfile`、scripts無効 |
| Yarn | reference-only | [`.yarnrc.yml`](secure/javascript/yarn/.yarnrc.yml)と[導入案内](secure/javascript/yarn/README.md) | [`yarn install --immutable --immutable-cache --check-cache`](https://yarnpkg.com/cli/install)を採用環境で検証してからenforce |
| Bun | reference-only | [`bunfig.toml`](secure/javascript/bun/bunfig.toml)と[導入案内](secure/javascript/bun/README.md) | [`bun ci`](https://bun.com/docs/pm/cli/install)と[`bun.lock`](https://bun.com/docs/pm/lockfile)を採用環境で検証してからenforce |

`reference-only`は、このrepositoryのtestで安全性を実証済みという意味ではない。Yarn／Bunを採用する場合はruntime versionとdistribution digestを固定し、safe input、manifest drift、transitive artifact改ざん、runtime不在を実環境で追加検証する。

## Self-testと期待結果

Repository rootからcanonical testを実行する。

```bash
make verify-control CONTROL=PSB-DEPS-003
```

またはcontrol-localに次を実行できる。

```bash
bash controls/dependency-security/lockfile-integrity/tests/test.sh
```

Self-testは外部registryへ接続せず、一時directoryに正規形式の`.tgz`／`.whl`、direct／transitive graph、workspace、platform-optional fixtureを生成する。

- Positive: reviewed lockからのnative installが成功し、lockfileのSHA-256が変化しない。
- Negative: manifest drift、hash欠落、validだがbyte-differentなtransitive artifact、missing lock、missing runtimeを拒否する。
- uv固有: `--locked`がstale manifestを拒否し、insecure exampleの`--frozen`が同じdriftを見逃す差を確認する。
- Expected: required profileがすべて通ればexit `0`。test runtime自体の欠落はexit `2`。pnpm runtime未指定時は`NOT_CHECKED`を表示し、missing-runtimeのfail-closed testだけを行う。

安定した期待内容は[`expected-results/README.md`](expected-results/README.md)に記録する。FixtureのPASSは採用組織のlive settingや実際のregistry安全性を証明しない。

## よくある失敗と復旧

| 結果 | 原因 | 復旧 |
| --- | --- | --- |
| manifestとlockの不一致 | manifestだけ変更した | dependency update用PRでnative lock commandを明示実行し、両方のdiffをreviewする |
| integrity mismatch | cache／mirror／artifactがlock時と異なる | 自動でhashを更新せず、取得元とadvisoryを調査し、承認後にlockを再生成する |
| missing integrity／unsupported source | directory link、mutable VCS、hash無しsource | workspace化、immutable commit＋artifactへ変換、または例外をowner・期限付きで管理する |
| runtime version mismatch | developer／CI runtime drift | [`PNPM_VERSION`](secure/javascript/pnpm/PNPM_VERSION)または[`UV_VERSION`](secure/python/uv/UV_VERSION)に一致する承認済みruntimeを用意する |
| scanner／package manager起動失敗 | runtime、cache、network、permission不備 | `ERROR`のまま止め、原因を直す。cleanとしてretry bypassしない |

## CI／server-side enforcement

Local wrapperは導入確認用であり、developerが任意に迂回できる。Branch protectionでrequired CI checkにし、通常build jobではこのwrapperだけをinstall経路にする。Dependency update jobは別workflow・最小権限・review必須とし、生成されたlockfileを通常jobが書き戻せないようにする。Registry originとegressは[Supply-chain principlesのpackage source boundary](../../../docs/SUPPLY_CHAIN_PRINCIPLES.md)に沿ってserver-side enforcementする。

## 誰が何をするか

- Development team: 対象profileをコピーし、manifestとlockfileを同一PRでreviewし、local self-testを行う。
- Repository administrator: Required CI check、通常jobとupdate jobの分離、lockfile保護を設定する。
- Platform／SRE: Package manager runtime、registry proxy、cache、network egress、credential injectionを管理する。
- Security: 例外、runtime pin、negative test結果、隣接controlとのcoverageをreviewする。

## Rollback

導入したwrapperへのCI参照とコピーしたdirectoryを一つのrevert PRで戻す。Rollback時も通常のmutable installへ無言で戻さず、直前のreview済みlockfileを使う既存immutable commandを維持する。Global Git、shell、IDE、package-manager設定は変更しないため、端末側のrollbackは不要である。

## 自動検証できない範囲と導入完了条件

このrepositoryで自動検証できるのは、isolated fixtureに対するnative installerのfreshness、immutability、transitive integrity、fail-closed behaviorである。採用組織のregistry、credential、egress、branch protection、実platform matrix、package manager distribution provenanceは自動証明できない。

導入完了は次のすべてを満たす状態とする。

- 対象ecosystemのcopy済みwrapperを通常CIが実行し、required checkになっている。
- Safe installとinert tamper testが期待どおり`0`／non-zeroになる。
- Lockfileが通常CIで変化せず、update経路とreview責任者が分離されている。
- 採用する全platform／workspace／optional dependencyを実projectで確認している。
- Registry source、runtime provenance、vulnerability detectionなど対象外のboundaryにownerがいる。

## Framework mappingと関連ガイド

Mappingはformal complianceの主張ではない。Machine-readable mappingは[`control.yaml`](control.yaml)に記録する。

- [MITRE ATT&CK Enterprise v19.1: T1195.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [NIST SP 800-218 SSDF 1.1: PW.4.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OpenSSF OSPS Baseline 2026-02-19: OSPS-BR-05.01](https://baseline.openssf.org/versions/2026-02-19#osps-br-0501)
- [npm `package-lock.json`](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/)
- [npm `npm ci`](https://docs.npmjs.com/cli/commands/npm-ci/)
- [pnpm install](https://pnpm.io/cli/install)
- [Yarn install](https://yarnpkg.com/cli/install)と[Yarn `checksumBehavior`](https://yarnpkg.com/configuration/yarnrc/#checksumBehavior)
- [Bun install](https://bun.com/docs/pm/cli/install)、[Bun lockfile](https://bun.com/docs/pm/lockfile)、[Bun auto-install](https://bun.com/docs/runtime/auto-install)
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [uv project sync](https://docs.astral.sh/uv/concepts/projects/sync/)と[uv CLI reference](https://docs.astral.sh/uv/reference/cli/)
- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/)（直接mappingはせず、build input／provenanceの隣接ガイドとして参照）
- [OWASP Software Component Verification Standard](https://scvs.owasp.org/)
- [CISA Securing the Software Supply Chain](https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-developers)

設計判断とtest matrixは[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)を参照する。
