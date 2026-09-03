# PSB-DEPS-003: native lockfileと取得artifactの完全性を強制する

## このcontrolを一枚で理解する

> **このcontrolの要点**
>
> Lockfile固定の役割は、「意図しないversion解決やinstall時の揺れを防ぎ、review済みの依存グラフを再現する」ことである。依存グラフとは、projectが直接指定したpackageだけでなく、そのpackageがさらに必要とする推移的dependencyまで含む関係全体を指す。毎回「その時点で条件に合うversion」を探すのではなく、review時に選ばれたgraphと取得artifact（npmのtarballやPythonのwheel等）を通常buildで使い続ける。
>
> **Secure defaultはversionかhashの二択ではなく、両方である。** Exact version／source／依存graphは「どのartifactを取得するか」を固定し、cryptographic hashは「取得したbytesがreview時と同一か」を固定する。Versionだけでは同じ識別子を名乗る別bytesを検出できず、hashだけではpackage名、依存関係、source、platformごとの候補を決められない。

### セキュリティ上の問題

`package.json`や`pyproject.toml`等のmanifestは、しばしば`^1.2.0`、`>=1.2`のように複数versionを許容する。推移的dependencyにも同様の条件がある。Lockfileが無い、manifestに対して古い、または通常CIがlockfileを書き換えられるinstall commandを使うと、resolverはreview時と異なるexact versionや推移的graphを選べる。

ただし、version rangeがあるだけで直ちに侵害されるわけではない。概ね次の条件がつながったときに実害になる。

1. Missing／stale lock、mutable install、誤ったpackage-manager option等により、通常buildで依存graphの再解決またはlockfile更新が許される。
2. その時点のregistry metadata、公開version、override、platform条件等から、review時とは異なるdependencyが選ばれる。
3. 選ばれたdependencyにmalicious code、既知でない脆弱性、破壊的変更等があり、install、test、buildまたは製品runtimeで読み込まれる。

別の経路として、lockfile上の名前とversionが同じでも、registry、mirror、cacheまたは通信経路から取得したbytesが差し替わる場合がある。Integrity metadataが欠落している、検証を無効化している、または検証失敗を無視する場合、そのbytesがinstall scriptとしてCI上で動く、build outputを改変する、あるいは製品artifactへ混入する可能性がある。

結果として、CI credentialやsourceを読まれる、build／release artifactを汚染される、未検証codeを製品へ含める、といったsecurity impactが生じ得る。悪意がないversion driftでも、developerとCIで結果が違う、SBOMと実artifactが一致しない、障害時に同じbuildを再現できない、といった運用上の被害になる。

### 誰から、または何から守るか

未reviewのmanifest変更を入れるcontributorやupdate bot、異なる結果を返すresolver／registry metadata、侵害されたpackage publisher、registry・mirror・cache上でbytesを差し替える攻撃者、lockfileやpackage managerの失敗を成功扱いするCI設定から守る。攻撃者がいなくても、runtime、platform、option、cache状態の違いによる偶発的な再解決を対象に含む。

### 何が対象か

JavaScriptの`package.json`と`package-lock.json`／`pnpm-lock.yaml`等、Pythonの`pyproject.toml`と`uv.lock`、完全hash付き`requirements.lock`、それらに記録されるdirect／transitive dependency、取得artifact、通常CIのinstall commandが対象である。Registry routing、packageの採用可否、CI credential自体は別controlの対象である。

### 何をするか

Review済みlockfileをcommitし、通常installをnative package managerのimmutable／frozen modeへ固定する。外部packageについて、exact version／source／direct・transitive graphと、取得artifactのstrong hashを一組の記録として扱う。Manifestとlockfileの鮮度、graph、artifact integrityを検証し、通常installではlockfileを生成・修復しない。npmは追加preflightで全外部artifact recordの強いSRIも確認し、pipは全requirementのexact pin、local SHA-256 hash、wheel-onlyを強制する。

### 成功状態

Clean environmentでreview済みのexact graphと許可されたartifact hashからinstallでき、install前後でlockfile digestが変わらない。Manifest drift、version／graphの再解決、hash欠落、validなpackage形式のまま差し替えたbytes、lockfile欠落、unsupported schema、runtime欠落は非zeroで停止する。検証不能はclean resultではなく`ERROR`または明示的な`NOT_CHECKED`になる。

### 対象外・残余リスク

Lockfileは推移的依存を安全に選ぶものではない。Resolverが選んだgraphとartifact identityを再現するため、malicious packageをreviewしてlockした場合も忠実に再現する。既知脆弱性、license、maintainer侵害、公開直後の危険、lockfile変更の妥当性、install scriptの権限、registry origin、network egress、package-manager binary自体の真正性は別controlとの組合せが必要である。

## まず、このcontrolの本質を理解する

Manifestとlockfileは役割が異なる。

| 要素 | 役割 | Security上の注意 |
| --- | --- | --- |
| Manifest | Projectが許容するdirect dependency条件を宣言する | Rangeは将来の候補を許す。これだけではexact graphにならない |
| Resolver | Manifest、registry metadata、override、platform等からdirect／transitive versionを選ぶ | 入力時刻や設定が違えば、再解決結果も変わり得る |
| Lockfile | Resolverが選んだexact graph、取得先、integrity等をecosystem固有形式で記録する | 記録内容が安全かどうかは判断しない。Review対象である |
| Immutable install | Manifestがlockと一致するか確認し、lockを変更せずinstallする | 通常buildに使う。Mismatchを自動修復しない |
| Integrity verification | 取得bytesをlock recordのhashと照合する | 同じ名前／versionを名乗る別bytesの利用を止める |

### 結論: lockfileはversionではなくhashにするのか

いいえ。Lockfileを「version指定の代わりにhashだけを並べるfile」にはしない。外部artifactのsecure recordには、少なくとも次の情報を同時に保持する。

1. **Package identity**: Package名とregistry／URL等のsource。
2. **Graph identity**: Exact versionと、そのpackageが必要とするdirect／transitive dependency。
3. **Artifact identity**: Installを許可するtarball／wheel等のcryptographic hash。

Versionだけを固定した場合、侵害されたregistry、mirror、cache等が同じ`name@version`を名乗る別bytesを返す経路が残る。逆にhashだけでは、そのbytesがどのpackageのどの依存edgeに対応するか、OS／CPU／Python ABIごとの複数artifactのうち何を許可するかを表現できない。例えば一つのPython releaseにmacOS、Linux、複数Python version用のwheelがある場合、exact versionに加えて、許可する各wheelのhash集合が必要になる。

各ecosystemのdefaultと、このcontrolのsecure defaultは次のとおりである。

| Ecosystem／形式 | Native toolが通常記録・検証する内容 | このcontrolのsecure default |
| --- | --- | --- |
| [npm `package-lock.json` v2／v3](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/) | Registry packageについてexact `version`、`resolved` URL、SRI `integrity`を記録する。古いlock、link、特殊source等では同じ条件にならない | 全外部artifact recordにSHA-256／384／512 SRIを必須化し、`npm ci`でgraphとhash mismatchを拒否する |
| [pnpm `pnpm-lock.yaml`](https://pnpm.io/lockfile) | Importerのspecifierとresolved version、完全graph、package resolutionのSRIを記録する | pnpm `11.25.0`へ固定し、`--frozen-lockfile`で記録済みversion／graph／integrityを使う |
| [pip requirements file](https://pip.pypa.io/en/stable/topics/secure-installs/) | `==`も`--hash`も記述者次第であり、通常の`pip install`はlocal hashを必須にしない | 全direct／transitive requirementを`==`で固定し、許可する全wheelのlocal SHA-256を列挙して`--require-hashes --only-binary=:all:`を使う |
| [uv project `uv.lock`](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile) | Index packageのexact resolved version、source、利用可能なdistribution recordとhashを管理する。`uv sync`はdefaultではlockを更新し得る | Pinned uvで`uv sync --locked`を使い、lockの鮮度と記録済みartifact integrityを維持する。Wheel-onlyが必要なら`--no-build`も使う |
| [uv requirements sync](https://docs.astral.sh/uv/reference/cli/#uv-pip-sync) | Requirements内に存在するhashは検証するが、defaultでは全requirementのhashを必須にしない | Exact pinと全artifact hashを用意し、`uv pip sync --require-hashes --only-binary :all:`を使う |

つまり、npm／pnpm／uv projectのnative lockは基本的にversionとhashを併記する。pip／uv requirements形式はhash checkingを明示的に有効化する必要がある。本controlはmanagerごとの差をwrapperとpreflightで吸収し、外部artifactに「exact resolution **and** strong hash」を要求する。Workspace等のrepository内sourceはdownload artifactではないため同じhash modelにせず、宣言済みworkspaceだけを例外として識別する。

なお、hashは「安全な内容」という判定ではなく「承認時と同じbytes」という判定である。Publisher／registryがlock生成前から侵害されていてmalicious artifactを取得した場合や、攻撃者がlockfileのversionとhashを同じPRで変更してreviewを通過した場合、そのmalicious bytesにも正しいhashが付く。Dependency review、release cooldown、vulnerability detection、registry boundary、provenanceは引き続き必要である。

```text
dependency update時だけ
manifest -> resolver -> lockfile差分をreviewしてcommit
                            |
                            v
通常のdeveloper／CI build -> immutable install -> locked graphとbytesを再現
```

このcontrolが維持する不変条件は三つである。

1. **Graph identity**: 通常buildでdirect／transitive dependencyを選び直さない。
2. **Artifact identity**: 取得したpackage bytesがlockfileのintegrityと一致する。
3. **Fail closed**: Lock、runtimeまたは検証が利用できなければ、再解決して続行せず止まる。

したがって、このcontrolは「安全なdependencyを発見するscanner」ではない。Reviewしていないdependency graphやbytesが、通常installの都合でbuildへ入り込む経路を狭めるcontrolである。

## 何が、どの条件で被害になるか

| 状況 | 被害が成立する主な条件 | 起こり得ること | このcontrolで止まる地点／残る境界 |
| --- | --- | --- | --- |
| 通常CIでmutable install | Manifestがlockと不一致またはlockが無く、installerがlockを生成・更新できる | 未reviewのexact versionやdependencyがbuildへ入る | Immutable installがmismatchを拒否する。意図したupdateは別PRで行う |
| 推移的dependencyの再解決 | 親packageの条件が複数versionを許し、lockを使わず再解決する | Direct dependency名は同じでも新しいtransitive codeが入る | Committed lockの完全graphを使い、通常buildでは再解決しない |
| Artifactの差替え | Registry／mirror／cacheが別bytesを返し、strong integrityが無いか検証されない | Install時code実行、build output改変、製品artifactへの混入 | Native integrity checkがbytes mismatchを拒否する。最初から悪性のlocked bytesは残る |
| 悪意あるlockfile更新 | Contributorやbotがmanifest、lock、hashを同時に変更し、reviewを通過する | 悪性dependencyが「期待したbytes」として固定される | 本controlだけでは止まらない。[Dependency change review](../dependency-change-review/README.md)が必要 |
| Verification failureの無視 | Runtime欠落、parser error、cache障害等をCIがwarningまたはsuccessへ変換する | 実際には未検証なのにreleaseが進む | Wrapperとtestは非zeroにし、pnpm未実行は`NOT_CHECKED`と表示する |
| Platformごとのinstall subset | Optional dependency、marker、CPU／OS条件があり、target testが不足する | 特定platformだけ別packageが入る、または不足がproductionで発覚する | Lock内の条件は保持するが、全target platformの実install確認は採用側が行う |

例えば、review済み`package-lock.json`が推移的な`helper@2.3.1`を記録しているとする。後の通常CIでlockfileが削除またはmanifestに対して古い状態になり、`npm install`がlockを自動生成すると、その時点で条件を満たす`helper@2.3.2`が選ばれる場合がある。Reviewerが確認したのは`2.3.1`でも、testやreleaseへ入るのは`2.3.2`になる。`2.3.2`が悪性ならinstall／build時のcode executionや製品混入につながり、悪性でなくても挙動差や再現不能が生じる。

同じ状況で`npm ci`を使い、manifestとlockが一致していれば`2.3.1`を再現する。不一致ならlockを直さず停止する。また、mirrorが`helper@2.3.1`という同じ名前とversionで別bytesを返しても、lock内のSRIと一致しなければinstallを拒否する。これがversion固定とartifact integrityを組み合わせる理由である。

被害の大きさはinstall場所の権限と、dependencyがいつ実行されるかで変わる。

- 優先度が高い: Dependency install／buildがsource write token、package publish credential、署名・release権限、internal networkを持つCIで行われ、dependency codeやinstall scriptがその場で実行される。
- 製品影響がある: CI credentialが無くても、差し替わったlibraryがrelease artifactへ入り、製品runtimeで実行される。
- 主に再現性への影響: 変更後のpackageが悪性でなくても、build失敗、未reviewのbehavior change、SBOM／incident調査対象のずれが起こる。
- この経路が成立しない例: Up-to-dateなreview済みlockfileをimmutable installし、artifact integrityが検証され、不一致時にrelease前で停止する。この場合、manifestにrangeが残っていても通常buildはそのrangeを再解決しない。

## 導入前に方式を選ぶ

| Projectの状態 | 推奨する開始点 | 導入前に決めること |
| --- | --- | --- |
| npmで`package-lock.json`をcommit済み | npm wrapperをそのままcopy | Supported lockfile v2／v3であること、既存CIから`npm install`を外せること |
| pnpmでworkspaceを使う | pinned pnpm wrapperをcopy | Workspace root、pnpm `11.25.0`、storeとtarget filterの扱い |
| Python applicationでwheelを利用できる | pip hash lockまたはuv wheel-only profile | 全transitive hash、Python version、sdistを拒否できること |
| Source distribution／native buildが必要 | Standard uv profileまたは個別設計 | Build dependency、compiler、network、install-script controlとの境界 |
| Yarn／Bunを使う | Reference configから採用側testを追加 | Exact runtime digest、manifest drift、tampered transitive artifactのnative test |
| 複数OS／CPUへreleaseする | 各profileにtarget matrixを追加 | Optional／marker／native packageをどのplatformで実installするか |

複数package managerや複数lockfileがあるrepositoryでは、一つのwrapperが全graphを守るとはみなさない。Releaseへ入る各lockfileに対応するprofileとrequired CI checkを用意する。

## 最短の導入手順

採用するpackage managerのprofileだけを選び、adopter repository内の`.security/lockfile-integrity/`等へcopyする。複数profileを一度に導入する必要はない。`tests/fixtures/`のmanifestやpackageはtest専用であり、製品のlockfileとしてcopyしない。

### 前提とtrust assumption

- macOSまたはLinux、Bash、対象ecosystemのnative runtimeを使う。
- package manager自体を信頼済み経路から導入する。pnpmとuvはこのcontrolに記録したversionへ固定する。
- manifestとlockfileを同じPRでreviewし、通常CIではlockfileを生成しない。
- dependency installが必要とするnetworkとregistry authenticationは採用側が設定する。このcontrolはregistry allowlistやegress制御を代替しない。

### JavaScript: npm

次の2 fileを含むnpm profileをrepositoryへコピーする。

- [`secure/javascript/npm/install-locked.sh`](secure/javascript/npm/install-locked.sh)
- [`secure/javascript/npm/verify-package-lock.mjs`](secure/javascript/npm/verify-package-lock.mjs)

既存targetがある場合は上書きせず停止し、人がmergeする。

```bash
test ! -e .security/lockfile-integrity/npm
mkdir -p .security/lockfile-integrity
cp -R controls/dependency-security/lockfile-integrity/secure/javascript/npm \
  .security/lockfile-integrity/npm
bash .security/lockfile-integrity/npm/install-locked.sh .
```

このwrapperは`package-lock.json` v2／v3の全外部artifact recordにSHA-256／384／512 SRIがあることをpreflightし、`npm ci --package-lock=true --ignore-scripts --no-audit --no-fund`を実行する。成功時はexit `0`、policy違反は`1`、入力またはruntime不備は`2`である。

### JavaScript: pnpm

次のdirectoryをrepositoryへコピーする。

- [`secure/javascript/pnpm/install-locked.sh`](secure/javascript/pnpm/install-locked.sh)
- [`secure/javascript/pnpm/PNPM_VERSION`](secure/javascript/pnpm/PNPM_VERSION)
- [`secure/javascript/pnpm/RUNTIME.md`](secure/javascript/pnpm/RUNTIME.md)

承認済みのpnpm `11.25.0` binaryを明示して実行する。

```bash
test ! -e .security/lockfile-integrity/pnpm
mkdir -p .security/lockfile-integrity
cp -R controls/dependency-security/lockfile-integrity/secure/javascript/pnpm \
  .security/lockfile-integrity/pnpm
PSB_PNPM=/approved/path/to/pnpm \
  bash .security/lockfile-integrity/pnpm/install-locked.sh .
```

Offline cacheを準備済みなら、`PSB_PNPM_OFFLINE=1`とrepository-localな`PSB_PNPM_STORE_DIR`も指定できる。wrapperはversion一致を検査し、`install --frozen-lockfile --ignore-scripts`を実行する。

### Python: pip

[`secure/python/pip/install-locked.sh`](secure/python/pip/install-locked.sh)をコピーし、全direct／transitive requirementを`==`と`--hash=sha256:...`で固定した`requirements.lock`を用意する。

```bash
test ! -e .security/lockfile-integrity/pip
mkdir -p .security/lockfile-integrity
cp -R controls/dependency-security/lockfile-integrity/secure/python/pip \
  .security/lockfile-integrity/pip
python3 -m venv .venv
PSB_PYTHON="$PWD/.venv/bin/python" \
  bash .security/lockfile-integrity/pip/install-locked.sh .
```

wrapperは専用virtual environmentを必須とし、`pip install --require-hashes --only-binary=:all:`と`pip check`を実行する。Source distributionを許可するprojectは、build isolation・build dependency・provenanceを別途設計し、wheel-only flagを黙って外さない。

### Python: uv project

[`secure/python/uv/`](secure/python/uv/)をコピーする。標準profileはmanifest freshnessを検査する`--locked`を使う。Runtimeの取得元、SHA-256、attestation手順は[`RUNTIME.md`](secure/python/uv/RUNTIME.md)に固定する。

```bash
test ! -e .security/lockfile-integrity/uv
mkdir -p .security/lockfile-integrity
cp -R controls/dependency-security/lockfile-integrity/secure/python/uv \
  .security/lockfile-integrity/uv
PSB_UV=/approved/path/to/uv \
  bash .security/lockfile-integrity/uv/install-locked.sh .
```

Wheel-only projectでは次を使う。

```bash
PSB_UV=/approved/path/to/uv \
  bash .security/lockfile-integrity/uv/install-locked-wheel-only.sh .
```

固定`requirements.lock`をuvで同期する場合は、virtual environmentのPythonを指定する。

```bash
PSB_UV=/approved/path/to/uv \
PSB_PYTHON="$PWD/.venv/bin/python" \
  bash .security/lockfile-integrity/uv/sync-hashed-requirements.sh .
```

uv projectで`--frozen`をこのcontrolの代わりに使ってはいけない。`--frozen`はlockfileを更新しない一方、`pyproject.toml`との鮮度確認を省く。ここではstale manifestを拒否する`uv sync --locked`を使う。

## Dependency updateと通常installを分ける理由

Lockfileは永遠に変更しないfileではない。Dependencyを追加・更新するときはresolverを動かし、direct／transitive graphとintegrityを更新する必要がある。重要なのは、その変更を通常build中に暗黙実行せず、意図したupdate PRへ閉じ込めることである。

- Update path: Network上のregistry metadataを使って再解決し、manifestとlockfileの両方を変更する。Direct／transitive差分、取得元、advisory等をreviewしてcommitする。
- Normal install path: Committed lockfileを入力として使い、manifest mismatchやartifact mismatchなら修復せず停止する。成功させるために`npm install`、`--fix-lockfile`、`--update-checksums`等へfallbackしない。

この分離により、「dependencyを変える操作」と「review済みdependencyでbuildする操作」が同じCI jobに混在しなくなる。

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

## 導入の副作用と判断基準

Immutable installは、従来なら自動修復されていた不整合を明示的な失敗に変える。そのため、導入には次の副作用がある。

| 副作用 | なぜ起こるか | 現実的な対応 |
| --- | --- | --- |
| Manifestだけを変えたPRが失敗する | Normal installがlockfileを更新しないため | Update PRでnative lock commandを明示実行し、lock差分もreviewする |
| Package-manager version差でlock formatや解決結果が変わる | Resolver semanticsがruntime versionに依存するため | DeveloperとCIのruntimeをpinし、runtime更新を独立PRにする |
| Source distributionやnative addonがinstallできない | pip／uv wheel-only profileがbuildを拒否するため | Standard uv profileとisolated buildを設計し、[install execution control](../install-script-execution/README.md)で承認する |
| Lifecycle scriptを必要とするpackageが壊れる | Reference wrapperが取得直後のcode executionを抑えるため | Scriptを一律に再有効化せず、packageとcommandを限定して別controlでreviewする |
| Cache corruptionやmirror差替えでbuildが止まる | Integrity mismatchを自動的に新しいhashへ合わせないため | Cacheを破棄してtrusted sourceから再取得し、継続するなら原因とlock updateをreviewする |
| OS／CPUごとのtestが増える | 同じlockからplatform固有subsetが選択され得るため | Release対象matrixだけをCIで実installし、未対象platformをsupportedと主張しない |
| Dependency updateの手順が一段増える | Resolveとnormal installを分離するため | Bot／専用jobでupdate PRを作成しても、通常buildのimmutable checkとhuman reviewは維持する |

開発速度とのtrade-offを隠さない。厳格profileを使えないdependencyがある場合は、全体のintegrity checkを外すのではなく、そのsource形式とbuild権限を限定したprofileまたは期限付き例外として扱う。

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
| package manager／preflight起動失敗 | runtime、cache、network、permission不備 | `ERROR`のまま止め、原因を直す。cleanとしてretry bypassしない |

## CI／server-side enforcement

Local wrapperは導入確認用であり、fileをcopyしただけではdeveloperによる別command実行を止めない。導入先では次をserver-sideの境界にする。

1. 通常build jobでは選択したwrapperだけをinstall経路にし、mutable commandへのfallbackを置かない。
2. Branch protection／rulesetで、そのjobをmerge前のrequired checkにする。
3. Dependency update jobは通常buildと分け、manifestとlockfileの変更をPRへ出し、通常jobからrepositoryへ書き戻せないようにする。
4. Package-manager runtimeとsecurity-critical optionをCI imageまたはrepository設定でpinする。
5. Registry／cache障害、runtime欠落、parse failureはjob failureにし、retryのためにhashやfrozen flagを外さない。

Registry origin、public fallback、credential injection、egressは[Supply-chain principlesのpackage source boundary](../../../docs/SUPPLY_CHAIN_PRINCIPLES.md)に沿って別途enforceする。CIが強いcredentialを持つほどdependency code実行時の被害が増えるため、[install execution control](../install-script-execution/README.md)とbuild isolationも組み合わせる。

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
