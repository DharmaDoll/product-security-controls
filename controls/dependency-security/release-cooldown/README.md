# PSB-DEPS-001: managed registry proxyとrelease cooldown

## このcontrolを一枚で理解する

### セキュリティ上の問題

公開直後のdependency versionを端末やCIが即時採用すると、maintainer侵害やmalicious releaseが発見・撤回される前に組織へ広がる。

### 誰から、または何から守るか

侵害されたmaintainer・registry、dependency confusion、typosquatting、public registry direct access、proxy障害時fallback、古い例外から守る。

### 何が対象か

Dependency update、package versionと公開時刻、managed registry proxy、client設定、artifact hash、cooldown policy、期限付き例外。

### 何をするか

Resolverまたはtrusted CIで新versionを既定7日間保留し、lockfileへ固定する。利用可能な組織では取得をapproved proxyへ限定し、必要な緊急採用だけをexact package・version・owner・期限付きで例外化する。

### 成功状態

採用versionがcooldownを満たすか有効なexact例外を持ち、通常buildがreview済みlockfileを再現する。Full profileでは取得元とartifact integrityも固定され、proxyまたはmetadata障害はpublic fallbackせず停止する。

### 対象外・残余リスク

Cooldown期間の経過は安全性を保証せず、既に悪性の旧version、private package compromise、既知脆弱性、runtime behaviorは別途評価が必要である。

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

## Cooldownとlockfileの役割分担

`package-lock.json`と`npm ci`は、既にreviewしたversionを固定して通常installでのdriftを防ぎます。
一方、`npm install <package>`、dependency update、localに存在しないpackageを使う`npx`では、
新しいversionをlockfileへ入れる前のresolutionが発生します。この段階で公開後の経過時間を確認するのが
cooldownです。

推奨する多層構成は、age gate、lockfile＋frozen install、integrity、install-script default deny、
sandbox、最小権限credentialの順です。HumanやAI agentへ毎回安全判断を求めるのではなく、通常の
dependency追加を要求できても、基準時間未満のversionをpackage manager／CIが物理的にresolveできない
構成にします。

個人開発では72時間が利便性との実用的な開始点になり得ますが、このcontrolのfull reference baselineは
168時間です。24時間、72時間、168時間のいずれもpackageの安全性を保証せず、publishからcommunity／
vendorの検知・削除までの時間を買うだけです。詳細とincident例は
[実装仕様書](docs/implementation-spec.md#2-cooldownとlockfileの役割分担)を参照してください。

## Managed proxyを利用できない場合

`registry.npmjs.org`等へ直接接続する環境でも、package managerのnative age gateまたはtrusted CI verifierを
使える場合はcooldownを自動化できます。失われるのは中央proxyによるmalware解析、経路強制、取得追跡、
事後通知であり、cooldownそのものとは区別します。

### npmの最短導入

前提はPython 3.10+、`min-release-age`が導入されたnpm `11.10.0`以上のreview済みruntime、official public
registryへのHTTPS接続です。古いnpmは未知の`.npmrc` keyを表示してもenforcementしないため、native gateとして
扱いません。このlocal導入手順で古いnpmからdependency updateを実行せず、supported npmへ更新するか、
隔離されたupdate serviceが作ったgraphの全candidateをProfile 2で判定します。
既存`.npmrc`と同名scriptがないことを確認し、repository rootで次を実行します。既存fileがある場合は停止し、
内容を手動でmerge reviewしてください。

```bash
(
  set -eu
  test ! -e .npmrc
  test ! -e scripts/check_npm_release_age.py
  mkdir -p scripts
  cp controls/dependency-security/release-cooldown/secure/direct-public-registry/.npmrc .npmrc
  cp controls/dependency-security/release-cooldown/scripts/check_npm_release_age.py scripts/
  chmod 0755 scripts/check_npm_release_age.py
)
```

`.npmrc`は`registry=https://registry.npmjs.org/`、`min-release-age=7`、`save-exact=true`、
`package-lock=true`だけを設定します。Global npm設定は変更しません。実効設定で7日未満へのoverrideや
`min-release-age-exclude`がないことも確認してください。

Networkを使わないpositive／negative self-testは次です。

```bash
python3 controls/dependency-security/release-cooldown/scripts/check_npm_release_age.py \
  --config controls/dependency-security/release-cooldown/secure/direct-public-registry/.npmrc \
  --package example-cooldown-package \
  --version 1.0.0 \
  --metadata-file controls/dependency-security/release-cooldown/tests/fixtures/npm-packument.json \
  --as-of 2026-07-27T00:00:00Z

python3 controls/dependency-security/release-cooldown/scripts/check_npm_release_age.py \
  --config controls/dependency-security/release-cooldown/secure/direct-public-registry/.npmrc \
  --package example-cooldown-package \
  --version 2.0.0 \
  --metadata-file controls/dependency-security/release-cooldown/tests/fixtures/npm-packument.json \
  --as-of 2026-07-27T00:00:00Z
```

最初は`ACCEPTED ... age_hours=624`とexit `0`、次は`COOLDOWN_WAIT ... remaining_hours=144`とexit `1`に
なります。Missing／malformed metadata、network failure、clock overrideは`ERROR`とexit `2`です。
Fixtureの`ACCEPTED`はlive registryやorganization adoptionの証拠ではありません。

実際の新規追加は、exact versionを選んで次のread-only checkを先に実行します。`--live`だけがnetwork accessを
有効にし、official npm registryのfull metadataを最大32 MiB、10秒timeout、redirectなしで取得します。
Package artifactはdownloadも実行もしません。

```bash
python3 scripts/check_npm_release_age.py \
  --config .npmrc \
  --package your-package-name \
  --version 1.2.3 \
  --live

# exit 0を確認してから実行する
npm install --save-exact --ignore-scripts your-package-name@1.2.3
```

CIでは、base-to-headのdependency deltaから得たすべてのexact package／versionについて、PRが変更できない
trusted copyのcheckerとconfigをinstallより前に実行します。Exit `1`は待機、exit `2`は検証不能として、どちらも
mergeとfull install CIをblockします。通常buildは`npm ci`を使います。Graph deltaの完全性は`PSB-DEPS-004`、
lockfile／integrityは`PSB-DEPS-003`、install script拒否は`PSB-DEPS-002`をcompositionしてください。
一件のdirect dependencyだけをcheckして、同時に追加されたtransitive dependencyを未確認のまま許可しません。

Native gateもCI verifierも使えない場合は、lockfileとhuman reviewを使うoperational fallbackとします。

1. 新規追加前にofficial registryのpublish timestampをread-only確認し、7日以上経過したexact versionを選ぶ。
2. npmでは`npm install --save-exact <package>@<version>`を使い、`package.json`と`package-lock.json`を同じPRへcommitする。
3. 通常のCI／release buildは`npm install`ではなく`npm ci`に固定する。
4. Dependabot等のyoung-version PRは、install／buildより先にageを判定し、7日未満なら`COOLDOWN_WAIT`として保留する。
5. 待機後にrelease、advisory、provenanceを再確認してから、install scriptsを原則拒否したsecretなしの隔離CIでtestする。

`npm ci`はmanifestとlockfileの不一致を失敗させ、install中にlockfileを書き換えませんが、artifactが安全で
あることやbytesが常に同一であることを単独では保証しません。Integrity検証、install-script制限、sandbox、
最小権限credentialを併用します。GreenなCIもmalware不在の証明にはなりません。緊急security updateと
詳細なDependabot flowは[実装仕様書](docs/implementation-spec.md#35-managed-proxyなしでpublic-registryへ直接接続する場合)を参照してください。

Recoveryではnpm version、実効config、UTC clock、registry到達性、package／version identityを直して再実行し、
age gateを下げたり除外を追加したりしません。Rollbackはcopyしたscriptと、新規作成した`.npmrc`だけをreviewの
上で削除します。既存`.npmrc`へmergeした場合は、この導入で追加した4行だけを戻します。Server-side required
checkを外す場合は、同等以上のnative／proxy enforcementへ移行したことを先に確認します。

## 脅威と失敗シナリオ

主な失敗シナリオは`DEPENDENCY-NEW-RELEASE-COMPROMISE`です。

1. 攻撃者がpackage maintainerまたはregistry accountを侵害する
2. 悪意あるversionを公開する
3. 開発端末や自動updateが公開直後のversionをresolveする
4. install script、build plugin、compiler pluginなどが開発者権限やCI権限で実行される

cooldownは公開直後の自動採用を遅らせますが、悪意あるversionそのものを安全化する
ものではありません。

もう1つの失敗シナリオは`DEPENDENCY-PROXY-BYPASS`です。各開発者がregistryを
任意設定すると、攻撃者または設定driftによってpublic registryへのdirect fallbackが
選ばれ、malicious-package検査、download追跡、事後通知を迂回できます。このcontrolは
full reference profileでclient経路をmanaged security proxyへ固定します。Proxyを使わないscopeでは、
native／CI age gateと明示したresidual riskで代替します。

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
- `registry-proxy-policy.json`
  - MDM／CI templateによる中央配布
  - public registryへのdirect egressとfallbackを拒否
  - proxy障害を`ERROR`として扱う
  - install用read-only proxyとpublish経路を分離
  - proxyのblocklistをcooldownの代替にしない
- `native-cooldown-policy.json`
  - repository-owned verifierを最終判定として維持
  - native設定にも168時間の下限を適用
  - metadata欠落を`ERROR`として扱い、永続的な除外を禁止
- `clients/`
  - npm、pip、uv、pnpm、Yarnのnative cooldown sample
  - npm、pip、Go、Composerのproxy-only client profile
- `direct-public-registry/.npmrc`
  - official npm registry、7日age gate、exact save、lockfile生成をrepository-localに設定
- `scripts/check_npm_release_age.py`
  - exact npm versionのpublish timestampをinstall前にread-only確認

安全なfixtureには、公開から7日以上経過した通常dependencyと、緊急security fixを
想定した、owner・理由・承認者・開始時刻・失効時刻付きのexact version例外が
含まれます。

### 安全でない例

`insecure/`は次の問題を明示します。

- cooldownが0時間
- allowlist外registry
- integrity欠落
- 公開から24時間しか経過していないversion
- 168時間未満または無効化されたnative cooldown設定
- package wildcard等を使う永続的なnative cooldown除外
- metadata欠落やlockfile再利用をfail-openにするpnpm設定
- developer任意のproxy設定とpublic registry fallback
- `pip`の`extra-index-url`、Goの`,direct`、ComposerのPackagist fallback
- proxy blocklistをrelease cooldownと誤認するpolicy
- plaintext credentialと、provider承認済みの無害なcanaryを指定しない動作確認
- direct-public npmでcooldownを0日とし、永続除外、`before` override、range保存、lockfile無効化を許可

fixtureで使用するpackage名、registry、artifactはすべてsyntheticです。

## 検証方法

```bash
make verify-control CONTROL=PSB-DEPS-001
```

直接実行する場合は、評価時刻を明示します。

```bash
python3 controls/dependency-security/release-cooldown/scripts/verify.py \
  --policy controls/dependency-security/release-cooldown/secure/cooldown-policy.json \
  --native-policy controls/dependency-security/release-cooldown/secure/native-cooldown-policy.json \
  --proxy-policy controls/dependency-security/release-cooldown/secure/registry-proxy-policy.json \
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

## Managed registry proxy

`secure/clients/`はproduction endpointを変更するinstallerではなく、組織ごとのURLへ
置換してMDM、configuration management、devcontainer、またはCI templateから配布する
ためのsampleです。repository cloneだけでglobal package-manager設定を書き換えることは
ありません。

Takumi Guardは、この構成で想定するproviderの一例です。公式documentationでは
package registry proxyによるmalicious-package blocking、install tracking、
breach notificationと、organization configuration／MDM／CIによる配布が説明されています。
Goでは`,direct`または`|direct`を付けるとproxyを迂回するため、このsampleは単一proxy
だけを許可します。npmのinstall proxyはread-onlyなので、login／publishは承認された
upstreamを明示する別経路にします。

一方、参照したTakumi Guardの公式documentationには「公開後168時間未満のpackageを
拒否する」というminimum-age保証はありません。このため役割を分離します。

- managed proxy: known-malicious packageのblocking、取得履歴、事後通知
- repository-owned verifier: 公開時刻に基づく168時間cooldown
- network／endpoint policy: public registryへのdirect egressとclient fallbackの拒否

providerが許可したpackageでもcooldownを通過したことにはなりません。逆にproxyが
利用不能な場合もpublic registryへfallbackせず、検証不能な`ERROR`として扱います。
block pathの確認にはproviderが用意する無害なtest packageだけを使い、実malwareを
取得・実行してはいけません。

## Package managerのnative cooldown

`cooldowns.dev`は、package manager、dependency update bot、registry proxyに存在する
cooldown機能を横断的に見つけるための、community-maintainedな運用リファレンスとして
参照します。frameworkや適合基準ではなく、各設定の意味と対応versionはpackage manager
の公式documentationを正とします。サイトで例示される待機期間に合わせて、このcontrolの
7日（168時間）baselineを短縮してはいけません。

`secure/native-cooldown-policy.json`は、現在確認済みのclient profileをまとめています。

| Client | Review対象の設定 | このcontrolでの境界 |
| --- | --- | --- |
| npm | `min-release-age=7` | wildcardを含む永続的な`min-release-age-exclude`を許可しない |
| pip | `uploaded-prior-to=P7D` | upload時刻を提供するindexでだけ有効。metadata不能は`ERROR` |
| uv | `exclude-newer = "7 days"` | package単位の永続的な`exclude-newer-package`を許可しない |
| pnpm | `minimumReleaseAge: 10080` | metadata欠落、若いversionへのfallback、lockfile再利用による再検証省略をfail-openにしない |
| Yarn | `npmMinimalAgeGate: "7d"` | `npmPreapprovedPackages`による永続的なcooldown除外を許可しない |
| Go／Composer | native profileなし | repository-owned verifierで公開時刻を判定する |

これらはdefense in depthであり、repository-owned pre-resolution verifierを置き換えません。
CLI option、環境変数、user-wide設定など、repository設定より優先される入力によるweakeningも
managed endpointとCIで別途監査します。緊急時はclientに永続的な除外を残さず、既存の
exact package・version・owner・期限付き例外へ戻します。

`cooldowns` repositoryのhelper scriptは、このcontrolではdownload、実行、vendoringを
しません。shell profileやsystem-wide設定の変更は明示的な端末管理changeとして扱う必要が
あり、repository cloneやverificationから暗黙に行うことを禁止します。Poetry、PDM、pixi、
Bun、Deno、Cargo、Bundler、Hex、Scala、mise等は、今後公式documentation、対応version、
fail-closed fixtureを確認してから追加する候補であり、現時点の実装済み対象ではありません。

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
8. proxy-only client profileを中央配布し、public registry egressをdenyする
9. proxy outageをcleanまたはdirect fallbackとして扱わない

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
- CLI option、環境変数、user-wide設定によるrepository profileの上書き
- client version差異、registryのupload時刻metadata欠落、設定precedenceの変化

このreference verifierは、与えられたmetadata snapshotを検査しますが、そのmetadataが
本物のregistryから取得されたことや署名済みであることは証明しません。production
integrationでは、許可したregistryからHTTPSで取得し、取得失敗をblockし、可能なら
署名・provenance・透明性情報を検証する必要があります。

cooldownはlockfile、hash／integrity、dependency review、SCA、registry制限、
install script制御と組み合わせる必要があります。

## 参考資料

- [実装仕様書](docs/implementation-spec.md)
- [Takumi Guard documentation](https://shisho.dev/docs/t/guard/)
- [Takumi Guard quickstart](https://shisho.dev/docs/t/guard/quickstart/)
- [Takumi Guard for Go](https://shisho.dev/docs/t/guard/quickstart/golang/)
- [Takumi Guard limitations](https://shisho.dev/docs/t/guard/limitation/)
- [Dependency Cooldowns](https://cooldowns.dev/)
- [mprpic/cooldowns](https://github.com/mprpic/cooldowns)
- [uv dependency resolution](https://docs.astral.sh/uv/concepts/resolution/)
- [uv settings reference](https://docs.astral.sh/uv/reference/settings/)
- [npm config reference](https://docs.npmjs.com/cli/v11/using-npm/config/)
- [npm CLI changelog: `min-release-age` added in 11.10.0](https://github.com/npm/cli/blob/latest/CHANGELOG.md#11100-2026-02-11)
- [npm registry package metadata response](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [pnpm dependency resolution settings](https://pnpm.io/settings/dependency-resolution)
- [Yarn configuration](https://yarnpkg.com/configuration/yarnrc/)
- [pip install reference](https://pip.pypa.io/en/stable/cli/pip_install/)
