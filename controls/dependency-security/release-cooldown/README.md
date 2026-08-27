# PSB-DEPS-001: dependency release cooldown

## このcontrolを一枚で理解する

| 項目 | このcontrolで行うこと |
|---|---|
| セキュリティ上の問題 | 公開直後のdependency versionをすぐ採用すると、maintainer侵害や悪性releaseが発見・削除される前に、開発端末やCIでそのコードを実行してしまう。 |
| 誰から、または何から守るか | 侵害されたmaintainer／registry、悪性versionを即座に取り込むupdate botやAI agent、cooldownを弱める設定drift、proxy迂回から守る。 |
| 何が対象か | 新しいdependencyの追加、既存dependencyの更新、lockfile再生成、Dependabot等のupdate PR。既にreview済みのlockfileを使う通常installは再判定の対象にしない。 |
| 何をするか | 新versionの公開から原則7日間はresolverまたはrequired CI checkで採用を止める。その後にexact versionをlockfileへ固定し、通常buildはfrozen／locked modeで再現する。 |
| 成功状態 | 7日未満のversionと判定不能なversionはinstall前かつmerge前に停止する。通常CIはreview済みlockfileだけを使い、緊急例外はexact version・別承認者・期限付きに限定される。 |
| 対象外・残余リスク | 7日経過はpackageの安全性を保証しない。長期潜伏malware、typosquatting、既知脆弱性、artifact差替え、install script、runtime behaviorは別controlで扱う。 |

## なぜ必要なのか

悪性versionが公開された瞬間に、それを「悪性」と判定できるとは限りません。利用者、security researcher、
registry、vendorが異常を発見し、警告や削除に至るまでには時間差があります。

Release cooldownは、この時間差を防御に利用します。新しいversionを一定期間採用せず、他者の検知とresponseが
進むための時間を買います。未知のmalwareを見破る機能でも、「24時間／7日経てば安全」という仕組みでもありません。

このcontrolのreference baselineは公開後7日（168時間）です。個人開発では72時間から始める判断もあり得ますが、
その場合はこのrepositoryの168時間baselineを満たしたとは扱いません。短くするほど更新しやすくなり、公開直後の
攻撃を見逃す可能性が上がります。長くするほど観測時間は増えますが、security fixまで遅らせる可能性があります。

実際のsecurity効果は、READMEやcheckerを置くことではなく、次のどれかが若いversionを本当に止めることから生まれます。

- package managerのnative age gate
- mergeを止めるtrusted CI required check
- minimum-age機能を持つmanaged registry proxy
- 自動化できない場合のprotected branchと人間によるmerge hold

## Cooldownとlockfileは役割が違う

`package-lock.json`と`npm ci`が守るのは、既に選び終えたdependency graphです。Review済みversionを固定し、
通常installのたびに別versionへ変わることを防ぎます。

Cooldownが守るのは、その一つ前です。

```text
npm install <new-package> / dependency update / unversioned npx
                         |
                         v
              まだlockfileにないversionを選ぶ
                         |
                         v
                  age gateで待たせる
                         |
                         v
               reviewしてlockfileへ固定
                         |
                         v
                  通常buildはnpm ci
```

したがって、lockfileがあるだけでは新規dependency追加時の公開直後リスクを防げません。逆に、cooldownだけでは
通常installのversion driftを防げません。両方が必要です。

## いつ、誰が、何をするか

この表が運用の中心です。

| タイミング | 担当 | 必ず行うこと | 次へ進める条件 |
|---|---|---|---|
| 初回導入 | Product owner、Security | 対象repositoryと待機期間を決める。推奨は168時間。緊急例外の承認者も決める | 対象scope、baseline、例外ownerが記録されている |
| 初回導入 | Repository administrator | Repository-local age gate、dependency update用required check、lockfile必須、通常CIのfrozen installを設定する | 7日未満と判定不能の両方がmergeできない |
| dependency追加・更新前 | DeveloperまたはAI agent | Exact versionを選び、install前にnative age gateまたはtrusted CI判定を通す | 公開後168時間以上、または有効な緊急例外がある |
| dependency PR作成時 | Developerまたはupdate bot | Manifestとlockfileを同じPRへ含める。新しく選ばれたdirect／transitive versionを明確にする | Graph差分がreview可能である |
| PR review時 | Reviewer | TestがGreenでも公開日時を確認する。若いversionはmergeせず待機する | 待機後にcurrent metadata、yank／deprecation、advisoryを再確認した |
| 通常のlocal／CI／release build | Developer、CI owner | 新しくresolveせず、committed lockfileを`npm ci`等で再現する | Manifestとlockfileが一致し、frozen installが成功する |
| 緊急security update | Product owner、Security、別approver | Exact package／versionだけを最大72時間の例外にし、追加reviewと隔離testを行う | 例外にowner、理由、承認者、作成時刻、失効時刻がある |
| metadata／proxy障害 | Repository administrator、Platform／SRE | `ERROR`として停止し、時計、registry、proxy、権限を復旧する | 判定を再実行できる。public registry fallbackやfloor短縮はしない |

AI agentだけに特別な経路を与えません。Agentはdependency追加を提案・実行できますが、人間と同じresolver設定、
required check、credential制限を通します。「Agentには自由に依存追加を要求させるが、3日／7日未満のversionは
package managerまたはCIが物理的に通さない」という境界にします。

## どの導入方法を選ぶか

最初からすべてを導入する必要はありません。npm projectなら案1から始め、team repositoryでは案2を追加します。
複数repositoryや複数ecosystemを管理する組織では案3を重ねます。

| 案 | 向いている環境 | Security効果が生まれる場所 | 位置付け |
|---|---|---|---|
| 案1: native age gate | npm、pip、uv、pnpm、Yarnの対応versionを使える | Package managerのresolver | 最小導入。Local guardrail |
| 案2: trusted CI required check | Team開発、update bot、複数ecosystem | PRが変更できないCI判定とbranch protection | Repository単位の強制境界 |
| 案3: managed registry proxy | 複数repository、managed endpoint、中央運用 | Proxy route、egress policy、provider検査 | Bypass防止とmalware検知を加える多層防御 |
| 運用fallback | Native gateもtrusted CIも使えない | Reviewerとprotected branch | 自動強制ではない。暫定運用 |

推奨構成は案1＋案2です。案3は案1／2の代わりではなく補完です。Proxyにminimum-age機能がなければ、proxyを
通しただけではcooldownになりません。

## 案1: npmで最短導入する

前提は次のとおりです。

- npm `11.10.0`以上を、開発端末とdependency update CIの両方で使う
- Official public registryへ直接接続する場合は`https://registry.npmjs.org/`を使う
- 既存の`.npmrc`を上書きせず、repository ownerが差分をreviewできる
- 通常CIを`npm ci`へ変更できる

Repository rootの`.npmrc`へ、次をmergeします。このrepositoryのcopy元は
[`secure/direct-public-registry/.npmrc`](secure/direct-public-registry/.npmrc)です。

```ini
registry=https://registry.npmjs.org/
min-release-age=7
save-exact=true
package-lock=true
```

既存`.npmrc`がなければ、次のように明示的にcopyできます。Global npm設定は変更しません。

```bash
test ! -e .npmrc
cp controls/dependency-security/release-cooldown/secure/direct-public-registry/.npmrc .npmrc
```

既存fileがある場合はcopyせず、4項目を手動でmergeしてください。特に次を確認します。

```bash
npm --version
npm config get min-release-age --location=project
npm config get save-exact --location=project
npm config get package-lock --location=project
```

期待値はnpm `11.10.0`以上、`7`、`true`、`true`です。npmは設定sourceの優先順位によりproject設定を
上書きできます。CIとmanaged endpointでは実効設定も確認し、`before`や`min-release-age-exclude`による
恒久的な迂回を許可しません。

Dependency追加は専用branchでexact versionを指定します。

```bash
npm install --save-exact --ignore-scripts package-name@1.2.3
git add package.json package-lock.json
```

7日未満のversionしかdependency条件を満たさない場合、npmのresolutionはnon-zeroで停止する必要があります。
通過後も、lockfile差分、release note、advisory、provenanceをreviewしてからmergeします。Install scriptsの
default deny／allowlistは`PSB-DEPS-002`の責務であり、ここでは例示時の自動実行を避けるため
`--ignore-scripts`を付けています。

通常の開発、CI、release buildでは次だけを使います。

```bash
npm ci
```

`npm ci`はlockfileを要求し、manifestと不一致なら失敗し、install中にlockfileを書き換えません。ただし、
dependencyの安全性やartifact bytesの真正性を単独で保証するものではありません。

## 案2: PRで確実に止める

Local `.npmrc`だけでは、開発者がCLI optionや別runtimeで迂回でき、server-sideのmergeを止められません。
Team repositoryでは、次を一般的な推奨設定とします。

1. Dependency update専用jobを、通常のfull install／testより先に置く。
2. Base-to-head graph差分から、新たに選ばれたすべてのdirect／transitive packageとexact versionを列挙する。
3. PRが同じ変更で書き換えられないtrusted policy／verifierを使う。
4. Approved registryのread-only metadataからversion publish timestampを取得する。
5. 168時間未満を`COOLDOWN_WAIT`、metadata取得・parse・時計の失敗を`ERROR`にする。
6. `COOLDOWN_WAIT`と`ERROR`をどちらもrequired checkのnon-passにする。
7. Age checkが通るまでdependency code、install script、build pluginを実行するjobを開始しない。
8. 通過後に、secretなし・最小権限・最小egressの隔離CIで`npm ci`とtestを行う。

Required checkの名前とbranch protectionはRepository administratorが管理します。Policy、verifier、exceptionを
dependency PRのauthorが同時に変更できる構成にはしません。CI Actionのpin、permissions、fork PR境界は
`PSB-CICD-*` controlを利用します。

### Dependabot PRの順序

```text
Dependabot PR
      |
      v
metadata-only age check（dependency codeはまだ実行しない）
      |
      +-- 168時間未満 --> COOLDOWN_WAIT / merge保留
      |
      +-- 判定不能 ----> ERROR / merge保留
      |
      v
待機後にcurrent metadataとadvisoryを再確認
      |
      v
secretなし・install script制限付きの隔離CI
      |
      v
dependency diff review + 別reviewer承認
```

PRがopenだった日数をpackage ageの代わりにしません。CIがGreenでもmalware不在の証明にはなりません。

## 案3: managed registry proxyを重ねる

Proxyは、各開発者がpublic registryへ直接接続してしまう別経路を減らし、known-malware blocking、download
tracking、breach notificationを追加します。実proxy、MDM、firewallはPlatform／SREが構築し、このrepositoryは
一般推奨設定とclient sampleだけを提供します。

| 項目 | 一般的な推奨設定 |
|---|---|
| Install endpoint | Approved HTTPS proxy一つだけ |
| Client配布 | MDM、CI template、必要に応じてdevcontainer／managed image |
| Public registryへのdirect egress | Deny |
| Client fallback | Deny。npmのalternate registry、pipの`extra-index-url`、Goの`,direct`／`|direct`等を残さない |
| Proxy障害 | `ERROR`として停止。Public registryへfallbackしない |
| Credential | URLやrepositoryへ保存せず、keychain／secret store／short-lived runtime injection |
| Installとpublish | Endpoint、identity、権限、承認を分離。Install identityにpublish権限を与えない |
| Minimum age | Providerの公式保証とharmless testを確認できる場合だけ168時間を設定。確認できなければ案1／2を併用 |
| 追加機能 | Malware blocking、download tracking、breach notificationを有効化 |

[`secure/clients/`](secure/clients/)にはnpm、pip、Go、Composer等のcredential-free sampleがあります。
`example.invalid`をapproved endpointへ置換し、既存設定へmerge reviewしてください。Client configだけで
bypass-proofとはみなさず、network policyでもdirect public egressを拒否します。

Rolloutはpilot repository → CI template → managed endpoint → egress deny → proxy outage testの順です。
Outage時だけ使える一時的なpublic fallbackは作りません。

## Proxyを使えない場合

Proxyがなくても、npm等のnative age gateまたは案2のtrusted CI checkはofficial registry metadataを使って
動作できます。Proxyなしで失われるのは、中央malware解析、経路強制、取得追跡、事後通知です。

Native gateもCI gateも導入できない場合に限り、次を暫定運用にします。

1. Reviewerがofficial registryでexact versionのpublish timestampを確認する。
2. 7日未満ならtestがGreenでもmergeしない。必要なら7〜14日へ強化する。
3. 待機後にcurrent metadata、yank／deprecation、security advisoryを再確認する。
4. Manifestとlockfileを同じPRへcommitし、通常CI／本番buildは`npm ci`だけを使う。
5. Branch protectionで別reviewerを必須にし、PRへpublish時刻、確認時刻、最短merge時刻を残す。

これは人間によるcooldownであり、自動強制やorganization-wide adoptionとは呼びません。

## `check_npm_release_age.py`の位置付け

[`scripts/check_npm_release_age.py`](scripts/check_npm_release_age.py)は補助的なread-only checkerです。
このscript自体はnpmの動作を変更せず、`npm install`を横取りせず、PRのmergeも止めません。

実行したときだけ、次を確認します。

- 指定した一つの`.npmrc` fileが、official registry、7日floor、exact save、lockfile有効等の期待値を持つか
- 指定した一つのexact package／versionのpublish timestampが、official npm registry metadata上で7日以上前か
- Metadataや入力が壊れていないか

確認しないものも重要です。

- CLI、environment、user-wide configを含むnpmの最終的な実効設定
- PRで新たに選ばれたdependency graph全体
- Checkerが毎回呼ばれていること
- npmやbranch protectionが結果を強制していること
- Packageのmalware、vulnerability、provenance、artifact integrity

したがって、checkerをcopyして一度`ACCEPTED`が出てもcontrol導入完了ではありません。設定例の確認、
troubleshooting、offline fixture test、CI adapterを設計する際の参考として使います。Productionで使うなら、
全candidateをtrusted側で列挙し、終了コード`0`以外をrequired checkでblockする別のwiringが必要です。

```bash
python3 scripts/check_npm_release_age.py \
  --config .npmrc \
  --package package-name \
  --version 1.2.3 \
  --live
```

| Exit | 意味 |
|---:|---|
| `0` | 指定した一候補は設定されたageを満たす |
| `1` | 若すぎる、または渡した設定fileがreference baselineを満たさない |
| `2` | 入力、network、HTTP、metadata、parse等の理由で判定不能 |

## 緊急security update

Active exploitationや重大なzero-dayでは、7日待つこと自体が危険になる場合があります。そのときも
`.npmrc`のfloorを恒久的に下げたり、package-wide exclusionを残したりしません。

最大72時間の例外へ次を記録します。

- exact packageとexact version
- 対象repository
- ownerと別approver
- 待機を短縮する具体的理由
- 作成時刻と失効時刻
- release note、tag／commit、advisory、provenance、integrityの追加確認
- rollback owner

必要な動的確認は、developer端末ではなく、secretなし・credentialなし・controlled egressの使い捨て環境で
行います。例外はcooldownだけを迂回し、registry、integrity、install execution、dependency reviewを迂回しません。
Shared exception lifecycleは`PSB-GOV-002`が所有します。

## 多層防御として使う

```text
新しいversion
    |
    v
age gate 72h／168h                 PSB-DEPS-001
    |
    v
dependency resolution
    |
    v
lockfile固定 + frozen install     PSB-DEPS-003
    |
    v
integrity／checksum                PSB-DEPS-003
    |
    v
install scripts制限               PSB-DEPS-002
    |
    v
sandbox／network制限              endpoint／build／AI runtime controls
    |
    v
最小権限credential                source／CI／AI credential controls
```

Proxyのmalware判定とcooldownは同じものではありません。Cooldownを通過したversionでもproxyが既知malwareを
止められます。Proxyがまだ知らない公開直後versionでもage gateが時間を稼げます。どちらも単独でpackageの
安全性を証明しません。

## 何を試せば導入済みと言えるか

### Repository sampleのself-test

```bash
bash controls/dependency-security/release-cooldown/tests/test.sh
make verify-control CONTROL=PSB-DEPS-001
make validate-controls
```

このtestは、old-enough、fresh、boundary直前、weak config、期限切れ例外、metadata errorをsynthetic fixtureで
区別します。全testが想定どおりならcommand全体はexit `0`となり、少なくとも次を表示します。

```text
PASS stable and exact-exception dependencies accepted
PASS direct-public npm age check accepts the boundary and waits before it
PASS direct-public npm config weakening metadata failure and clock override fail closed
```

内部のpositive fixtureはold-enough versionを`ACCEPTED`／exit `0`、negative fixtureはfresh versionを
`COOLDOWN_WAIT`／exit `1`、metadata failureを`ERROR`／exit `2`として確認します。Test suiteは期待した
negative resultを観測したうえで全体をexit `0`にします。Fixtureの成功はreference implementationの
regression testであり、実環境への適用証拠ではありません。

### 実環境で確認すること

| Test | 実際の操作 | 成功状態 |
|---|---|---|
| Effective setting | 対象repository／CIでpackage managerの実効設定をread-only確認 | 168時間以上、persistent exclusionなし |
| Fresh-version negative | Review済みの無害なfresh versionをtest branchで評価 | Artifact／dependency code実行前にnon-pass |
| Metadata failure | Test scopeでmetadata取得を失敗させる | Cleanではなく`ERROR`、merge不可 |
| Normal build | Committed lockfileで`npm ci` | Lockfileを変更せず成功 |
| Manifest drift | Test branchでmanifestだけを変更 | `npm ci`がnon-zeroで停止 |
| Dependabot flow | Fresh update PRを作る | Age判定前にfull install CIを実行せず、merge保留 |
| Proxy route（採用時） | Effective config、proxy log、direct接続を確認 | Proxyだけを使い、public direct accessを拒否 |
| Proxy outage（採用時） | Pilot scopeでproxy到達不能を試す | Public fallbackせず`ERROR` |

Real malware、production credential、production package、破壊的network変更はtestに使いません。Providerが
公式のharmless canaryを提供する場合だけ、その手順を利用します。

### 導入完了の判定

少なくとも次が揃ったとき、対象repositoryで導入済みと判断できます。

1. Dependency追加／更新時のage gateが明示され、168時間未満を実際に拒否した。
2. 判定不能が`ERROR`となり、required checkを通過しない。
3. Manifestとlockfileが同じPRでreviewされ、通常CI／releaseはfrozen installを使う。
4. Agent、bot、developerのいずれも同じpolicyを通る。
5. 緊急例外がexact、別承認者、期限付きである。
6. 未確認のlive設定をfixtureのPASSで補っていない。
7. Proxyを採用した場合は、direct egress、fallback、outageも実環境で確認した。

## 安全な例と安全でない例

`secure/`には168時間policy、native client設定、proxy-only client設定、lockfile／metadata fixtureがあります。
`insecure/`には0時間cooldown、persistent exclusion、public fallback、credential-bearing URL、metadata fail-open等を
隔離してあります。いずれもproduction設定やlive evidenceではありません。

## Recoveryとrollback

`ERROR`時は、UTC clock、registry／proxy到達性、metadata authority、権限、package manager version、設定の
優先順位を直して再実行します。復旧のためにfloorを下げる、persistent exclusionを追加する、public fallbackを
有効化する、errorをcleanへ読み替えることは禁止します。

Rollbackでは、この導入で追加したrepository-local設定とCI wiringだけをreviewの上で外します。既存`.npmrc`へ
mergeした場合は追加した項目だけを戻します。Proxyやegress controlはPlatform／Securityのchangeとして扱い、
repository scriptから自動変更しません。Required checkを外す前に、同等以上のenforcementへ移行済みか確認します。

## 既存controlとの分担

| Control | このcontrolでは扱わないこと |
|---|---|
| `PSB-DEPS-002` | Install script、native build、source buildのdefault deny／allowlist |
| `PSB-DEPS-003` | Manifest／lockfile graph、frozen install、artifact digestの本格的な検証 |
| `PSB-DEPS-004` | Dependency差分、vulnerability、license、source、provenance、non-author review |
| `PSB-DETECT-001` | Repository／artifact vulnerability scanning |
| `PSB-SOURCE-001` | Endpoint全体のMDM、EDR、local isolation |
| `PSB-GOV-002` | Shared security exception lifecycleとregister |
| `PSB-CICD-*` | Action pin、workflow権限、fork／untrusted PR境界 |

## Framework mapping

Canonical mappingは[`control.yaml`](control.yaml)にあります。次の関係は、このcontrolが各framework全体を満たす、
またはpackageの安全性を証明するという意味ではありません。

| Framework | Version／ID | Relationship | このcontrolとの関係 | 主なatomic checks |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise | `v19.1` / `T1195.001` Compromise Software Dependencies and Development Tools | `mitigates` | 公開直後versionの自動採用とproxy迂回を減らし、software dependency compromise直後の露出を狭める。悪性dependency自体の検出は行わない | `COOL-001`、`002`、`003`、`007`、`008`、`009`、`010` |
| NIST SSDF | `1.1 (SP 800-218, 2022)` / `PW.4.1` Acquire and Maintain Well-Secured Software Components | `supports` | Third-party componentの取得元、version、公開時刻、例外を管理し、controlled acquisitionとmaintenanceを支援する | `COOL-001`〜`005`、`007`〜`010` |

`COOL-006`のfail-closed error handlingには、現時点でreview済みのframework mappingを付けていません。
Mappingはadoption evidenceでもformal compliance claimでもありません。

## 残るリスク

- 168時間経過後もmalicious packageや長期潜伏backdoorは採用され得る。
- Compromised registryが偽のpublish timestampを返す場合、age判定だけでは検出できない。
- Native設定はCLI、environment、user-wide設定、package manager version差異で上書きされ得る。
- Proxy自体、proxy credential、internal registry、package manager clientも侵害され得る。
- Cooldownによってknown-vulnerability fixが遅れ、緊急例外が必要になる場合がある。
- Direct public registry構成では中央malware blocking、取得追跡、事後通知、egress enforcementがない。
- Manual holdはpublish timestampの見落としや早期mergeを防ぎ切れない。
- 正しいage、registry、lockfile、hashはpackageのmalware不在、license、provenanceを証明しない。

## 参考資料

- [実装仕様書](docs/implementation-spec.md)
- [npm installと`min-release-age`](https://docs.npmjs.com/cli/install/)
- [npm config reference](https://docs.npmjs.com/cli/v11/using-npm/config/)
- [npm CLI changelog](https://github.com/npm/cli/blob/latest/CHANGELOG.md)
- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- [npm registry package metadata response](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [Yarn security: age gate](https://yarnpkg.com/features/security)
- [uv dependency resolution](https://docs.astral.sh/uv/concepts/resolution/)
- [pnpm dependency resolution settings](https://pnpm.io/settings/dependency-resolution)
- [Dependency Cooldowns](https://cooldowns.dev/)
- [Bitwarden Statement on Checkmarx Supply Chain Incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- [Axios npm supply-chain compromise postmortem](https://github.com/axios/axios/issues/10636)
