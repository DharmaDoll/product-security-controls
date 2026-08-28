# PSB-DEPS-001 実装仕様書

## 文書情報

| 項目 | 値 |
|---|---|
| Control ID | `PSB-DEPS-001` |
| Domain | `dependency-security` |
| 仕様version | `1.0` |
| 実装方式 | Native設定、repository-owned CI verifier、managed registry proxyのhybrid |
| Reference baseline | 公開後`168`時間、例外は最大`72`時間 |
| 状態 | Prototype。Fixture verificationはE3、live organization adoptionは`NOT_CHECKED` |
| 主な担当 | Developer、repository administrator、Platform／SRE、Security |

この文書の「必須」はreference implementationまたは明示したadoption profileの要件を表す。
Fixtureの成功、設定sampleのcopy、policy JSONの存在だけではlive dependency acquisitionが安全になったと
判定しない。

## 1. 目的

Dependency updateが公開直後のversionを自動採用することを防ぎ、maintainer／registry侵害の発見、
packageのyank、advisory公開等のための観測時間を確保する。

Security向上は次の実状態から生まれる。

- Resolverまたはupdate jobが公開後`168`時間未満のexact versionを選択しない。
- CIが同じ判定をrequired checkとして実行し、findingと判定不能をblockする。
- Dependency metadataとartifact取得をapproved registry／proxyへ限定する。
- Managed proxy profileでは、proxy障害時にpublic registryへfallbackしない。
- 緊急採用はexact versionへ限定した、owner・別approver・期限付き例外として扱う。

`168`時間はpackageの安全性を保証する値ではない。公開直後の攻撃に対する観測時間を設ける運用baselineで
あり、vulnerability、license、provenance、runtime behaviorの評価を代替しない。

## 2. Cooldownとlockfileの役割分担

### 2.1 異なる時間境界を守る

Lockfileとcooldownは補完関係にあり、同じ問題を解くものではない。

既存projectでreview済みのdependency graphが`package-lock.json`に固定されている場合、通常installを
`npm ci`に限定することで、npmは`package.json`との不一致時に失敗し、lockfileを書き換えずに既知versionを
再現する。これは「既に選択したversionが次のinstallで勝手に変わる」ことを防ぐ。

一方、次の操作は既存lockfileにないpackage／versionを新しくresolveする。

```bash
npm install <some-package>
npm install @bitwarden/cli
npx <some-command>
```

既存projectにlockfileがあっても、追加対象のentryはまだ存在しない。このresolution前にpublish timestampを
評価し、若すぎるversionをcandidateから外すのがcooldownである。`npx`／`npm exec`もrequested packageが
local dependencyにない場合はnpm cacheへinstallして実行し得るため、同じage gateとexecution policyを
適用する。Age gateを保証できないunversioned `npx`は許可経路にしない。

| Control layer | 守る時間境界 | 防ぐこと |
|---|---|---|
| Cooldown | 新versionをresolveする前 | 公開直後versionの即時採用 |
| Lockfile＋`npm ci` | Review済みgraphの再install | Installごとのversion driftとlockfile暗黙更新 |
| Integrity／checksum | Artifact取得後 | 同じname／versionを装うbytesの差替え |
| Install-script policy | Artifact展開・install時 | Dependency-controlled codeの自動実行 |

### 2.2 推奨する組合せ

開発負担を抑えながら守る基準構成は次とする。

1. Minimum package age: 個人開発の実用的な開始点は`72`時間、full reference baselineは`168`時間。
2. Lockfile: 必須。Manifestと同じreview単位でcommitする。
3. Normal install: npmでは原則`npm ci`とし、dependency追加／更新と通常installを分離する。
4. Install scripts: `PSB-DEPS-002`で原則禁止し、必要なexact package／versionだけをallowlist reviewする。
5. Agentによるpackage追加: Humanと同じrepository／CI policyを必ず適用し、agent固有のbypassを作らない。
6. Credential authority: Install／build／agent runtimeから不要なsource、registry publish、cloud credentialを
   除き、漏洩時のblast radiusを小さくする。

筋の良いdeveloper experienceは、HumanやAI agentへ毎回release ageの判断を求めることではない。Agentは
通常のdependency追加操作を要求できるが、package managerまたはtrusted CIが基準時間未満のversionを
物理的にresolveできず、CLI option、environment、package-wide除外で迂回できない構成にする。

### 2.3 Observation windowの意味と調整

Age gateが見るのはversionのpublish timestampだけである。Package内容を解析したり、malware判定を行ったり
する機能ではない。このcontrolは「悪性versionのpublishからcommunity／vendorによる検知・削除までの時間差」
を利用した攻撃への露出を減らす。言い換えると、他者の検知とresponseが進むための時間を買う仕組みである。

| Window | 位置付け | Trade-off |
|---:|---|---|
| `24h` | 最小の限定的guardrail | 数時間で収束するincidentには効き得るが、検知が1日を超える攻撃を通しやすい |
| `72h` | 個人開発の実用的な開始点 | 24hより観測時間を確保しつつ、通常updateの待機を抑える。ただしreference PASSではない |
| `168h` | `PSB-DEPS-001` full reference baseline | 最も強い標準profileだが、security fixも最大7日遅らせ得る |

`72h`を選ぶ個人projectは、利便性との明示的trade-offとして記録し、`COOL-003`の168時間reference stateを
満たしたと主張しない。`24h`経過も`168h`経過もpackageの安全を意味しない。長いwindowでknown-vulnerability
fixが遅れる場合は、package-wide persistent exclusionではなく、exact versionへbindした最大72時間の
`PSB-GOV-002`例外を使う。

### 2.4 高速検知incidentから得られる示唆

- [Bitwarden公式声明](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)では、maliciousな`@bitwarden/cli@2026.4.0`がnpm経由で配布された既知windowは
  2026-04-22 17:57から19:30 ETまでの93分だった。
- [Axios公式postmortem](https://github.com/axios/axios/issues/10636)では、`axios@1.14.1`が2026-03-31 00:21 UTCに公開され、最初の外部検知が
  約01:00 UTC、malicious versionの削除が03:15 UTCで、公開状態は約3時間だった。

この二つの時系列だけからの推論では、迂回不能な24時間gateでも既知の悪性window中の新規resolutionを
避けられた可能性が高く、72時間または168時間ならさらに余裕がある。しかし、すべてのincidentが24時間以内に
検知される証拠ではない。長期間潜伏するmalwareはどのwindowも通過し得る。

[Yarn公式documentation](https://yarnpkg.com/configuration/yarnrc/#npmMinimalAgeGate)も、`npmMinimalAgeGate`をnpm registryのpublish dateに基づいてversionを候補から外し、
compromised packageをinstallする可能性を下げる機能と説明している。公式settings pageは`1w`を例示し、
security pageはYarn 4.12のdefaultが`1d`であることも明記する。このcontrolは強いreference profileとして
`1w`を採用する。

### 2.5 多層防御

Cooldownを単独防御として扱わない。

```text
Human／AI agentのdependency追加要求
              |
              v
       age gate 72h／168h        PSB-DEPS-001
              |
              v
       dependency resolution
              |
              v
          lockfile固定           PSB-DEPS-003
              |
              v
      integrity／checksum        PSB-DEPS-003
              |
              v
       install scripts制限       PSB-DEPS-002
              |
              v
       sandbox／network制限      endpoint／build／AI runtime controls
              |
              v
       最小権限credential        source／CI／AI credential controls
```

Managed proxyのmalware analysis、blocking、tracking、notificationはage gateと補完関係にある。Cooldownを
通過したversionでもproxyが既知malwareをblockでき、proxyがまだ知らない公開直後versionでもage gateが
resolutionを遅らせられる。どちらのallowもpackageが安全であることを単独では証明しない。

## 3. 採用profile

### 3.1 Profile 1: native cooldown

Package manager公式のminimum-age機能をrepository-localまたはcentrally managedな設定で有効化する。
最も導入負担が小さいprofileであり、resolverに近いdefense in depthとする。

### 3.2 Profile 2: repository-owned CI verifier

Exact package／version、approved registry、publish timestamp、評価時刻を正規化し、package manager非依存の
判定器で評価する。Native機能がないecosystem、ecosystem間でのpolicy統一、CI required checkに使用する。

### 3.3 Profile 3: managed registry proxy

Dependency取得経路をorganization-managed proxyへ固定し、client fallbackとpublic registryへのdirect
egressを拒否する。Proxy service自体はこのrepositoryで構築せず、一般推奨設定、client sample、rollout、
live verification contractを提供する。

### 3.4 Adoption level

| Level | 構成 | 主張できる範囲 |
|---|---|---|
| Local guardrail | Profile 1 | 対象repositoryのnative設定がreview済み。上書きや別経路は未確認 |
| Repository enforced | Profile 1または2＋required CI | 対象update pathで168時間判定がblockされる |
| Full reference profile | Repository enforced＋Profile 3 | Proxy-only route、direct egress deny、outage fail-closedまでlive確認済み |
| Operational fallback | Lockfile＋protected branch＋human hold | 自動gateを使えないscopeのreview手順。機械的強制を主張しない |

一段低いlevelを「full adoption」と呼ばない。三profileを一つの巨大なpolicy engineへ統合せず、adopterが
必要なecosystemとlevelだけを段階的に導入できるようにする。

### 3.5 Managed proxyなしでpublic registryへ直接接続する場合

#### 3.5.1 位置付け

社内proxyを使わず`registry.npmjs.org`等のofficial public registryへ直接接続する構成は、Profile 1または
Profile 2を適用できる配備形態であり、「cooldownが必ず自動化できない」状態とは限らない。Native resolverの
minimum-age機能、またはinstallより前にtrusted metadataを読むCI verifierは、public registryをmetadata
authorityとしても動作できる。

Proxyなしで失われる主な性質は次である。

- Providerによるknown-malware解析とblock。
- Organization全体の単一取得経路、public registryへのdirect egress deny、fallback制御。
- Download tracking、breach notification、中央telemetry。
- Cache済みartifactを含むprovider側の追加検査とincident response。

このため、direct-public-registry構成はProfile 1または2で`Repository enforced`まで主張できるが、Profile 3の
live要件を満たさない限り`Full reference profile`とはしない。Proxyがないことを理由にage gateまで外さない。
Native gateもtrusted CI verifierも導入できない場合だけ、humanによるrelease-age確認とmerge holdを
`Operational fallback`として使用する。このfallbackはorganization adoptionの自動証明にならない。

#### 3.5.2 通常のdependency追加・更新

通常flowは次の順序に固定する。

1. HumanまたはAI agentはdependency専用branch／PRを作り、default branchへ直接追加しない。
2. Native gateがある場合はrepository-local settingを有効化する。ない場合はinstall前にofficial registryの
   read-only metadataから対象exact versionのpublish timestampを確認する。
3. 基準時間未満ならresolve／installせず待機する。自動gateがないfallbackではreference baselineの7日を
   merge条件とし、組織が14日へ強化する場合はdelivery delayも記録する。
4. npmでは`latest`やrange任せにせず、`npm install --save-exact <package>@<version>`でreview対象を明確にする。
   Repository全体で同じ方針を採る場合はreview済みのrepository-local `save-exact=true`も選択できる。
5. 生成された`package.json`と`package-lock.json`を同じPRへcommitし、manifestだけの変更を拒否する。
6. Dependency update jobだけが明示的にresolve／lockfile regenerationを行う。通常のlocal install、CI、release
   buildは`npm ci`を使い、lockfileを変更しない。
7. Install scriptsをdefault denyまたはexact allowlistにし、testはsecretなし、最小権限、必要最小限のegressを
   持つephemeral environmentで行う。

`npm ci`は既存`package-lock.json`を要求し、`package.json`と不一致なら失敗し、install中にmanifest／lockfileを
書き換えない。この性質はreview済みgraphからのdriftを防ぐ。一方、registry／cacheから取得したartifactの
安全性やliteralな1-bit同一性を単独で保証しない。Lockfileのintegrity、artifact verification、取得元固定は
`PSB-DEPS-003`の境界であり、このcontrolと併用する。

Unversioned `npx`／`npm exec`はlocalにないpackageをresolveして実行し得る。Native gateまたは同等の
pre-resolution判定が効くことを確認できない場合は許可せず、review済みdevDependencyと`npm ci`を使う。

#### 3.5.3 Dependabot security update PR

Dependabot security updateは脆弱dependencyを修正versionへ更新するPRを作るが、PRのCIがGreenであることは
dependencyにmalwareがないことを証明しない。特にfull CIが先に`npm ci`を行うと、merge前でもfresh artifactを
downloadし、install scriptやbuild pluginをCI authorityで実行し得る。

Proxyなしの推奨順序は次とする。

```text
Dependabot PR作成
      |
      v
trusted metadata-only age check（dependency codeを実行しない）
      |
      +-- 168h未満 --> COOLDOWN_WAIT / merge保留 / full install CIを起動しない
      |
      v
待機後にmetadata、yank／deprecation、advisory、release、provenanceを再確認
      |
      v
install-script default deny + secretなし + 最小egressのephemeral CIでnpm ci
      |
      v
full test + dependency diff review + 別reviewerのmerge承認
```

Metadata-only checkはtrusted baseのverifierとpolicyを使用し、PRが変更できるscriptやdependencyを実行しない。
Young versionはtest failureではなく`COOLDOWN_WAIT`として識別してよいが、required merge条件ではnon-passのまま
保つ。7日経過は以前の判定結果から自動的にPASSへ変換せず、current metadataとadvisory状態を再取得する。
自動gateを構築できないscopeでは、reviewerがpublish timestampとPR作成時刻を記録し、7日（組織判断で
7〜14日）のhold後に再確認する。単にPRをopenのまま残した日数をpackage ageの代用にしない。

#### 3.5.4 緊急security update

Active exploitationや重大なzero-dayにより7日待つriskが採用riskを上回る場合は、baselineを恒久的に下げず、
最大72時間のexact exceptionを使用する。少なくとも次を別approverが確認する。

1. Exact package／version、対象repository、期限、緊急性、rollback owner。
2. Official maintainer repositoryのrelease note、tag、commitとの整合性。
3. 利用可能なprovenance、Trusted Publishing等のpublisher情報、lockfile integrity。
4. Advisoryが示すfixed versionと採用versionの一致、代替mitigationの有無。
5. 必要な動的確認はdeveloper端末ではなく、secretなし、credentialなし、controlled egressの使い捨て環境で行い、
   不審な外部通信とinstall-time processを観測する。

これらはpackageの無害性を証明する手順ではない。待機を短縮したresidual riskを記録し、例外失効後は通常policyへ
自動的に戻す。緊急PRでもdeveloper／agentのpersonal credential、registry publish token、cloud credentialを
test environmentへ渡さない。

## 4. Scope

### 4.1 In scope

- Dependency updateまたはlockfile regenerationで新しく選ばれるexact package／version。
- Registryが提供するversion publish timestampとUTC評価時刻。
- `168`時間のpolicy floorと、短縮・無効化・persistent bypassの拒否。
- npm、pip、uv、pnpm、Yarnのnative cooldown reference profile。
- Go、Composerを含むrepository-owned release-age decision。
- npm、pip、Go、Composerのproxy-only client reference profile。
- Proxy outage、metadata欠落、parse failureをcleanにしないresult model。
- Exact、owned、別承認者、最大`72`時間の緊急例外。

### 4.2 Out of scope

| 対象外 | Owning controlまたは境界 |
|---|---|
| Install script、native build、source buildの実行可否 | `PSB-DEPS-002` |
| Manifest／lockfile graph、frozen install、artifact digest | `PSB-DEPS-003` |
| Vulnerability、license、source、provenance、dependency review | `PSB-DEPS-004` |
| Repository／artifact vulnerability scanning | `PSB-DETECT-001` |
| Endpoint全体のMDM、EDR、local isolation | `PSB-SOURCE-001` |
| Shared exception lifecycleとregister | `PSB-GOV-002` |
| CI Action pin、permissions、untrusted PR境界 | 該当する`PSB-CICD-*` |
| Proxy／MDM／firewall serviceの構築 | AdopterのPlatform／SRE authority |

Current fixtureはinput bindingを説明するためintegrityも検査するが、general-purpose lockfile／artifact
verificationへ拡張しない。

## 5. 前提条件とtrust assumptions

- Adopterは対象repository、ecosystem、package manager major version、dependency update pathを特定できる。
- Approved registry／proxy endpointとpublish timestampのauthorityを決めている。
- CIはtrusted policyとverifierを、untrusted PRが同じdecision内で書き換えられない位置から実行できる。
- Registry metadata取得に認証が必要な場合、read-only short-lived credentialをfork PRへ渡さずに配送できる。
- Profile 3では、Platform／SREがproxy owner、support path、availability expectation、outage recoveryを定める。
- Securityはbaselineと例外をreviewし、requesterまたはownerとapproverを分離できる。
- Package manager option、default、precedence、対応versionは採用時に公式documentationで再確認する。
- Windows固有profileは対象外とし、具体的要件とtestが揃うまで追加しない。

## 6. 役割と責務

| Role | 必須作業 | 完了証跡 |
|---|---|---|
| Product owner | 待機によるdelivery impactと緊急update優先度を決める | 対象scopeとrisk decision |
| Developer | Frozen installを使い、dependency updateをapproved command／botから行う | Repository-local effective config |
| Repository administrator | Native設定、trusted verifier、required check、protected policyを設定する | CI settingと実拒否結果 |
| Platform／SRE | Metadata access、CI template、trusted UTCを構築し、Profile 3ではproxyとdirect egress denyも構築する | Current metadata／proxy／egress evidence |
| Security | 168時間floor、例外、bypass、live routing、evidence freshnessをreviewする | Review decisionとexception status |

## 7. Repository成果物

| File | 役割 |
|---|---|
| `README.md` | 一枚summary、最短導入、検証、制限事項 |
| `docs/implementation-spec.md` | 三profile、判定契約、推奨設定、受入条件 |
| `secure/cooldown-policy.json` | 168時間floor、registry、integrity、reference exception |
| `secure/native-cooldown-policy.json` | Native profile共通要求と対象client inventory |
| `secure/registry-proxy-policy.json` | Proxy-only routeとfail-closed reference state |
| `secure/clients/` | Ecosystem別copyable client sample |
| `secure/direct-public-registry/.npmrc` | Official npm registry向けrepository-local age gate |
| `secure/lockfile.json` | Exact dependencyを表すnormalized reference input |
| `secure/registry-metadata.json` | Publish timestampを表すsynthetic reference input |
| `insecure/` | 隔離されたpolicy weakening、fallback、fresh release例 |
| `scripts/verify.py` | Offlineのreference decisionとconfig regression verification |
| `scripts/check_npm_release_age.py` | Official npm metadataを読むsingle-package pre-install adapter |
| `tests/test.sh` | Positive、negative、exception、tamper、error test |
| `expected-results/` | Sanitized deterministic output |
| `control.yaml` | Atomic checksとmappingのcanonical metadata |

Official npm registry向けread-only adapterだけを実装済みとする。他ecosystemのproduction adapter、proxy
service、MDM profile、firewall rule、production credential、架空のlive evidenceはrepository成果物にしない。

## 8. Decision flow

```text
dependency update request
        |
        +--> Profile 1: native resolver age gate
        |
        +--> Profile 2: exact version + trusted publish timestamp
        |                -> 168h decision -> CI required check
        |
        +--> Profile 3: proxy-only metadata/artifact route
                         -> direct public egress denied
        |
        v
reviewed lockfile -> frozen install -> PSB-DEPS-002 install-execution policy
```

Normal installは既にreviewされたlockfileを再現する。Cooldown判定のために毎回network resolveせず、
dependency updateまたはlockfile変更時に判定を行う。

## 9. 必須security requirements

### SR-1: Release age floor

- Effective minimumは`max(policy value, 168)`時間とする。
- `age = evaluation_time_utc - published_at_utc`で計算する。
- `age >= 168h`だけを通常許可し、boundary直前は拒否する。
- Filesystem mtime、Git time、lockfile commit time、cache ageをpublish timestampの代用にしない。

対応check: `COOL-001`、`COOL-003`。

### SR-2: Exact identityとmetadata authority

- Package名、exact version、registry originを一つのdecisionへbindする。
- Registry URLはcredential、query、fragmentを含まないapproved HTTPS originとする。
- Timestampはapproved registry／proxyのread-only interfaceから取得する。
- Missing package／version、future timestamp、origin mismatch、malformed timestampは`ERROR`またはfindingとする。
- PR本文、contributor作成の手書きtimestamp、local cache metadataをlive authorityにしない。

対応check: `COOL-004`、`COOL-006`。

### SR-3: Native cooldown

- Repository-ownedまたはmanaged templateとしてreview可能に配布する。
- Baselineを168時間未満にできる設定、persistent package exclusion、missing metadataのfail-openを拒否する。
- CLI option、environment、user-wide config等のprecedence overrideはlive verification対象とする。
- Native機能はresolver近傍のguardrailであり、cross-ecosystem authoritative decisionと誤認しない。

対応check: `COOL-009`、`COOL-010`。

### SR-4: CI verifier

- Dependency update／lockfile regeneration時に、install-time code executionより前に実行する。
- Verifier、policy、adapterはtrusted baseまたはcentrally reviewed templateから取得する。
- Exit `0`だけをmerge可能とし、exit `1`と`2`をrequired checkでblockする。
- Metadata adapterはnormalized recordを出すsingle-purpose componentとし、dynamic plugin loadingやpackage
  installationを行わない。
- Partial response、timeout、rate limit、authentication、parser、tool failureをcleanにしない。

対応check: `COOL-001`、`COOL-003`、`COOL-006`、`COOL-008`。

### SR-5: Managed proxy

- Dependency install endpointをapproved HTTPS proxyだけへ固定する。
- Client fallbackとpublic registryへのdirect egressを拒否する。
- Proxy、DNS、TLS、authentication、metadata failureを`ERROR`とし、public fallbackを行わない。
- Install／read pathとpublish pathを別endpoint、別identity、別approvalにする。
- Credentialはkeychain、approved secret store、short-lived runtime injectionで配送し、URLやfileへ埋め込まない。
- Proxy blocklist、tracking、notificationをrelease-age判定の代替にしない。

対応check: `COOL-007`、`COOL-008`。

### SR-6: Exception

- Cooldownだけを迂回するexact package、exact version、owner、具体的理由、別approver、created／expiryを要求する。
- Reference maximum durationは`72`時間とする。
- Future、expired、duplicate、unused、wildcard、package-wide、owner自己承認を拒否する。
- Registry、integrity、install execution、dependency reviewを例外で迂回しない。
- New integrationは`PSB-GOV-002`の`psb-security-exception/v1` decisionを消費する。Local JSONを新しい横断
  exception schemaへ拡張しない。
- 例外適用時もunderlying checkを`PASS`へ変更せず、applied exceptionを別状態で記録する。

対応check: `COOL-002`、`COOL-010`。

### SR-7: Outputと機密性

- Outputはpackage identifier、version、age、result、sanitized reasonに限定する。
- Credential-bearing URL、authorization header、private package名、raw provider responseを保存しない。
- Real secret、provider-valid credential、malware、production packageをrepository testで使用しない。

### SR-8: Direct public registry運用

- Direct接続先を対象ecosystemのofficial HTTPS registryへ限定し、credential-bearing URLを使用しない。
- Native gateまたはtrusted CI verifierをinstall／buildより前に適用する。
- 自動gateがないscopeでは、protected branch、別reviewer、publish timestampに基づく7日のmanual holdを必須にし、
  `Operational fallback`として記録する。
- Normal CI／releaseはcommitted lockfileからのfrozen installに限定し、dependency update jobと分離する。
- Dependency update PRが基準時間未満の場合、full install CIを開始せず`COOLDOWN_WAIT`でmergeをblockする。
- Proxyのmalware analysis、central telemetry、egress enforcementがないresidual riskを明記する。

対応check: `COOL-001`、`COOL-003`、`COOL-006`。Profile 3の`COOL-007`は`N/A`または未採用として扱い、
direct接続で満たしたと主張しない。

## 10. Profile 1 推奨設定

| Ecosystem | Repository／managed setting | 必須の拒否条件 |
|---|---|---|
| npm 11.10.0+ | `min-release-age=7` | `min-release-age-exclude*`を持たない。古いnpmのunknown-key保持をsupportと誤認しない |
| pip | `[install] uploaded-prior-to = P7D` | Timestamp非対応indexをclean扱いしない |
| uv | `exclude-newer = "7 days"` | `exclude-newer-package`を持たない |
| pnpm | `minimumReleaseAge: 10080` | Missing time、young fallback、lockfile trustをfail-openにしない |
| Yarn | `npmMinimalAgeGate: "7d"` | `npmPreapprovedPackages`を持たない |
| Go | Native profileなし | Profile 2でpublish timestampを判定する |
| Composer | Native profileなし | Profile 2でpublish timestampを判定する |

pnpmのreference値は次を含む。

```yaml
minimumReleaseAge: 10080
minimumReleaseAgeIgnoreMissingTime: false
minimumReleaseAgeStrict: true
trustLockfile: false
```

Sample変更時は対象major versionと公式documentationを再確認する。Unsupported ecosystemに推測した設定を
追加しない。

## 11. Profile 2 CI verifier仕様

### 11.1 Reference CLI

```bash
python3 scripts/verify.py \
  --policy secure/cooldown-policy.json \
  --native-policy secure/native-cooldown-policy.json \
  --proxy-policy secure/registry-proxy-policy.json \
  --lockfile secure/lockfile.json \
  --metadata secure/registry-metadata.json \
  --as-of 2026-07-27T00:00:00Z
```

`--as-of`はRFC 3339 UTCで末尾`Z`を必須とする。Testでは固定値、live adapterではtrusted UTC clockを使う。

### 11.2 Input contract

| Input | 必須内容 | Failure |
|---|---|---|
| `cooldown-policy.json` | 168時間以上、approved registries、最大72時間例外 | Invalid type／missing collectionは`ERROR`、weak policyはfinding |
| `native-cooldown-policy.json` | Schema 1.0、168時間、managed scope、no persistent bypass | Malformedは`ERROR`、weak stateはfinding |
| `registry-proxy-policy.json` | Schema 1.0、proxy-only、no fallback、outage `ERROR` | Malformedは`ERROR`、weak stateはfinding |
| `lockfile.json` | Unique exact package／version、registry、reference artifact binding | Missing／duplicate／unsafe pathは`ERROR` |
| `registry-metadata.json` | Exact package／versionのrelease UTC、registry、integrity | Missing／future／malformedは`ERROR` |

Artifact pathはlockfile directoryからのrelative pathだけを許可し、path escapeを`ERROR`にする。Artifact digest
のfull ownershipは`PSB-DEPS-003`にある。

### 11.3 Decision algorithm

1. すべてのJSON、timestamp、relative pathをparseする。読めなければexit `2`。
2. Policy floor、exception duration、native baseline、proxy stateを評価する。
3. Dependencyごとにexact identity、approved registry、metadata recordを照合する。
4. `floor((as_of - released_at) / 1 hour)`を求める。
5. 168時間未満なら、有効なexact exceptionがある場合だけage findingを抑制する。
6. Unused exceptionをfindingにする。
7. Findingが1件以上ならexit `1`、なければexit `0`とする。

### 11.4 Output contract

| Exit | Prefix／summary | 意味 |
|---:|---|---|
| `0` | `ACCEPTED <n> dependencies; <m> cooldown exception(s)` | Reference inputを受理 |
| `1` | `FAIL ...`＋`REJECTED <n> cooldown finding(s)` | Policy違反を検出 |
| `2` | stderr `ERROR ...` | Input、metadata、parser、tool failureで判定不能 |

Reference outputはlive organization adoptionを証明しない。

### 11.5 Production adapter contract

- Package manager固有graphをexact package／versionへnormalizationする。
- Approved registry／proxyから対象versionのpublish timestampをread-only取得する。
- Target、source、API／client version、取得時刻、complete scope、freshnessを記録する。
- Pagination、rate limit、timeout、permission failureをexit `2`へ変換する。
- Credential不要のmetadataはcredentialなしで取得し、必要な場合はread-only short-lived credentialを使う。
- Verifierとadapterをuntrusted PR checkoutから実行せず、fork PRへprivileged credentialを渡さない。

### 11.6 Implemented npm direct-registry adapter

`scripts/check_npm_release_age.py`はProfile 2の最小npm sliceとして、次を実装する。

- `secure/direct-public-registry/.npmrc`のofficial registry、7日floor、no exclusion、no `before`、exact save、
  lockfile有効を検査する。
- Native configはnpm `11.10.0`以上だけをsupportedとし、古いnpmがunknown keyを保持・表示することを
  enforcement evidenceにしない。古いnpmによるlocal updateはこのsliceのsupported pathに含めない。
- Exact npm package／semantic versionだけを受け付け、dist-tag、range、wildcardを入力にしない。
- `--live`を明示した場合だけ`GET https://registry.npmjs.org/{package}`を実行し、full metadataの`time[version]`
  と`versions[version]`をexact identityへbindする。
- Redirectを追わず、10秒timeout、32 MiB response上限、`application/json`、UTC timestampを要求する。
- Artifact、tarball、package codeはdownloadも実行もしない。Authentication headerやregistry credentialも使わない。
- Live modeはcurrent UTC以外を許可せず、fixture modeだけ固定`--as-of`を要求する。
- Old-enoughはexit `0`、young versionは`COOLDOWN_WAIT`とexit `1`、network／HTTP／metadata／parse failureは
  `ERROR`とexit `2`にする。

Adapterは一回に一つのpackage／versionだけを判定する。CIは`PSB-DEPS-004`がtrusted base-to-head graph delta
から列挙した全candidateへ適用し、PR作成者が指定した一件だけの成功をcomplete scopeとみなさない。

## 12. Profile 3 managed proxy仕様

### 12.1 推奨policy

| Property | 推奨値 |
|---|---|
| Mode | `managed-security-registry-proxy` |
| Distribution | MDMとCI template。必要に応じてdevcontainer／managed image |
| Direct registry egress | `denied` |
| Client fallback | `denied` |
| Outage state | `ERROR` |
| Credential handling | Keychain、secret store、runtime injection |
| Install／publish | Separate explicit paths and identities |
| Proxy minimum-age claim | 公式保証を確認できない限り`not-relied-upon` |
| Supporting capabilities | Malware blocking、download tracking、breach notification |

### 12.2 Client推奨設定

| Ecosystem | 推奨状態 | 拒否する状態 |
|---|---|---|
| npm | 単一`registry=https://<proxy>/` | 複数registry、credential-bearing URL |
| pip | 単一`index-url=https://<proxy>/simple` | `extra-index-url`、public fallback |
| Go | 単一`GOPROXY=https://<proxy>` | `,direct`、`|direct` |
| Composer | Canonical proxy＋`{"packagist.org": false}` | Packagist fallback、non-canonical proxy |

Client configだけをbypass-proofとみなさず、public registryへのnetwork egressもdenyする。

### 12.3 Minimum-age capability

Providerがminimum-age enforcementを提供する場合、次を公式仕様とharmless testで確認してから使用する。

- 対応ecosystemとprovider／client version。
- Publish timestampのsourceとtime semantics。
- Metadata欠落、provider outage、cache hit時の挙動。
- Exact version exceptionのscope、owner、expiry。
- CLI／client／alternate endpointからのbypass可否。

確認できない場合、blocklistやreputation verdictをcooldownと呼ばず、Profile 2をauthoritative decisionとして
併用する。

### 12.4 Rollout

1. 対象ecosystem、pilot repository、Platform owner、Security reviewerを決める。
2. Credentialなしのclient sampleをcopyし、`example.invalid`をapproved endpointへ置換する。
3. Effective client configとnormal installをpilotで確認する。
4. CI templateへ同じrouteとProfile 2 decisionを適用する。
5. Managed endpointへ配布し、config precedenceを確認する。
6. Public registryへのdirect egressをdenyする。
7. Harmless canary、direct access denial、proxy outageを試験する。
8. Support path、availability、exception、rollbackをreviewして対象scopeを拡大する。

## 13. 最短導入手順

### 13.1 Profile 1

1. 対象package managerの`secure/clients/` fileだけを選ぶ。
2. 既存設定がある場合は上書きせず、差分をmerge reviewする。
3. Repository-local settingとしてcopyし、168時間floorを有効化する。
4. `make verify-control CONTROL=PSB-DEPS-001`でreference self-testを実行する。
5. Effective configをread-only確認し、dependency updateだけに適用する。

### 13.2 Profile 2

1. Trusted verifierとpolicyをrepositoryまたはcentrally reviewed CI templateへ配置する。
2. 対象ecosystemのmetadata adapterを接続する。
3. Dependency update PRでpositive、fresh-version negative、metadata failureを試験する。
4. Exit `0`だけを許可するrequired checkにする。
5. Normal installをfrozen／locked modeにする。

### 13.3 Profile 3

1. `secure/clients/`から対象ecosystemのproxy sampleだけをcopyする。
2. Approved endpointへ置換し、credentialを別のapproved deliveryで設定する。
3. CI／managed endpointへ配布し、public fallbackを削除する。
4. Network policyでdirect public egressをdenyする。
5. Read-only effective config、harmless canary、outage failureを確認する。

### 13.4 Proxyなしの最短導入

1. Official registryをpublish timestamp authorityとして承認し、npmでは
   `secure/direct-public-registry/.npmrc`と`scripts/check_npm_release_age.py`だけをcopyする。
2. 既存`.npmrc`／scriptがあれば上書きせず、4設定とsingle-purpose adapterをmerge reviewする。
3. Bundled packumentでold-enough exit `0`、fresh exit `1`、missing metadata exit `2`を確認する。
4. `--live`でexact candidateをinstall前に判定し、exit `0`の後だけ`npm install --save-exact`を行う。
5. CIはtrusted graph deltaの全candidateをinstall前に判定し、exit `1`／`2`をrequired non-passにする。
6. 通常pipelineは`npm ci`とし、`PSB-DEPS-002/003/004`のinstall execution、integrity、change reviewをcompositionする。
7. 自動gateが不可能な場合だけ、branch protectionと7日のmanual holdを採用し、ownerと別reviewerを決める。
8. Proxy由来のmalware block、tracking、notification、direct egress denyがないことをresidual riskへ記録する。

Global Git、shell、IDE、package-manager、OS settingをrepository scriptから暗黙変更しない。

## 14. Verification仕様

### 14.1 Repository self-test

```bash
bash controls/dependency-security/release-cooldown/tests/test.sh
make verify-control CONTROL=PSB-DEPS-001
make validate-controls
```

最低限、次を検証する。

| Test | Expected |
|---|---|
| Stable release | 168時間以上のexact versionをaccept |
| Fresh release | 168時間未満をexit `1`でreject |
| Valid exception | Exactかつactiveな例外だけage checkを迂回 |
| Expired／unused exception | Exit `1` |
| Weak native config | Floor短縮、persistent bypass、missing-time fail-openをexit `1` |
| Weak proxy config | Direct fallback、outage clean、publish混在をexit `1` |
| Missing／malformed metadata | Exit `2` |
| Malformed native／proxy policy | Exit `2` |
| Direct npm boundary | 168時間ちょうどをacceptし、1秒未満側を`COOLDOWN_WAIT` |
| Weak direct npm config | 0日、persistent exclusion、`before`、range save、lockfile無効をexit `1` |
| Direct npm adapter failure | Missing／malformed metadataとlive clock overrideをexit `2` |
| Credential redaction | Credential-bearing registry configを拒否し、値をoutputしない |

Boundary直前（167時間59分59秒）と168時間ちょうどは、同じ固定UTC fixture内の隣接versionとして人が
読める形で検証する。

### 14.2 Live verification

| Test | 操作 | Expected |
|---|---|---|
| Effective age setting | 対象repository／managed templateの実効設定をread-only確認 | 168時間以上、persistent bypassなし |
| CI positive | Old-enoughな専用test dependency updateを評価 | Required checkが成功 |
| CI negative | Harmlessなfresh-version test inputを評価 | Install前にblock |
| Metadata failure | Test scopeでmetadata取得を失敗させる | Cleanでなく`ERROR` |
| Proxy route | Effective client configとproxy logを確認 | Approved proxyだけを使用 |
| Direct access | Public registryへのread-only接続をtest scopeで試す | Network policyが拒否 |
| Proxy outage | Pilot scopeでproxyを到達不能にする | Public fallbackせず`ERROR` |
| Provider canary | Provider公式の無害なtest packageを使用 | Artifact download前に期待どおり拒否 |

Real malware、production credential、production package、破壊的network変更をself-testに使用しない。

### 14.3 Direct public registry運用のmanual verification

| Test | 操作 | Expected |
|---|---|---|
| Exact update | Review用packageを`--save-exact`で追加 | Manifestとlockfileに同じexact versionが記録される |
| Frozen normal build | Committed lockfileで`npm ci` | Lockfileを書き換えず成功する |
| Manifest drift | Test branchでmanifestだけを安全に変更 | `npm ci`がnon-zeroで停止する |
| Fresh Dependabot input | Harmlessなfresh-version metadataを評価 | Install前に`COOLDOWN_WAIT`となりmerge不能 |
| Wait completion | 7日経過相当のtest時刻でcurrent metadataを再評価 | Ageだけでなくyank／advisory確認後に次段へ進む |
| Install isolation | Harmless test dependencyを隔離CIで処理 | Secretなし、install script拒否、許可外egressなし |

Manual holdしか採用しない場合、PRにexact version、registry publish timestamp、確認時刻、最短merge時刻、
reviewer、緊急例外の有無を記録する。この記録はそのPRの運用証跡であり、自動gateが有効だというevidenceではない。

### 14.4 Result model

| State | 意味 |
|---|---|
| `PASS` | Current settingまたは実拒否がrequired stateを証明した |
| `FAIL` | Current stateまたは実試験がunsafe stateを示した |
| `NOT_CHECKED` | Plan、authority、endpoint、evidenceがなく未確認 |
| `ERROR` | Collection、network、authentication、parse、freshness等に失敗 |
| `N/A` | Reviewed reasonにより対象ecosystem／profileが存在しない |

## 15. Evidence contract

導入完了に使用するevidenceは次を満たす。

- Target repository／CI job／managed endpoint、取得時刻、source、reviewer、authorityが分かる。
- Package managerとprovider／API major version、effective setting、policy revisionが分かる。
- CI rejectionはexact package／version、sanitized reason、exit stateへ相関できる。
- Proxy evidenceはroute、egress denial、outage behaviorをcurrent stateとして示す。
- Credential、authorization header、private package名、不要なhost／user identifierを含まない。
- Missing、stale、partial、malformed evidenceを`PASS`へ変換しない。

Fixture outputはreference regression evidenceであり、live adoption evidenceではない。実evidenceがなければ
`NOT_CHECKED`のままにし、架空のevidence fileを作らない。

## 16. 導入完了条件

### 16.1 Repository reference implementation

1. 三profileの推奨state、activation、verification、rollback、residual riskが文書化される。
2. Secure／insecure sampleが分離され、global settingを変更しない。
3. Positive、negative、exception、failure testが決定的に成功する。
4. Exit `0`、`1`、`2`がclean、finding、errorを区別する。
5. `control.yaml`の`COOL-001..010`と仕様のrequired stateが矛盾しない。
6. Direct-public npm adapterがnetwork opt-in、exact identity、live clock、redirect拒否、response上限、sanitized
   outputを実装し、fixture PASSをlive adoptionとみなさない。

### 16.2 Local guardrail adoption

1. 対象ecosystemとsupported versionが明記される。
2. Effective native configが168時間以上でpersistent bypassを持たない。
3. Positive、fresh-version negative、metadata unavailableの結果が確認される。
4. CLI／environment／user-wide precedenceの未確認範囲が記録される。

### 16.3 Repository-enforced adoption

1. Trusted metadata authorityとUTC clockが決まっている。
2. Dependency update pathがinstall前にProfile 2 decisionを実行する。
3. Exit `1`と`2`がrequired checkでblockされる。
4. Exceptionがexact、別承認者、期限付きで、expired stateがblockされる。
5. Normal installがfrozen／locked modeである。

### 16.4 Operational fallback adoption

1. Native gateとtrusted CI verifierを使えない理由と対象scopeがreviewされている。
2. Official registry、exact version、publish timestamp、最短merge時刻をPRへ記録する。
3. 7日未満のPRをGreenなtest結果だけでmergeできないbranch ruleとreview手順がある。
4. Normal pipelineはcommitted lockfileを`npm ci`等のfrozen modeで使用する。
5. Install scripts、CI secret、network egress、agent credentialの制限を実環境で確認する。
6. Human errorとdirect-registry exposureを残余riskとしてacceptし、`Repository enforced`とは呼ばない。

### 16.5 Full reference profile adoption

1. Repository-enforced adoptionを満たす。
2. Managed endpointとCIがapproved proxyだけを使う。
3. Public registryへのdirect egressとclient fallbackが拒否される。
4. Proxy outageがcleanまたはdirect fallbackにならない。
5. Install／publish identityとendpointが分離される。
6. Current live evidenceが揃い、未確認項目をfixtureで補完していない。

## 17. Recoveryとrollback

- `ERROR`時はUTC clock、metadata authority、registry／proxy availability、credential、config precedence、
  parser compatibilityを確認して再実行する。
- Recoveryのために168時間floorを下げる、persistent exclusionを追加する、public fallbackを有効化する、
  failureをcleanへ変換することを禁止する。
- 緊急security updateはProfile設定を恒久変更せず、`PSB-GOV-002`のexact expiring exceptionを使用する。
- Rollbackは導入時にcopy／参照したrepository-local configとCI wiringだけをreviewの上で外す。
- Proxy／egress rollbackはPlatform／Securityのchangeとして実施し、repository scriptから自動化しない。

## 18. 残余risk

- 168時間経過後もmalicious package、長期潜伏backdoor、typosquatting、dependency confusionは残る。
- Compromised registryが偽のpublish timestampを返す場合、reference verifierだけでは検出できない。
- Native configはCLI、environment、user-wide setting、client version差異で上書きされ得る。
- Proxy自体、proxy credential、internal registry、package manager clientの侵害は別のtrust boundaryである。
- Proxy blocklistは未知または未検知のmalwareを許可し得る。
- Cooldownによりknown-vulnerability修正の採用が遅れ、例外reviewが必要になる場合がある。
- Direct-public-registry構成では、central malware block、取得追跡、事後通知、route enforcementがない。
- Manual holdはpublish timestampの見落とし、PR ageとの取り違え、早期merge等のhuman errorを防ぎ切れない。
- 正しいage、registry、hashはpackageの安全性、license、provenanceを証明しない。

## 19. 参照

- [Control README](../README.md)
- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- [npm install](https://docs.npmjs.com/cli/install/)
- [npm CLI changelog: `min-release-age` added in 11.10.0](https://github.com/npm/cli/blob/latest/CHANGELOG.md#11100-2026-02-11)
- [npm config: `save-exact`、`ignore-scripts`、`allow-scripts`](https://docs.npmjs.com/using-npm/config/)
- [npm registry package metadata response](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [npm public registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
- [npx](https://docs.npmjs.com/cli/commands/npx/)
- [GitHub: Dependabot pull requests](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/supply-chain-security/dependabot-pull-requests)
- [GitHub: Managing Dependabot pull requests](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/manage-dependabot-prs)
- [GitHub: Automating Dependabot with GitHub Actions](https://docs.github.com/en/code-security/tutorials/secure-your-dependencies/automate-dependabot-with-actions)
- [Bitwarden Statement on Checkmarx Supply Chain Incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- [Axios npm supply-chain compromise postmortem](https://github.com/axios/axios/issues/10636)
- [Takumi Guard documentation](https://shisho.dev/docs/t/guard/)
- [Dependency Cooldowns](https://cooldowns.dev/)
- [Yarn security: age gate](https://yarnpkg.com/features/security)
- [uv dependency resolution](https://docs.astral.sh/uv/concepts/resolution/)
- [npm config reference](https://docs.npmjs.com/cli/v11/using-npm/config/)
- [pnpm dependency resolution settings](https://pnpm.io/settings/dependency-resolution)
- [Yarn configuration](https://yarnpkg.com/configuration/yarnrc/)
- [pip install reference](https://pip.pypa.io/en/stable/cli/pip_install/)
