# PSB-DEPS-003 implementation instructions

この file は `PSB-DEPS-003`（`dependency-security`）に固有の実装境界を定める。
repository root と `controls/AGENTS.md` を先に読み、共通規約をここへ複製しない。

## Control outcome and boundary

この control が守るのは、review された dependency resolution と、通常の developer／CI install が実際に使う
package version／artifact bytes の一致である。

- Committed lockfileをpackage-manager nativeのimmutable／frozen modeで使用する。
- Manifestとlockfileが不一致なら、lockfileを暗黙更新せずinstallを拒否する。
- Lockfileが記録するdirect／transitive packageのexact resolutionとartifact integrityをinstall時に検証する。
- Missing lock、missing integrity、artifact mismatch、unsupported input、package-manager failureをcleanにしない。
- Dependency update pathとnormal install pathを分離し、normal installで再解決しない。

Security効果は実際の`npm ci`、`pnpm install --frozen-lockfile`、Yarn immutable install、Bun frozen install、
またはpip hash-checkingをdeveloper／CI pathで強制することから生まれる。README、policy JSON、synthetic artifact、
独自schema verifierをcopyしただけではprojectのdependency installationは変わらない。

このcontrolは次を証明しない。

- Locked packageが無害、脆弱性なし、適切なlicense、trusted maintainerであること。
- Maliciousまたは不完全なlockfile変更がreviewで承認されないこと。
- Install script、native build、runtime behaviorが安全であること。
- Registry／proxy、package-manager binary、CI runner、review authority自体が侵害されていないこと。
- すべてのOS、CPU、runtime、workspace、peer／optional dependencyで同じphysical treeになること。

## Transitive dependencies: 正確な説明

「lockfileは推移的依存を解決しない」と一般化してはいけない。npmの`package-lock.json`、pnpm／Yarn／Bunの
lockfile、`uv.lock`、complete hashed requirementsは、通常direct dependencyから解決されたtransitive graphを
記録する。Frozen installにより、親packageのrangeだけを見て新しいtransitive versionを勝手に選び直すことを防ぐ。

ただし、lockfileが解決するのはidentityとbytesの再現であり、安全性の判断ではない。次の問題は残る。

- 悪性または脆弱なtransitive packageも、正しくlockされていれば忠実にinstallされる。
- Contributorがlockfileとintegrityを同じPRで悪性bytesへ更新すると、hashはその変更を正当化しない。
- Peer、optional、bundled、workspace、platform marker、CPU／OS別packageで、実install subsetが変わり得る。
- Git、URL、local path、editable sourceはregistry artifactと異なるidentity／integrity semanticsを持つ。
- Hoistingによりundeclared dependencyが偶然利用できる、またはtarget platformだけで不足が表面化する場合がある。

対策を次のように分ける。

1. 本control: package-manager versionとeffective configを固定し、manifest／lock freshness、complete resolved graph、
   strong integrity、clean frozen install、target別実installを検証する。
2. `PSB-DEPS-004`: base-to-headのdirect／transitive graph delta、source、vulnerability、license、provenance、
   override／resolution、non-author approvalをreviewする。
3. `PSB-DETECT-001`: current graphをSCAし、scanner／database failureをcleanにしない。
4. `PSB-DEPS-002`: lifecycle script、source build、native build executionをdefault denyまたは明示承認する。
5. `PSB-DEPS-001`: registry route、direct fallback denial、release cooldownを強制する。

READMEの早い位置に「lockfileがしてくれること」「してくれないこと」「transitive riskへのcomposition」をこの境界で
説明する。Lockfile integrityをdependency safety、SCA、meaningful reviewの代替として案内しない。

## Supported profiles and assumptions

- JavaScriptを第一級profileとする。Initial implementationはnpmとpnpmをrunnable／testedにし、複数のJS fixtureで
  transitive、workspace、peer／optional、artifact tamperを扱う。
- Modern YarnとBunも具体的なcopy可能例を用意する。ただし、対象versionをpinしnative testを実行できるまでは
  implemented profileと主張しない。Yarn ClassicをModern Yarnと同じsemanticsで扱わない。
- PythonはPython 3.11+／pip hashed requirementsとuv project lockをrunnable profileとして維持する。
- Primary developer environmentはmacOS／VS Code、CIはLinuxを想定する。Windowsは具体的requirementとtestが
  揃ってから追加する。
- Node、npm、pnpm、Yarn、Bun、Python、pip、uvはadopterが承認したruntimeをprerequisiteとする。Version、取得元、
  integrity、lockfile format compatibilityを明記し、activation中に暗黙download／upgradeしない。
- Package-manager option、default、config precedence、lockfile schemaは変わり得る。Profile変更時はcurrent official
  documentationと対象major versionの実挙動を確認する。
- Registry credential、private package名、production lockfile、developer home pathをfixtureやexpected outputへ入れない。

Current baseline sourcesは次である。これらはtool dependencyではなくbehavior review sourceである。

- [npm `ci`](https://docs.npmjs.com/cli/commands/npm-ci/)
- [pnpm install](https://pnpm.io/cli/install)
- [Yarn install](https://yarnpkg.com/cli/install)
- [Bun install](https://bun.com/docs/pm/cli/install)
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [uv project sync](https://docs.astral.sh/uv/concepts/projects/sync/)

## Implementation decision before changes

Profileを追加・変更する前に次を明示する。

1. Security stateを変えるnative commandと、lock／manifest／runtime／config fileは何か。
2. Lockfileがdirectとtransitiveのどのidentity、integrity、platform selectionを記録するか。
3. Package-managerがmanifest drift、missing lock、artifact mismatchをどのexitで拒否するか。
4. Copy対象、explicit activation、normal install、update command、CI required check、rollbackは何か。
5. Offline fixtureで検証できる範囲と、live registry route／CI protection／platform matrixでしか確認できない範囲は何か。
6. Existing controlのregistry、install execution、risk review、SCA、provenanceを重複していないか。

Official behavior、supported version、tool identity、harmless offline testのいずれかが不足する場合は、推測したsecure
sampleを追加しない。Unsupported／future adapterとして不足情報を記録する。

## Target implementation shape

実装は共通plugin engineではなく、短いprofile別wrapperとnative fixtureにする。

```text
secure/
├── javascript/
│   ├── npm/
│   ├── pnpm/
│   ├── yarn/
│   └── bun/
└── python/
    ├── pip/
    └── uv/
insecure/
├── javascript/
└── python/
tests/
├── fixtures/javascript/
│   ├── basic/
│   ├── transitive-change/
│   ├── workspace/
│   └── platform-optional/
├── fixtures/python-package/
└── test.sh
```

- Wrapperはsingle-purposeとし、固定manifest／lock pathとsecurity-critical flagsを使う。任意argument passthroughで
  frozen／integrity enforcementを無効化できないようにする。
- 以前のpackage-manager-neutral JSONと`scripts/verify.py`はprototype modelとして削除済みである。Live enforcement
  authorityとして再追加しない。Native testが同じassertionを直接証明するなら、形式維持のため二重verifierを残さない。
- Insecure exampleはdefault activationやCIから参照しない。Real package-manager inputを使い、架空schemaだけで
  unsafe stateを表現しない。
- Organization-specific registry、proxy、runtime distributionはsampleに埋め込まず、adopter tuningへ分離する。

## JavaScript profiles

### npm: required primary profile

- `package.json`とroot `package-lock.json`をcommitし、normal installは`npm ci`だけを使う。
- `npm ci`がmanifest mismatch、missing lockを拒否し、manifest／lockを書き換えないことをactual commandでtestする。
- Supported lockfile versionを明示し、external registry／tarball nodeにstrong SRI `integrity`があることをNode standard
  libraryの小さなread-only preflightで確認してよい。Weak legacy hash、missing integrity、mutable Git ref、credential
  bearing URL、unreviewed local／bundled sourceをstrict sampleでacceptしない。
- npm tree-shaping optionはrepository-local configとしてlock生成時とCIで一致させる。`legacy-peer-deps`、`force`、
  `package-lock=false`等を説明なくsecure sampleへ入れない。
- Lifecycle scriptsは`npm ci`でも実行され得るため、`PSB-DEPS-002`をcomposeする。本controlのPASSをcode execution
  safetyと表現しない。
- JS fixturesは最低限、direct package、二段transitive package、workspace、optional／peerまたはplatform-specific
  package、tampered tarballを含める。一つの巨大fixtureへ混ぜない。

### pnpm: required secondary profile

- `package.json`、`pnpm-lock.yaml`、必要な`pnpm-workspace.yaml`をcommitし、normal installは明示的に
  `pnpm install --frozen-lockfile`を使う。CI defaultへ暗黙依存しない。
- Manifest drift、missing lock、tarball integrity mismatchがhard failureになるsupported versionをpinする。
- `--update-checksums`、`--fix-lockfile`、`--lockfile-only`はreviewed update pathに限定し、normal CIのrecoveryに使わない。
- Workspace全体とfilterされたproduction installの差を説明し、lockに記録されたgraphとtargetへphysical installされる
  subsetを混同しない。
- Store reuse時もintegrity verificationを無効化しない。Store corruption／missing dataをcleanにしない。

### Yarn and Bun: additional JS examples

- Modern Yarnは`yarn install --immutable`をbaselineとする。Checked-in cache／Zero-Installs例では
  `--immutable-cache --check-cache`と`checksumBehavior: throw`を使い、external PRがcacheとlockを同時改変するriskを
  negative testする。
- Bunはcommitted text `bun.lock`と`bun ci`または`bun install --frozen-lockfile`を使い、auto-installをdisableする。
  Manifest mismatch、missing lock、platform-specific selectionをtestする。
- Yarn／BunのruntimeやActionをfloating tag／versionで取得しない。Pinned runtimeを用意できなければcommand tableだけを
  実装済みと表現せず、prerequisite不足を明記する。
- Yarn Classic、Modern Yarn、Bunのlockfile migrationを通常CIで自動実行しない。Migrationは独立update PRでreviewする。

## Python pip profile

- Complete `requirements.lock`をapplication install authorityとし、全direct／transitive requirementをexact `==`と
  local SHA-256へbindする。`pyproject.toml`のcompatible range自体はfindingにしない。
- Normal installはfresh virtual environmentで
  `python -m pip install --require-hashes --only-binary=:all: -r requirements.lock`を実行する。
- Application自体はlocked dependenciesの後に`python -m pip install --no-deps .`でinstallし、必要なら
  `python -m pip check`を実行する。
- `--no-require-hashes`、unhashed optional dependency、automatic sdist fallback、weak hashを禁止する。
- Editable、VCS、local path、direct URL、sdist、複雑なmarkerはfirst profileでunsupportedとする。PEP 508を正規表現で
  parseしてmanifest／lock一致を主張しない。

## Python uv profile

- `pyproject.toml`と`uv.lock`をcommitし、normal project installは`uv sync --locked`を使う。
- `--locked`はmanifest freshnessを確認し、missing／outdated lockを拒否する。`--frozen`はlock freshnessを確認せず
  manifest driftを無視できるため、normal CIのsecurity activationにしない。
- Wheel-only sampleでは`uv sync --locked --no-build`を追加hardeningとして示す。Source buildが必要なprojectは
  `PSB-DEPS-002`の承認境界とcomposeする。
- `uv.lock`はuv native validationをauthorityとし、独自parserでschemaやgraph equalityを再実装しない。
- Exact uv version、取得元、checksum／signature、lock schema compatibilityを明記し、activation中にdownload／upgradeしない。
- Positive、manifest drift、missing lock、transitive wheel tamper、unsupported schema、runtime unavailableをactual uv commandで
  testする。`uv sync --frozen`がmanifest driftを拒否しないことはisolated insecure exampleとして示す。
- Universal resolutionとtarget Python／OS／CPU markerで実installされるsubsetを混同しない。
- Hashed requirements利用者向けの追加例では`uv pip sync --require-hashes requirements.lock`を使い、defaultのhash存在時のみ
  検証するmodeをcomplete integrity enforcementと表現しない。

## Minimal adoption path

READMEのmandatory one-page summary直後に、npmを最初のJS path、pipとuvをPython pathとして独立表示する。

1. Package-manager／runtime version、target OS／CPU、既存manifest／lock、update ownerを確認する。
2. 対象profileのwrapper／configだけをcopyする。既存fileは上書きせずadopterがmerge reviewする。
3. Adopter自身のlockfileをreviewしてcommitする。Fixture lockをproduction dependencyとしてcopyしない。
4. Repository-local activationでclean frozen installを実行する。Global shell、IDE、package-manager設定を変更しない。
5. Safe positive、manifest drift、transitive artifact tamperのnegative self-testとexpected exitを確認する。
6. 同じcommandをCI required checkにし、normal installからmutable install commandを外す。
7. Target platform／workspace／production subsetでlive install結果を確認する。

Recoveryはruntime／config／manifest／lock／artifactをreviewed update pathで修正して再実行することである。Frozen flag、
hash check、checksum failureを無効化しない。Rollbackはcopyしたrepository-local wrapperとCI wiringだけをreviewの上で外し、
organizationのregistry／egress controlを弱めない。

## Roles

- Developer: reviewed update pathでmanifestとlockを更新し、normal installではfrozen wrapperを使う。
- Repository administrator: runtime／config／lock pathをprotected review対象にし、clean installをrequired checkにする。
- Platform／SRE: approved runtime distribution、CI image、registry route、credential injection、target matrixを管理する。
- Security: strong integrity、transitive delta handoff、override／resolution、bypass、live rejection evidenceをreviewする。

File copyだけではCI enforcementやorganization adoptionにならないことをREADMEへ明記する。

## Relationship to other controls

- `PSB-DEPS-001`: managed registry proxy、direct fallback denial、release cooldownを所有する。
- `PSB-DEPS-002`: lifecycle script、source／native build execution policyを所有する。
- `PSB-DEPS-004`: direct／transitive graph deltaとvulnerability、license、source、provenance、approvalを所有する。
- `PSB-DETECT-001`: known vulnerability scanningとscanner healthを所有する。
- `PSB-REL-001`: signature／provenance expectationとartifact subject verificationを所有する。
- `PSB-GOV-002`: shared exception lifecycleを所有する。Artifact mismatchをconvenience exceptionで`PASS`にしない。
- `PSB-CICD-*`: Action pin、permission、untrusted PR、trusted policy executionを所有する。

Hash matchはpackage safety、publisher identity、provenance、vulnerability-freeを証明しない。Override／resolutionはtransitive
remediationのupdate mechanismであり、lockを再生成・reviewした後も本controlのintegrity enforcementを通す。

## Verification strategy

Testはactual package-manager behaviorをoffline、temporary、non-destructiveに検証する。

- Repository-owned inert package sourceからlocal tarball／wheelと二段transitive graphを作る。Network、real package、
  provider credential、install script、malwareを使わない。
- Positive: correct manifest、lock、artifactでclean frozen installが成功する。
- Negative: manifestだけの変更、transitive artifactの1-byte改変、missing／weak integrity、missing lockを個別に拒否する。
- Boundary: workspaceとoptional／peer／platform-specific nodeがlockに記録され、対象install subsetが説明どおりになる。
- Error: unavailable runtime、unsupported lock schema、malformed lock、missing artifactがclean resultにならない。
- Wrapperとnative toolのexitを確認し、human-readable stderrをbrittleにparseして偽の`PASS`を作らない。
- Testはtemporary install root／venv／cacheだけを使い、global cacheやdeveloper configを変更しない。
- Outputはcredential-bearing URL、private package名、home path、raw provider responseを含めない。
- README文字列、handwritten `secure: true`、synthetic `PASS`だけを検査するtest、no-op testを追加しない。

Fixture successはreference regression evidenceであり、live lock、CI protection、registry route、organization adoptionの
evidenceではない。

## Metadata, evidence, and acceptance

- `control.yaml`をatomic checkのcanonical sourceとし、`check_context_version: "1.0"`とrow固有contextを保持する。
- Current `LOCK-001..005`は実装に合わせて狭めてよい。Registry proxyやmanifest range拒否を番号維持のため残さない。
- Checksは少なくとも、manifest／lock freshness、direct／transitive resolved graph、artifact integrity、frozen install、
  verification unavailableのfail-closedを分離する。
- README／metadataはtested profileだけをimplementedと主張し、fixtureとlive adoptionを分離する。
- Live evidenceはexact commit／lock digest、runtime version、required-check identity、実行時刻、harmless rejection resultを
  sanitizedに記録する。架空receiptや自己申告JSONを作らない。
- Framework mappingはcheck-specific relationshipであり、formal complianceやcomplete supply-chain coverageではない。

完了条件は、npmとpnpmとpipとuvのcopy pathが実行可能で、複数JS fixtureがtransitive graphとartifact tamperを示し、
Yarn／Bunのclaimがtest状態と一致し、各controlへの残余境界が一読で分かることである。

## Required verification after changes

Repository rootから少なくとも次を実行する。

```bash
bash controls/dependency-security/lockfile-integrity/tests/test.sh
make verify-control CONTROL=PSB-DEPS-003
make validate-controls
```

Metadataを変更した場合はcanonical generatorを実行し、`PSB-DEPS-003`由来のindex、mapping、checklist差分だけをreviewする。
Testを通すためにfrozen install、strong integrity、transitive coverage、fail-closed behaviorを弱めない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
