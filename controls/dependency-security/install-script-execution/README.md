# PSB-DEPS-002: install時の任意コード実行をdefault denyにする

## このcontrolを一枚で理解する

### セキュリティ上の問題

Dependency installはfile展開だけではなく、lifecycle hook、native build、Python build backendを
developer端末やCIの権限で起動し得る。

### 誰から、または何から守るか

侵害・偽装されたpackage、悪意あるmaintainer、typosquatting、transitive dependency、
source distribution fallback、危険な全許可overrideから守る。

### 何が対象か

npm 12／11.16+、pnpm 11／12、Bun、pipによるdeveloper端末、pull request CI、build環境での
dependency installを対象とする。

### 何をするか

Package managerのnative default denyと明示approvalを利用し、危険なoverrideを拒否する。
pipはbinary-onlyにしてsource buildを止める。

### 成功状態

未reviewのdependency scriptまたはsource buildが実行されず、危険な全許可と設定破損が
`FAIL`または`ERROR`としてCIを停止する。

### 対象外・残余リスク

Install後のimport、test、compiler plugin、application runtime、承認済みscript、wheel内codeの安全性は
保証しない。

## 最短の導入手順

### 前提

- 対象package managerとmajor versionを固定または記録できる。
- Repository-owned configをreviewし、CIでも同じconfigを使える。
- Python 3.11+でreference verifierを実行できる。
- 既存configがある場合は上書きせず、該当keyをmerge reviewする。

### Copyまたはmergeするfile

利用するecosystemの行だけを採用する。

| Ecosystem | 対象file | 実際に変わる状態 |
| --- | --- | --- |
| npm 12／11.16+ | [`secure/npm/.npmrc`](secure/npm/.npmrc) | unreviewed install scriptをnon-zeroで停止し、全許可を禁止 |
| pnpm 11／12 | [`secure/pnpm/pnpm-workspace.yaml`](secure/pnpm/pnpm-workspace.yaml) | unreviewed buildを停止し、native approvalを明示 |
| Bun | [`secure/bun/bunfig.toml`](secure/bun/bunfig.toml) | projectとtrusted dependencyを含む全install scriptを停止 |
| pip | [`secure/pip/requirements.txt`](secure/pip/requirements.txt) | source distributionを選択せず、build backend起動を防止 |

Greenfield repositoryでは対象fileが存在しないことを確認してからcopyする。既存projectではsnippetを
該当fileへmergeし、project固有のworkspaceやdependency情報を保持する。

### Activation

1. 対象configをrepository rootのpackage managerが読む位置へ置く。
2. pipでは`--only-binary=:all:`を実際に使用するprotected requirements inputへ含める。
3. Local self-testを実行する。

```bash
python3 controls/dependency-security/install-script-execution/scripts/verify.py \
  --profile-dir controls/dependency-security/install-script-execution/secure
```

4. 同じ判定をCI required checkにする。

```bash
make verify-control CONTROL=PSB-DEPS-002
```

Expected result:

```text
PASS install execution guardrails: npm pnpm Bun and pip profiles verified
```

| Exit | 意味 |
| --- | --- |
| `0` | Reference configはこのcontrolのbaselineを満たす |
| `1` | 全許可、broad approval、source fallback等のsecurity finding |
| `2` | File欠落、parse失敗、unsupported structure等で判定不能 |

`1`と`2`をどちらもCIでblockする。Fixtureの`PASS`はadopter repositoryで設定が有効になったことを
証明しない。

### Recoveryとrollback

- Failure時はpackage manager version、config path、key、precedence、native approvalを確認して再実行する。
- 復旧のためにdangerous all-allowやsource fallbackを追加しない。
- Rollbackは、この導入でmergeしたrepository-local keyとCI wiringだけをreviewの上で戻す。
- Global package-manager、Git、shell、IDE、OS設定はこのcontrolから変更しない。

## 動作原理

Package managerはdependency graphを解決してartifactを取得した後、利用可能な形へ準備する。この準備段階に
package-controlled code execution pointがある。

```text
package publish／account compromise
              ↓
directまたはtransitive dependencyとして解決
              ↓
lifecycle hook／native build／PEP 517 backend
              ↓
developer shellまたはCI runnerの権限で実行
              ↓
credential・source・build output・network authorityへ到達
```

Node.js系では`preinstall`、`install`、`postinstall`が代表的である。Git、file、link dependencyでは
`prepare`もinstall中の実行経路になる。明示scriptがなくても`binding.gyp`から`node-gyp rebuild`が
暗黙に起動される場合がある。

pipがsource distributionを選ぶと、isolated build environmentを作り、build requirementを取得し、
PEP 517 backendを使ってmetadataとwheelを生成する。Build isolationはdependencyを分離する仕組みであり、
backend codeを実行しない仕組みではない。

## 現在のdefaultとversion境界

| Manager | Native behavior | このreferenceの選択 |
| --- | --- | --- |
| [npm 12](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/) | 未登録dependency scriptはdefault deny | `strict-allow-scripts=true`でskipだけでなくCI failureにする |
| [npm 11.16+](https://docs.npmjs.com/cli/v11/commands/npm-install-scripts/) | allow policyを導入した移行期で、versionによりunlisted behaviorが異なる | 同じstrict settingをmigration guardとして使う |
| [pnpm 11／12](https://pnpm.io/settings/build) | `strictDepBuilds=true`、unlisted build denyがdefault | defaultをrepositoryに明示し、dangerous overrideを禁止 |
| [Bun](https://bun.com/docs/pm/cli/install) | untrusted dependency scriptは実行しない。default trusted listと明示trustは別 | script不要project向けに`ignoreScripts=true`で全面停止 |
| [pip](https://pip.pypa.io/en/stable/reference/build-system/) | wheelがなければsdistのbuild backendを利用し得る | `--only-binary=:all:`でsource buildを拒否 |

安全なdefaultが存在しても、古いmajor、command-line override、user／global config、明示trustにより実効状態は
変わる。Adoption時はpackage manager versionとeffective configを確認する。

## 悪用手法

このsectionは攻撃経路をreviewできる粒度で説明する。実行可能なmalwareや外部callbackは提供しない。

| 手法 | 何が起きるか | Review point |
| --- | --- | --- |
| Malicious lifecycle hook | packageのinstall hookがshell／runtime commandを起動する | direct／transitiveを問わず未review hookを止める |
| Implicit native build | `binding.gyp`等から明示されていないbuildが起動する | 表示されたscriptだけでなくnative build要求を見る |
| Git dependency prepare | registry tarball以外のsource取得後に`prepare`が動く | exact commit、source type、prepare permissionを確認 |
| Transitive insertion | direct dependency更新が新しいscript-bearing packageを導入する | lockfile diffとpending script一覧をreview |
| pip sdist fallback | wheel不在時にbuild requirementとbackend codeが動く | binary-only failureをsource fallbackで回避しない |
| Blanket approval | 現在と将来のdependency scriptを一括許可する | dangerous flag、trust-all、name-only approvalを拒否 |
| Config precedence | repository policyがCLI、environment、user configで弱められる | supported versionのeffective configをlive確認 |
| Authority amplification | install processがCI token、SSH agent、cloud credentialを継承する | install jobから不要なcredentialとegressを外す |

Inertな理解用の例は次のようなmarker生成までに留める。

```json
{
  "scripts": {
    "postinstall": "node write-temporary-marker.js"
  }
}
```

このfixtureを実際にinstallする必要はない。重要なのは、`postinstall`の内容がpackage publisherにより
変更でき、install processのauthorityで起動する点である。

## Native approvalが必要な場合

Scriptを必要としないprojectではapprovalを作らない。必要な場合は次を確認する。

- Exact package、resolved version、artifact identity。
- 実行するscript／native buildと生成物。
- Dependency ownerとindependent reviewer。
- Version更新時の再review。
- Credentialなし、必要最小限egressのisolated buildが必要か。
- Shared exceptionが必要なら
  [PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md)のactive exact decision。

Native操作:

- npm: [`npm install-scripts ls／approve／deny`](https://docs.npmjs.com/cli/v11/commands/npm-install-scripts/)
- pnpm: [`pnpm approve-builds`](https://pnpm.io/cli/approve-builds)
- Bun: [`bun pm untrusted／trust／default-trusted`](https://bun.com/docs/pm/cli/pm)

`approve --all`、`dangerously-allow-all-scripts`、`dangerouslyAllowAllBuilds`、Bunのtrust-allを通常手順に
しない。Valid approvalがあってもpackageの安全性を意味しない。

## 安全な実装と安全でない実装

`secure/`はcopy可能なstrict baselineである。

- npmはunreviewed scriptをerrorにし、全許可overrideを無効化する。
- pnpmはnative default denyを明示し、allowlistをemptyから開始する。
- Bunはdefault denyより強い全install-script停止profileを提供する。
- pipはsource distributionを禁止する。

`insecure/`は次のinertな設定退行を示す。

- npm／pnpmのdangerous all-allow。
- pnpmのversion wildcard approval。
- Bunのstrict mode解除とsynthetic trusted dependency。
- pipの`--prefer-binary`によるsdist fallback。

## Verification

[Verifier](scripts/verify.py)はrepository fixtureのstatic propertyだけを確認する。

```bash
bash controls/dependency-security/install-script-execution/tests/test.sh
```

Testは次を区別する。

1. Secure profile: exit `0`。
2. Dangerous override／source fallback: exit `1`。
3. Missing／malformed config: exit `2`。

Network、real package、install script、build backend、provider-valid credentialは使用しない。Verifierは
effective user／global config、CI required-check設定、実際のscript blockingを証明しない。

## 誰が何をするか

- Developer: manager versionを確認し、対象configをmergeし、pending native approvalをreviewする。
- Repository administrator: verifierをrequired checkにし、policyとCI wiringの同時弱体化をreview対象にする。
- Platform／SRE: scriptが不可欠ならcredential-free、least-egressのisolated buildを提供する。
- Security: dangerous override、broad approval、例外、effective config、version更新をreviewする。

## 関連control

- [PSB-DEPS-001: release cooldownとregistry route](../release-cooldown/README.md)
- [PSB-DEPS-003: lockfileとartifact integrity](../lockfile-integrity/README.md)
- [PSB-DEPS-004: dependency change review](../dependency-change-review/README.md)
- [PSB-BUILD-001: build containment](../../build-security/build-containment/README.md)
- [PSB-DETECT-001: integrity-verified scanner](../../detection-verification/integrity-verified-scanner/README.md)
- [PSB-GOV-002: time-bound security exceptions](../../governance-operations/time-bound-security-exceptions/README.md)

## Framework mappings

これらはreview済みの関係であり、formal complianceまたはsoftware supply chain全体のcoverageを意味しない。

- [MITRE ATT&CK v19.1 T1195.001: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [NIST SSDF 1.1 PW.4.1: Acquire and Maintain Well-Secured Software Components](https://csrc.nist.gov/pubs/sp/800/218/final)

関連するframework候補。Direct mappingを追加する場合はcheck-specific rationaleを別途reviewする。

- [OpenSSF OSPS Baseline 2026.02.19 OSPS-BR-05.01: Use Standardized Dependency Management Tools](https://baseline.openssf.org/versions/2026-02-19#osps-br-0501)

## 実装・運用guide

- [npm 12 security default changes](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/)
- [npm install-script approvals](https://docs.npmjs.com/cli/v11/commands/npm-install-scripts/)
- [npm lifecycle scripts](https://docs.npmjs.com/cli/using-npm/scripts/)
- [pnpm Build Settings](https://pnpm.io/settings/build)
- [pnpm approve-builds](https://pnpm.io/cli/approve-builds)
- [pnpm supply-chain security](https://pnpm.io/supply-chain-security)
- [Bun install and lifecycle scripts](https://bun.com/docs/pm/cli/install)
- [Bun trusted dependencies](https://bun.com/guides/install/trusted)
- [Bun bunfig.toml](https://bun.com/docs/runtime/bunfig)
- [pip Secure Installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [pip Build System Interface](https://pip.pypa.io/en/stable/reference/build-system/)
- [OWASP NPM Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [CISA Securing the Software Supply Chain: Recommended Practices for Developers](https://www.cisa.gov/sites/default/files/2023-12/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.pdf)

## 制限事項

- npm 12、pnpm、Bunのdefault denyはpackage manager majorやconfig precedenceが変われば再確認が必要である。
- Bun strict profileはlegitimate native dependencyも停止する。
- Wheel-onlyはbuild backend executionを止めるがwheel内runtime codeを安全にしない。
- Install processのcredential／network isolationは別controlとadopter environmentが必要である。
- Fixture successはlive developer endpoint、CI、organization adoptionのevidenceではない。
