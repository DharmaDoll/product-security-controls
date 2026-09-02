# PSB-CICD-007: CI runnerをjobごとに隔離し、使用後に破棄する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | 長寿命または共有runnerでは、先行jobが残したprocess、workspace、credential、改変が後続jobへ残り、cloud metadata、host socket、management networkへの足場にもなり得る。 |
| 誰から、または何から守るか | 悪意あるcontributor、侵害されたdependency／Action、runner imageへのimplant、広すぎるrunner group、provision・log転送・teardownの失敗から守る。 |
| 何が対象か | GitHub Actionsのrunner選択、managed runner契約、self-hosted runner group、JIT registration、runner image、compute、ephemeral storage、host境界、外部log。 |
| 何をするか | 原則としてjobごとにfreshなGitHub-hostedまたはmanaged ephemeral VMを使う。self-hostedが必要なtrusted jobだけを、限定group・JIT one-job・fresh compute・host遮断・外部log・破棄のlifecycleへ載せる。 |
| 成功状態 | 二つの連続jobが別generationで動き、先行jobのmarkerを読めない。self-hostedでは許可済みrepository／workflowだけがgroupを使え、job後にrunner、compute、storageが消え、対応するlogが外部に残る。 |
| 対象外・残余リスク | GitHubまたはmanaged provider内部のtenant isolationを本PJだけで証明しない。cache、artifact、token、job内privilege／egress、runtime threat detection、CI control-plane侵害は関連controlまたはprovider assuranceの対象である。 |

## セキュリティ向上の効果はどこから生まれるか

効果はrepository内のJSONやtestからではなく、次の実設定と運用から生まれます。

- jobをfreshなVMへ割り当て、job後にそのVMを再利用しないrunner service;
- self-hostedの場合の限定runner group、JIT one-job registration、fresh compute provisioner;
- cloud metadata、management network、internal service、host runtime socketを遮断する境界;
- job完了後のderegistration、compute／storage破棄、外部log保全;
- 失敗時にrunnerを再利用せず、`ERROR`または`NOT_CHECKED`として扱う運用。

このdocumentationやworkflowをcopyしただけではrunner fleetは安全になりません。copyしたworkflowをlive環境で
有効化し、[導入・確認runbook](docs/ADOPTION.md)に従ってprovider設定と実際のjob lifecycleを確認して初めて
security stateが変わります。

## 誰が何をするcontrolなのか

| 担当 | 作業 |
|---|---|
| Product owner | self-hosted固有要件とmanaged serviceの費用・data boundaryを承認する。 |
| Developer | 承認されたworkflowの`runs-on`を使い、MacBookや常用workstationをrunner登録しない。 |
| Repository administrator | 対象workflow、branch protection、runner groupから実行できるworkflowを限定する。 |
| Organization owner | runner groupを`Selected repositories`／`Selected workflows`へ限定し、GitHub App権限をreviewする。 |
| Platform／SRE | self-hosted時のimmutable image、JIT provision、network deny、external log、compute／storage destructionを実装する。 |
| Security | provider assurance、group設定、live negative test、例外、evidence freshnessをreviewする。 |
| Incident response | 外部logへaccessし、不審なrunner generationを再利用せずcontainmentへ接続する。 |

## 最短の導入手順

まずprofileを一つ選びます。self-hosted固有要件がなければProfile Aが推奨です。

| Profile | 選ぶ条件 | copyするfile | 主な運用主体 |
|---|---|---|---|
| A. GitHub-hosted | 通常のLinux build／test。最小の導入負担を優先する。 | [secure/github-hosted.yml](secure/github-hosted.yml) | Repository administrator |
| B. Takumi Runner | 1 job 1 VMに加えてprocess／network／file traceをmanaged serviceで得たい。GitHub.com／GHEC、Linux x86_64が対象。 | [secure/takumi-runner.yml](secure/takumi-runner.yml) | Organization owner + Security |
| C. Organization JIT | private network、特殊hardware、独自image等によりorganization-owned computeが不可欠。 | [secure/self-hosted-jit.yml](secure/self-hosted-jit.yml) | Organization owner + Platform／SRE |

最短手順は共通して次のとおりです。

1. 選んだfileを`.github/workflows/runner-isolation-self-test.yml`へcopyする。既存fileを自動上書きしない。
2. Profile BはTakumi setup、Profile Cは限定runner groupとJIT provisionerを先に有効化する。
3. `workflow_dispatch`からself-testを二回実行する。両方が`PASS clean runner generation`、exit `0`であることを確認する。
4. Profile BはTakumiの`Runner > Jobs`で二回分のtraceを確認する。Profile Cは別runner generation、外部log到着、GitHubからのderegistration、compute／storage destructionを確認する。
5. Profile Cでは、未許可repository／workflowがgroupを選べないことと、runner namespaceからhost資産への無害なprobeが拒否されることを確認する。

前提条件、画面項目、positive／negative test、復旧、rollbackは[導入・確認runbook](docs/ADOPTION.md)にあります。

## Secure／insecure example

- [GitHub-hosted workflow](secure/github-hosted.yml): versioned hosted imageで無害なmarker testを行う最小例。
- [Takumi Runner workflow](secure/takumi-runner.yml): `runs-on: takumi-runner`へ切り替える最小例。
- [Self-hosted JIT workflow](secure/self-hosted-jit.yml): exact runner groupとlabelを指定する最小例。
- [Persistent self-hosted anti-pattern](insecure/README.md): generic `self-hosted` labelと長寿命hostの危険を示す、trigger無効の非deploy例。

workflow例はrunner lifecycleの入口です。provider内部のVM破棄やorganization-owned provisionerの成功を、YAMLだけで
証明するものではありません。

## Verification

本controlの本質はlive provider設定と実computeのlifecycleなので、synthetic evidenceを検査する
`tests/test.sh`は置きません。canonical commandは手順への入口として残します。

```bash
make verify-control CONTROL=PSB-CICD-007
```

live evidenceがcommandへ渡されていないため、expected resultは成功ではなくexit `2`です。

```text
NOT_CHECKED PSB-CICD-007 requires external-evidence verification
See: controls/cicd-security/runner-hardening/docs/ADOPTION.md#live-verification
```

正式な判定は[Live verification](docs/ADOPTION.md#live-verification)で行います。

- `PASS`: 対象、取得元、取得時刻、権限境界が明確なcurrent settingと実job結果が全項目を満たす。
- `FAIL`: broad group、host再利用、marker残留、host資産への到達、log欠落、teardown不成立のいずれかが確認された。
- `NOT_CHECKED`: live環境または必要な権限がなく確認していない。
- `ERROR`: API、provider、collector、pagination、job実行、log query等が失敗し、安全性を判断できない。

workflow self-testのPASSはmarker isolationだけを示し、organization adoption全体のPASSではありません。

## 既存controlとの分担

| 境界 | Owning control |
|---|---|
| 未信頼fork／PRの分類とcredential-free routing | [PSB-CICD-005](../untrusted-pr-boundary/README.md) |
| job内credential、privilege、egress、sandbox、runtime telemetry／threat detection | [PSB-BUILD-001](../../build-security/build-containment/README.md) |
| `GITHUB_TOKEN`のleast privilege | [PSB-CICD-004](../actions-least-privilege/README.md) |
| cloud OIDC trust policy | [PSB-CICD-006](../audience-bound-oidc-federation/README.md) |
| runner group等の管理面変更に対するhuman identityとaudit | [PSB-CICD-008](../privileged-control-plane-change/README.md) |
| provisioner用GitHub App／tokenのlifecycle | [PSB-SOURCE-004](../../source-protection/source-access-credential-lifecycle/README.md) |
| time-bound exception | [PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md) |

Takumi Runnerのtrace／threat notificationやStepSecurity Harden-Runnerは有用な補完です。しかし、検知機能は
runner破棄そのものではありません。PSB-CICD-007では外部logが残ることまでを扱い、検知rule、egress baseline、
alert triageは[PSB-BUILD-001](../../build-security/build-containment/README.md)側へ置きます。

## 運用上の制約とrollback

- GitHub-hostedのVM lifecycleとtenant isolationはprovider-owned assuranceです。`ubuntu-slim`は共有VM上のcontainerなので、本controlの既定例には使いません。
- Takumi Runnerは契約、GitHub App、vendor data processing、Linux x86_64／GitHub.com系の制約をreviewします。traceは全攻撃の検知やreal-time preventionを保証しません。
- Organization JITは最も自由ですが、image patch、capacity、network、log、destruction、on-callの負担を組織が所有します。runnerの自動deregistrationだけではVM wipeの証明になりません。
- 問題時は対象workflowをGitHub-hosted profileへ戻し、managed／self-hosted groupへの新規dispatchを停止します。既存runnerのscopeを広げたりpersistent runnerへ戻したりしません。
- cacheやartifact経由のcross-job state、provider control-plane、runtime compromise、secret masking、retentionは残余リスクです。

詳細は[障害時の復旧](docs/ADOPTION.md#common-failure-recovery)と[Rollback](docs/ADOPTION.md#rollback)を参照してください。

## 関連するframework／guide一覧

`control.yaml`のmappingは関連性を示すものであり、formal complianceや完全coverageを主張しません。

| Framework／guide | Version／項目 | このcontrolとの関係 |
|---|---|---|
| [GitHub Security Guidance](../../../frameworks/github-security-guidance/README.md) | `GHAS-CONCEPT-COMPROMISED-RUNNERS`, `GHAS-REF-SECURE-USE` | self-hosted runnerのpersistent compromiseを減らす。 |
| [NIST SSDF](../../../frameworks/nist-ssdf/README.md) | SP 800-218 v1.1, `PW.6.1` | build toolchainをreview済み・隔離済み環境で実行することをsupportsする。 |
| [OpenSSF OSPS Baseline](../../../frameworks/openssf-osps-baseline/README.md) | `2026.02.19`, `OSPS-BR-01.03` | untrusted codeとprivileged CI assetの分離をsupportsする。 |
| [MITRE ATT&CK](../../../frameworks/mitre-attack/README.md) | v19.1, [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/), [`T1133`](https://attack.mitre.org/techniques/T1133/) | cloud metadata credential取得とexternal remote service経路をmitigatesする。 |

実装・理解のための一次資料:

- [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub self-hosted runners reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
- [GitHub runner group access](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/manage-runners/self-hosted-runners/manage-access)
- [GitHub self-hosted runner REST API／JIT configuration](https://docs.github.com/en/rest/actions/self-hosted-runners)
- [Takumi Runner quickstart](https://shisho.dev/docs/t/runner/quickstart/)
- [Takumi Runner ephemeral VM architecture](https://shisho.dev/docs/t/runner/architecture/ephemeral/)
- [Takumi Runner limitations](https://shisho.dev/docs/t/runner/limitation/)
- [StepSecurity Harden-Runner detections](https://docs.stepsecurity.io/harden-runner/detections)
- [Repository CI/CD threat-matrix reconciliation](../../../docs/CICD_THREAT_MATRIX_RECONCILIATION.md)
- [Repository security-guidance source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-014)
