# PSB-CICD-007: CI runnerをjobごとに隔離し、使用後に破棄する

## このcontrolを一枚で理解する

### セキュリティ上の問題

CI runnerは、workflowに書かれたcommandを実際に動かすコンピュータです。同じself-hosted runnerを複数のjobで
使い回すと、先のjobが残したfile、書き換えたtool、動き続けるprocessが、後のjobにも影響することがあります。

特に、pull request、dependencyのinstall script、外部Actionなどの未信頼codeを実行した後、同じrunnerでreleaseや
deployを行う構成は危険です。攻撃者は先のjobで仕掛けを残し、後のjobに渡されるrepository write token、signing key、
cloud権限を盗んだり、release artifactを改ざんしたりできます。またrunnerからcloud metadata、社内network、hostの
Docker socket等へ到達できる場合は、次のjobを待たずにrunner外へ侵入される可能性があります。

### 誰から、または何から守るか

悪意あるpull requestの投稿者だけが対象ではありません。侵害されたdependencyや外部Action、意図せず危険なcommandを
実行したbuild script、改ざんされたrunner image、runnerを破棄できなかった運用障害も同じ問題を起こします。

### 何が対象か

対象はGitHub Actionsのworkflowそのものではなく、jobを実行するrunnerとその周辺です。具体的にはrunnerの選択、
self-hosted runner group、登録用の権限、起動image、workspace、process、ephemeral disk、cloud metadataや社内networkへの
接続、job終了後の破棄、調査用logを含みます。

### 何をするか

通常のbuildやtestは、jobごとに新しいVMが割り当てられるGitHub-hosted runnerを使います。実行中のprocess、network、
file操作をmanaged serviceで記録したい場合はTakumi Runnerも選べます。private network、特殊hardware、独自image等の理由で
self-hostedが不可欠なjobだけは、許可対象を限定したrunner groupへ送り、jobごとに新しいrunnerとcomputeを作成し、終了後に
computeとstorageを破棄します。

### 成功状態

連続して実行した二つのjobが別々のrunner／VMで動き、先のjobが置いた無害な確認fileを後のjobから読めない状態です。
self-hostedでは、許可したrepositoryとworkflowだけがrunner groupを使え、job終了後にGitHub上のrunner登録と実際のVM／diskが
消えます。runner内のlogを消す前に、jobとrunnerを特定できるlogが外部へ保存されている必要があります。

### 対象外・残余リスク

GitHubやmanaged runner provider内部のVM破棄や他tenantとの分離は、利用者側から完全には検証できません。providerの公開仕様、
契約、監査報告等で確認する範囲が残ります。また、GitHub cacheやartifactを介した汚染、workflow tokenの権限、job内のroot権限や
外向き通信、実行中の脅威検知は別controlの対象です。runnerをjobごとに破棄しても、これらが自動的に安全になるわけではありません。

## どのような条件で被害が起きるか

Runnerを使っただけで直ちに侵害されるわけではありません。深刻な被害につながりやすいのは、次の条件が重なった場合です。

1. pull request、dependency、外部Actionなど、攻撃者が影響できるcodeをrunnerが実行する。
2. 同じmachineが後のjobでも使われる、またはjobからhost credential、cloud metadata、社内network、runtime socketへ到達できる。
3. 後のjobまたはrunner hostに、release、deploy、signing、repository更新等の価値ある権限がある。

例えば、未信頼なtest jobが`PATH`上のtoolを書き換え、そのmachineが後でrelease jobに再利用されると、release jobが正規のtoolの
つもりで攻撃者のprogramを実行することがあります。そのprogramはrelease用tokenを外部へ送信したり、生成物へ不正なcodeを
混ぜたりできます。見た目上はtestもreleaseも成功するため、外部logがなければ発見が遅れる可能性があります。

次の条件では、このcontrolが扱うリスクは相対的に低くなります。

- jobごとに新しいVMを使い、前のjobのdiskやprocessを引き継がない。
- 未信頼codeを実行するjobにsecretやwrite権限を与えず、社内networkへ接続させない。
- release／deployを別のjobと権限境界へ分離する。

一方、GitHub上でrunnerを`ephemeral`として一job後に登録解除しても、同じunderlying VMを初期化せず再利用すればfileやprocessは
残り得ます。このcontrolではrunner登録の解除だけでなく、実際のcomputeとstorageを破棄するところまでを一つの要件にしています。

## セキュリティ向上の効果はどこから生まれるか

実際の効果を生むのは、次の設定と運用です。

- GitHub-hostedまたはmanaged runner serviceがjobごとに新しいVMを割り当て、終了後に再利用しないこと。
- Self-hostedでは、runner groupを許可済みrepository／workflowだけに限定すること。
- Self-hosted runnerをjob直前に一度だけ登録し、新しいVMから起動すること。
- Runnerからcloud metadata、管理用network、社内service、host runtime socketへ接続できないようにすること。
- Job終了後にrunner登録、VM、workspace、disk、残存processを破棄すること。
- 破棄前にrunnerの診断logを外部へ送り、失敗した場合は安全と判断せずrunnerを再利用しないこと。

このrepositoryが提供するworkflowは、設定を始めるためのcopy可能な例と無害な確認手順です。fileをcopyしただけではGitHubの
runner group、network、VMの作成・破棄は変わりません。[導入・確認runbook](docs/ADOPTION.md)に従い、実環境で設定とjob結果を
確認して初めて導入済みと判断できます。

## 誰が何をするcontrolなのか

| 担当 | 具体的な作業 |
|---|---|
| Product owner | self-hostedでなければ満たせない要件が本当にあるか判断し、managed serviceの費用とdataの扱いを承認する。 |
| Developer | 承認された`runs-on`をworkflowで使う。MacBookや日常利用する開発machineをrunnerとして登録しない。 |
| Repository administrator | 対象workflowをreviewし、どのrepository／workflowがrunner groupを使えるか限定する。 |
| Organization owner | GitHub側のrunner groupとGitHub App権限を設定し、public repositoryからの利用を既定で禁止する。 |
| Platform／SRE | self-hostedのimage、jobごとのVM作成、network遮断、log転送、VM／storage破棄を実装・運用する。 |
| Security | providerの前提、GitHub設定、実jobによる確認結果、例外、証跡の新しさをreviewする。 |
| Incident response | 外部へ保存したlogを調査し、不審なrunnerを再利用せず、関連credentialの失効へつなげる。 |

一般のDeveloperへOrganization Owner権限、cloud account、runner登録token、local Docker daemonの管理を要求しません。

## 最短の導入手順

### 通常はGitHub-hosted runnerを使う

Private networkや特殊hardwareが不要なbuild／testでは、[GitHub-hosted workflow](secure/github-hosted.yml)を使います。
追加serviceやself-hosted基盤を導入せず、jobごとに新しいVMを使えるため、最も導入負担が小さい構成です。

### 実行内容の記録も必要ならTakumi Runnerを使う

1 job 1 VMに加えて、process、network接続、file操作の記録をmanaged serviceで確認したい場合は、
[Takumi Runner workflow](secure/takumi-runner.yml)を使います。GitHub App、subscription、vendorへ送られるtrace data、
Linux x86_64／GitHub.com系という対応範囲を採用前にreviewします。Threat detectionは有用な追加機能ですが、runner破棄の代わりにはなりません。

### Self-hostedが不可欠なjobだけ自組織のJIT runnerを使う

Private network、特殊hardware、独自image等が必要なtrusted jobでは、[Self-hosted JIT workflow](secure/self-hosted-jit.yml)を
使います。この場合、GitHubの設定だけでは不十分です。Platform／SREがjobごとのfresh VM、network遮断、外部log、compute／storage
破棄を運用する必要があり、三つの構成の中で最も負担が大きくなります。

導入の共通手順:

1. 要件を満たす構成のfileを`.github/workflows/runner-isolation-self-test.yml`へcopyする。既存workflowを自動上書きしない。
2. Takumi RunnerではserviceとGitHub Appを、self-hostedでは限定runner groupとJIT provisionerを先に有効化する。
3. GitHubの`workflow_dispatch`から`force_negative=false`で二回実行する。どちらも`PASS clean runner generation`、exit `0`になることを確認する。
4. `force_negative=true`で一回実行する。このjobは意図的に確認fileを作るため、`FAIL prior-job marker exists`、exit `1`になるのが正常です。
5. Takumi Runnerでは`Runner > Jobs`のtraceを確認する。Self-hostedでは二回が別runner／computeであること、外部log到着、GitHubからの登録解除、VM／storage破棄を確認する。
6. Self-hostedでは、未許可repository／workflowがrunner groupを使えず、runnerからhost資産への無害な接続確認が拒否されることも確認する。

必要な権限、GitHubの画面項目、障害時の復旧、rollbackは[導入・確認runbook](docs/ADOPTION.md)にあります。

## Secure／insecure example

- [GitHub-hosted workflow](secure/github-hosted.yml): versionを明示したhosted VMで確認fileが残っていないことを調べる最小例。
- [Takumi Runner workflow](secure/takumi-runner.yml): `runs-on: takumi-runner`を使い、同じ確認を行う最小例。
- [Self-hosted JIT workflow](secure/self-hosted-jit.yml): 許可済みrunner groupとlabelを明示する最小例。
- [Persistent self-hosted anti-pattern](insecure/README.md): 未信頼codeをgenericな`self-hosted` runnerへ送る危険な構成。triggerは無効で、実行用ではない。

確認fileは、前のjobからhome directoryが引き継がれた場合に失敗させるための無害なmarkerです。このtestだけでVMの物理的な
破棄、host credentialの不存在、network遮断まで証明することはできません。

## Verification

本controlの安全性は、GitHubやrunner service上の実設定と、実際のVM作成・破棄から生まれます。そのため、架空のJSONに
`destroyed: true`と書いて検査する`tests/test.sh`は置きません。canonical commandは正式な確認手順への入口です。

```bash
make verify-control CONTROL=PSB-CICD-007
```

このcommandはlive環境へ接続しないため、安全だと判定せずexit `2`を返します。

```text
NOT_CHECKED PSB-CICD-007 requires external-evidence verification
See: controls/cicd-security/runner-hardening/docs/ADOPTION.md#live-verification
```

正式な判定は[Live verification](docs/ADOPTION.md#live-verification)で行います。

- `PASS`: 対象、確認元、確認時刻、確認に使った権限が明確で、GitHub設定と実job結果がすべての要件を満たす。
- `FAIL`: runner groupが広すぎる、machineが再利用された、確認fileが残った、host資産へ接続できた、logや破棄を確認できない等の問題が見つかった。
- `NOT_CHECKED`: live環境や必要な閲覧権限がなく、まだ確認していない。
- `ERROR`: GitHub API、provider、job実行、log検索等が失敗し、安全かどうか判断できない。

Workflow self-testの成功は、jobから見えるhome directoryに確認fileが残っていないことだけを示します。これをcontrol全体や
organization導入の`PASS`として扱いません。

## 既存controlとの分担

| 確認すること | 担当するcontrol |
|---|---|
| どのpull request／forkを未信頼として扱い、privileged jobから分離するか | [PSB-CICD-005](../untrusted-pr-boundary/README.md) |
| job内へ渡すcredential、root権限、外向き通信、sandbox、実行時telemetry／脅威検知 | [PSB-BUILD-001](../../build-security/build-containment/README.md) |
| `GITHUB_TOKEN`へ何の操作を許可するか | [PSB-CICD-004](../actions-least-privilege/README.md) |
| GitHub Actionsがcloud権限を得るためのOIDC trust policy | [PSB-CICD-006](../audience-bound-oidc-federation/README.md) |
| runner group等の管理設定を誰が、どの承認で変更したか | [PSB-CICD-008](../privileged-control-plane-change/README.md) |
| runnerを登録するGitHub App／tokenの保管、期限、失効 | [PSB-SOURCE-004](../../source-protection/source-access-credential-lifecycle/README.md) |
| persistent runner等を一時的に認めるsecurity exception | [PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md) |

Takumi Runnerのtrace／threat notificationやStepSecurity Harden-Runnerは、job実行中の不審なprocessや通信を見つけるための
補完策です。PSB-CICD-007は「runnerを使い回さず、調査用logを外部へ残す」ところまでを扱います。検知rule、許可する通信先、
alert対応は[PSB-BUILD-001](../../build-security/build-containment/README.md)で扱います。

## 運用負担、制約、rollback

- GitHub-hosted runnerは導入が最も簡単ですが、VM破棄や他tenantとの分離はGitHubを信頼する部分が残ります。共有VM上のcontainerで動く`ubuntu-slim`は本controlの既定例にしていません。
- Takumi RunnerではGitHub Appの権限、利用料金、trace dataの保存場所と保持期間、vendor障害時の扱いをreviewします。traceがあるだけで全攻撃を検知できるわけではなく、real-time preventionでもありません。
- Self-hosted JITは自由度が高い一方、image更新、capacity、network、log、VM／disk破棄、障害対応を組織が所有します。GitHub上でrunnerが自動的に消えただけでは、VMやdiskが消えた証拠になりません。
- cacheやartifactを介したjob間の汚染、CI service自体の侵害、log内secretのmaskingと保持期間は残余リスクです。

問題が起きた場合は、managed／self-hosted runnerへの新規job割り当てを止め、可能ならGitHub-hosted runnerへ戻します。
必要なjob要件をGitHub-hostedで満たせない場合は、安全性を確認できるまでworkflowを一時停止します。scopeを広げる、または
persistent self-hosted runnerへ戻すことを通常のrollbackにはしません。詳細は[障害時の復旧](docs/ADOPTION.md#common-failure-recovery)と
[Rollback](docs/ADOPTION.md#rollback)を参照してください。

## 関連するframework／guide一覧

`control.yaml`のmappingは関連性を示すものであり、formal complianceや完全coverageを主張しません。

| Framework／guide | Version／項目 | このcontrolとの関係 |
|---|---|---|
| [GitHub Security Guidance](../../../frameworks/github-security-guidance/README.md) | `GHAS-CONCEPT-COMPROMISED-RUNNERS`, `GHAS-REF-SECURE-USE` | self-hosted runnerへ仕掛けを残し、後続jobを侵害するriskを減らす。 |
| [NIST SSDF](../../../frameworks/nist-ssdf/README.md) | SP 800-218 v1.1, `PW.6.1` | build toolchainをreview済み・隔離済み環境で実行することをsupportsする。 |
| [OpenSSF OSPS Baseline](../../../frameworks/openssf-osps-baseline/README.md) | `2026.02.19`, `OSPS-BR-01.03` | 未信頼codeと重要なCI assetの分離をsupportsする。 |
| [MITRE ATT&CK](../../../frameworks/mitre-attack/README.md) | v19.1, [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/), [`T1133`](https://attack.mitre.org/techniques/T1133/) | cloud metadata credential取得と外部からのremote access経路をmitigatesする。 |

実装とriskを理解するための一次資料:

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
