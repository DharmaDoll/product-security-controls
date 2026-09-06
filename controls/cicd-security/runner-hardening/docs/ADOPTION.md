# PSB-CICD-007 adoption and live verification runbook

このrunbookは、copyするfileより先にlive runnerのtrust boundaryを決めます。real token、JIT configuration、
provider response、private log本文をrepositoryへcommitしないでください。

## Prerequisites and trust assumptions

共通前提:

- GitHub.comまたはGitHub Enterprise CloudでGitHub Actionsを利用している。
- [PSB-CICD-005](../../untrusted-pr-boundary/README.md)に従い、未信頼PRをprivileged workflowから分離している。
- workflowの`permissions`、secret、OIDCはそれぞれのowning controlで制限されている。
- self-test用workflowを追加でき、`workflow_dispatch`を二回実行できる。
- live evidenceを確認するRepository administratorまたはOrganization ownerがいる。

構成ごとの追加前提:

| 構成 | 追加の前提 |
|---|---|
| GitHub-hosted | GitHub standard hosted runnerを利用できる。provider-owned lifecycleを受容する。 |
| Takumi Runner | Shisho Cloud organization、有効なsubscription、GitHub Organization admin、Takumi Manager／API Integration Manager、GitHub Appとtrace dataのvendor review。 |
| Organization JIT | fresh computeをjobごとに作成・破棄できるPlatform／SRE、GitHub runner管理権限、immutable image、network policy、external log backend、on-call。 |

このcontrolのためにlocal Docker daemon、global Git setting、developer workstationへのrunner登録は不要です。

## GitHub-hosted runnerを使う場合

GitHubはstandard hosted runnerについて、single-CPUの`ubuntu-slim`を除きjobごとにnew VMを提供すると説明しています。
通常のbuild／testではこれを最短baselineにします。

### Activate

1. [secure/github-hosted.yml](../secure/github-hosted.yml)を対象repositoryの
   `.github/workflows/runner-isolation-self-test.yml`へcopyする。
2. `runs-on: ubuntu-24.04`を維持する。別OSが必要なら、[GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)でGAかつVM-basedのversioned labelを選ぶ。
3. Pull requestで`permissions: {}`、`workflow_dispatch`のみ、third-party Actionなしであることをreviewしmergeする。

### Harmless self-test

1. GitHubの`Actions > Runner isolation self-test - GitHub hosted > Run workflow`を開く。
2. `force_negative=false`で二回実行する。
3. 二回とも`PASS clean runner generation for run ...`、job exit `0`であることを確認する。
4. `force_negative=true`で一回実行する。inert markerをそのjob自身が作成するため、`FAIL prior-job marker exists`、job exit `1`がexpectedです。
5. negative run後に`force_negative=false`を再実行し、exit `0`へ戻ることを確認する。

このtestが確認するのはjob-visibleなhome stateの分離とfail branchです。GitHub内部のhypervisor、disk wipe、
tenant isolationを独立にattestしません。provider assuranceは[GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)と契約条件でreviewします。

## Takumi Runnerを使う場合

Takumi RunnerはGitHub Actions self-hosted runnerとして連携し、vendor documentation上はjobごとにdedicated ephemeral
VMを作成・破棄します。process、network、file traceを取得できます。導入は軽量ですが、GitHub App権限、契約、
data processing、retention、availabilityはmanaged provider boundaryになります。

### Activate

1. [Takumi Runner quickstart](https://shisho.dev/docs/t/runner/quickstart/)のprerequisitesを満たす。
2. Shisho Cloud consoleの`Runner > Setup`でRunner featureとusage-based subscriptionを明示的に有効化する。
3. setup wizardの`Install GitHub App`で`Only select repositories`を選び、対象repositoryだけをinstall scopeへ含める。Organization Ownerが[GitHub App permissions](https://shisho.dev/docs/t/runner/architecture/integration)をreviewする。
4. GitHub Organizationの`Settings > Actions > Runner groups`で、`takumi-runner`が登録されるgroupを確認する。`Repository access`を`Selected repositories`へ設定し、対象だけを追加する。public repository accessは既定でoffに保つ。
5. plan／groupがworkflow restrictionをsupportする場合は`Workflow access`を`Selected workflows`にし、対象のowner／repository／pathとreview済みrefだけを許可する。
6. [secure/takumi-runner.yml](../secure/takumi-runner.yml)を
   `.github/workflows/runner-isolation-self-test.yml`へcopyし、review後にmergeする。

Public repositoryを対象にするにはGitHub側の`Allow public repositories`が必要ですが、未信頼contributorがjobを
起動できる範囲とorganization課金が広がります。採用する場合は[PSB-CICD-005](../../untrusted-pr-boundary/README.md)の
trust decisionと費用上限を先にreviewしてください。

### Harmless self-test

1. `force_negative=false`を二回dispatchし、両方がexit `0`になることを確認する。
2. Shisho Cloudの`Runner > Jobs`で二つのjobを開き、別job identityでprocess／network／file traceが到着していることを確認する。
3. `force_negative=true`を一回dispatchし、exit `1`になることを確認する。traceに`touch`とfailureが含まれることを確認するが、command argumentにsecretを入れない。
4. `force_negative=false`を再実行し、前jobのmarkerがないことを確認する。
5. test用の未許可repositoryがある場合だけ同workflowを置き、2分以内にTakumi側でVM／traceが作られないことを確認してqueued jobをcancelする。test repositoryがなければrunner groupのread-only setting reviewをnegative evidenceとし、dispatchしたと偽らない。

Takumi traceの存在は全攻撃の検知を保証しません。制約は[Takumi Runner limitations](https://shisho.dev/docs/t/runner/limitation/)をreviewしてください。Threat notificationを使う場合、そのruleとtriageは[PSB-BUILD-001](../../../build-security/build-containment/README.md)のruntime detectionとして管理します。

## Organization-owned JIT runnerを使う場合

この構成はprivate network、特殊hardware、独自image等でmanaged runnerを使えないtrusted job向けです。
GitHub runnerの`ephemeral`／JIT登録と、underlying computeのfresh provision／destructionは別のpropertyです。
両方を実装してください。

### Activate

1. GitHub Organizationの`Settings > Actions > Runner groups > New runner group`で
   `psb-one-job-runners`を作成する。
2. `Repository access`を`Selected repositories`、`Workflow access`を`Selected workflows`へ設定する。public repository accessをoffにし、review済みworkflow path／refだけを許可する。
3. Platform／SREは、job要求ごとにreview済みimage digestからfresh VMまたは同等のdestroyable computeを作る。containerだけを削除して同じprivileged host、workspace、runtime socket、credentialを再利用する構成は不可です。
4. [GitHub JIT configuration endpoint](https://docs.github.com/en/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-an-organization)でone-job runnerをgroupへ登録する。encoded JIT configurationをfile、image、log、repositoryへ保存しない。API authorityは[PSB-SOURCE-004](../../../source-protection/source-access-credential-lifecycle/README.md)で管理する。
5. runner namespaceからcloud metadataのIPv4／IPv6、management CIDR、internal service、host runtime socketをdenyする。jobが必要とするpublic egressは[PSB-BUILD-001](../../../build-security/build-containment/README.md)で管理する。
6. ordinary SSH等のinteractive ingressを閉じ、break-glassをrunner identityから分離する。
7. runner／worker diagnostic logをjob IDとrunner generationに紐付けてexternal backendへ転送する。
8. job終了後にGitHubからderegisterし、compute、workspace、ephemeral disk／key、残存processを破棄する。log export failure時もhostをpoolへ戻さない。
9. [secure/self-hosted-jit.yml](../secure/self-hosted-jit.yml)のgroupとlabelを実値へ変更し、
   `.github/workflows/runner-isolation-self-test.yml`へcopyする。

このpackageはcloud／Kubernetesを一つに固定しないため、credential-bearing toy provisionerを提供しません。provider
固有のactivation、destroy API、network boundaryをPlatform／SREが既存基盤へ実装します。

### Harmless self-test

1. `force_negative=false`を二回dispatchし、両方がexit `0`になることを確認する。
2. provisionerとGitHubのread-only viewで、二回のjob IDが異なるrunner generation／compute IDへ対応することを確認する。
3. 一回目のlogが外部backendへ到着した後、runnerがGitHubから消え、compute、workspace、ephemeral storageがprovider上でdestroyedであることを確認する。
4. `force_negative=true`でexit `1`、その後の`force_negative=false`でexit `0`に戻ることを確認する。
5. test repository／workflowを使い、未許可scopeからgroupへdispatchされないことを確認する。production release workflowでnegative testをしない。
6. adopterが定義したmetadata endpoint、management test endpoint、host socketへ、response bodyを保存しない無害なconnection probeをrunner namespaceから行い、すべてdenyされることを確認する。任意のinternal addressを推測でscanしない。

## Live verification

Securityまたはcontrol ownerは次を一つのreviewとして実施します。workflow self-testだけを全体の`PASS`にしません。

| Check | Live確認 | 必要なactual evidence | PASS condition |
|---|---|---|---|
| `RNR-001` | workflowの`runs-on`とcurrent runner groupをread-only確認する。 | workflow revision、group visibility、selected repositories／workflows、public access setting | 全jobが承認済みrunner構成へ一致し、self-hosted scopeにwildcardや未信頼workflowがない。 |
| `RNR-002` | 連続二jobのdispatch、runner generation、compute IDを相関する。 | GitHub job IDs、runner IDs、provider provision／destroy events | self-hosted／managed ephemeralは1 job 1 fresh computeで再利用されない。 |
| `RNR-003` | managed providerのcurrent image contract、またはself-hosted image digestとrunner versionを確認する。 | provider documentation／release、image digest、provenance verification、version decision | mutable imageやunsupported runner versionを使用しない。 |
| `RNR-004` | 二回のpositive marker testとstartup stateを確認する。 | workflow run links、sanitized startup observation | prior marker、foreign process、host／cloud／SSH credentialがない。 |
| `RNR-005` | adopter定義のmetadata、management、internal、host socket probeを実runnerから行う。 | targetを秘匿化したdeny result、network policy revision | host authorityへの全probeがdenyされる。 |
| `RNR-006` | registration authority、interactive ingress、break-glassをreviewする。 | JIT request metadata、TTL／one-use decision、firewall setting、break-glass approval path | reusable tokenを保持せず、ordinary ingressがなく、break-glassが分離される。 |
| `RNR-007` | job完了後のGitHubとcompute providerを確認する。 | deregistration event、exact-generation compute／storage destruction event | runner、compute、workspace、storage、processが定義時間内に消える。 |
| `RNR-008` | destruction前後にexternal backendをqueryする。 | job ID／runner generation付きlog query result | investigationに必要なrunner logがlocal disk外へ残る。 |
| `RNR-009` | API permission denial、partial result、provider／log outage時の運用を確認する。 | error result、runbook／alert、assignment停止記録 | 判断不能を`PASS`にせず`ERROR`または`NOT_CHECKED`とし、unsafe generationを再利用しない。 |

Evidence recordには、control ID、対象organization／repository／workflow、runner構成、取得元、取得時刻、collectorの
権限境界、job ID、runner generation、判定、reviewerを含めます。provider responseの必要fieldだけを保存し、token、
encoded JIT config、authorization header、secret-bearing command line、private log本文をcontrol repositoryへcommitしません。

判定規則:

- `PASS`: 全適用checkにcurrentかつcompleteなlive evidenceがある。
- `FAIL`: 一つ以上のsecurity propertyが成立しない。
- `NOT_CHECKED`: live環境、権限、対象runner構成がなく確認していない。未導入と同義ではなく、未確認です。
- `ERROR`: collector、API、pagination、provider、workflow、log query等が失敗した。clean resultではありません。

`make verify-control CONTROL=PSB-CICD-007`はlive credentialを受け取らず、exit `2`と手順linkを返します。

## Adoption completion criteria

導入完了は次をすべて満たす状態です。

- 対象jobとrunner構成、runner group、責任者が記録されている。
- copyしたworkflowのpositive二回、negative一回がexpected exit statusになった。
- 適用する`RNR-001`から`RNR-009`のlive evidenceをreviewし、未適用項目には理由がある。
- log、image update、capacity、failure recovery、periodic review、incident accessのownerが割り当てられている。
- synthetic fixtureやREADMEの存在をorganization adoption evidenceとしていない。

## Common failure recovery

| Failure | Recovery |
|---|---|
| jobがqueuedのまま | `runs-on` label、runner groupのselected repository／workflow、subscription、GitHub App install scope、capacityを確認する。scopeを`All repositories`へ広げて解決しない。 |
| marker testがFAIL | 対象generationをquarantine／destroyし、persistent host、home mount、workspace mount、snapshot reuseを調査する。clean directoryだけ作って再開しない。 |
| runnerは消えたがcomputeが残る | 新規assignmentを停止し、provider側compute／disk／keyをdestroyする。GitHub deregistrationをwipe evidenceにしない。 |
| external logがない | 対象generationを再利用せずdestroyし、exporter、permission、retention、correlation keyを修復して再testする。 |
| metadata／management probeが到達 | 新規jobを止め、network／host boundaryをdenyへ修正し、露出したidentityをowning controlでrotate／containする。response bodyをticketやlogへ貼らない。 |
| provider／APIが失敗 | `ERROR`として扱い、last-known-goodをcurrent `PASS`にしない。manual read-only confirmationかservice recovery後の再取得を行う。 |

## Rollback

1. 問題のあるmanaged／self-hosted groupへの新規dispatchを停止する。
2. 対象workflowの`runs-on`をreviewの上で[GitHub-hosted runner構成](../secure/github-hosted.yml)へ戻す。job要件が満たせなければworkflowを一時停止する。
3. active runnerをderegisterし、provider側compute／storageをdestroyする。log保全が必要ならIncident responseの指示に従う。
4. Takumiを撤去する場合はworkflow labelを戻し、GitHub App install scope、subscription、data retentionをvendor runbookに従ってreviewする。
5. self-test workflowが不要になった場合だけrepositoryから削除する。global developer settingは変更していないためlocal rollbackは不要です。

Persistent self-hosted runnerやbroad runner groupへ戻すことはrollbackではなくsecurity exceptionです。
[PSB-GOV-002](../../../governance-operations/time-bound-security-exceptions/README.md)でowner、期限、代替策を管理してください。

## References

- [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub self-hosted runners reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
- [GitHub runner group REST API](https://docs.github.com/en/rest/actions/self-hosted-runner-groups)
- [GitHub JIT runner REST API](https://docs.github.com/en/rest/actions/self-hosted-runners)
- [Takumi Runner quickstart](https://shisho.dev/docs/t/runner/quickstart/)
- [Takumi Runner GitHub integration](https://shisho.dev/docs/t/runner/architecture/integration)
- [Takumi Runner ephemeral VM model](https://shisho.dev/docs/t/runner/architecture/ephemeral/)
- [Takumi Runner limitations](https://shisho.dev/docs/t/runner/limitation/)
- [Takumi Runner threat detection](https://shisho.dev/docs/r/202608-takumi-runner-threat-detection/)
- [StepSecurity Harden-Runner detections](https://docs.stepsecurity.io/harden-runner/detections)
