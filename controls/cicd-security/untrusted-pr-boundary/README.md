# PSB-CICD-005: forkと未信頼PRをprivileged CIから分離する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Pull request（PR）の作成者は、PR内のcode、test、build script、dependencyを変更できる。ただし、PRを作成しただけでrepositoryやsecretを奪取できるわけではない。実害が成立するのは、概ね次の三条件が揃った場合である。

1. PR作成者が変更できるcommandやdependencyがworkflow上で実際に実行される。
2. そのjobから、write可能なtoken、workflowで参照されたsecret、OIDC、protected Environment、persistent runner、internal network、または後続jobが信用するstateへ到達できる。
3. 攻撃codeがAPI操作、外部通信、runnerへの永続化、またはtrusted consumerへのpoisoningによって、その権限を利用できる。

例えば、`contents: write`が実効権限として付与されれば、そのscopeとbranch／rulesetの許す範囲でcommit、tag、release等を変更できる可能性がある。Workflowで参照されrunnerへ渡されたsecretは、log maskingがあっても外部HTTP通信等で持ち出せる。`id-token: write`はそれ単体でcloud管理権限ではないが、cloud側trust policyがそのworkflowのclaimを受理する場合は一時cloud credentialを取得できる。したがって被害は一律ではなく、実効権限と外部側policyによって決まる。

GitHub公式documentationでも、`GITHUB_TOKEN`はjobごとに発行され`github.token` contextからActionが参照できること、workflowが参照したsecretは悪意ある処理に取得され得ること、log redactionは意図的な持ち出しを防ぐsecurity boundaryではないことが説明されている。詳細は[`GITHUB_TOKEN` behavior](https://docs.github.com/en/actions/concepts/security/github_token)と[compromised runner impact](https://docs.github.com/en/actions/concepts/security/compromised-runners)を参照する。

ここでいう「権限奪取」は、必ずorganization administratorやGitHub account全体を乗っ取るという意味ではない。Workflow jobへ意図して与えた権限を、PR作成者のcodeが本来の目的外で利用できる状態を指す。被害範囲は、そのtokenやcredentialが許すrepository、package、cloud role、deployment target等に限定される。

逆に、forkからの`pull_request`がread-only token・secret非配送で動き、jobがpersistent runnerやtrusted cacheへ到達せず、後続処理もその出力を実行しないなら、上記の高権限奪取経路は大きく制限される。このcontrolは、その状態をworkflow textだけで推測せず、provider設定と実runで確認する。

### 誰から、または何から守るか

PRを作成または更新でき、workflowが実行するfileや入力を制御できる悪意あるfork contributor、侵害されたcontributor account、意図せず危険になったbuild／test、`pull_request_target`の誤用、PR由来のcache／artifactを過度に信頼する設計から守る。PR内容が実行されず、権限あるconsumerにも渡らない場合は、このattack pathは成立しない。

### 何が対象か

PRを処理するGitHub Actions workflow、実行するrevision、`GITHUB_TOKEN`、secret、OIDC、Environment、runner、cache／artifact、reusable workflow、権限を持つ後続処理。

### 何をするか

最初に、どのstepがPR作成者の変更を実行するかと、そのstepから何へ到達できるかを調べる。「PR作成者が変更できるものを実行するjob」は未信頼と分類し、write token、参照secret、OIDC、protected Environment、persistent runner等を外す。権限が必要な処理は、未信頼codeや未検証artifactを実行しない別の境界へ分ける。このreferenceでは、PRをread-onlyの`pull_request` jobで検証し、権限処理はreview／merge後の別runへ置く。

### 成功状態

すべてのPR関連jobについて、誰が変更できるcodeを実行するか、実効token permission、配送されるsecret、OIDC可否、Environment approval、runner到達性、後続data flowが確認されている。未信頼codeが権限を利用できる経路がなく、確認できない項目は`PASS`ではなく`NOT_CHECKED`または`ERROR`になっている。

### 対象外・残余リスク

Reference workflowのcopyだけでは、既存の危険なworkflowを無効化せず、GitHubのfork setting、branch／Environment protection、runner-group policyも変更しない。導入先で設定と実runを確認する必要がある。

## まず、このcontrolの本質を理解する

危険なのは特定のevent名そのものではない。未信頼処理、利用可能な権限、悪用経路の三つがつながることである。

```text
PR作成者が変更できる処理が実行される
                    +
その処理から重要な権限やstateへ到達できる
                    +
API・外部通信・後続consumer等の利用経路がある
                    =
具体的な被害へ進めるtrust-boundary violation
```

「PR作成者が変更できるもの」には、source codeだけでなく、`Makefile`、test、package lifecycle hook、compiler plugin、configuration、artifact、cache、workflow outputも含まれる。

「権限」には、secretやwrite可能な`GITHUB_TOKEN`だけでなく、OIDC、protected Environment、release署名鍵、persistent self-hosted runner、internal network、後続のtrusted buildが信用するcacheも含まれる。ただし、名前がworkflowに書かれているだけでは利用可能とは限らない。Event、repository／organization設定、job-level permission、secret参照、Environment protection、cloud側trust policyを合わせて実効状態を判断する。

したがって、このcontrolが要求する不変条件は三つだけである。

1. 何がPR作成者に変更可能かを特定する。
2. それを実行する場所には、奪われて困る権限や到達性を置かない。
3. 権限を持つ処理へ移る場合、未信頼runのcodeや実行可能stateをそのまま持ち込まない。

このrepositoryが提供する2-workflow方式は、この条件を分かりやすく満たすための保守的なreferenceである。「あらゆるrepositoryで必ずmerge後まで全処理を待て」という唯一の実装方式ではない。

具体例として、現在のworkflowが`pull_request_target`でPR branchをcheckoutし、secretを使って`make test`しているとする。このcontrolでは、まず`make test`をsecretなしで動く部分とsecretが必要な部分へ分ける。前者はread-onlyのPR workflowで実行し、後者はreview済みcodeから始まる別runへ移す。つまり、同じtestを別名で追加するのではなく、「未信頼codeを実行する場所から権限を移動する」のが変更内容である。

## 何が、どの条件で被害になるか

| 対象 | 被害が成立する主な条件 | 起こり得ること | 条件が揃わない例 |
|---|---|---|---|
| `GITHUB_TOKEN` | 未信頼処理が動くjobにwrite scopeが実効付与され、そのscopeで対象操作が許可される | branch／tag／release／issue等の変更。Exact impactはscopeとruleset次第 | Fork `pull_request`でread-onlyへ制限され、write APIが拒否される |
| Repository／organization secret | WorkflowまたはActionがsecretを参照し、jobへ配送された後に未信頼処理が動く | External endpointへの送信、外部serviceへのなりすまし | Fork PRへsecretが配送されない、またはworkflowがsecretを参照しない |
| Environment secret | JobがEnvironmentを参照し、branch ruleやrequired reviewer等のprotectionを通過する | Deploy credentialやproduction endpointの悪用 | JobがEnvironmentを参照しない、またはapproval前に停止する |
| OIDC | Jobに`id-token: write`があり、cloud側trust policyが発行されたclaimを受理する | 一時cloud credentialの取得と、そのroleが許す操作 | `id-token: write`がない、またはcloud側subject／audience条件で拒否される |
| Self-hosted runner | 未信頼処理がpersistent filesystem、daemon socket、host credential、internal networkへ到達する | Credential窃取、横展開、後続jobへの永続化 | Jobごとに破棄され、privileged mountやinternal routeを持たない隔離runner |
| Cache／artifact／output | 未信頼runが内容を作り、後のprivileged consumerがcode、dependency、script、unsafe inputとして利用する | Trusted buildやreleaseへのcode injection | Consumerがdigestとproducerを検証し、非実行dataとして安全にparseする |

この表は「対象が存在すれば必ず侵害される」という判定ではない。実際のworkflowについて左から右へdata flowをたどり、条件が成立する経路だけをfindingとする。

### 対応優先度の目安

これは固定severityではなく、導入先でのtriage順序である。

- 最優先: 未信頼codeが、release／package公開権限、cloud credential、production secret、write token、またはinternal networkを持つpersistent runner上で実行される。
- 高: PR由来artifact、cache、output、dependencyを、署名・release・deployを行う後続jobが実行する。前段がread-onlyでも後段のauthorityを間接利用できる。
- 要設計review: `pull_request_target`等でmetadataだけを処理するが、PR title／bodyをshellへ展開する、permissionが目的より広い、将来checkoutを追加しやすい。
- Referenceの許容状態: Fork PRがGitHub-hosted runnerで動き、effective tokenはread-only、secret／OIDC／Environmentなし、後続privileged consumerなし。この場合もcompute abuse、public network通信、test結果の偽装等は残るが、repository／cloud権限奪取の主要経路は遮断される。

## 導入前に方式を選ぶ

最初に、PRで何を実行し、なぜ権限が必要なのかを整理する。次の表から最も近い方式を選ぶ。

| 状況 | 推奨方式 | 主な副作用 |
|---|---|---|
| Public forkを受け付け、testをcredential-freeにできる | このreferenceをそのまま使う | private dependencyやshared cacheを使いにくい |
| Private dependencyが必要だがmock／mirrorへ置換できる | PRではmock／credential-free mirror、実物はmerge後test | PR段階の検証範囲が狭くなる |
| PRへlabelやcommentを書きたいがPR codeは実行しない | metadata-onlyの`pull_request_target`を別workflowとして設計 | input injectionと将来のcode-loading追加を継続reviewする必要がある |
| Self-hosted runnerが不可欠 | [`PSB-CICD-007`](../runner-hardening/README.md)でone-job、ephemeral、network-isolatedなrunnerを先に用意する | 運用、cost、isolation verificationが増える |
| Merge前にproduction相当のsecretやnetworkが必須 | このreferenceを無理に適用せず、credential scope、isolated Environment、data flowを個別設計する | 設計とlive negative testが必要で、単純copyでは安全にならない |

権限が必要な理由が「今のtestがそう作られているから」だけなら、まずtestをcredential-freeに分割する。逆に、規制、hardware、private dataset等の理由で分割できない場合は、referenceの制限を黙って緩めず、例外ではなく別のtrust designとしてreviewする。

## Reference implementationをcopyすると何が起こるか

二つのfileは役割が異なる。

| File | 起動条件 | 実際に行うこと | 行わないこと |
|---|---|---|---|
| [`secure/pr-validation.yml`](secure/pr-validation.yml) | PRの作成・更新 | GitHub-hosted runnerでPRのmerge revisionをcheckoutし、credentialをGitに残さず`make test`を実行する | Secretを参照せず、write permission、`id-token: write`、Environment、deployを設定しない |
| [`secure/trusted-after-merge.yml`](secure/trusted-after-merge.yml) | `main`へのpush | review済みbranchから新しいrunが始まったことを示すread-onlyのboundary markerを実行する | PR runのartifactやoutputを受け取らず、referenceのままではrelease／deployもしない |

`pr-validation.yml`を`.github/workflows/`へ置いてdefault branchへmergeすると、その後のPRでvalidation jobが起動する。JobはPRの変更内容を実行するため、未信頼jobとして扱う。`GITHUB_TOKEN`を完全に消すのではなく、checkoutに必要な`contents: read`だけを与え、write scope、secret参照、OIDC、Environmentを持たせない。

`trusted-after-merge.yml`は、PR runと権限処理を分ける位置を示す最小templateである。Copy直後は`echo`するだけであり、production deployは開始しない。実際のreport、release、deployを追加するときは、そのjobに必要な権限だけを[`PSB-CICD-004`](../actions-least-privilege/README.md)に従って追加する。

Copyしても、次のことは自動では起こらない。

- 既存の`pull_request_target`、`workflow_run`、self-hosted PR workflowは停止しない。
- Repository／organizationのtoken、fork、runner、Environment設定は変わらない。
- Default branchのreviewやrequired checkは有効にならない。
- `make test`がsecretなしで成功するようにはならない。
- PR artifactやcacheを使う別workflowの安全性は確認されない。

このため、file copyではなく「既存経路のinventory → reference導入 → provider設定 → 実run確認」までが導入作業である。

## 最短の導入手順

### 1. 既存のPR実行経路を確認する

Repository rootで次を実行し、該当行を人が確認する。

```bash
rg -n 'pull_request_target|pull_request|workflow_run|issue_comment|self-hosted|secrets:|environment:|permissions:|actions/cache' \
  .github/workflows
```

確認する問いは次のとおり。

- PRが変更できるcode、script、dependency、artifact、cacheはどれか。
- それを実行または読み込むjobはどれか。
- そのjobにsecret、write token、OIDC、Environment、self-hosted runner、internal networkはあるか。
- 後続workflowがPR由来のdataをcodeとして実行していないか。

Workflowが存在しない、検索できない、dynamicな呼出しを分類できない場合は`PASS`ではなく`NOT_CHECKED`とする。

### 2. PRで残す処理を決める

PR jobには、secretなしで安全に失敗できるlint、unit test、build等だけを残す。Private registry、release、deploy、production dataを必要とする処理は、credential-freeな代替へ置き換えるかtrusted phaseへ移す。

ここで「何をPR段階から外すか」を決めずにworkflowだけcopyすると、testが失敗するか、後から権限を戻して境界を壊すことになる。

### 3. 二つのfileをcopyする

既存fileを上書きしない。既に同名fileがあれば停止し、差分を人がmergeする。

```bash
test ! -e .github/workflows/pr-validation.yml
test ! -e .github/workflows/trusted-after-merge.yml
cp controls/cicd-security/untrusted-pr-boundary/secure/pr-validation.yml \
  .github/workflows/pr-validation.yml
cp controls/cicd-security/untrusted-pr-boundary/secure/trusted-after-merge.yml \
  .github/workflows/trusted-after-merge.yml
```

変更してよい箇所は、default branch名、approved runner label、`make test`、trusted phaseの処理である。Third-party Actionのfull commit SHA、top-level `permissions: {}`、checkout credential非保存は維持する。

### 4. GitHub側の防御を有効にする

Repository administratorが`Settings > Actions > General`を開く。

1. `Workflow permissions`をread-onlyへ設定する。
2. `Allow GitHub Actions to create and approve pull requests`を無効にする。
3. Private forkを使う場合、`Send write tokens`と`Send secrets and variables`を無効にする。
4. Fork workflow approvalを有効にする。Public repositoryでは外部contributor全員のapprovalを推奨する。
5. Default branchのrulesetでreviewと`pr-validation` required checkを必須にする。
6. PR workflowがself-hosted runner groupやprotected Environmentを選べないことを確認する。

Organization／enterprise policyがrepository設定を上書きする場合がある。画面の有無とeffective settingは[GitHub Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)と[fork workflow approval](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)で確認する。

Approvalはcompute abuseを抑えるための手順であり、PR codeをtrustedに変えたりsecretを渡してよい根拠にはならない。

Environment required reviewerも同様に、approval前はjob開始やEnvironment secretへのaccessを止めるgateである。Approval後はjobがsecretを利用できるため、未信頼codeを実行するjobへEnvironmentを付けたまま「人が押すから安全」とは判断しない。ReferenceのPR jobはEnvironment自体を参照しない。[Environment protectionの挙動](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)も導入先planを含めて確認する。

GitHub.comでは、forkからの`pull_request`は通常read-only `GITHUB_TOKEN`かつsecret非配送になる。一方、private forkではorganization／repository ownerがwrite tokenやsecret配送を許可できる。また、同一repository内branchからのPRや`pull_request_target`等はforkと同じ制限ではない。このためevent名だけを見ず、workflowの明示的permission、secret参照、providerのeffective settingを確認する。Provider差の詳細は[events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)と[Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)を参照する。

### 5. 新旧workflowの役割を切り替える

新しいPR validationが動くことを確認してから、既存workflowのうち未信頼codeと権限を同居させる経路を削除またはtrusted-onlyへ変更する。Referenceを追加しただけで古い危険な経路が残っていれば、このcontrolは未導入である。

Trusted phaseに処理を移す場合は、PR runのworkspace、artifact、cache、job outputをそのまま実行しない。Review済みbranchを新しくcheckoutし、必要な入力はdataとして検証する。

## 導入の副作用と判断基準

この方式は強い分離を行うため、副作用がある。問題がないのではなく、導入前に受け入れるか代替設計する必要がある。

| 副作用 | なぜ起こるか | 現実的な対応 |
|---|---|---|
| Fork PRでprivate dependencyを取得できない | secretを渡さないため | public／read-only mirror、mock、merge後integration testへ分ける |
| PR feedbackが遅くなる | cacheを保守的に使わない、testを分割するため | secretを含まないread-only cacheを[`PSB-CICD-009`](../cache-provenance-isolation/README.md)で別途設計する |
| Merge後にしか検出できない問題が増える | privileged integration testを後段へ移すため | merge queue、staging branch、即時rollback、small PRを組み合わせる |
| CI実行回数とcostが増える | PR runとtrusted runを分けるため | trusted phaseを必要なbranch／pathに限定する |
| External contributorの待ち時間が増える | fork run approvalが必要なため | reviewer ownerと応答時間を決める。Approval省略で権限を渡さない |
| Self-hosted hardware／networkを使えない | referenceがGitHub-hosted runnerを選ぶため | isolated ephemeral runnerを別controlとして構築する |

安全性と開発速度のtrade-offを隠さない。副作用を許容できない場合は、権限をPR jobへ戻すのではなく、上の方式選択へ戻ってtrust boundaryを再設計する。

## Harmless self-test

### Positive test

1. 権限を持たないtest accountのforkからdocumentation-only PRを作る。
2. PR runの`Set up job`でeffective token permissionがread-only以下であることを確認する。
3. GitHub-hosted runnerで`pr-validation`だけが実行されることを確認する。
4. Merge前に`trusted-after-merge`が開始しないことを確認する。
5. Review後にmergeし、trusted runがmergeされた`main` commitから新しく開始することを確認する。

期待結果は`make test`のexit `0`、PR jobの`success`、PR runとtrusted runが別run IDであること。Secret値をcanaryとして置かず、production処理をself-testに使わない。

### Negative test

Disposable fork PRで`pr-validation.yml`へ`contents: write`を要求する変更だけを加える。Write操作は追加せず、mergeしない。

- Runtime確認では、fork settingによりeffective permissionがread-onlyへ制限されること。Writeになれば`FAIL`。
- Source reviewでは、不要なwrite要求自体を`FAIL`とし、required reviewによってmergeしないこと。
- Manual approval後もsecret、Environment、self-hosted runnerが解禁されないこと。

Jobはwrite操作をしないため、test command次第でexit `0`になり得る。Job成功をsecurity reviewの`PASS`と読み替えない。Manual reviewのprocess exit statusは`N/A`と記録する。

このnegative testで確認できるのはtokenのeffective permissionとreview運用である。Secret非配送を証明するために本物のsecretやcanary credentialを出力・送信してはならない。Secret参照がないこと、fork settingが無効であること、Environmentをjobが参照しないことを別々に確認する。

[`insecure/workflow.yml`](insecure/workflow.yml)は複数の危険な経路を集めたreview用fixtureである。実repositoryの`.github/workflows`へcopy、enable、deployしない。

## `pull_request_target`は全面禁止なのか

全面禁止ではない。`pull_request_target`はbase repositoryのworkflowで動き、base側`GITHUB_TOKEN`やrepository／organization secretを利用できるeventである。ただし、実際に使えるscopeはworkflowの`permissions`、secret参照、repository／organization設定、Environment protectionに依存する。PR codeを実行せず、label付与やtriage等のmetadata-only処理に限定できる場合は安全に設計できる。

危険になるのは、PR head、merge ref、artifact、cache、dependency等をcheckout／download／fetchし、`make test`、`npm install`、build script等で実行したときである。

```text
fork PR
  -> pull_request_targetのbase-side context
  -> write tokenまたは参照secret等が実際に利用可能
  -> PR head／artifact／dependencyを取得
  -> attacker-controlled codeとして実行
  -> secret窃取、repository改ざん、release汚染
```

この経路でも、write tokenやsecretが配送されず、runnerや後続stateにも価値がなければ記載した最大被害は成立しない。しかし、未信頼codeをprivileged eventへ持ち込む設計は、将来permissionやsecretが追加された時に境界が崩れるため、referenceでは避ける。

Metadata-only workflowでも、PR titleやbodyをshellへ直接展開すればcommand injectionになる。採用する場合は、次を満たす専用workflowとしてreviewする。

- PR code、artifact、cache、dependencyを実行しない。
- PR由来文字列をshellやcode expressionへ直接展開しない。
- `permissions`をlabel、comment等の目的に必要なscopeだけへ限定する。
- 将来の変更でcheckoutやcode-loadingが追加されないようrequired reviewを設定する。

このreferenceが`pull_request_target`を使わないのは、metadata automationまで禁止したいからではない。初回導入で「どこまでがdataで、どこからがcode executionか」を誤りにくくするためである。詳細は[GitHubのpull_request_target guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)と[GitHub Security Labのpwn request解説](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)を参照する。

GitHubは`actions/checkout`にunsafe PR checkoutを防ぐ保護を追加しているが、manual `git fetch`、`gh`、artifact download、別repository、明示的opt-out等の経路は残る。[保護の範囲](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/)を理由にtrust reviewを省略しない。

## 実在事例から理解する

### GHSL-2020-372: 直接的なpwn request脆弱性

[GitHub Security LabのGHSL-2020-372](https://securitylab.github.com/advisories/GHSL-2020-372-418sec-huntr-workflow/)では、実在workflowが`pull_request_target`でforkのmerge refをcheckoutし、`npm ci`とsecret-bearing処理を実行していた。問題はevent名だけでなく、privileged contextへ未信頼codeを持ち込んだことである。

### Ultralytics 2024: cacheを介した実インシデント

[PyPIによるUltralytics攻撃分析](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)では、GitHub Actions cacheへの攻撃後、悪意あるcodeを含む複数のPyPI releaseが公開された。これは`pull_request_target`単独の事件とは断定せず、低信頼runとtrusted buildをcacheがつないだ場合の実被害例として扱う。

二つの事例が示す共通点は、未信頼stateがauthorityのある処理へ渡ったことである。`permissions: {}`だけ設定しても、後続のtrusted buildがpoisoned stateを実行すれば境界にはならない。

## 誰が何をするcontrolなのか

- Development team: PRで必要なtestを分類し、credential-free部分とtrusted integration部分に分ける。
- Repository administrator: workflowをcopy／mergeし、Actions／fork setting、ruleset、required review／checkを設定する。
- CI platform: approved runnerを提供し、untrusted jobがinternal network、persistent workspace、privileged reusable workflowへ到達しないようにする。
- Organization owner: organization／enterprise levelのtoken、private-fork、runner policyをdeny-orientedに保つ。
- Security: workflow inventory、`pull_request_target`、cross-run data flow、例外、actual runとlive settingを独立reviewする。

同じPR作成者またはworkflowだけに、trust分類、権限付与、evidence生成、最終判断を完結させない。

## Verification

このcontrolはcustom parserやsynthetic PASSをsecurity evidenceにしない。対象repositoryで次を確認する。

| Check | 確認者 | Live確認 | 成功状態 |
|---|---|---|---|
| `PRB-001` | Repository administrator | PR runのeffective permission、secret／OIDC／Environment | 未信頼jobからprivileged authorityへ到達しない |
| `PRB-002` | CI platform | Runner label、lifecycle、runner-group／network access | 未信頼jobからpersistent assetやinternal networkへ到達しない |
| `PRB-003` | Repository administrator | Checkout、code-loading path、actual revision | 宣言したtrust境界と実行revisionが一致し、credentialを残さない |
| `PRB-004` | Security | 全PR-related event、cache、artifact、output、reusable workflow | 未信頼の実行可能stateをprivileged contextへ自動昇格しない |
| `PRB-005` | Repository administrator | Ruleset、trust decision、trusted run event／SHA | 権限処理は未信頼runと別のreview済みcontextから始まる |
| `PRB-006` | Security | Repository内の全workflow inventoryとprovider evidence | 未分類pathや取得失敗を`PASS`にしない |

Statusは次のように記録する。

- `PASS`: current live settingとactual runが期待状態を満たす。
- `FAIL`: 未信頼codeとprivileged authorityを結ぶ経路がある。
- `NOT_CHECKED`: live setting、workflow、run、data flowを確認していない。
- `ERROR`: 権限不足、API failure、partial inventory等で評価不能。

```bash
make verify-control CONTROL=PSB-CICD-005
```

このcommandはlocal testを捏造せず`NOT_CHECKED`とこの手順へのlinkを表示し、exit `2`を返す。Automationが「commandを実行できた」ことを対象repositoryの`PASS`と誤認しないためである。Live確認は上表に従って別途実施する。

## Recoveryとrollback

- PR testが失敗する場合は、branch名、test command、fork approval、runner availability、private dependencyを確認する。Secret配送やwrite permissionを戻して直さない。
- Trusted phaseが必要なdataを受け取れない場合は、そのdataがcodeか単なるdataか、producer identityとintegrityを確認してからhandoffを設計する。
- Rollbackはcopyしたrepository-local workflowとrequired checkをreviewの上で外す。Organizationのdeny-oriented token／fork settingやbranch protectionを自動で弱めない。
- Urgent rollback後も古いprivileged PR workflowを復活させず、PR testを一時停止して`NOT_CHECKED`とする方が安全である。

## 他controlとの役割分担

- [`PSB-CICD-001`](../action-sha-pinning/README.md): Third-party Actionのimmutable SHA
- [`PSB-CICD-003`](../actions-static-analysis/README.md): GitHub Actions workflowのstatic analysis
- [`PSB-CICD-004`](../actions-least-privilege/README.md): Job目的ごとのexact token permission
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): Trusted deploy jobのOIDC claimとcloud trust
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner image、registration、network、one-job lifecycle、teardown
- [`PSB-CICD-009`](../cache-provenance-isolation/README.md): Cache producer／consumer provenanceとtrust namespace
- [`PSB-BUILD-001`](../../build-security/build-containment/README.md): Build sandbox、egress、telemetry、deploy separation
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): Organization-wide Actions／fork policy
- [`PSB-CICD-008`](../privileged-control-plane-change/README.md): Provider設定変更のactor、approval、audit chain
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Exact、owned、time-boundなsecurity exception

## Framework mappings

Machine-readableな正本は[`control.yaml`](control.yaml)である。Mappingはformal complianceや完全なcoverageを意味しない。

- [GitHub Security Guidance registry](../../../frameworks/github-security-guidance/README.md)
  - `GHAS-REF-SECURE-USE`
  - `GHAS-REF-PULL-REQUEST-TARGET`
  - `GHAS-CONCEPT-COMPROMISED-RUNNERS`
  - `GH-ADMIN-ACTIONS-REPOSITORY`
- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-BR-01.03](https://baseline.openssf.org/versions/2026-02-19#osps-br-0103)

## 関連frameworkとguidance

次は理解を補助する関連情報であり、`control.yaml`の正式mappingでないものを含む。

### Framework／threat taxonomy

- [MITRE ATT&CK T1195.002 — Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/): CI compromiseからrelease汚染へ至るattack behaviorとの関連。ATT&CKはcompliance requirementではない。
- [NIST SP 800-218 SSDF Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final): Secure development environmentの考え方。Exact task mappingは別reviewが必要。

### GitHub公式guidance

- [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [`GITHUB_TOKEN` behavior](https://docs.github.com/en/actions/concepts/security/github_token)
- [Secrets behavior](https://docs.github.com/en/actions/concepts/security/secrets)
- [OIDC token requirements](https://docs.github.com/en/actions/reference/security/oidc)
- [Deployment Environment protection and secret availability](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Compromised runner impact](https://docs.github.com/en/actions/concepts/security/compromised-runners)
- [Workflow syntax — permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [Managing Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [Approving workflow runs from forks](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)
- [Managing self-hosted runner access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access)
- [Dependency caching security](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching)
- [Safer pull_request_target defaults for actions/checkout](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/)
- [Read-only Actions cache for untrusted triggers](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/)

### Research／incident guidance

- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitHub Security Lab — New workflow vulnerability patterns and mitigations](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/)
- [GHSL-2020-372](https://securitylab.github.com/advisories/GHSL-2020-372-418sec-huntr-workflow/)
- [GHSL-2025-038 — IssueOps TOCTOU](https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/)
- [PyPI — Ultralytics supply-chain attack analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [Repository-owned security guidance source records](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-010)
