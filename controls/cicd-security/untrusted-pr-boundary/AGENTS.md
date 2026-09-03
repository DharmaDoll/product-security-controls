# PSB-CICD-005 implementation instructions

この file は `PSB-CICD-005` 固有の trust boundary を定める。作業前に
[repository root の AGENTS.md](../../../AGENTS.md)、
[controls の AGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、
[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、
[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、
[ROADMAP](../../../docs/ROADMAP.md)、この package の
[README.md](README.md) と [control.yaml](control.yaml) を読むこと。

## Control essence

- Control ID は `PSB-CICD-005`、domain は `cicd-security` である。
- PR 作成者は PR 内の code、test、build script、dependency、workflow 変更を制御できる。
- 本質は event 名の禁止ではなく、attacker-controlled code／executable state と privileged authority を
  同じ job、runner、または cross-run data flow に置かないことである。
- 未信頼 code を実行する場所から secret、write token、OIDC、protected Environment、persistent
  runner、internal network、trusted consumer が信用する state を除く。
- 権限を必要とする処理へ移る前に trust boundary を再確立し、未信頼runの実行可能stateを持ち込まない。
- PR の承認、workflow run の承認、actor、label、author association は、code を trusted にしない。
- Security 効果は、実際に有効な workflow、repository／organization setting、ruleset、runner
  routing から生まれる。documentation を copy しただけでは導入済みにならない。
- 「PRを作ればsecretやrepositoryを奪取できる」と無条件に記述しない。各attack pathについて、
  attacker-controlled処理が実行される条件、jobから実際に利用できるauthority、そのauthorityを使う
  API／network／consumer経路、条件が成立しない場合を示す。

## Supported profile and prerequisites

Reference profile は GitHub.com／GitHub Enterprise Cloud の GitHub Actions で、fork PR を
`pull_request` event で検証する repository である。

最小前提は次のとおり。

- review を必須にした default branch
- GitHub-hosted runner
- credential-free で実行できる PR test
- Actions setting と ruleset を変更できる repository administrator
- PR validation と merge 後の privileged processing を別 run にできる workflow 構成

Reference の trusted branch は `main`、runner label は `ubuntu-latest` である。導入先では実際の
protected branch と approved hosted label に置き換える。PR input や expression で runner を選ばせない。

PR test が private registry、cloud credential、production data、self-hosted network を必要とする場合、
credential を PR に渡さない。公開 dependency、credential-free emulator、mock、または merge 後の
trusted test へ分離する。

GitHub Enterprise Server、GitHub 以外の CI、metadata-only の `pull_request_target`、安全な一方向
artifact promotion は、control全体で禁止しないが、このcopy可能なreference profileには含めない。
必要なら event semantics、実行されるbyte、authority、data flow、live verificationを先に設計する。

## Implementation style

この control は guidance-first／configuration-first で実装する。

- Copy 可能な実装は
  [`secure/pr-validation.yml`](secure/pr-validation.yml) と
  [`secure/trusted-after-merge.yml`](secure/trusted-after-merge.yml) の二つに保つ。
- README はcopy commandより前に、controlの不変条件、適用判断、各fileの起動条件と非機能、copyで
  変わらないprovider state、副作用を説明する。最短手順を単なるfile操作にしない。
- GitHub 管理画面の設定、ruleset、実際の fork run は README の manual verification で確認する。
- Workflow の static analysis が必要な場合は
  [`PSB-CICD-003`](../actions-static-analysis/README.md) と組み合わせる。
- この package 固有の YAML parser、sidecar policy JSON、synthetic evidence、自己申告 assessment、
  README 文字列 test、no-op test を追加しない。
- Provider setting を変更する automation は、誤設定時の影響と provider／plan 差が大きいため、
  baseline に含めない。Read-only API check は、安全性と完全性を示せる場合だけ追加できる。
- `make verify-control CONTROL=PSB-CICD-005` は manual control として `NOT_CHECKED` を返す。
  これを live repository の PASS と表現しない。

## Security invariants and reference profile

- 未信頼codeまたはexecutable stateを実行するcontextには、奪われて困るcredential、write authority、
  persistent compute、internal reachabilityを置かない。
- Privileged contextはPR head、artifact、cache、dependency、outputを無条件にcodeとして実行しない。
- Metadata-onlyのprivileged workflowは、PR codeをloadせず、PR由来文字列をshell／code expressionへ
  直接展開せず、目的に必要なexact permissionだけを持つ場合に限り個別designできる。
- Workflow 自体を PR で変更できるため、required check、review、CODEOWNER 等の server-side enforcement を
  維持する。PR 内の self-check だけで bypass を防げると主張しない。

Copy可能なreference profileは、さらに次へ限定する。

- PR validationは`pull_request`、top-level `permissions: {}`、job-level `contents: read`以下で動く。
- PR jobはsecret、`id-token: write`、write token、protected Environmentを持たない。
- PR jobはreviewed GitHub-hosted runnerを使う。Self-hostedが必要なら[`PSB-CICD-007`](../runner-hardening/README.md)
  でephemeral、one-job、network-isolatedなprofileを先に設計する。
- `actions/checkout`はimmutable full commit SHA、`persist-credentials: false`を使い、eventが選んだmerge
  revisionを維持する。
- Privileged reporting、release、deployはprotected branchのreview済みrevisionから別runで始める。
- Referenceのtrusted workflowはboundary markerだけであり、copy直後にdeployやwrite操作を行わない。

READMEで資産別riskを説明するときは、次の条件を省略しない。

- `GITHUB_TOKEN`: event、repository／organization default、workflow／job `permissions`、rulesetから決まる
  effective scope
- Secret: workflow／Actionが参照し、provider policyとEnvironment protectionを通ってjobへ配送されること
- OIDC: `id-token: write`に加え、cloud側trust policyがissuer、audience、subject等を受理すること
- Environment: jobが参照し、required reviewerやbranch rule等を通過して初めてsecretが利用可能になること
- Runner: persistent filesystem、host credential、daemon socket、internal network等の実在する到達先
- Cache／artifact: privileged consumerが未信頼内容をcode／dependency／unsafe inputとして利用するdata flow

最大impactだけでなく、fork `pull_request`のread-only token・secret非配送、credential-free hosted runner、
privileged consumerなし等、attack pathが成立しない状態も併記する。

## `pull_request_target` documentation contract

`pull_request_target` に触れる場合は、単に「危険」と書かず、次を説明する。

1. Workflow file と `GITHUB_TOKEN`／secret は base repository 側の privileged context から来る。
2. PR head の checkout、script、dependency、cache、artifact を同じ run で実行すると、attacker-controlled
   byte がその authority を利用できる。
3. GitHub の追加保護があっても、明示的な unsafe checkout、間接的な code loading、cross-run state、
   provider／Enterprise Server 差を消すものではない。
4. 実例は、一次資料へ link し、確認できる事実と類似 attack path を分ける。
5. Ultralytics incident は cache／cross-run trust の実例として扱い、純粋な
   `pull_request_target` incident だったとは主張しない。
6. `pull_request_target`自体を全面禁止と表現しない。Metadata-onlyで成立する条件と、reference profileが
   採用しない理由を分ける。

各種参照、関連 control、framework、guide は Markdown link にする。Mapping は formal compliance の
主張ではなく、relationship、version、confidence、rationale を `control.yaml` に記録する。

## Roles

- Development team: PR処理を先に分類し、credential-freeなtestとtrusted phaseへ分けた後で二つの
  workflowをcopy／mergeする。
- Repository administrator: Actions default permission、fork policy、required review／check、ruleset、
  Environment access を設定する。
- CI platform／organization owner: approved runner と organization-level deny-oriented setting を提供し、
  PR job が self-hosted runner や privileged reusable workflow へ到達しないようにする。
- Security: workflow inventory、`pull_request_target`／cross-run data path、例外、live setting、実際の
  positive／negative run を独立 review する。

同一の PR 作成者または workflow だけに、trust classification、privilege 付与、evidence 生成、最終判定を
完結させない。

## Atomic checks and evidence

`control.yaml` が canonical source である。既存 check ID は生成済み checklist の参照を保つため、意味を
変えたり不要に renumber したりしない。

- `PRB-001`: PR validation に write token、secret、OIDC、protected Environment を与えない。
- `PRB-002`: 未信頼codeをpersistent assetやinternal networkへ到達できないrunnerで実行する。
- `PRB-003`: Checkout／code-loadingが宣言したtrust境界と一致し、credentialを残さない。
- `PRB-004`: Privileged event、cache、artifact、reusable workflow による automatic elevation を防ぐ。
- `PRB-005`: Privileged workを未信頼runと分離し、review済みtrust contextから開始する。
- `PRB-006`: Workflow inventory と provider evidence が不完全なら `NOT_CHECKED`／`ERROR` とし、
  clean と扱わない。

Repository に架空の evidence file を置かない。Evidence は対象 repository、取得元、取得時刻、確認者、
権限境界が分かる実際の Actions run、effective permission、ruleset、runner routing、設定画面または
read-only API result とする。Secret 値、private data、provider-valid token は保存しない。

Manual verification は `PASS`、`FAIL`、`NOT_CHECKED`、`ERROR` を区別する。未確認、権限不足、partial
result、API failure、workflow inventory の欠落を PASS に丸めない。

## Relationship to other controls

- [`PSB-CICD-001`](../action-sha-pinning/README.md): third-party Action の immutable SHA pinning
- [`PSB-CICD-003`](../actions-static-analysis/README.md): workflow repository 全体の static analysis
- [`PSB-CICD-004`](../actions-least-privilege/README.md): job 目的ごとの exact token permission
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): trusted job の OIDC trust policy
- [`PSB-CICD-007`](../runner-hardening/README.md): runner image、network、lifecycle、teardown
- [`PSB-CICD-009`](../cache-provenance-isolation/README.md): cache producer／consumer provenance
- [`PSB-BUILD-001`](../../build-security/build-containment/README.md): build job 内部の sandbox と egress
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): organization-wide
  Actions setting
- [`PSB-CICD-008`](../privileged-control-plane-change/README.md): privileged provider setting の変更管理
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): exception lifecycle

別 control の実装をこの package に copy して、見かけ上 self-contained にしない。

## Required verification after changes

Repository root から次を実行する。

```bash
make verify-control CONTROL=PSB-CICD-005
make validate-controls
python3 -m unittest tests.test_control_metadata
```

最初の command の期待結果は `NOT_CHECKED` である。README の live manual verification が完了するまで、
導入済みまたは PASS と主張しない。Generated index／mapping は user が明示的に求めた場合だけ更新し、
手書き source と同じ変更へ混ぜない。
