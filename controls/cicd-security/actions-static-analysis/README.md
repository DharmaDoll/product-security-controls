# PSB-CICD-003: GitHub Actionsの静的解析

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHub Actionsのworkflowは、runnerで何を実行し、どのtokenやsecretを使えるかを決めるprogramである。Reviewだけでは、
外部入力をshell commandへ混ぜる記述、後から参照先を変更できるAction tag、未信頼codeを権限あるjobへ持ち込むtrigger、
必要以上のpermissionを見落とすことがある。

ただし、そのような記述やscanner findingが一つあるだけで、直ちにrepositoryやcloudが侵害されるわけではない。具体的な
被害は、概ね次の条件がつながったときに成立する。

1. 攻撃者、侵害されたaccount、または設定ミスが、workflow、Action参照、workflowへ入る値のいずれかを変更できる。
2. 変更された処理が、到達可能なeventや後続jobで実際に実行または信用される。
3. その処理から、write可能な`GITHUB_TOKEN`、workflowが参照したsecret、OIDC、release／package権限、private source、
   persistent runner、internal network、または権限ある後続処理へ到達できる。
4. Security scanがrequired checkになっていない、scanner workflow自体を同じPRで弱められる、またはscanner失敗を
   「findingなし」と扱うため、安全でない変更がdefault branchへ到達する。

条件が揃うと、付与されたscopeと外部policyの範囲で、source／tag／releaseの変更、credentialやprivate sourceの持ち出し、
package公開、cloud credential取得、trusted buildへの汚染が起こり得る。反対に、未信頼値がcommandとして実行されず、
jobがread-onlyでsecretやtrusted handoffを持たないなら、repository／cloud権限を奪う経路は大きく制限される。

Scanner停止だけで侵害が発生するわけでもない。危険なworkflow変更が同時に存在し、その変更を止める別のreviewやgateが
ないときに、検査不能をcleanと誤認することが被害への条件になる。

### 誰から、または何から守るか

Workflowを変更できる悪意あるcontributorや侵害されたcollaborator account、権限とeventの組合せを誤るmaintainer、
mutableなscanner参照を書き換えられるupstream publisher、scanner／registry障害から守る。ContributorがPRを作成しただけで
被害が成立するのではなく、その変更が実行され、価値のある権限やdata flowへ接続されることが必要である。

### 何が対象か

Repository内のGitHub Actions workflow定義、scannerとして動くzizmor Action／container、PRのmerge可否を決めるjob、
Code Scanningへ結果を送るjob、required checkとその保護を対象にする。Workflowから呼ばれるapplication source、shell
script、third-party Action内部の実装そのものは解析対象ではない。

### 何をするか

Versionと配布identityを固定したzizmorで`.github`のYAMLを実行せずに読み、既知の危険な構造を指摘する。PRでは
`contents: read`だけのjobを使い、zizmorへGitHub API tokenを渡さず、findingまたはscanner errorならmerge checkを
失敗させる。SARIFを書き込むjobはreview済みdefault branchへのpushへ分離する。

### 成功状態

既存の`.github`にblocking findingがない状態では、documentationだけを変えるsafe PRで
`Block workflow security findings`が成功する。Inertな危険例、入力不在、scanner取得失敗では成功しない。そのcheckがactive
rulesetでrequiredになり、`.github/workflows/**`とCODEOWNERS自体の変更には独立したcode-owner reviewが必要である。
SARIF write権限はreview済みdefault-branch pushだけに存在する。

この成功状態は「検査対象のworkflowにzizmorが報告するfindingがなく、検査経路が予定どおり動いた」ことを示す。
Workflow全体がexploit不可能であることや、finding一件ごとの実害を証明するものではない。

### 対象外・残余リスク

Static analysisはruntimeの値やdata flowを観測せず、jobのpermissionが実処理に対して最小か、external Action内部、呼び出す
script、cloud側OIDC policy、runner／network、live rulesetを完全には証明しない。Findingはreviewすべき構造であり、現在
悪用可能という判定ではない。例えば、到達不能なworkflow内のmutable tagもfindingになるが、その時点でAction codeが
実行されなければ直ちに被害は起きない。

また、gate jobにもGitHubが自動発行するrepository-scoped tokenは存在し、`contents: read`へ制限してcheckoutに使う。
`token: ""`はzizmorへonline audit用tokenを渡さない設定であり、jobからtokenが完全に消えるという意味ではない。Pinned
scannerが悪意あるcodeを既に含む場合やprivate sourceを外部送信する場合は、SHA pinningだけでは防げない。

## まず、このcontrolの本質を理解する

静的解析とは、workflowを実行する前にYAMLをdataとして読み、危険になりやすい構造を探すことをいう。このcontrolの
直接的な効果は「見落とし得るworkflow変更をmerge前のreview対象にし、検査不能もmerge可能なgreenへ変えない」ことである。
実害の有無と大きさは、findingを起点にevent、実行されるcode、実効permission、secret、runner、後続data flowをたどって
別途判断する。

このREADMEでは、`finding`を「scannerが人の確認を求める指摘」、`gate`を「PRをmerge可能にするか決めるcheck」、`SARIF`を
「scannerの指摘をCode Scanningへ渡す標準形式」と呼ぶ。

主実装は[secure workflow](secure/workflow.yml)と、GitHub側のrequired status check／required code-owner reviewである。

```text
pull_request
  -> read-only checkout
  -> .githubをcodeとして実行せずzizmorで解析
  -> cleanならgate成功
  -> finding／scanner errorならgate失敗
  -> active rulesetがmergeを止める

review済みdefault-branch push
  -> 同じ解析を実行
  -> security-events: writeでSARIFだけをCode Scanningへ送る
```

GitHubはjobごとに`GITHUB_TOKEN`を自動発行する。[`GITHUB_TOKEN`の仕様](https://docs.github.com/en/actions/concepts/security/github_token)
に従い、gateではその権限を`contents: read`へ限定する。Checkoutはこのtokenを使うが、`persist-credentials: false`により
Git設定へ残さない。Zizmorには`token: ""`を渡し、GitHub APIを使うonline auditを無効にする。つまり「tokenが存在しない」
のではなく、「PRの解析にwrite権限や追加credentialを与えない」という境界である。

Gateはcheckoutとpinned zizmor Actionだけを実行し、PR内のbuild／test scriptを実行しない。これにより、PR作成者がscanner
対象のYAMLへ危険な文字列を書いても、それがscanner jobのcommandとして動く経路を作らない。ただし、pinned Action自体を
信頼する必要は残り、private repositoryではcheckoutされたsourceを読める。Pinningはsilent updateを防ぐが、review済み
bytesが安全であることやnetwork exfiltration不在を証明しない。

`gate`と`report`を分ける理由は、SARIF modeではfindingをresult内に記録してもprocessが成功し得る一方、uploadには
`security-events: write`が必要だからである。PRはblocking mode、write権限を持つreportはtrusted pushだけにする。

Repository-local workflowは同じPRで変更できる。攻撃者がjob名だけ残しscanner stepを無効化すれば、required status check
だけでは偽のgreenを作り得る。このため`.github/workflows/**`とCODEOWNERS file自体をsecurity ownerの対象にし、rulesetで
code-owner reviewを必須にする。より強い
[organization rulesetのrequired workflow](https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization)
を使う場合は、provider plan、workflow source、`merge_group`、concurrency behaviorを確認した別profileとして設計し、この
referenceがそのまま対応すると推測しない。

Workflowを置いただけではmerge protectionもreview保護も発生しない。Repository administratorがlive rulesetをactiveにし、
safe／finding／scanner failure／missing checkとworkflow改変のreviewを実際に確認して初めて導入完了となる。

## Findingが実害につながる条件

| Scannerが示す構造 | 被害が成立する主な条件 | 起こり得ること | その構造だけでは言えないこと |
| --- | --- | --- | --- |
| 外部入力のcommand展開 | 攻撃者が値を変更でき、到達可能なjobのshellへcodeとして入り、jobに価値のある権限やhandoffがある | Job内command実行、check偽装、credential窃取、権限範囲内の変更 | 固定値またはdataとして安全に処理される値なら、外部actorのcommand実行経路はない |
| MutableなAction参照 | Upstream tag／branchが書き換わり、その後のrunが変更codeを取得し、jobの権限を利用できる | Source／secretの持ち出し、repository／release操作、result改ざん | Tagがmutableであることは、現在のActionが既に悪意あるという証明ではない |
| 危険になり得るtrigger | `pull_request_target`等の権限あるcontextがPR code／artifact／dependencyを取得して実行する | Base repository側のtokenやsecretを未信頼codeが利用する | Metadataだけを固定APIへ渡し、PR codeを実行しなければ同じattack pathは成立しない |
| 過剰なpermission | Job内で未信頼または侵害された処理が動き、対象API操作をrulesetや外部policyが許す | Permission scope内のsource、package、release、security result等の変更 | 広いpermissionが未使用であるだけなら侵害済みではないが、将来の失敗時の被害範囲を広げる |
| Scanner failure／入力なし | 同時に危険な変更があり、errorでもrequired checkが成功または不要になる | 未検査のworkflowがmergeされ、後のrunで上記経路が成立する | Registry outageやparser error単体はsecurity compromiseではなく、検査不能とCI停止である |
| Scanner supply-chain drift | Mutable scanner参照が差し替わる、またはreview済みscanner自体が悪意あるcodeを含み、workspaceやjob権限へ到達する | Private sourceの読取り／送信、scan result改ざん、report権限の悪用 | Full SHA／digestは別bytesへのsilent差替えを防ぐが、固定bytesの安全性までは保証しない |

Findingの優先度は、この表の二列目を実workflowで確認して決める。Findingを無条件に「侵害」と扱わず、反対にread-only job
だからすべて無害とも扱わない。Read-onlyでもcheck偽装、private sourceの読取り、CI resource abuse、trusted artifactへの
間接的な影響は残り得る。

## 誰が何をするか

| 担当 | 作業 |
| --- | --- |
| Development team | Workflowをpull requestで追加し、findingの到達可能event、実行code、権限、後続data flowを確認して修正する |
| Repository administrator | Default branch、required check、code-owner review、ruleset、Code Scanningを設定する |
| CI platform／organization owner | External Action、`ghcr.io`、approved runnerを利用可能にする |
| Security | Scanner identity、workflow／CODEOWNERS変更、findingのimpact、期限付きexception、live negative testをreviewする |

開発者へ追加scanner、独自runtime、provider mutation scriptを要求しない。最小導入はworkflow一つ、required check、
workflow変更の独立reviewである。独立reviewを用意できない場合、scanner workflowをPR author自身が弱められるため、
導入完了とは扱わない。

## 最短の導入手順

ここで有効にするcontrolは`PSB-CICD-003`の「workflow変更をmerge前にzizmorで検査するgate」である。変更するfileは
`.github/workflows/actions-security.yml`と、必要に応じて`.github/CODEOWNERS`である。GitHub側ではdefault branchのrulesetを
変更する。完了時にはsafe PRだけがgreenとなり、finding、scanner failure、missing check、未承認のscanner workflow変更は
mergeできない。

### 前提

- GitHub.com、またはこのprofileを確認済みのGitHub Enterprise Cloud。
- GitHub-hosted Ubuntu runnerを利用できる。
- GitHub Marketplace Actionと`ghcr.io`からreview済みzizmor imageを取得できる。
- Repository administratorが[GitHub ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)を変更できる。
- `.github/workflows/**`とCODEOWNERS fileをreviewする、PR authorとは別のownerがいる。
- Referenceのdefault branchは`main`。異なる場合は次の手順で明示する。
- Required check化する前に、現在の`.github`にあるzizmor findingを確認し、修正するか、owner・理由・期限を持つ狭い例外として
  reviewできる。未解決findingがあるままrequiredにすると、無関係なPRも止まる。
- SARIF reportingを使う場合は対象repositoryで[Code ScanningへのSARIF upload](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)を利用できる。

### 1. Scanner workflowをrepositoryへ追加する

Repository rootで次を実行し、[secure/workflow.yml](secure/workflow.yml)を
`.github/workflows/actions-security.yml`として追加する。既存fileがあれば上書きせず停止する。

```bash
workflow_target=.github/workflows/actions-security.yml
test ! -e "$workflow_target" || {
  echo "ERROR $workflow_target already exists; review and merge it manually" >&2
  exit 1
}
mkdir -p .github/workflows
cp controls/cicd-security/actions-static-analysis/secure/workflow.yml \
  "$workflow_target"
```

別repositoryへ導入する場合、実行に必要なcontrol fileは[secure/workflow.yml](secure/workflow.yml)だけである。
[scripts/verify.py](scripts/verify.py)と[tests/test.sh](tests/test.sh)はblueprint referenceのregression testであり、adopterの
runtimeへcopyする必須fileではない。既存workflowへ手作業で組み込む場合も、gateとreportを一つの権限あるjobへ統合しない。

### 2. Default branchを合わせる

Default branchが`main`でなければ、次の2か所だけを実branchへ変更する。

- `on.push.branches`
- `report.if`の`refs/heads/main`

Control packageのlocal verifierも利用する場合は同じbranchを明示する。

```bash
python3 controls/cicd-security/actions-static-analysis/scripts/verify.py \
  workflow .github/workflows/actions-security.yml \
  --default-branch <default-branch>
```

### 3. 実害を起こさないPRでscannerを起動する

READMEまたはcommentだけを変えるpull requestを作り、`Block workflow security findings`が実行されることを確認する。
Runの`Set up job`とworkflow sourceで、job permissionが`contents: read`だけであり、checkoutとzizmor以外のstepを実行せず、
zizmor inputの`token`が空であることを確認する。Jobに`GITHUB_TOKEN`が存在しないとは記録しない。

### 4. Gateとscanner workflow変更をrulesetで保護する

GitHubのrepository settingsでrulesetを開き、default branchを対象に`Block workflow security findings`を
required status checkへ追加する。設定方法は
[GitHubのrequired status check説明](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging)を参照する。

同じrulesetでpull requestとcode-owner reviewを必須にし、可能ならstale approvalの破棄または最新pushのapprovalを要求する。
[GitHubのsecure use guidance](https://docs.github.com/en/actions/reference/security/secure-use#using-codeowners-to-monitor-changes)に従い、
`.github/CODEOWNERS`でworkflow directoryとCODEOWNERS file自体をsecurity ownerへ割り当てる。

```text
/.github/workflows/ @your-organization/product-security
/.github/CODEOWNERS @your-organization/product-security
```

`@your-organization/product-security`は、導入先で実在しPR authorと独立してreviewできるteam slugへ置き換える。Fileが存在する
だけではreviewはrequiredにならないため、rulesetの`Require review from Code Owners`がactiveであることも確認する。Bypass
actorが広い場合は、誰がscannerを無効化できるかを記録し、そのauthorityを残余リスクとしてreviewする。

Failed、cancelled、missingのいずれでもmergeできず、scanner workflowを変更したPRはcode-owner approvalなしでmergeできない
ことを確認する。SARIF alertだけをmerge gateにしない。

### 5. SARIF reportingを確認する

SARIFを利用できる場合、default branchへのtrusted pushで`Upload trusted-branch SARIF`が実行され、Code Scanningに
resultが表示されることを確認する。Pull requestではこのjobがskipされることを確認する。

SARIFを利用できない場合も`gate`によるblockingは使用できる。ただし[`SAS-003`](control.yaml)の適用可否を記録し、
reportingを導入済みと扱わない。

### 導入完了の観測結果

| 確認対象 | 完了状態 |
| --- | --- |
| Safe PR | 既存の`.github`にblocking findingがなければ`Block workflow security findings`が成功する |
| Inert finding | Gateが失敗し、mergeできない |
| Scanner／registry failure | Gateがgreenにならず、mergeできない |
| Missing／cancelled check | Rulesetがmergeを許可しない |
| Scanner workflow変更 | 独立したcode-owner approvalがなければmergeできない |
| SARIF report | PRではskipし、review済みdefault-branch pushだけで実行する |

一項目でもliveに確認していなければ、その項目は`NOT_CHECKED`であり、local fixtureの成功で補わない。

## Safe self-test

### Blueprint referenceのlocal positive test

次のcommandは、このBlueprint repository内でscanner workflowのevent、permission、Action identity、zizmor inputを検査する。
Zizmor本体を実行してrepositoryのworkflow weaknessを探すcommandではなく、live rulesetも確認しない。最短導入で
`secure/workflow.yml`だけを別repositoryへcopyしたadopterは、このlocal testをcopyする必要はなく、後述のlive testを行う。

```bash
python3 controls/cicd-security/actions-static-analysis/scripts/verify.py \
  workflow .github/workflows/actions-security.yml \
  --default-branch main
```

Expected resultはexit `0`と`ACCEPTED zizmor 1.28.0 workflow with separate blocking and trusted SARIF jobs`である。
これはscannerを安全なprofileで起動する構造が保たれているという意味であり、検査対象がcleanという意味ではない。
Default branchが異なるadopterは`main`を実branchへ置き換える。Blueprint repositoryのmaintainerは、続けてcanonical testを
実行する。

```bash
make verify-control CONTROL=PSB-CICD-003
```

### Live positive test

既存の`.github`にblocking findingがないことを確認してから、commentまたはREADMEだけを変更したsafe PRを作り、次を確認する。

- `Block workflow security findings`がgreenになる。
- `Upload trusted-branch SARIF`はPR上でskipされる。
- Runがcheckoutとpinned zizmorだけを実行し、repository-local build／test scriptを実行しない。
- Code-owner approvalを含むruleset条件を満たした場合だけmerge可能になる。

既存workflowのfindingで失敗した場合、そのPRが新しい危険を加えたとは限らない。ZizmorはPR差分だけでなく指定した`.github`
全体を読むためである。Findingを修正または期限付き例外としてreviewするまでrequired checkをfail-openにせず、baseline整備を
導入作業として扱う。

### Live negative test

Mergeしないtest branchで、次のinert workflowを一時的に`.github/workflows/actions-security-negative-test.yml`へ置く。
これは意図的にinsecureである。Default branchへmergeしない。

```yaml
name: Actions security negative self-test

on:
  workflow_dispatch:

permissions: {}

jobs:
  inert:
    if: ${{ false }}
    runs-on: ubuntu-latest
    steps:
      - name: Inert mutable reference
        uses: actions/checkout@v4
```

Jobは常にskipされるためActionは実行されないが、offline `unpinned-uses` auditはmutable tagを検出する。Expected resultは
`Block workflow security findings`の失敗である。確認後にtest fileを削除する。さらに、failed check、
cancelled check、required checkが起動しない状態でmergeできないことを確認する。

このtestが示すのは「mutable referenceという既知のpolicy findingをlive gateが拒否した」ことだけである。`@v4`が現在
maliciousであることや、実際にcredentialが盗まれたことを示さない。本物のsecret、canary token、write操作は追加しない。

## 結果の読み方

Local `scripts/verify.py`は、CIやassessmentが三状態を混同しないよう次へ正規化する。

| Local verifierの状態 | Exit status | 扱い |
| --- | ---: | --- |
| Workflow policyまたはSARIFを正常に検査し、findingなし | `0` | この検査範囲だけaccepted |
| Workflow policy違反またはSARIF findingあり | `1` | Finding。merge判断へ使う場合はblock |
| Input不足、parser error、scanner failureを示すSARIF | `2` | 判定不能。cleanとして扱わない |

Zizmor本体のnative exit codeは別である。通常modeではfinding severityに応じて`11..14`、audit errorは`1`、argument errorは
`2`、inputなしは`3`を返す。SARIF modeではfindingがあっても`0`になり得る。詳細は
[zizmorのexit code](https://docs.zizmor.sh/usage/#exit-codes)と
[GitHub Actions integration](https://docs.zizmor.sh/integrations/#github-actions)を参照する。この差があるため、live PRの
blocking gateとSARIF reportingを同じ成功判定にしない。

GitHub上では、正常なblocking scanだけをgreenとする。Finding、Action取得失敗、container起動失敗、registry outage、
inputなしのいずれもgateはgreenにしない。Logでfindingとtool failureを区別し、`continue-on-error`、`|| true`、
`fail-on-no-inputs: false`、無条件fallbackで成功へ変換しない。

## Live verification

Local fixtureの成功とlive adoptionを分離する。

| 確認対象 | Source | Success state |
| --- | --- | --- |
| Workflow revision | Git repositoryのexact revision | [secure workflow](secure/workflow.yml)とreview済み差分だけ |
| Safe PR | GitHub Actions run | `contents: read`だけのgateがsuccessし、zizmorへAPI tokenを渡さない |
| Inert finding | Mergeしないnegative test PR | `gate`がfailure |
| Merge enforcement | GitHub ruleset current setting | Failed／cancelled／missing checkではmerge不可 |
| Workflow tamper protection | CODEOWNERSとruleset current setting | Workflow／CODEOWNERS変更は独立reviewなしでmerge不可 |
| SARIF authority | PR runとdefault-branch push run | PRではskip、trusted pushだけで実行 |
| Failure handling | Actual failed runまたはapproved staging test | Scanner failureがsuccessにならない |

Evidenceにはrepository、exact revision、run IDまたはURL、event、ref、取得時刻、reviewer、rulesetのcurrent sourceを含める。
Token、secret、private source、raw event payloadはcommitしない。設定未確認、権限不足、partial result、provider failureは
`NOT_CHECKED`または`ERROR`であり、`PASS`ではない。

## Secure implementation details

[secure/workflow.yml](secure/workflow.yml)は次のidentityを固定する。

- [`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`](https://github.com/actions/checkout/tree/de0fac2e4500dabe0009e67214ff5f5447ce83dd)（v6.0.2）
- [`zizmorcore/zizmor-action@6fc4b006235f201fdab3722e17240ab420d580e5`](https://github.com/zizmorcore/zizmor-action/tree/6fc4b006235f201fdab3722e17240ab420d580e5)（v0.6.1）
- `zizmor` `1.28.0`
- OCI digest `sha256:8e6b3e4fb74d1aa5d23e83ea369f386c66eced0d1fb944d32cd8b2aac100b00d`

固定したActionは内蔵version tableからdigestを解決する。Update時はcanonical release、Action commit、source内version
table、OCI digest、release note、audit／exit behaviorを同じ変更でreviewする。Pinningはmalicious pinned bytesや
scanner ruleの完全性までは証明しない。

`online-audits: false`かつ`token: ""`にするため、GitHub APIが必要なonline-only auditは対象外になる。Baselineへtokenを
追加してcoverageを広げない。Online auditが必要なら別のtrusted profileとしてauthorityとfailure stateを設計する。

Gate jobの`contents: read`はprivate repositoryのcheckoutを可能にするため、scanner Actionが侵害されればsourceを読まれる
可能性は残る。`inputs: .github`はzizmorの解析範囲であり、malicious containerに対するfilesystem sandboxではない。この
referenceはfull SHAとAction内のOCI digest bindingでsilent差替えを防ぎ、write permissionを与えないことで被害範囲を
抑える。Scanner source review、update review、runner egress controlは別途必要である。

## Insecure example

[insecure/workflow.yml](insecure/workflow.yml)は、次を意図的に組み合わせた実行されないfixtureである。複数条件を一つの
sampleへ集めているため、各行が単独で同じimpactを持つという意味ではない。

- Pull requestだけでprivileged reportingを実行する。
- `permissions: write-all`とself-hosted runnerを使う。
- Top-level `env`でtokenをscannerへ再注入し、blocking gateを`if: false`でskipする。
- Scanner jobの中でpull-request repository commandを実行する。
- Checkoutとscannerにfloating tagを使う。
- Online auditへ`GITHUB_TOKEN`を渡す。
- `continue-on-error: true`でscanner failureを隠す。
- `latest`、不完全な入力、`fail-on-no-inputs: false`を使う。

このfixtureは`.github/workflows`外に隔離し、defaultで実行しない。

この例で実害へ近づくのは、PR-controlled commandを実行するstep、write authority、self-hosted runner、token配送が同じjobに
集まるためである。Floating tagだけを見つけた場合は「現在侵害済み」とせず、参照先を誰が変更でき、次のrunでどの権限へ
到達するかを確認する。`continue-on-error`は脆弱性そのものではないが、scanner failureやfindingをmerge可能な状態へ変える
ため、このcontrolのdecision boundaryを壊す。

## Automated verification

[scripts/verify.py](scripts/verify.py)と[tests/test.sh](tests/test.sh)はPython standard libraryとshellだけを使い、
次を検査する。

- Event、default branch、`gate`／`report` job構造。
- Jobごとのrunner、permission、checkout credential境界。
- Gateをskipするcondition、job／step追加、environment経由のcredential再注入。
- Action full SHA、zizmor Action commit、scanner version、input、mode。
- Failureを隠す`continue-on-error`。
- Diagnosticへuntrusted scanner input値を出さないこと。
- Clean、finding、scanner failure、malformed SARIFの状態。
- Repositoryで採用したworkflowとreferenceのdrift。

Verifierはzizmor audit engineを再実装しない。Workflow policy testはscannerを起動するworkflow自体がreview済みprofileを
保つことを確認し、SARIF fixtureはclean、finding、scanner errorのdecision parserを確認する。Handcrafted SARIFは実scannerの
検出力、findingのexploitability、organization adoptionを証明しない。

Repository rootから実行する。

```bash
bash controls/cicd-security/actions-static-analysis/tests/test.sh
make verify-control CONTROL=PSB-CICD-003
```

Expected output:

```text
PASS secure scanner workflow policy accepted
PASS alternate default branch accepted when declared explicitly
PASS mutable privileged token-bearing and failure-ignoring workflow rejected
PASS untrusted scanner input values omitted from diagnostics
PASS clean and finding SARIF states distinguished
PASS scanner execution failure distinguished from a clean result
PASS malformed SARIF fails closed
PASS missing and unsupported workflow inputs fail closed
PASS adopted workflow matches the reviewed secure example
```

README文字列test、手書きJSONの`secure: true`、no-op test、provider-valid credential、real secret、synthetic fixtureの
organization `PASS`化は追加しない。

## Recovery and rollback

| 状況 | Recovery |
| --- | --- |
| Workflow finding | 対象lineを修正し、broad ignoreを追加せず再実行する |
| Safe PRが既存findingで失敗する | FindingがPR差分由来か既存baseline由来かを確認し、既存分も修正またはowner・理由・期限付きでreviewする。Gateを無条件成功にしない |
| Scanner identity drift | [secure workflow](secure/workflow.yml)のreview済みidentityへ戻す |
| Registry／Actions outage | Service回復後にrerunする。Failureをwarningへ変えない |
| SARIFだけ利用不可 | Blocking gateを維持し、reportingを`NOT_CHECKED`として扱う |
| 誤ったdefault branch | Branch filterとreport conditionを同時に修正し、verifierへ同じbranchを渡す |
| Workflowを変えてもcode-owner reviewが出ない | CODEOWNERS path、team access、rulesetのrequired review、bypass actorを確認する |
| 不自然にgreenになる | 実行revision、job step、check source、workflow差分を確認し、review済みprofileへ戻す |

完全rollbackが必要な場合は、repository administratorとSecurityが既知のgood scanner versionへ戻す。Workflowを削除する
場合は、required checkが永続的にmissingとなってmergeを停止しないよう、ruleset変更とfile削除を一つのreview済み
rollbackとして扱う。Rollback後もmanual workflow reviewは必要であり、同等のserver-side scannerがない限り検出力は下がる。

## Existing controlsとの分担

- [PSB-CICD-001: Action SHA pinning](../action-sha-pinning/README.md)は全third-party Action、reusable workflow、Docker Actionのimmutable referenceを所有する。
- [PSB-CICD-002: Actions command injection](../actions-command-injection/README.md)はActions expressionからrunner shellへの直接injectionを所有する。
- [PSB-CICD-004: Actions least privilege](../actions-least-privilege/README.md)はjob operationに対するsemantic token／OIDC least privilegeを所有する。
- [PSB-CICD-005: Untrusted PR boundary](../untrusted-pr-boundary/README.md)はuntrusted code、credential、runner、cross-run dataの一般境界を所有する。
- [PSB-CICD-007: Runner hardening](../runner-hardening/README.md)はrunner image、network、lifecycle、teardownを所有する。
- [PSB-BUILD-001: Build containment](../../build-security/build-containment/README.md)はjob内sandbox、egress、credential、telemetryを所有する。
- [PSB-SOURCE-006: GitHub Organization governance](../../source-protection/github-organization-governance/README.md)はorganization-wide Actions policyを所有する。
- [PSB-GOV-002: Time-bound security exceptions](../../governance-operations/time-bound-security-exceptions/README.md)はexceptionのscope、approval、expiryを所有する。

Zizmorがこれらの問題をfindingとして検出しても、本controlは各owner controlの完全な実装やlive adoptionを証明しない。

## Complementary tool boundary

| Tool | Potential contribution | Current decision |
| --- | --- | --- |
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions向けsecurity static analysis | Adopted |
| [actionlint](https://github.com/rhysd/actionlint) | Syntax、expression type、Action interface、embedded shell lint | Unique negative fixtureが確認できるまで追加しない |
| [poutine](https://github.com/boostsecurityio/poutine) | Pipeline supply-chain issueとrepository／organization inventory | Existing controlと重複しないgapが確認できるまで追加しない |

候補scannerは、既存経路が見逃す必須のinert finding、pinned executable、integrity verification、clean／finding／error
semantics、owner、CI costを示せる場合だけ追加する。Tool数をcoverageとして扱わない。

## Limitations and operational cost

- Findingは危険になり得る構造を示すsignalであり、actor control、event reachability、runtime authorityを合わせないと実害や
  severityは決まらない。
- Zizmorはworkflow／Action定義を静的に読むため、external Action内部、repository script、download後のcode、runtime value、
  network／credential useは観測しない。
- Static ruleはjobが実際に必要とするsemantic permissionを証明しない。広いpermissionがfindingでも、利用可能な攻撃codeが
  ない場合は直ちに侵害ではない。一方、将来の変更時の被害範囲は広い。
- Offline profileはGitHub APIを必要とするauditを実行しない。
- SARIF upload単体はmerge gateではなく、SARIF modeのprocess successはfindingなしを意味しない。
- Repository-local scanner workflowは同じPRで変更できる。CODEOWNERSとrequired reviewがliveでなければ、job名を残した
  bypassを防げない。
- Pinned scannerにもsource review、review済みupdate、registry availabilityが必要である。Private sourceの読取りやrunner
  network egressをSHA pinningだけでは防げない。
- 全PRでcontainerを取得して`.github`を解析するため、CI時間とexternal registry dependencyが増える。
- Rulesetのbypass actor、direct push、administrator変更、CODEOWNERSの実効性はprovider evidenceが必要である。
- Findingのreachability、business impact、false positiveにはhuman triageが必要である。

## Framework mappings

Machine-readable sourceは[control.yaml](control.yaml)である。Mappingはsupporting relationshipであり、formal complianceや
organization adoptionを示さない。

- [GitHub Actions Secure Use Reference — GHAS-REF-SECURE-USE](https://docs.github.com/en/actions/reference/security/secure-use)
  - Version: `github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24)`
  - Relationship: `supports`
  - Confidence: `high`
  - Rationale: Action固定、最小権限、untrusted PRとprivileged reportingの分離を自動reviewで支援する。
- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-VM-06.02](https://baseline.openssf.org/versions/2026-02-19#osps-vm-0602)
  - Relationship: `supports`
  - Confidence: `medium`
  - Rationale: Workflow変更をsecurity testing policyの対象にし、findingとscanner failureを区別する。

NIST SSDF、SLSA、MITRE ATT&CK等は、exact requirementへの直接的なevidenceをreviewできるまで新規mappingを追加しない。

## Guides and references

- [zizmor GitHub Actions integration](https://docs.zizmor.sh/integrations/)
- [zizmor usage and result behavior](https://docs.zizmor.sh/usage/)
- [zizmor audit rules](https://docs.zizmor.sh/audits/)
- [zizmor exit codes and static-analysis limitations](https://docs.zizmor.sh/usage/#exit-codes)
- [zizmor-action pinned source](https://github.com/zizmorcore/zizmor-action/tree/6fc4b006235f201fdab3722e17240ab420d580e5)
- [zizmor reviewed source snapshot](https://github.com/zizmorcore/zizmor/tree/6ea55f583ef6681a59b1c180950e47861a3c0293)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub `GITHUB_TOKEN` behavior](https://docs.github.com/en/actions/concepts/security/github_token)
- [GitHub compromised runner impact](https://docs.github.com/en/actions/concepts/security/compromised-runners)
- [GitHub workflow permission syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [GitHub CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [GitHub ruleset rules and required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub organization rulesets and required workflows](https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization)
- [GitHub SARIF upload guidance](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- [Repository-reviewed zizmor source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-002)
- [Repository-reviewed scanner comparison record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-008)
