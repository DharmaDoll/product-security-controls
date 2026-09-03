# PSB-CICD-002: Prevent GitHub Actions command injection

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHub Actionsは`${{ ... }}`をshell起動前に評価し、`run:`から生成するtemporary shell scriptへ結果を
文字列置換する。このため、PR title、Issue body、branch名、workflow input等の外部入力を`run:`へ直接展開すると、
見た目を`"..."`で囲っていても、入力中のquoteやshell metacharacterがscript自体の構文を壊し、追加commandを
runner上で実行できる。

ただし、危険な記述が1行あれば、誰でも直ちにrepositoryやcloudを乗っ取れるという意味ではない。具体的な被害は、
概ね次の条件がつながったときに成立する。

1. 攻撃者または侵害されたactorが、展開される値をshell構文を壊せる範囲で変更できる。
2. その値を含むworkflow eventとjobを、対象actorが起動または到達させられる。
3. 値が`run:`へ直接挿入され、固定scriptとdataの境界が失われる。
4. 実行先jobから、価値のあるtoken、secret、OIDC、artifact／cache、persistent runner、internal network、
   または後続のtrusted処理が信用するstateへ到達できる。

最初の3条件が揃えば、少なくともjob内での任意command実行は成立する。4番目の権限やdata flowが強いほど、被害は
test結果の偽装やresource abuseから、credential窃取、repository改ざん、release／cloud侵害へ拡大する。

### 誰から、または何から守るか

PR、Issue、branch、tag、manual input等を変更できるexternal contributor、侵害されたcollaborator account、
およびGitHub expressionを「shellで安全にquote済み」と誤解するworkflow authorから守る。値を変更できるactorが存在せず、
該当jobへ到達できない場合、外部actorによるattack pathの優先度は下がるが、将来のtrigger変更や内部actorの侵害を
考慮し、このcontrolはsourceごとの例外を設けない。

### 何が対象か

GitHub Actions workflowの`run:` scalarと、そこへ流入するevent metadata、workflow input、matrix value、step／job output、
environment boundary、repository-local verifier、そのCI gateを対象とする。Commandが実際に動くrunner user、workspace、
token／secret、network、後続artifact consumerが被害範囲を決めるため、導入時のrisk評価対象に含める。

### 何をするか

`${{ ... }}`の`run:`直接補間を一律に禁止し、必要な値を`env:`へ移し、quoted shell variableまたは
固定allowlistでdataとして扱う。Verifierは「このsourceは現在安全そうか」を推測せず、code生成境界そのものを固定する。
Job権限の削減やuntrusted PR分離は重要だが、別controlと組み合わせる防御層である。

### 成功状態

実repositoryの全`run:`に直接expressionがなく、安全例、finding、verification errorが別状態で検査され、
exit `1`と`2`の両方がmergeをblockする。さらに、inertなnegative pull requestでrequired checkの拒否を確認し、
各jobの実効権限を別途把握している。Verifierのexit `0`は、この限定されたcode生成経路にfindingがないことを示し、
workflow全体が安全またはorganizationへ導入済みであることは示さない。

### 対象外・残余リスク

`env:`は値を無害化するsanitizerではなく、固定scriptとdataを分離する境界である。移した値もshell側でquoteし、
commandを選ぶ値はallowlist化する必要がある。Composite Action、呼び出し先script、external Action内部、
PowerShell／Windows、`eval`、`bash -c`、untrusted code checkout、過剰なjob権限、live GitHub rulesetの有効性は
このverifierだけでは証明しない。

## まず、成立条件と被害の大きさを理解する

このcontrolの直接対象は「GitHub expressionの結果がshell source codeへ入る経路」である。Riskは次の連鎖として
確認すると、単に`${{ ... }}`という文字列を数えるより適切に判断できる。

```text
actorが変更できる値
  -> actorが到達できるworkflow event／job
  -> run:のtemporary shell scriptへ直接挿入
  -> shell構文を壊して追加commandを実行
  -> jobの実効権限、runner、network、またはtrusted data flowを悪用
```

### 何が入力になり得るか

代表例はPR／Issueの`title`や`body`、comment、label、branch／tag／ref、commit metadata、`workflow_dispatch`や
reusable workflowのinputである。Matrix valueやstep／job outputも、それ自体の名前ではなく、上流で未信頼値から
導出されていればattack inputになり得る。GitHubも`body`、`head_ref`、`label`、`message`、`name`、`ref`、`title`
等をpotentially untrustedなcontextとして挙げ、branch名にもshell metacharacterを含められると説明している。
詳細は[GitHubのScript injections](https://docs.github.com/en/actions/concepts/security/script-injections)を参照する。

反対に、値が固定literalである、actorが変更できない、または対象eventからjobへ到達できない場合、その時点の
外部attack exploitabilityは低い。ただし本controlは完全なtaint analysisを行わない。Source classificationやtriggerが
後から変わってもcode生成境界を維持できるよう、`run:`の直接expressionを一律にfindingとする。

### 実際に何が起こり得るか

| Jobの実効状態 | 起こり得る主な被害 | この状態だけでは通常できないこと |
|---|---|---|
| Ephemeral GitHub-hosted runner、write token／参照secret／OIDCなし、trusted handoffなし | Workspace内fileやtest processの改変、check結果の偽装／停止、log汚染、CI resource abuse、許可されたnetwork通信 | 未配送credentialが得られるわけではなく、repository writeやcloud操作には別のauthority pathが必要 |
| PR runのartifact、cache、outputをprivileged jobが信用する | 後続build／releaseが実行・読込するstateのpoisoning。前段tokenがread-onlyでも後段authorityを間接利用し得る | Consumerがproducer、digest、形式を検証し、非実行dataとして扱えば同じ経路は制限される |
| Write可能な`GITHUB_TOKEN`またはworkflowへ配送されたsecretがある | Token scopeとrulesetの範囲でrepository／package操作、secretが許す外部serviceへのなりすましや外部送信 | Tokenにないscopeや、外部policyが拒否する操作まで可能になるわけではない |
| `id-token: write`、protected Environment、deploy credentialがある | Environment approvalとcloud側trust policyを通過した場合の一時credential取得、deploy target操作 | OIDC permissionだけでcloud権限が生まれるわけではなく、cloud側claim条件が必要 |
| Persistent self-hosted runner、daemon socket、host credential、internal routeがある | Runnerへの永続化、credential取得、internal serviceへの横展開、別jobへの影響 | One-job ephemeral isolationとnetwork分離が実効なら同じimpactは縮小する |

ここでの「任意command実行」はrunner jobのsecurity context内での実行を意味し、GitHub organization administrator権限を
自動取得するという意味ではない。最大被害はworkflow textだけで決めず、event、effective permission、secret参照、
Environment、cloud trust、runner lifecycle、cross-job data flowを合わせて評価する。

### 対応優先度の目安

- 最優先: 直接expressionが、write token、secret、OIDC、production Environment、persistent runner、internal networkを
  持つjobにある。
- 高: Findingのあるjobが生成したartifact、cache、outputを、署名・release・deploy等のtrusted jobが実行または信用する。
- 修正必須だがimpactを分けて記録: Read-only、secretなしのephemeral job。この場合もjob内command実行とcheck偽装は
  成立するが、repository／cloud侵害には追加のauthority pathが必要である。
- Policy findingだがcurrent exploitabilityは低い: `github.sha`等の厳しく制約された値、または現状actorが到達できない
  event。例外化する代わりに`env:`へ移し、triggerやdata sourceの将来変更でriskが再発しないようにする。

PR jobが既にPR作成者の変更可能なsource codeやbuild scriptを同じ権限で実行している場合、command injectionが
そのjobに新しいauthorityを追加するとは限らない。それでも意図したvalidation順序を迂回できるため修正対象だが、
主なtrust-boundary対策は[`PSB-CICD-005`](../untrusted-pr-boundary/README.md)である。反対に、PR codeを実行せず
metadataだけを処理するはずの`pull_request_target`、`issues`、`issue_comment`等のprivileged jobでは、この欠陥が
data-only処理をcode executionへ変えるため、同じ1行でも優先度が大きく上がる。

### 実在報告が示す条件差

- [GHSL-2020-230: aws/aws-sam-cli workflow](https://securitylab.github.com/advisories/GHSL-2020-230-aws-aws-sam-cli-workflow/)
  はpublic PR titleからBash command injectionが成立した実例である。一方、`pull_request`のlimited tokenかつsecretなし
  だったため、報告上のimpactは主にCI denial of serviceとrunner context内のcode executionに限定された。
- [GHSL-2025-090: harvester workflow](https://securitylab.github.com/advisories/GHSL-2025-090_harvester_harvester/)
  ではPR titleが`pull_request_target`のjobへ直接展開され、custom GitHub tokenもjobへ配送されていた。報告では
  high-privilege contextでのcode executionとsecret exposureの可能性が指摘された。

両方とも同じexpression-to-script欠陥だが、triggerとjob authorityによってimpactが異なる。このcontrolは欠陥を
一律に除去し、triage時にはその差を隠さず記録する。

## 10分で導入する

このcontrolの最短経路は、2つのstandard-library scriptと1つのread-only workflowをcopyする方法である。
Installer、package manager、Docker、network access、global developer settingは不要である。

### Prerequisites and trust assumptions

- GitHub Actionsを使用し、対象workflowに`run:` stepがある。
- 最小profileはGitHub-hosted UbuntuとBash／POSIX shellである。
- Developer環境とCIにPython 3.10+とBashがある。
- Repository administratorがrequired status checkを設定できる。
- Copy元のverifierをreviewし、workflowとverifierの変更を保護するownerがいる。

PowerShell、Windows `cmd`、Composite Actionを対象にする場合は、このprofileを安全と推測せずshell固有の
exampleとtestを追加する。

Copy前に、対象workflowごとに次を1行で書き出す。これがないとfindingは検出できても、被害の大きさを判断できない。

| 確認項目 | 最小限記録する内容 |
|---|---|
| Entry point | `pull_request`、`issues`、`workflow_dispatch`、reusable caller等、誰が起動できるか |
| Expression source | PR title、branch、input、matrix、step output等、誰が値を変更できるか |
| Shell sink | Direct expressionを含むjob／stepと、Bash等の実shell |
| Authority | Effective `GITHUB_TOKEN` permission、参照secret、OIDC、Environment、runner、network |
| Trusted handoff | Artifact、cache、output、workspaceを後続のrelease／deploy jobが利用するか |

権限が分からない場合でもlocal verifierは導入できるが、live risk評価は`NOT_CHECKED`のままとする。推測で
「read-onlyだから無害」または「必ずrepository takeover」と判定しない。

### Copyするfile

| Copy元 | Adopter repositoryでの推奨先 | 用途 |
|---|---|---|
| [`scripts/verify.py`](scripts/verify.py) | `.security/actions-command-injection/verify.py` | `run:`の直接expressionを検査 |
| [`scripts/self-test.sh`](scripts/self-test.sh) | `.security/actions-command-injection/self-test.sh` | safe／finding／errorとinert payloadを確認 |
| [`secure/local-gate.yml`](secure/local-gate.yml) | `.github/workflows/actions-command-injection.yml` | Read-only required check sample |

既存fileを上書きしない。次はcopy元とadopter repositoryのabsolute pathを設定して実行する例である。

```bash
control_source=/absolute/path/to/product-security-controls/controls/cicd-security/actions-command-injection
adopter_repository=/absolute/path/to/adopter-repository

test -d "$control_source"
test -d "$adopter_repository/.git"
test ! -e "$adopter_repository/.security/actions-command-injection/verify.py"
test ! -e "$adopter_repository/.security/actions-command-injection/self-test.sh"
test ! -e "$adopter_repository/.github/workflows/actions-command-injection.yml"

mkdir -p "$adopter_repository/.security/actions-command-injection"
mkdir -p "$adopter_repository/.github/workflows"
cp "$control_source/scripts/verify.py" \
  "$adopter_repository/.security/actions-command-injection/verify.py"
cp "$control_source/scripts/self-test.sh" \
  "$adopter_repository/.security/actions-command-injection/self-test.sh"
cp "$control_source/secure/local-gate.yml" \
  "$adopter_repository/.github/workflows/actions-command-injection.yml"
```

既存のsecurity workflowや同名checkがある場合はcopyを止め、adopter-owned reviewでmergeする。

### Local activation and self-test

Adopter repositoryのrootで実行する。

```bash
bash .security/actions-command-injection/self-test.sh
python3 .security/actions-command-injection/verify.py .github/workflows
```

Self-testの期待出力は次のとおりで、終了statusは`0`である。

```text
PASS safe environment boundary and allowlist accepted
PASS direct expression rejected
PASS inert shell metacharacters remained data
PASS verifier output omitted environment values
PASS missing input reported as verification error
```

Verifierは`0=accepted`、`1=direct expression finding`、`2=input／parser／execution error`を返す。
`1`と`2`はどちらもcleanではない。

### CI and server-side activation

1. Copyした3 fileをreviewし、通常のpull requestで追加する。
2. `Actions command injection gate / Reject direct expressions in run`が実repositoryで成功することを確認する。
3. Repositoryの`Settings` → `Rules` → `Rulesets`で、実際に生成されたcheckをrequired status checkにする。
4. `.github/workflows/**`と`.security/actions-command-injection/**`をCODEOWNERS対象にする。
5. Secret、write操作、production Environmentを使わないdisposable branchで、inertな直接expressionを含むtest pull
   requestがblockされ、`env:`へ修正すると通ることを確認する。
6. Verifier errorでもmergeできないことを確認する。

GitHubのrequired check設定は、このrepositoryのfixtureでは検証できない。Live rulesetを確認して初めて
server-side enforcementが有効になる。

### Common failure recovery

| 状態 | 原因例 | Recovery |
|---|---|---|
| Exit `1` | `run:`へ`${{ ... }}`を直接記述 | 値を`env:`へ移し、consumption pointでquoteする |
| Exit `2`: unsupported `run` | Alias、flow style、multiline quoted scalar | `run: |`または通常のsingle-line scalarへ書き換える |
| Exit `2`: no run steps | 対象pathが誤り、またはcontrol非該当 | 対象pathを直す。非該当なら人が`N/A`を判断し、PASSを捏造しない |
| Exit `2`: Python unavailable | Python 3.10+がない | Approved developer／CI runtimeを復旧する |
| Required checkが出ない | Workflow未起動、caller削除、GitHub設定不備 | Workflow runとrulesetを確認し、required checkを外して回避しない |

### Rollback

Rollbackはadopter-owned changeとして行う。先にrulesetのrequired checkと代替controlをreviewし、その後に
この導入でcopyしたworkflow、self-test、verifierだけを削除する。Global Git、shell、IDE、Python、OS設定に
変更はない。Rollbackすると直接expressionを自動blockできなくなるため、`PSB-CICD-003`等の独立したgateを
残すか、残余リスクを明示する。

## なぜcommand injectionになるのか

GitHub Actionsは`${{ ... }}`をshellより先に評価する。`run:`の内容はtemporary scriptとしてrunnerへ渡され、
expression結果がそのscriptへ直接挿入される。

```text
Vulnerable
untrusted PR title
  -> GitHub expression evaluation
  -> generated temporary shell scriptへ文字列を挿入
  -> shell metacharacterがcodeとして実行

Safe boundary
untrusted PR title
  -> environment value
  -> fixed shell script
  -> quoted "$PR_TITLE"としてdata利用
```

したがって、次の引用符は対策にならない。引用符自体を壊す文字列がscript生成時に挿入されるためである。

```yaml
run: echo "${{ github.event.pull_request.title }}"
```

例えば、検証専用PRのtitleが次の無害な文字列だったとする。

```text
docs"; printf '%s\n' 'INERT-INJECTION'; #
```

Runnerへ渡されるscriptは概念的に次の形になり、元の`echo`とは別の`printf`が実行される。実攻撃ではこの追加commandが
credential取得、file改変、外部送信等へ置き換わる。被害範囲は前節のjob authorityで決まる。

```sh
echo "docs"; printf '%s\n' 'INERT-INJECTION'; #"
```

この例はsyntax boundaryを理解するためのinert payloadであり、production workflowやreal secretを使って試さない。
[`scripts/self-test.sh`](scripts/self-test.sh)はtemporary directoryだけで同じ性質を確認する。

このcontrolは、危険なproperty一覧を追跡しない。Branch、title、body、label、workflow input、matrix、outputに
限らず、`run:`内の直接expressionを一律に拒否する。`github.sha`等の形式が制約された値も例外にしない。
単純なinvariantの方がreviewしやすく、新しいcontext propertyの見落としを避けられるためである。

## Secure patterns

GitHubは、inline scriptを避けてreview済みActionへ値をargumentとして渡す方法と、intermediate environment
variableを使う方法を案内している。このcontrolの最小pathは、新しいActionを増やさず既存inline stepを直せる
`env:`方式である。すでにreview済みActionがある場合は`with:`へdataとして渡してよいが、そのAction内部の
処理は別のtrust boundaryである。

### Free-form textはenvironmentへ移す

```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: printf '%s\n' "$PR_TITLE"
```

`env:`へ移すことで、値はscript生成ではなくprocess environmentを通る。Shell variableは引き続きquoteする。
`${{ env.PR_TITLE }}`を`run:`で使うと再びtemplate expansionになるため使用しない。

これは入力からquoteやmetacharacterを削除する処理ではない。入力のbytesをdataのまま渡し、固定済みscriptの構文を
変えさせない処理である。そのため、値を`printf '%s\n' "$PR_TITLE"`のようにdataとして消費する限り、payloadが
そのまま表示されても追加commandにはならない。一方、`eval "$PR_TITLE"`のように再解釈すれば境界は失われる。

### 値が動作を選ぶ場合はallowlistを使う

```yaml
env:
  REQUESTED_TARGET: ${{ inputs.target }}
run: |
  case "$REQUESTED_TARGET" in
    lint|test|verify)
      make "$REQUESTED_TARGET"
      ;;
    *)
      printf 'Unsupported target: %s\n' "$REQUESTED_TARGET" >&2
      exit 1
      ;;
  esac
```

User inputからcommand stringを作らない。`eval`、補間した`bash -c`、sourced file、generated scriptは、
`env:`を使っていてもcommand injectionを再導入できる。

### Non-executable fieldは別扱いにする

```yaml
concurrency:
  group: verify-${{ github.workflow }}-${{ github.ref }}
```

このexpressionはshell sourceではないため、本controlのfindingにはしない。Field固有の安全性は別途reviewする。

## Verification boundary

[`scripts/verify.py`](scripts/verify.py)はconventionalなsingle-line、literal block、folded blockの`run:`を
deterministicに検査するrestricted parserである。

判定の意味は次のとおりである。

| Exit | 判定 | 正しく読み取る内容 |
|---|---|---|
| `0` | Accepted | Supportedな全`run:`に直接expressionがない。このinvariantだけの結果であり、shell全体やjob権限の安全性は未証明 |
| `1` | Finding | 直接expressionがある。攻撃成立条件とimpactは別途triageするが、code生成境界を直すまでgateは通さない |
| `2` | Verification error | Input、syntax、runtime等の理由で評価不能。Cleanへ読み替えず、検査可能になるまでgateは通さない |

検査するもの:

- `run:`内のsingle-line／multiline `${{ ... }}`;
- lineをまたいだexpression;
- supported `run:` scalarの有無;
- unreadable／invalid UTF-8 input;
- unsupported alias、flow-style、multiline quoted syntax;
- malformed／nested expression;
- tab indentation等の解析不能状態。

証明しないもの:

- Expression sourceを誰が変更できるか、対象eventからjobへ到達できるかというtaint／reachability analysis;
- Findingを利用した場合のseverityや、jobのeffective authority;
- `env:`を消費する任意shell codeの完全な安全性;
- Composite Actionやrepository script内のcommand construction;
- External Actionが`with:` inputを安全に処理すること;
- Runtime filesystem、network、credential、runner isolation;
- Live required check、CODEOWNERS、rulesetの有効性。

Unsupported formをcleanと推測しない。Full YAML parserや追加dependencyは、具体的にsupportすべきsyntaxと
negative fixtureが確認された場合だけ検討する。

## 案2: PSB-CICD-003と組み合わせる

[`PSB-CICD-003`](../actions-static-analysis/README.md)はpinned `zizmor`、unprivileged pull-request gate、
trusted SARIF reportingを所有する。本controlはscanner platformを複製せず、expression-to-shell boundaryの
単純なinvariantと最小local verifierを所有する。

| PSB-CICD-002 | PSB-CICD-003 |
|---|---|
| 全`run:` direct expressionを一律拒否 | 複数種類のworkflow security findingを検出 |
| Python standard-library verifier | Version／digest固定のzizmor |
| 修正patternとlocal self-test | PR gateとSARIF lifecycle |
| Restricted syntaxはexit `2` | Scanner／SARIF failureを別状態で処理 |

zizmorの[`template-injection` audit](https://docs.zizmor.sh/audits/#template-injection)は関連する防御層である。
ただしtaint判定を行うscanner ruleと、本controlの一律禁止ruleが常に同じfinding集合になるとは主張しない。
Zizmorを既に採用していても、本controlのstrict invariantを置き換える場合は同じnegative fixtureで差を確認する。

## 案3: Central trusted gate PoC

多数repositoryへ配布する場合は、repository-local verifierの改変リスクと更新負担を減らすため、中央security
repositoryのreusable workflowへ移行できる。思想、copyable skeleton、manual PoCは
[`docs/CENTRAL_GATE_POC.md`](docs/CENTRAL_GATE_POC.md)に示す。

このPoCは次を証明しない。

- Organization-wide rolloutが完了していること;
- Private reusable workflowへのaccessが正しいこと;
- Ruleset、required check source、CODEOWNERSがliveで有効なこと;
- Callerやstatus checkのspoofを完全に防止できること;
- GitHub plan固有機能が利用可能なこと。

Central repository、exact commit SHA、consumer、rulesetを実環境で確認して初めてadoption evidenceになる。

## Roles

- Developer: Expression sourceとshell sinkを特定し、direct expressionを`env:`へ移してquoted variableまたはallowlistで
  利用する。修正後にlocal self-testとrepository workflow scanを実行する。
- Repository administrator: 対象eventとactorの到達性、effective token permission、secret／OIDC／Environment、
  trusted handoffをinventoryし、verifier、required check、CODEOWNERS、rulesetを設定する。
- Platform／SRE: Self-hosted runnerやinternal networkがある場合に実到達性を確認する。多数repositoryへ展開する場合だけ
  central gateのavailability、pin、更新、support pathを管理する。
- Security: Findingをsource、reachability、job authority、data flowでtriageし、invariant、negative fixture、verifier変更、
  例外、live required checkをreviewする。

このcontrolのlocal pathではOrganization OwnerやPlatform構築を必須にしない。

## Evidence and adoption boundary

Repository fixtureの`ACCEPTED`はreference implementationのregression evidenceであり、organization adoptionを
証明しない。

Live adoptionを判断するには、少なくとも次を結び付ける。

- Review済みverifierのidentityまたはdigest;
- 対象repositoryとrevision;
- 実`.github/workflows`全体のcurrent result;
- Findingを含む、または含んでいたjobのevent、effective permission、secret／OIDC／Environment、runner、trusted handoff;
- 実required check／ruleset state;
- Acquisition timeとresponsible owner;
- Inert negative pull requestの拒否結果。

これらを取得していない場合は`NOT_CHECKED`とし、synthetic evidence fileを作らない。

## Limitations and operational cost

- Repository-local verifierは同じpull requestで変更できるため、CODEOWNERSとrequired reviewが必要である。
- Restricted parserは一部のvalid YAML formをexit `2`にする。Review可能なscalarへ書き換える運用costがある。
- 全direct expressionを拒否するため、形式が制約された値にも例外を設けない。
- Exit `1`はpolicy findingであり、すべてが同じimpactではない。Triageではjob authorityとtrusted handoffを別途確認する。
- `env:`はscript生成境界を分離するが、unquoted variable、`eval`、`bash -c`、command constructionを防がない。
- GitHub-hosted runnerを使ってもnetwork exfiltrationやmalicious repository code execution自体は防がない。
- PowerShell、Windows、Composite Action、called scriptを追加するときは別のshell-aware implementationが必要である。
- Minimum token permissionは`PSB-CICD-004`、untrusted PR isolationは`PSB-CICD-005`、runner containmentは
  `PSB-BUILD-001`が所有する。

## Framework and threat relationships

| 種別 | 参照 | このcontrolでの扱い |
|---|---|---|
| GitHub implementation guidance | [Script injections](https://docs.github.com/en/actions/concepts/security/script-injections) | Temporary script生成と直接expression riskの根拠 |
| GitHub implementation guidance | [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) | Intermediate environment variableとquoted variableの根拠 |
| OpenSSF requirement framework | [OSPS Baseline 2026.02.19 — OSPS-BR-01.01](https://baseline.openssf.org/versions/2026-02-19#osps-br-0101) | Untrusted CI/CD metadataを使用前にvalidate／sanitizeするrequirementへの限定的evidence |
| SITF threat taxonomy | [SITF 1.0.0 — T-C004 Workflow Script Injection](https://github.com/wiz-sec-public/SITF/blob/d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59/techniques.json) | 関連attack behavior。Compliance requirementではない |
| Weakness taxonomy | [CWE-78 OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) | Codeとexternally influenced dataの混在を理解する補助。Current `control.yaml` mappingではない |
| Repository registry | [GitHub Security Guidance registry](../../../frameworks/github-security-guidance/registry.json) | Pinned sourceとreview済みmapping version |
| Repository registry | [OpenSSF OSPS registry](../../../frameworks/openssf-osps-baseline/registry.json) | Exact releaseとrequirement inventory |
| Cross-control profile | [SITF coverage policy](../../../policies/integration/sitf-coverage.json) | `T-C004`と`INJ-001／002／004`の関連を管理 |

Mappingは`control.yaml`のexact checkへ限定する。GitHub guidance、OSPS、SITF、CWEのいずれも、このfixtureの
PASSだけでcompliance、complete mitigation、live adoptionを意味しない。NIST SSDFやOWASP Top 10は名称や
二次的relationだけから追加せず、exact requirementをreviewした場合だけmappingする。

## Related guides and tools

GitHub official:

- [Workflow syntax for GitHub Actions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Reuse workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [About CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Managing GitHub Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)

Scanner and practitioner guidance:

- [zizmor `template-injection` audit](https://docs.zizmor.sh/audits/#template-injection)
- [GitHub Actions Best Practice 2025](https://suzuki-shunsuke.github.io/slides/github-actions-best-practice-2025)
- [Mercari 社内用GitHub Actionsのセキュリティガイドライン](https://engineering.mercari.com/blog/entry/20230609-github-actions-guideline/)
- [GMO Flatt SecurityのGitHub Actions検知ツール比較](https://blog.flatt.tech/entry/2026-github-actions-security-part4)
- [Repository-owned source review records](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-002)

Practitioner guidanceは背景理解とtool boundaryの参考であり、framework mappingやdependency adoptionの根拠へ
自動変換しない。
