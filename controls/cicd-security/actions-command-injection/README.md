# PSB-CICD-002: Prevent GitHub Actions command injection

## このcontrolを一枚で理解する

### セキュリティ上の問題

Attacker-influenced GitHub expressionを`run:`へ直接展開すると、その値がrunnerのtemporary shell scriptへ
source codeとして挿入され、任意command injectionになる。

### 誰から、または何から守るか

Fork contributor、悪意あるIssue／PR metadata、変更可能なworkflow input、侵害されたcollaborator、
YAML／shell境界の誤解、verifierやparserの失敗から守る。

### 何が対象か

GitHub Actions workflowの`run:` scalar、event expression、workflow input、environment boundary、
repository-local verifierとそのCI gate。

### 何をするか

`${{ ... }}`の`run:`直接補間を一律に禁止し、必要な値を`env:`へ移し、quoted shell variableまたは
固定allowlistでdataとして扱う。

### 成功状態

実repositoryの全`run:`に直接expressionがなく、安全例、finding、verification errorが別状態で検査され、
exit `1`と`2`の両方がmergeをblockする。

### 対象外・残余リスク

Environmentへ移した値もshell側で安全に引用する必要がある。Composite Action、呼び出し先script、
external Action内部、PowerShell／Windows、`eval`等の一般shell injection、live GitHub rulesetの有効性は
このverifierだけでは証明しない。

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
5. Inertな直接expressionを含むtest pull requestがblockされ、`env:`へ修正すると通ることを確認する。
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

検査するもの:

- `run:`内のsingle-line／multiline `${{ ... }}`;
- lineをまたいだexpression;
- supported `run:` scalarの有無;
- unreadable／invalid UTF-8 input;
- unsupported alias、flow-style、multiline quoted syntax;
- malformed／nested expression;
- tab indentation等の解析不能状態。

証明しないもの:

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

- Developer: direct expressionを`env:`へ移し、quoted variableまたはallowlistで利用する。
- Repository administrator: verifierとworkflowをcopyし、required check、CODEOWNERS、rulesetを設定する。
- Platform／SRE: 多数repositoryへ展開する場合だけcentral gateのavailability、pin、更新、support pathを管理する。
- Security: invariant、negative fixture、verifier変更、例外、live required checkをreviewする。

このcontrolのlocal pathではOrganization OwnerやPlatform構築を必須にしない。

## Evidence and adoption boundary

Repository fixtureの`ACCEPTED`はreference implementationのregression evidenceであり、organization adoptionを
証明しない。

Live adoptionを判断するには、少なくとも次を結び付ける。

- Review済みverifierのidentityまたはdigest;
- 対象repositoryとrevision;
- 実`.github/workflows`全体のcurrent result;
- 実required check／ruleset state;
- Acquisition timeとresponsible owner;
- Inert negative pull requestの拒否結果。

これらを取得していない場合は`NOT_CHECKED`とし、synthetic evidence fileを作らない。

## Limitations and operational cost

- Repository-local verifierは同じpull requestで変更できるため、CODEOWNERSとrequired reviewが必要である。
- Restricted parserは一部のvalid YAML formをexit `2`にする。Review可能なscalarへ書き換える運用costがある。
- 全direct expressionを拒否するため、形式が制約された値にも例外を設けない。
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
