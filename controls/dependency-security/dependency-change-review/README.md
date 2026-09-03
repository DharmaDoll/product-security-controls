# PSB-DEPS-004: Dependency change review

## このcontrolを一枚で理解する

### セキュリティ上の問題

Dependency更新は外部componentのcodeを製品、build、testへ取り込む変更である。ただし、dependencyが変わっただけで
直ちに被害が発生するわけではない。概ね次の条件がつながったときに実害へ進む。

1. PRで追加・更新されたdirectまたはtransitive dependencyが、lockfile解決後に実際のbuild、test、package、
   runtimeのいずれかへ入る。
2. 選択されたversionに既知脆弱性があり、製品やCIがその脆弱な機能を実行する、または攻撃者が到達できる入力へ
   露出する。
3. Dependency固有の差分やadvisoryがreviewerへ表示されない、checkが`warn-only`である、またはcheckがmerge条件で
   ないため、修正前に変更がmergeされる。
4. Merge後のbuild、release、deployまたはdeveloper installを通じてaffected componentが利用される。

起こり得る被害はadvisoryの内容と利用方法によって異なり、remote code execution、認証回避、情報漏えい、任意file
操作、service停止、build artifact改ざん等になり得る。一方、affected機能を使用せず攻撃入力から到達不能なら、同じ
severity labelでも実際の影響は小さい場合がある。したがって`high`というlabelだけで被害を断定せず、まずmergeを止め、
利用経路と影響を調査する。

通常のcode reviewではmanifestに書かれたdirect dependencyだけを見て、長いlockfile内で一緒に更新されたtransitive
dependencyを見落としやすい。このcontrolはbase-to-headのdependency差分と、その時点で公開済みのknown
vulnerabilityをPR上へ出し、評価が成功しない限りmergeできない状態を作る。

GitHubのdependency reviewは、PRにより追加・更新・削除されるdependencyと脆弱性情報を表示する機能である。
Provider上の挙動は[GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
を参照する。

### 誰から、または何から守るか

既知の脆弱なversionを意図せず選ぶdeveloper／update bot、侵害されたaccountから送られるdependency更新、direct
dependencyだけを見てtransitive変更を見落とすreview、`warn-only`やoptional checkの設定ミス、依存関係データ／
Action／API／runnerの失敗をclean resultとして扱う運用から守る。

このcontrol単独では、公開直後でadvisoryがないmalicious packageや、正規maintainerが悪意あるcodeを混入した更新を
自動判定できない。それらに対して提供するのはdependency差分の可視化までであり、確実なblockではない。

### 何が対象か

Default branchへmergeするpull request、GitHubが依存関係として読み取れるmanifest／lockfile、baseとheadの
依存関係の解決結果、追加・更新されたdirect／transitive dependency、version、scope、manifest／lockfile、known
vulnerability、Dependency Review job、default-branch ruleset。

Repository全体に既に存在する未変更dependencyの継続監視、registryから取得したartifactのhash、package install時の
script実行は対象外である。

### 何をするか

GitHub Dependency Review Actionがbase／head間の依存関係の解決結果を比較し、changed dependencyとknown vulnerabilityを
PR上へ表示する。Referenceはruntime、development、unknown scopeの`high`以上をjob failureにする。
Repository administratorはそのjobをactive rulesetのrequired checkにし、failure、error、cancel、missing checkが
merge条件を満たさないようにする。

### 成功状態

Harmlessなdependency updateでdirect／transitive差分が確認でき、既知high vulnerabilityを記録したinert testでは
jobが失敗する。そのfailureを残した状態と、jobをcancel／missingにした状態の両方でdefault branchへmergeできない。
Supported ecosystem、provider result、rulesetのいずれかを確認できなければ`PASS`ではなく`NOT_CHECKED`または
`ERROR`である。

### 対象外・残余リスク

Clean resultはdependencyが安全であることを保証しない。Advisory未公開の脆弱性、malicious-but-unadvised code、
maintainer intent、dependency confusion、registry substitution、artifact hash、install script、provenance、license、
merge後に公開された脆弱性は別controlまたは継続運用が必要である。

## まず、このcontrolの本質を理解する

問題は「dependencyを使っていること」ではなく、危険な変更が利用経路へ入り、merge gateがそれを止めないことである。

```text
PRでaffected dependency versionが追加・更新される
                         +
そのcomponentがbuild／test／runtimeで実際に利用される
                         +
脆弱な機能へ攻撃入力または価値あるCI assetから到達できる
                         +
dependency reviewのfinding／failureがmergeを止めない
                         =
advisoryに記載された影響が製品やsoftware supply chainで現実化し得る
```

このcontrolが直接保証するのは、式の最初と最後、つまり「何が変わったかを表示すること」と「known-highまたは評価失敗を
merge前に止めること」である。実際のreachability、exploitability、事業影響はadvisory、製品構成、network exposure、
CI authority等を使って別途判断する。

例えば、directなweb frameworkの更新に伴い、lockfile内のtransitive parserもaffected versionへ更新されたとする。
Applicationがuntrusted fileをそのparserへ渡し、advisoryの脆弱な処理を使うなら、deploy後にfile操作、情報漏えい、
code execution等へ進む可能性がある。Manifestだけを見るreviewではparser変更を見落とせるが、dependency reviewが
transitive差分とknown-high advisoryを表示してrequired checkを失敗させれば、merge前に調査できる。

逆に、parserが製品へpackageされない、またはaffected機能を一切呼ばないことを再現可能なevidenceで確認できる場合、
実riskは異なる。その判断はjobを`warn-only`にする理由ではなく、[`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)
で対象version、advisory、owner、期限を限定して扱う。

## GitHub Dependency Reviewがこの実装でしていること

結論として、このcontrolの**Reference実装はGitHub Dependency Reviewを中心にしている**。ただし、Actionを1個実行する
だけのcontrolではない。Security outcomeは次の4段階がすべてつながったときに生まれる。

このREADMEでいう「依存関係の解決結果」は、direct dependencyだけでなく、そのdependencyが必要とするtransitive
dependencyまで含めた「packageとversionの一覧」である。`A`が`B`を、`B`が`C`を必要とするなら、A・B・Cとその関係が
入る。GitHubはこの一覧とつながりを正式には**Dependency graph**と呼ぶが、本READMEでは製品名を示す場所以外では
「依存関係の解決結果」または「依存関係の差分」と呼ぶ。

```text
supported manifest／lockfile、またはdependency submission
                           ↓
 GitHub Dependency graph（依存関係の一覧・つながり）のdata
                           ↓
       base commit ... head commitのdependency差分
                           ↓
 Dependency Review Actionのpolicy判定（high以上ならfailure）
                           ↓
      active ruleset（non-successならmergeを拒否）
```

| 段階 | GitHub機能 | このcontrolでの役割 | ここで実際に確認すること |
|---|---|---|---|
| 1. Data | GitHub Dependency graph | Supported manifest／lockfileとsubmission済みsnapshotからdependency情報を得る | 対象ecosystemとfileがsupportedで、期待したdirect／transitive dependencyが取得される |
| 2. Diff | Dependency review／REST API | Baseとheadの間で追加、更新、削除されたdependencyを比較し、known vulnerability情報を結び付ける | PRのrich diffまたはjob summaryをlockfileの実差分と照合する |
| 3. Decision | `actions/dependency-review-action` | Changed dependencyへseverity、scope等のpolicyを適用してjob conclusionを出す | Inertなknown-high更新で`Dependency Review`が`failure`になる |
| 4. Enforcement | Repository ruleset | Actionの結果をmerge条件にする | Failure、error、cancelled、missingの各状態でdefault branchへmergeできない |

### Lockfile固定との補完関係

[`PSB-DEPS-003`](../lockfile-integrity/README.md)のlockfile integrityは、「reviewした依存関係の解決結果をexact versionで
固定し、install時に勝手に別versionへ解決させない」ためのcontrolである。それだけでは、review対象のlockfileへ**既知の
脆弱性がある新versionが意図的または見落としで記録された**ことまでは判定しない。固定された解決結果は再現可能になるが、
それが安全であるとは限らない。

このcontrolはPRのbase-to-head差分に対して「何がdirect／transitiveに変わったか」と「その変更がknown-high／critical
vulnerabilityを新規に持ち込むか」を確認し、merge前に止める。逆にDependency Reviewはlockfileの改ざん、registry
substitution、artifact hash、未知またはadvisory未公開のmalicious packageを防がない。両controlを組み合わせても、
未知のriskやpackageのoriginは別controlで扱う。

| 確認したいこと | 主担当 |
|---|---|
| Install時にreview済みと異なるversion／依存関係の解決結果へ変わらないか | `PSB-DEPS-003` lockfile integrity |
| 今回のPRがknown-vulnerableなdependency versionを新しく導入しないか | `PSB-DEPS-004` Dependency Review |
| Registry、artifact、provenanceが信頼できるか | release／supply-chain integrity control |
| Merge済みのdependencyに後からadvisoryが公開されていないか | 継続SCA（[`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md)） |

GitHubの画面に出るdependency reviewと、GitHub Actionsで実行するDependency Review Actionは同じではない。前者は
`Files changed`でdependency差分を人が確認するrich diffであり、後者は
[Dependency review REST API](https://docs.github.com/en/rest/dependency-graph/dependency-review)でbase／head差分を取得してpolicyを
自動判定する実行componentである。さらに、Actionがfailureを返してもrequired checkまたはrequired workflowにしなければ
mergeは止まらない。[GitHubのdependency review解説](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
も、Actionによるfailureがmergeを止めるにはrepository ownerがcheckをrequiredにする必要があるとしている。

### 何が表示・判定されるか

Supported manifest／lockfileでは、追加・更新・削除、versionまたはversion range、direct／indirect dependency、known
vulnerability等を確認できる。GitHubのrich diffは利用可能な場合にrelease age、dependent数、license、advisory ID、
severity、patched version等も表示する。詳細は
[Reviewing dependency changes in a pull request](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-dependency-changes-in-a-pull-request)
を参照する。ただし、このbasic profileがmerge判定に使うのは**changed dependencyのknown vulnerability、severity、scope**
だけであり、licenseやOpenSSF Scorecardは別のpolicy判断と混同しないよう無効化している。

Reference workflowの主要設定は次の意味を持つ。
[Pinned Actionのconfiguration](https://github.com/actions/dependency-review-action/blob/a1d282b36b6f3519aa1f3fc636f609c47dddb294/README.md#configuration)
も併せて参照する。

| Setting | Reference value | 意味 |
|---|---|---|
| `vulnerability-check` | `true` | Changed dependencyのknown vulnerabilityを判定する |
| `fail-on-severity` | `high` | High／criticalをmerge前の調査対象としてjob failureにする |
| `fail-on-scopes` | `runtime, development, unknown` | Action既定のruntimeだけでなく、build／test toolと分類不能な変更も除外しない |
| `warn-only` | `false` | Findingをwarning付きsuccessへ変換しない |
| `license-check` | `false` | License policyをこのcontrolのsecurity claimへ含めない |
| `retry-on-snapshot-warnings` | `true`、最大120秒 | Dependency submissionとのraceでsnapshot warningが出た場合だけbounded retryする |
| `show-openssf-scorecard` | `false` | Package reputationのinformational signalをvulnerability gateと混同しない |

`retry-on-snapshot-warnings`はunsupported ecosystem、parse漏れ、恒久的なprovider failureを安全に変える設定ではない。
Retry後も評価できなければ`PASS`ではなく`NOT_CHECKED`または`ERROR`として扱う。

### Trivyとの違い

Trivyは不要なのではなく、**別の時間軸と対象を受け持つ**。GitHub Dependency ReviewはPRのbase-to-head差分を見て、
今回の変更が新しく持ち込むriskをmerge前に止める。一方、通常の`trivy fs`／`trivy repo`はcheckoutされた現在状態の
repositoryやfilesystemをscanするため、変更されていない既存dependencyやmerge後に公開されたadvisoryの継続検出に向く。

| Tool／control | 主な問い | 実行時点 | このpackageでの位置付け |
|---|---|---|---|
| GitHub Dependency Review | このPRで依存関係の何が変わり、known-highを新しく持ち込むか | PR、merge前 | Reference実装の中心 |
| Trivy | 現在のrepository／filesystem／artifactにknown vulnerabilityがあるか | Default branch、定期、release | [`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md)へ委譲 |

したがって、GitHub対応repositoryへ同じPR gateとして素のTrivy scanを重ねることはbasic profileに含めない。全体scanは
このPRと無関係な既存findingでも失敗し得て、base-to-headのdependency差分という`DCR-001`の証拠にはならないためである。
GitHub Dependency Reviewを利用できないproviderやunsupported ecosystemでは、Trivy等を代替実装に選べるが、その場合も
changed dependencyを識別する方法、scanner／DB failureのfail-closed処理、required check、tool pinとintegrity verificationを
別profileとして定義する。Trivy自体の対象は[Filesystem](https://trivy.dev/docs/latest/target/filesystem/)および
[Repository](https://trivy.dev/docs/latest/target/repository/)の公式説明を参照する。

## 何が、どの条件で被害になるか

| 変更対象 | 被害が成立する主な条件 | 起こり得ること | 条件が揃わない例 |
|---|---|---|---|
| Runtime dependency | Affected versionがdeploy artifactへ入り、脆弱なAPI／parser／protocolへattacker-controlled inputが届く | Advisoryに応じたRCE、認証回避、情報漏えい、file操作、DoS | Componentをpackageしない、affected機能を使わない、入力が防御境界で到達不能 |
| Development／build dependency | Affected toolやpluginをdeveloper endpointまたはCIが実行し、脆弱な入力を処理する | Source／build artifact改ざん、CI credential悪用、build停止。Exact impactはjob authority次第 | Toolを実行しない、isolated jobに価値あるcredential／networkがない |
| Transitive dependency | Direct dependency更新によりchild versionが変わり、childが実際に実行またはpackageされる | Reviewerが認識しないままruntime／build vulnerabilityが導入される | Resolver結果が変わらない、childがoptionalで最終artifactへ入らない |
| Known finding | Providerがaffected versionを正しく特定したが、workflowが`warn-only`またはrequiredでない | Findingを認識しながらmergeし、後続環境で上記影響が現れる | Required checkがfailureとなり、修正または限定例外までmerge不可 |
| 依存関係データ／Action failure | Unsupported manifest、依存関係データの欠落、API／runner failureをempty safe diffと解釈する | 実際には未評価のdependency変更がreview済みとしてmergeされる | `ERROR`／`NOT_CHECKED`としてrequired checkを満たさない |

この表は「high advisoryがあれば必ず侵害される」「development dependencyは常にruntime dependencyと同じ被害になる」
という意味ではない。Changed componentがどこで実行され、どの入力とauthorityへ接続されるかを確認する。

### 対応優先度の目安

- 最優先: Internet-facingなruntime pathで到達可能なRCE、認証回避、機密情報漏えい、任意file操作。
- 最優先: Release／signing／deploy authorityを持つCIで実行されるbuild toolのcode execution。
- 高: Exploitabilityが未確認だが、affected componentがproduction artifactまたはstandard build pathへ入る。
- 要調査: Development-only、optional、feature-disabled等の理由で到達不能と考えられるが、再現可能な根拠がない。
- `NOT_CHECKED`: Ecosystem、manifest、transitive dependency、provider resultを確認できない。低riskという意味ではない。

## そもそもこのcontrolは必要か

最初に、現在のPR gateが次の3成果をすでに提供しているか確認する。

| Question | Yes | No |
|---|---|---|
| Dependency変更PRでdirect／transitive差分が表示されるか | 既存結果を利用 | このcontrolが必要 |
| 基準以上のknown vulnerabilityでcheckが失敗するか | 既存結果を利用 | このcontrolが必要 |
| Failed／error／missing checkでmergeできないか | 別workflowは不要 | Ruleset設定が必要 |

既存SCAが3点すべてを満たすなら、このworkflowを重複追加しない。既存check名、対象branch、severity／scope、negative
test、ruleset resultを`PSB-DEPS-004`のadoption evidenceとして記録する。

次は代替にならない。

- Merge後や夜間だけに動くSCA: 危険な変更をmerge前には止めない。
- Manifestのdirect dependencyだけを見るbot summary: Transitive resolver変更を確認できない。
- Actionが任意実行できるだけの状態: Missingまたはskipped jobでもmergeできる。
- Workflow fileのlocal lint: Liveの依存関係データやactive rulesetを証明しない。

## 重要なのは3点だけ

| Check | 確認すること | 導入完了の判断 |
|---|---|---|
| `DCR-001` Dependency diff | PRで追加・更新されたdirect／transitive dependency、version、scope、manifest／lockfileが表示される | Safe updateの実差分とlockfileを照合 |
| `DCR-004` Risk gate | Changed dependencyのhigh／critical known vulnerabilityでjobが失敗する | Inert negative PRがfailure |
| `DCR-009` Merge enforcement | Failure、error、cancel、missing checkをmerge許可にしない | Active rulesetによる拒否を確認 |

Workflow fileの存在やlocal testの`PASS`だけでは導入完了ではない。

## 導入前に確認する

1. どのmanifest／lockfileがdefault branchへmergeされ、どのpackage managerがそれをinstallするか。
2. そのecosystemとfileが
   [supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
   に含まれ、direct／transitiveのどこまで取得できるか。
3. Runtime、development、unknown dependencyがそれぞれproduction artifact、developer endpoint、CIのどこで実行されるか。
4. 既存SCAがbase-to-head差分を評価しており、このcontrolを重複導入せずに済むか。
5. Default branch、release branch、merge queueで同じrequired checkがeffectiveか。
6. Provider outageやfalse positive時に誰が調査し、例外を誰が期限付きで承認するか。

Supportedな依存関係データを取得できない場合、Reference workflowをcopyしてempty diffを得てもcontrol導入にはならない。その
ecosystemに対応する既存SCAをrequired PR gateにするか、package-manager固有の実装を別profileとして設計する。

## Referenceをcopyすると何が起こるか

| File | 実際に行うこと | 行わないこと |
|---|---|---|
| [`secure/github/dependency-review.yml`](secure/github/dependency-review.yml) | `pull_request`でGitHub REST APIからbase／head dependency差分を取得し、全scopeのknown-high findingでjobを失敗させる | Dependencyをcheckout／install／executeせず、ruleset、Dependency graph、継続SCA、例外を設定しない |

Workflowはtop-level `permissions: {}`とjob-level `contents: read`を使い、Dependency Review Actionをfull commit
SHAへ固定する。PRへcommentを書くpermissionやcheckoutは追加していない。

Copyしただけでは次は変わらない。

- GitHubのDependency graph（依存関係の一覧・つながり）は自動で有効にならない。
- Unsupported manifestがsupportedになるわけではない。
- Default branchのrequired checkやbypass restrictionは有効にならない。
- 既存のoptional／`warn-only` dependency workflowは停止しない。
- Provider outageや依存関係データの欠落を組織がどう扱うかは決まらない。
- Merge済みdependencyの継続監視は始まらない。

したがって導入作業は「coverage確認 → workflow導入 → active ruleset → live positive／negative／error test」までである。

## 最短の導入手順

### Prerequisites

- GitHub dependency reviewを利用できるrepository plan
- GitHub Dependency graph（依存関係の一覧・つながり）が有効
- Supported manifest／lockfileと、そのcoverageを説明できるowner
- GitHub-hosted runnerとrepository administrator権限
- Severity findingとprovider failureへ対応するSecurity／development owner

### 1. Workflowをcopyする

Adopter repository rootから実行する。既存workflowは上書きしない。

```bash
test ! -e .github/workflows/dependency-review.yml
mkdir -p .github/workflows
cp controls/dependency-security/dependency-change-review/secure/github/dependency-review.yml \
  .github/workflows/dependency-review.yml
```

Referenceは`high`以上をblockする。Thresholdを変える場合は、対象productのexposure、既存SCA policy、remediation SLAを
Security ownerがreviewする。低くするとmerge blockingとtriage負荷が増え、高くするとmedium以下がmerge可能になる。

### 2. Required checkにする

1. Workflowをdefault branchへ通常PRで追加する。
2. Dependency-only PRを1回作り、job名`Dependency Review`を確定する。
3. `Settings` → `Rules` → `Rulesets`でdefault branch向けbranch rulesetを作る。
4. `Enforcement status`を`Active`にする。
5. `Require status checks to pass`または`Require workflows to pass before merging`で
   `Dependency Review`を必須にする。
6. Merge queueやrelease branchを使う場合、その経路でもcheckが実行・要求されることを確認する。
7. Bypass主体を必要最小限にし、通常のdependency updateでadmin bypassを使わない。

Organization-wide設定は
[Enforcing dependency review across an organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)、
ruleset項目は
[Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
を参照する。

### 3. 古い経路を確認する

新しいrequired checkが動くことを確認した後、既存dependency workflowが`warn-only`、narrow scope、optionalのまま
別名で残っていないか確認する。Referenceを追加しても、別のmerge経路がcheckを要求しなければ未導入である。

## 導入の副作用と判断基準

| 副作用 | なぜ起こるか | 現実的な対応 |
|---|---|---|
| Provider outage時にmergeが止まる | 評価失敗をclean resultへ変換しないため | Ownerを決めて復旧を待つ。緊急時は[`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)で限定判断 |
| Unreachableなadvisoryも一度blockする | Provider severityはproduct固有reachabilityを判断しないため | 利用pathを調査し、version更新またはexactな期限付き例外を選ぶ |
| Development dependencyでもblockする | Build／test toolがCIやdeveloper endpointで実行され得るため | 実行場所とauthorityを確認する。Scope全体を黙って除外しない |
| Unsupported ecosystemをcoverできない | GitHub Dependency graphにparser／snapshotがないため | 対応SCAをrequired PR gateにするか別profileを設計する |
| Dependency updateのfeedbackが遅くなる | Snapshot生成、advisory query、retryが必要なため | Update PRを小さく保ち、provider failureとfindingを別々にtriageする |

Availabilityを優先して`warn-only`へ変えると、このcontrolのsecurity outcome自体が失われる。副作用を受け入れられない
場合は、optional workflowへ戻すのではなく、既存SCAやmerge queueを含む別のrequired gateを選ぶ。

## Harmless self-test

Sandbox repositoryまたは削除予定test branchで次の順番どおり確認する。

### Positive test: dependency差分が本当に見えるか

1. Organizationが既に利用を認め、current advisory findingがないdependencyをexact versionでlockfile-only更新する。
2. Manifestとlockfileだけをcommitし、dependency code、install script、testを実行しない。
3. PRの`Files changed`にあるdependency reviewとjob summaryでpackage、before／after version、direct／indirect、
   scope、manifest／lockfileを確認する。
4. Lockfile diffに存在する変更がdependency reviewから欠落していないか人が照合する。

期待結果はjob `success`、changed dependencyの表示、exit status相当がsuccessであること。表示されない変更があれば
`PASS`ではなくcoverage gapまたは`NOT_CHECKED`とする。

### Negative test: known-highを止められるか

[GitHub Advisory Database](https://github.com/advisories)から、対象ecosystemで修正版があるknown-high advisoryを選ぶ。
Disposable test branchへaffected versionをmanifest／lockfileとして記録するだけにし、packageをinstall、import、
executeしない。npmの例:

```bash
npm install --package-lock-only --ignore-scripts --save-exact PACKAGE@AFFECTED_VERSION
```

次を確認する。

1. Summaryにexpected package、affected version、advisory、severityが表示される。
2. `Dependency Review` jobが`failure`になる。
3. Failureを残したままmergeを試すとactive rulesetが拒否する。
4. Threshold、scope、`warn-only`、allow ruleを変更せずtest branchを削除できる。

### Error test: 未評価をsafeと扱わないか

Disposable branchでjobをcancelする、またはtest用rulesetが要求するcheckを未生成の状態にする。Production repositoryの
GitHub Dependency graphを故意に無効化しない。

期待結果はcancelled／missing checkがrequired ruleを満たさずmerge不可になること。Provider outage、runner failure、
snapshot warningが自然発生した場合も同じ観点で記録し、成功した別jobをdependency evaluationの代替にしない。

Test用PRとbranchは結果を記録した後に削除する。実在malware、credential、production dependencyを使わない。

## Verificationと判定

| Check | 確認者 | Live確認 | 成功状態 |
|---|---|---|---|
| `DCR-001` | Development team | Safe PRのdependency review／job summaryと実lockfile diff | Supported direct／transitive変更がversion、scope、manifest／lockfile付きで表示される |
| `DCR-004` | Security | Inert known-high PRのsummaryとjob conclusion | Expected advisoryが表示されjob failureになる |
| `DCR-009` | Repository administrator | Active ruleset、failed／cancelled／missing checkでのmerge attempt | すべてdefault branchへのmergeを拒否する |

Statusは次のように記録する。

- `PASS`: Supported live dependency diff、negative job failure、ruleset拒否をすべて確認した。
- `FAIL`: Changed dependencyが欠落する、known-highがjobを失敗させない、またはnon-successでもmergeできる。
- `NOT_CHECKED`: Ecosystem coverage、live setting、actual run、merge拒否をまだ確認していない。
- `ERROR`: API、runner、permission、partial snapshot等により評価不能。

Local regression test:

```bash
make verify-control CONTROL=PSB-DEPS-004
```

Expected output:

```text
PASS pull-request dependency review is SHA-pinned and read-only
PASS high-severity changed dependencies use blocking mode across all scopes
PASS warn-only configuration is rejected and missing workflow remains ERROR
NOT_CHECKED live dependency diff and required-ruleset merge rejection
```

Local referenceが保たれていればexit `0`。このcommandはworkflowのstatic propertyだけを確認し、live adoptionを
`PASS`にしない。Live確認は上表に従って別途実施する。

## 誰が何をするcontrolなのか

- Development team: 対象manifest／lockfile、package manager、runtime／development利用経路を特定し、safe
  dependency-only PRを作る。
- Repository administrator: GitHub Dependency graph、workflow、default／release branch ruleset、required check、
  bypass restrictionを設定する。
- Security: Threshold、known-high negative test、reachability、coverage gap、期限付き例外をreviewする。
- Platform／SRE: Runnerとprovider outageを復旧し、availability incidentをclean dependency resultへ変換しない。
- Product owner: Merge停止のoperational costとremediation priorityを受け入れ、対象productとbranchを決める。

Workflow authorだけにcoverage判断、ruleset設定、negative test、最終adoption判定を完結させない。

## 他controlとの役割分担

- [`PSB-DEPS-001`](../release-cooldown/README.md): Registry routeとrelease cooldown
- [`PSB-DEPS-002`](../install-script-execution/README.md): Install時のcode execution
- [`PSB-DEPS-003`](../lockfile-integrity/README.md): Exact version、frozen lockfile、artifact hash
- [`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md): Merge済みrepository／artifactの継続SCA
- [`PSB-CICD-001`](../../cicd-security/action-sha-pinning/README.md): Action SHA pin
- [`PSB-CICD-004`](../../cicd-security/actions-least-privilege/README.md): Workflow permission
- [`PSB-CICD-005`](../../cicd-security/untrusted-pr-boundary/README.md): Untrusted PRからCI authorityを分離
- [`PSB-REL-001`](../../release-integrity/signature-provenance-verification/README.md): Provenance verification
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Exact、owned、time-bound exception

License policy、non-author approval、provider-neutral lockfile parserはこのbasic profileへ含めない。

## Recovery、evidence、rollback

- Diffが表示されない場合はmanifest support、GitHub Dependency graph、base／head、lockfile commit、transitive coverageを確認する。
- Jobが起動しない場合はworkflow path、event、Actions availability、runner、rulesetのexpected check nameを確認する。
- Findingの場合はaffected version更新、dependency置換、利用path調査、期限付き例外の順で判断する。
- Provider errorではrequired checkを外さず復旧を待つ。緊急判断はprovider failureとrisk acceptanceを分けて記録する。

導入証跡にはrepository、default branch、取得時刻、supported manifest、workflow commit／Action SHA、active ruleset、
required check、positive／negative／error testのPRまたはrun URL、確認者を残す。Token、private package名、source code、
raw log、license adviceをpublic evidenceへ保存しない。

Rollback時は代替のrequired PR dependency gateを先に有効化し、rulesetの該当checkとcopyしたworkflowだけをreview付きで
外す。GitHub Dependency graph、branch protection、他security workflowを一括無効化しない。代替がなければ状態を
`NOT_CHECKED`へ戻し、merge前のdependency riskが未評価であることを明示する。

## Limitations

- GitHub plan、GitHub Dependency graph、supported ecosystem、advisory dataへ依存する。
- Provider severityはproduct固有のreachabilityやbusiness impactを決定しない。
- Clean resultはunknown vulnerabilityやmalicious packageがないことを保証しない。
- Snapshot warningのretryはprovider dataの完全性を証明しない。
- Static repository testはliveの依存関係データ、provider availability、active rulesetを証明しない。
- Mappingはformal complianceやcomplete supply-chain coverageを意味しない。

## Framework mappings

Machine-readableな正本は[`control.yaml`](control.yaml)である。Mappingはformal complianceや完全coverageを意味しない。

- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-VM-05.01／05.02／05.03](https://baseline.openssf.org/versions/2026-02-19#osps-vm-05)
- [NIST SP 800-218 SSDF 1.1 — PW.4.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATT&CK T1195.001 — Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)

## 関連frameworkとguidance

次は理解と実装を補助する関連情報であり、すべてが`control.yaml`のformal mappingという意味ではない。

### GitHub公式guidance

- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [Configure the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- [Dependency Review Action](https://github.com/actions/dependency-review-action)
- [Dependency review REST API](https://docs.github.com/en/rest/dependency-graph/dependency-review)
- [GitHub dependency graph](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph)
- [Supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
- [Enforce dependency review across an organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)
- [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)

### Repository guidance

- [`REF-DEPS-002` source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-deps-002)
- [Software supply-chain implementation principles](../../../docs/SUPPLY_CHAIN_PRINCIPLES.md)
