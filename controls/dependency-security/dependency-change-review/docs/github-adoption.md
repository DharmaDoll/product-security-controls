# GitHub dependency review adoption

このguideは[`secure/github/dependency-review.yml`](../secure/github/dependency-review.yml)を
GitHub repositoryへ導入し、実際のmerge条件にする最短手順です。Workflowをcopyしただけでは
security stateは変わりません。Dependency graph、active ruleset、required check、non-author
reviewを実repositoryで有効にして初めてenforcementになります。

## Prerequisites and trust assumptions

- GitHub.comのpublic repository、またはdependency reviewを利用できるprivate repository
- Repository administrator権限
- GitHub dependency graphが有効
- 対象manifest／lockfileが
  [GitHubのsupported ecosystem](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
  に含まれる
- GitHub-hosted runnerを利用できる
- Security／Legalがreviewしたvulnerability thresholdとSPDX license allowlist
- Dependency manifest／lockfileを担当するauthor以外のreviewerまたはCODEOWNER

ReferenceはDependency Review Action `v5.0.0`をfull commit SHAへ固定しています。V5はNode 24を使い、
self-hosted runnerでは最低version要件があります。Self-hostedへ変更する場合は
[release note](https://github.com/actions/dependency-review-action/releases/tag/v5.0.0)とrunner isolationを
先に確認してください。

## Files to copy

Adopter repository rootから実行します。既存workflowを上書きしません。

```bash
test ! -e .github/workflows/dependency-review.yml
mkdir -p .github/workflows
cp controls/dependency-security/dependency-change-review/secure/github/dependency-review.yml \
  .github/workflows/dependency-review.yml
```

このcontrol packageを別repositoryから参照する場合は、review済みcopyを取得してから同じtargetへ配置します。
Remote `config-file`やprivate tokenは最短profileでは使いません。

Copy後、次をproduct owner、Security、Legalとreviewします。

- `fail-on-severity: high`
- `fail-on-scopes: runtime, development, unknown`
- `allow-licenses`
- Pinned Action releaseとrunner互換性

Reference allowlistは導入例です。製品のlicense、link方式、配布形態、契約へ適用可能かを判断せずに
そのまま採用しないでください。[SPDX License List](https://spdx.org/licenses/)のidentifierを使います。

## Enable the actual enforcement

1. Repositoryの`Settings`を開く。
2. `Security`または`Code security and analysis`でDependency graphを有効にする。
3. Workflowをdefault branchへreview付きで追加する。
4. Harmlessなdependency-only PRを作成し、`Dependency Review` jobが実行されることを確認する。
5. `Settings` → `Rules` → `Rulesets`でdefault branchを対象とするbranch rulesetを作る。
6. `Enforcement status`を`Active`にする。
7. `Require a pull request before merging`を有効にし、最低1 approvalを要求する。
8. `Dismiss stale pull request approvals when new commits are pushed`を有効にする。代わりにlatest
   reviewable pushへのnon-author approvalを使う場合も、最新差分が別主体に承認されることを確認する。
9. `Require status checks to pass`または`Require workflows to pass before merging`へDependency Reviewを追加する。
10. Required status checkのsourceを選べる場合はGitHub Actionsに限定する。
11. Dependency manifest／lockfile pathを既存`CODEOWNERS`のdependency reviewer teamへ割り当てる。
12. Bypass主体を必要最小限にし、通常運用でadmin bypassを使わない。

GitHub Organizationへ一括適用する場合は
[Enforcing dependency review across an organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)
を使用します。Required reviewとstatus checkの詳細は
[protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
を参照してください。

## Harmless positive self-test

Disposable branchで、既にorganizationが承認しておりcurrent advisory findingがないdependencyのexact
versionだけを更新します。Manifestとlockfileを同じPRに含め、dependency codeは実行しません。

期待結果:

- `Dependency Review` jobが`success`
- Summaryにbase-to-head dependency changeが表示される
- Author以外のrequired approvalがない間はmerge不可
- Approval後、他のrequired checkも含めてmerge条件を満たせる

この成功は、そのrepositoryの設定とその時点のPRに限った結果です。Dependencyが無害であること、別repository、
別branch、将来のprovider healthを証明しません。

## Inert negative self-test

Production repositoryへ危険versionを入れず、disposable test repositoryまたは削除予定のtest branchで行います。
[GitHub Advisory Database](https://github.com/advisories)から、対象ecosystemで修正済みの既知脆弱versionを1件選び、
dependency codeをinstallせずmanifest／lockfileだけを更新します。npmを使う場合の例は次です。Network accessは
registry metadataとlockfile生成に限り、script実行を無効化します。

```bash
npm install --package-lock-only --ignore-scripts --save-exact PACKAGE@AFFECTED_VERSION
```

期待結果:

- Action summaryにadvisoryとpackageが表示される
- Severityが`high`以上なら`Dependency Review` jobがfailure
- Required checkによりmerge不可
- Thresholdを下げる、`warn-only`を有効にする、GHSAをbroad allowする操作なしにtest branchを削除できる

実在するmalwareやprovider-valid credentialは使用しません。Test対象packageをinstall、import、executeしません。

## Error and coverage self-test

次はfixtureではなく、adopterのsandbox repositoryで確認します。

- Dependency graphを一時的に利用できないtest repositoryではjobが成功扱いにならない。
- Required workflowがmissing、cancelled、timed out、action-requiredの場合にmergeできない。
- 対象manifestがsupported listにない場合、empty diffをcontrol successとして記録しない。
- Snapshot warningがretry後も残る場合、Action conclusionとruleset結果を確認する。
- Licenseがunknownの場合、Action successをlicense approvalにせず、non-author reviewerが解消または
  [`PSB-GOV-002`](../../../governance-operations/time-bound-security-exceptions/README.md)のexact decisionを確認する。

Action v5の公式configurationは、license不明を通知しても必ずしもjobをfailさせないと明記しています。
[Configuration options](https://github.com/actions/dependency-review-action#configuration-options)を確認し、unknown
licenseを自動block済みと報告しないでください。

## Expected status and recovery

| State | Meaning | Merge |
|---|---|---|
| `PASS` | Supported graphを評価し、threshold／license policy findingなし | Review条件を満たせば候補 |
| `FAIL` | Vulnerability、license、review policy違反 | Block |
| `ERROR` | Action、API、runner、graph、workflow評価失敗 | Block |
| `NOT_CHECKED` | Unsupported ecosystem、live setting未確認、evidenceなし | Blockまたはmanual fallback |

Failure recoveryはDependency graph、repository plan、runner、API、manifest coverage、policyを修正して再実行します。
`warn-only`、threshold緩和、required check解除、public fallbackで通しません。Provider outage時はrequired checkを
維持し、復旧を待つかapproved manual fallbackへ明示的に切り替えます。

## Evidence to retain

Organization-owned evidenceには次だけをsanitized recordとして残します。

- Stable repository identityとdefault branch
- 取得時刻
- Dependency graphが有効であること
- Supported manifest／lockfile
- Workflow pathとpinned Action SHA
- Active ruleset IDまたはURL
- Required workflow／status check名
- Required reviewとstale／latest-push setting
- Positive／negative／error testのrun URLまたはcontent-free receipt

Token、private dependency名、source、raw logs、PR本文、license legal adviceはpublic evidenceへ保存しません。

## Rollback

1. Manual fallbackとownerを先に有効化する。
2. Required workflow／status check entryだけをrulesetからreview付きで外す。
3. Copyした`.github/workflows/dependency-review.yml`だけを通常PRで削除する。
4. Dependency graph、branch protection、他のsecurity workflow、organization rulesetを一括無効化しない。
5. Adoption stateを`NOT_CHECKED`へ戻し、残るmanual reviewと移行期限を記録する。

Rollback後は自動dependency reviewがないため、human error、stale advisory、unsupported transitive graphのriskが増えます。
