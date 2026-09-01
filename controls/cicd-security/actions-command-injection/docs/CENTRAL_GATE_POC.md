# Central trusted gate PoC

この文書は、多数repositoryで`PSB-CICD-002`を運用するときのcentral distributionを理解するための
非本番PoCである。GitHub Organizationへ自動導入せず、live setting、required check、private repository
access、status sourceを確認していない状態をadoptedと扱わない。

## このPoCが解決すること

Repository-local gateは導入が簡単だが、candidate pull requestがverifierやworkflowも変更できる。
CODEOWNERSとrequired reviewで変更を保護できるものの、repository数が増えるとverifier更新とpolicy reviewが
各repositoryへ分散する。

Central gateは、review済みverifierとworkflowをsecurity-owned repositoryのexact commitに固定し、consumer
repositoryでは小さなcallerだけを持つ。

```text
Consumer repository
  └─ SHA-pinned caller
          |
          v
Central security repository
  ├─ reusable workflow
  ├─ composite wrapper
  └─ verify.py
          |
          v
Candidate .github/workflowsをdataとしてscan
          |
          v
Required status check
```

Central化しても、candidate sourceをcheckoutするrunner、GitHub Actions service、central repository owner、
ruleset administratorはtrust boundaryに残る。

## Prerequisites

- Security teamが管理するdedicated repositoryがある。
- Consumer repositoryからcentral reusable workflowを参照できる。
- Central commitと内部Actionをfull commit SHAで固定できる。
- Consumer jobはGitHub-hosted runner、`contents: read`、secretなしで実行できる。
- Repository administratorがrequired status checkとCODEOWNERSを設定できる。
- GitHub planとrepository visibilityが必要なreusable workflow accessをsupportする。

GitHubはreusable workflowの参照にcommit SHAを使う方法を、stabilityとsecurityのための最も安全なoptionとして
説明している。詳細は[Reuse workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)を
参照する。

## PoC repository layout

Central repositoryで次の最小layoutをreviewする。

```text
security-workflows/
├── .github/workflows/actions-command-injection.yml
└── actions/actions-command-injection/
    ├── action.yml
    └── verify.py
```

`verify.py`はこのcontrolの[`scripts/verify.py`](../scripts/verify.py)と同じreview済み内容を使う。Dynamic plugin、
package install、network downloadを追加しない。

## Consumer caller skeleton

次は説明用skeletonであり、`example-security`と`<REVIEWED_40_CHARACTER_COMMIT_SHA>`を実際のreview済み値へ
置換するまでdeployしない。

```yaml
name: Central actions command injection gate

on:
  pull_request:

permissions: {}

jobs:
  actions-command-injection:
    permissions:
      contents: read
    uses: example-security/security-workflows/.github/workflows/actions-command-injection.yml@<REVIEWED_40_CHARACTER_COMMIT_SHA>
```

Callerからsecretを渡さない。`secrets: inherit`、write permission、environment、self-hosted runner選択を追加しない。

## Central reusable workflow skeleton

Central workflowはcandidate repositoryをcheckoutするが、そのbuild、test、script、dependencyを実行しない。
Workflow fileをdataとしてverifierへ渡す。

```yaml
name: Actions command injection

on:
  workflow_call:

permissions: {}

jobs:
  scan:
    name: Reject direct expressions in run
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - name: Check out candidate workflows as data
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - name: Run the centrally reviewed verifier
        uses: example-security/security-workflows/actions/actions-command-injection@<REVIEWED_40_CHARACTER_COMMIT_SHA>
```

Central wrapperは入力をcommand stringとして受け取らず、固定pathだけを検査する。

```yaml
name: Verify Actions command injection
description: Reject direct GitHub expressions in run scripts

runs:
  using: composite
  steps:
    - name: Scan workflow files
      shell: bash
      run: python3 "$GITHUB_ACTION_PATH/verify.py" .github/workflows
```

Composite wrapperはcentral distributionのためだけに使う。Composite Action自身の
`runs.steps[*].run`を一般検査するscope expansionではない。

## Trust decisions to review

| Decision | Minimum PoC state | Fail-closed condition |
|---|---|---|
| Central code identity | Callerとwrapperがreview済みfull SHAを参照 | Tag、branch、短縮SHA、unknown commit |
| Candidate handling | Workflow filesをdataとしてscan | Candidate script／dependencyを実行 |
| Token authority | `contents: read`のみ、secretなし | Write scope、OIDC、inherited secret |
| Runner | GitHub-hosted Ubuntu | Unreviewed self-hosted runner |
| Scanner result | `0=accepted`、`1=finding`、`2=error` | Errorをzero findingsへ変換 |
| Merge enforcement | Expected checkがrulesetでrequired | Missing／skipped checkでmerge可能 |
| Change ownership | Caller、central workflow、verifierにreview owner | Candidate authorが単独でweakening可能 |

## Harmless PoC procedure

Production repository、credential、deployment workflowを使わず、sandbox consumer repositoryで行う。

1. Central repositoryへwrapper、verifier、reusable workflowをreviewしてcommitし、exact SHAを記録する。
2. Sandbox consumerへSHA-pinned callerを追加する。
3. Callerを一度実行し、実際に生成されたcheckをrulesetのrequired status checkへ登録する。
4. `env:`とquoted variableを使うsafe pull requestがpassすることを確認する。
5. 次のinert findingを`.github/workflows`へ置いたpull requestがfailすることを確認する。

   ```yaml
   run: printf '%s\n' "${{ github.event.pull_request.title }}"
   ```

6. Unsupported `run:` alias等でverifier exit `2`を発生させ、mergeがblockされることを確認する。
7. Callerを削除またはskipするpull requestでrequired checkが欠落し、mergeできないことを確認する。
8. Callerと同名のjobを追加してcheck sourceをspoofできないかreviewする。GitHub UIでexpected sourceを限定できる
   場合は限定し、できない場合はCODEOWNERSとruleset limitationとして記録する。
9. Safe patternへ修正し、同じrevisionのcheckがpassしたことを確認する。

PoCでreal secret、provider-valid token、malware、production branch、deployment authorityを使用しない。

## Evidence and completion boundary

PoC完了時に保存してよいevidenceは次に限定する。

- Central repositoryとexact commit SHA;
- Consumer repositoryとtested revision;
- Reusable workflow accessのcurrent setting;
- Required check／rulesetのcurrent read-only screenshotまたはAPI response;
- Safe、finding、error、missing-checkのsanitized run URLとresult;
- Acquisition time、reviewer、authority boundary。

このrepositoryに架空のevidence JSONを追加しない。上記live stateを取得していない場合は`NOT_CHECKED`である。

## Limitations

- Callerが存在するだけではrequired checkは有効にならない。
- Private central repository access、GitHub plan、organization policyにより利用方法が変わる。
- Status check nameだけに依存するとspoofやambiguous sourceのreviewが必要になる。
- Central repository compromiseは全consumerへ影響するため、owner、branch protection、release reviewが必要である。
- Central outage、GitHub Actions outage、access denialはcleanではなくblocking errorになる。
- このPoCはOrganization-wide rollout、fleet inventory、automatic remediation、live policy collectorを実装しない。

## References

- [GitHub: Reuse workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [GitHub: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub: About CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [GitHub: Managing Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [`PSB-CICD-003` workflow static analysis](../../actions-static-analysis/README.md)
- [`PSB-CICD-004` least-privilege permissions](../../actions-least-privilege/README.md)
- [`PSB-CICD-005` untrusted PR boundary](../../untrusted-pr-boundary/README.md)
