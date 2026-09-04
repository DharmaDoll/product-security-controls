# Optional central distribution PoC

## これは何か

このPoCは、`PSB-CICD-002`の別実装や新しいscannerではない。各repositoryへcopyしている
[`verify.py`](../scripts/verify.py)をsecurity-owned repositoryのcomposite Actionとして一度だけ置き、consumer workflowから
full commit SHAで呼ぶ配布例である。

```text
consumerのcandidate workflows
  -> consumerのread-only workflow
  -> central composite Action @ exact SHA
  -> 同じverify.pyでscan
  -> consumerのrequired status check
```

防御原理はlocal方式と同じで、`${{ ... }}`を`run:`へ直接挿入させないことである。Central化で増えるのは検出能力ではなく、
verifier sourceとそのreview ownerを一か所へ置けることだけである。

## Defaultにしない理由

- 1個または少数のrepositoryなら、READMEの3-file local pathの方が依存先も障害点も少ない。
- Immutable SHAで参照するため、新versionのrolloutには各consumerでSHA更新pull requestが必要である。
- Consumer workflowの削除、古いSHAの放置、required checkの未設定はcentral repositoryから防げない。
- Central Actionのaccess failureや侵害が、多数consumerへ同時に影響する。

したがって、これはorganization-wide enforcementでも、自動更新platformでもない。多数repositoryでverifier codeのcopyを
減らしたい具体的な需要と、継続所有するPlatform／Security teamがある場合だけ検討する。

## 最小PoC

Central repositoryに必要なのは2 fileだけである。

```text
security-workflows/
└── actions/actions-command-injection/
    ├── action.yml
    └── verify.py
```

### Central Action

`verify.py`にはこのcontrolの[`scripts/verify.py`](../scripts/verify.py)をreviewしてcopyする。`action.yml`は固定pathでそれを
呼ぶだけにする。

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

Package install、network download、dynamic plugin、consumerからのcommand inputは追加しない。Composite Action自身の
`runs.steps[*].run`を一般検査するscope expansionでもない。

### Consumer workflow

Sandbox consumerの`.github/workflows/actions-command-injection.yml`に次を置く。

```yaml
name: Actions command injection gate

on:
  pull_request:

permissions: {}

jobs:
  actions-command-injection:
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

`example-security`とplaceholderは実ownerとreview済みfull commit SHAへ置換する。Tag、branch、短縮SHA、secret、write permission、
OIDC、Environment、self-hosted runnerをPoCへ追加しない。Private Actionの利用条件は
[Sharing actions and workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/share-across-private-repositories)を
参照する。Shared private repositoryはrunnerへdownload tokenを渡すため、central repositoryにはsecretやconsumerへ
配布できない資料を置かず、Action codeをconsumer contributorから完全に秘匿できるとは想定しない。

## Harmless verification

Production repository、real secret、deployment authorityを使わず、sandbox consumerで確認する。

1. Centralの2 fileをreviewしてcommitし、full commit SHAをconsumerへ設定する。
2. Consumer workflowを実行し、生成されたcheckをrulesetのrequired status checkにする。
3. `env:`とquoted variableを使うsafe pull requestがexit `0`で通ることを確認する。
4. `run: printf '%s\n' "${{ github.event.pull_request.title }}"`を含むinert fixtureがexit `1`でblockされることを確認する。
5. Unsupported `run` aliasのfixtureがexit `2`となり、cleanへ変換されないことを確認する。
6. Consumer workflowを削除またはcentral SHAを差し替えるpull requestが、required reviewまたはmissing required checkで
   mergeできないことを確認する。

Safe、finding、errorが区別され、Action取得失敗もmergeをblockし、consumerのgate変更がreview対象ならPoC成功である。
Live rulesetや実runを確認していなければ`NOT_CHECKED`とする。

## 何を中央化できないか

- Consumer workflow、CODEOWNERS、required status check、ruleset;
- 各consumerが使用するSHAの更新とinventory;
- GitHub plan／visibilityに依存するprivate Action access;
- Shared private repositoryのcontentとdownload tokenに関するaccess boundary;
- Shell全体、Composite Action、called script、job authorityの検証;
- Organization全体への強制rolloutとlive adoption evidence。

これらまで中央強制したい場合、この2-file PoCを拡張するのではなく、利用中のGitHub planでorganization rulesetやrequired
workflow相当のprovider機能を別途評価する。

## Rollback

ConsumerをREADMEのlocal 3-file gateまたは同等のprovider enforcementへ先に移し、同じnegative testがblockされることを
確認する。その後、central Action参照とrequired checkをreviewして削除する。

## References

- [GitHub: Sharing actions and workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/share-across-private-repositories)
- [GitHub: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub: About CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [`PSB-CICD-003` workflow static analysis](../../actions-static-analysis/README.md)
- [`PSB-CICD-005` untrusted PR boundary](../../untrusted-pr-boundary/README.md)
