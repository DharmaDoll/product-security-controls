# PSB-CICD-005: forkと未信頼PRをprivileged CIから分離する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Forkや未信頼PRのcodeをsecret、write token、OIDC、protected environment、self-hosted runnerがあるcontextで実行すると、contributorがrepository、release、cloudの権限を奪取できる。

### 誰から、または何から守るか

悪意あるfork contributor、侵害されたcontributor account、PRから変更できるbuild／test／dependency、`pull_request_target`の誤用、PR由来artifactやcacheから守る。

### 何が対象か

Pull request workflow、checkout revision、GitHub token、secret、Environment、runner、cache／artifact、workflow trigger、merge後のprivileged run。

### 何をするか

PR validationをcredential-freeなGitHub-hosted jobへ限定し、権限が必要な処理はreview済みrevisionがprotected branchへmergeされた後の別runとして開始する。

### 成功状態

未信頼PR jobからprivileged assetへ到達できず、trusted jobはPR runの実行可能stateを継承せずにreview済みbranch revisionから開始する。

### 対象外・残余リスク

Reference workflowをcopyしただけではGitHubのfork setting、branch／Environment protection、runner-group policy、実際のsecret非配送は証明されない。これらは導入先で確認する。

## 最短の導入手順

### 前提条件とtrust assumption

- GitHub.comまたはGitHub Enterprise CloudでActionsを使用する。
- Forkまたはwrite権限を持たないcontributorからPRを受け付ける。
- `main`相当のdefault branchにreviewとrequired checkを強制できる。
- PRで実行するtestはsecret、private registry、cloud credential、production data、internal networkを必要としない。
- Untrusted PRにはreview済みGitHub-hosted runnerを使用する。

PR testにcredentialが必要な場合は、このcontrolを弱めて渡さない。Credential-free emulator、public dependency、mock、またはmerge後のtrusted testへ処理を分ける。

### Copyするfile

新規workflowとして次の2 fileをcopyする。既存fileがある場合は停止し、内容を人がmergeする。

```bash
test ! -e .github/workflows/pr-validation.yml
test ! -e .github/workflows/trusted-after-merge.yml
cp controls/cicd-security/untrusted-pr-boundary/secure/pr-validation.yml \
  .github/workflows/pr-validation.yml
cp controls/cicd-security/untrusted-pr-boundary/secure/trusted-after-merge.yml \
  .github/workflows/trusted-after-merge.yml
```

- [`secure/pr-validation.yml`](secure/pr-validation.yml): 未信頼PRのcredential-free validation。
- [`secure/trusted-after-merge.yml`](secure/trusted-after-merge.yml): review／merge後のtrusted処理。

導入先で変更するのは、原則としてdefault branch名、approved GitHub-hosted runner label、`make test`、trusted処理の内容だけである。Third-party Actionのfull commit SHA、deny-all permission、checkout credential非保存は維持する。Trusted workflowもreferenceではread-onlyであり、write権限が必要な処理を追加するときは[`PSB-CICD-004`](../actions-least-privilege/README.md)に従ってjob目的に必要な権限だけを追加する。

### GitHubで有効にする設定

Repository administratorが`Settings > Actions > General`を開き、次を確認する。

1. Default `GITHUB_TOKEN` permissionをread-onlyにする。
2. Actionsによるpull request作成／承認を無効にする。
3. Private forkを使う場合、fork workflowへのwrite token配送とsecret／variable配送を無効にする。
4. Fork workflowの実行前approvalを有効にする。Approvalはcompute abuseを抑える手順であり、PR codeをtrustedに変えない。
5. Default branchのrulesetでpull request reviewとPR validation checkを必須にする。
6. Untrusted workflowがself-hosted runner groupやprotected Environmentを選べないことを確認する。

画面とsettingの詳細は[GitHub Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)と[fork workflow approval](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)を参照する。

### Harmless positive self-test

1. 権限を持たないtest accountのforkからdocumentation-only PRを作る。
2. PR runの`Set up job`表示でeffective token permissionがread-only以下であることを確認する。
3. GitHub-hosted runnerで`pr-validation`だけが実行されることを確認する。
4. Merge前に`trusted-after-merge`が開始しないことを確認する。
5. Review後にmergeし、trusted runがexact `main` commitから新しく開始することを確認する。

Secret値をcanaryとして置かず、production処理をself-testに使わない。

### Harmless negative self-test

Disposable fork PRで`pr-validation.yml`へ`contents: write`を要求する変更だけを加え、mergeしない。

- Fork settingがwrite token配送を無効にしているため、runのeffective permissionがread-onlyへ制限されること。
- Workflow security reviewerが過剰なpermission要求を`FAIL`として記録し、required reviewによってmergeされないこと。
- Manual approval後もsecret、Environment、self-hosted runnerが解禁されないこと。

[`insecure/workflow.yml`](insecure/workflow.yml)はreview用の非実行fixtureである。実repositoryの`.github/workflows`へcopyしない。

Positive testは`make test`がexit `0`となりPR jobが`success`、negative testはeffective permissionがread-onlyのままでmanual resultが`FAIL`となることが期待結果である。Negative testのjob自体はtest command次第でexit `0`になり得るため、job成功をsecurity reviewの`PASS`と読み替えない。Manual reviewにはprocess exit statusがないため`N/A`として記録する。

### Recoveryとrollback

- Workflowが動かない場合はbranch名、test command、Actions policy、fork approval、runner availabilityを確認する。Secret配送やwrite permissionを追加して直さない。
- PRでprivate dependencyが必要になった場合はcredential-free mirror／mockまたはmerge後testへ分離する。
- Rollbackはcopyしたrepository-local workflowをreviewの上で外す。Organizationのdeny-oriented fork setting、default token restriction、branch protectionを自動で弱めない。

## セキュリティ向上の効果はどこから生まれるか

Security効果は、実際に有効な二つのworkflowとGitHub provider settingから生まれる。

```text
untrusted fork PR
        |
        v
pull_request / credential-free hosted job
        |
        +---- no secret, no write token, no OIDC, no Environment
        |
        v
human review + protected merge
        |
        v
new push run from reviewed main revision
        |
        v
trusted reporting / release / deploy
```

README、fixture、manual checklistをcopyするだけでは境界は有効にならない。Workflowをactivationし、GitHub設定と実runを確認して初めて導入済みと判断する。

## 誰が何をするcontrolなのか

- Development team: 二つのworkflowをcopy／mergeし、credential-free test commandだけを設定する。
- Repository administrator: Actions／fork setting、protected branch、required check、workflow owner reviewを設定する。
- CI platform: approved GitHub-hosted runnerとorganization Actions policyを提供し、untrusted routingをself-hosted／privileged reusable workflowから分離する。
- Organization owner: default tokenとprivate-fork policyをdeny-orientedに保つ。
- Security: `pull_request_target`、run間handoff、例外、actual runとlive settingを独立reviewする。

同じPR作成者またはworkflowだけに、trust分類、権限付与、evidence生成、最終判断を完結させない。

## `pull_request_target`が危険になる理由

`pull_request_target`はbase repositoryのcontextで動き、repository token、secret、default-branch cache等のprivileged assetへ到達し得る。Metadata-onlyのlabel付与等に使えるeventだが、forkのhead codeをcheckout、download、fetchして実行するとpwn requestになる。

```text
fork PR
  -> pull_request_targetのprivileged context
  -> PR head／artifact／cacheを取得
  -> make test、npm install、build script等で実行
  -> secret窃取、repository改ざん、release汚染
```

Checkout stepだけが実行点ではない。PRから変更できる`Makefile`、test、package lifecycle hook、compiler plugin、configurationもcode executionになる。Actor、label、author association、workflow approvalだけではPR codeはtrustedにならない。詳細は[GitHubのpull_request_target security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)と[GitHub Security Labのpwn request解説](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)を参照する。

GitHubは`actions/checkout`へ一般的なfork head checkoutを拒否する保護を追加したが、manual `git fetch`、`gh`、別repository、他event、明示的opt-outは境界外である。[checkout protectionの範囲](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/)を理由にprivileged eventで未信頼codeを実行しない。

## 実在事例から理解する

### GHSL-2020-372: 直接的なpwn request脆弱性

[GitHub Security LabのGHSL-2020-372](https://securitylab.github.com/advisories/GHSL-2020-372-418sec-huntr-workflow/)では、実在workflowが`pull_request_target`でforkのmerge refをcheckoutし、`npm ci`とsecret-bearing処理を実行していた。Impactはbase repositoryの不正変更またはsecret exfiltrationである。本controlの二段workflowは、この組合せ自体を作らない。

### Ultralytics 2024: cacheを介した実インシデント

[PyPIによるUltralytics攻撃分析](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)では、GitHub Actions cacheが攻撃され、悪意あるcodeを含む複数のPyPI releaseが公開された。これは`pull_request_target`単独の事件とは断定せず、低信頼runからtrusted buildへcacheが橋を架けた場合の実被害例として扱う。`permissions: {}`だけでは、後段がpoisoned cacheを実行すれば境界にならない。

## 安全な例と危険な例

| 観点 | 安全な構成 | 危険な構成 |
|---|---|---|
| PR event | `pull_request` | `pull_request_target`でPR codeを実行 |
| Token | deny-all＋必要なreadだけ | `contents: write`／`id-token: write` |
| Secret／Environment | なし | repository secret／production Environment |
| Runner | reviewed GitHub-hosted | persistent self-hosted |
| Checkout | event merge revision、credential非保存 | fork headを明示checkout、credential保存 |
| State handoff | merge後のreview済みrevisionからnew run | PR artifact／cache／outputをprivileged runで実行 |
| Elevation | protected branch `push` | actor、label、comment、同一runの`needs` |

Secure referenceは[`pr-validation.yml`](secure/pr-validation.yml)と[`trusted-after-merge.yml`](secure/trusted-after-merge.yml)、危険例は[`insecure/workflow.yml`](insecure/workflow.yml)である。

## 導入後のmanual verification

このcontrolはcustom parserやsynthetic PASSをsecurity evidenceにしない。次をactual repositoryで確認する。

| Check | 確認者 | Live確認 | 成功状態 |
|---|---|---|---|
| `PRB-001` | Repository administrator | PR runのeffective permission、secret／Environment参照 | write、secret、OIDC、Environmentなし |
| `PRB-002` | CI platform | Job runner labelとrunner-group access | approved GitHub-hosted runnerだけ |
| `PRB-003` | Repository administrator | Actual workflowとcheckoutされたrevision | credential非保存、PRのevent merge revision |
| `PRB-004` | Security | 全PR-related event、cache、artifact、reusable workflow | automatic privileged handoffなし |
| `PRB-005` | Repository administrator | Ruleset、merge commit、trusted run event／SHA | review済みmainからnew run |
| `PRB-006` | Security | Repository内の全workflow inventory | 未分類pathを`PASS`にしない |

Statusは次のように記録する。

- `PASS`: current live settingとactual runが期待状態を満たす。
- `FAIL`: privileged assetへの到達経路がある。
- `NOT_CHECKED`: live setting、workflow、runを確認していない。
- `ERROR`: 権限不足、API failure、partial inventory等で評価不能。

```bash
make verify-control CONTROL=PSB-CICD-005
```

このcommandはlocal testを捏造せず`NOT_CHECKED`とREADME手順を表示し、command自体はexit `0`となる。Exit `0`はmanual controlを正しく案内できたという意味であり、controlのlive `PASS`を意味しない。

## 自動検証できる範囲とできない範囲

| 項目 | Workflow static analysis | Live provider確認 |
|---|---:|---:|
| Event、permission、secret expression、checkout ref | 一部可能 | Actual runでも確認 |
| Fork secret／write-token setting | 不可 | 必須 |
| Branch／Environment protection | 不可 | 必須 |
| Runner-group access | labelのみ | 必須 |
| Actual revisionとrun separation | 不完全 | 必須 |
| Organization adoption | 不可 | 必須 |

Workflow static analysisは[`PSB-CICD-003`](../actions-static-analysis/README.md)へ委譲する。本control専用parser、policy JSON、README文字列test、自己申告evidenceは追加しない。

## 他controlとの役割分担

- [`PSB-CICD-001`](../action-sha-pinning/README.md): Third-party Actionのimmutable SHA。
- [`PSB-CICD-003`](../actions-static-analysis/README.md): GitHub Actions workflowのstatic analysis。
- [`PSB-CICD-004`](../actions-least-privilege/README.md): Job目的ごとのexact token permission。
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): Trusted deploy jobのOIDC claimとcloud trust。
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner image、registration、network、one-job lifecycle、teardown。
- [`PSB-CICD-009`](../cache-provenance-isolation/README.md): Cache producer／consumer provenanceとtrust namespace。
- [`PSB-BUILD-001`](../../build-security/build-containment/README.md): Build sandbox、egress、telemetry、deploy separation。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): Organization-wide Actions／fork policy。
- [`PSB-CICD-008`](../privileged-control-plane-change/README.md): Provider設定変更のactor、approval、audit chain。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Exact、owned、time-boundなsecurity exception。

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
- [Workflow syntax: permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [Managing Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [Approving workflow runs from forks](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)
- [Managing self-hosted runner access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access)
- [Safer pull_request_target defaults for actions/checkout](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/)
- [Read-only Actions cache for untrusted triggers](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/)

### Research／incident guidance

- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitHub Security Lab: New workflow vulnerability patterns and mitigations](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/)
- [GHSL-2020-372](https://securitylab.github.com/advisories/GHSL-2020-372-418sec-huntr-workflow/)
- [GHSL-2025-038: IssueOps TOCTOU](https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/)
- [PyPI: Ultralytics supply-chain attack analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [Repository-owned security guidance source records](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-010)

## 制限事項と運用コスト

- GitHub UI、API、plan、event semanticsは変化するため、導入時に公式documentationとcurrent settingを確認する。
- GitHub-hosted runnerでも未信頼testは公開networkへ通信できる。Credentialを渡さないことが主要境界で、egress controlは`PSB-BUILD-001`が所有する。
- Metadata-onlyの`pull_request_target`、safe artifact handoff、trusted cacheは現在のconservative baseline外である。
- PR testをcredential-freeにするため、private dependencyのmirror／mockやmerge後testが必要になる場合がある。
- Manual verificationはownerとreview cadenceがなければ陳腐化する。未確認状態をlast-known-good `PASS`で埋めない。
