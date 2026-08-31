# PSB-SOURCE-006: GitHub Organizationの基本設定を安全にする

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHub Organizationの設定が広すぎると、必要のない人やAppがソースコードへアクセスできます。
メンバーが確認なしでリポジトリを作ったり、GitHub Actionsへ強い権限を与えたりすることもできます。

### 誰から、または何から守るか

乗っ取られたアカウント、退職後も残っているアカウント、使われていないApp、設定ミスから守ります。

### 何が対象か

会社やチームで使っている一つのGitHub Organizationが対象です。メンバー、リポジトリの初期設定、
GitHub Actions、GitHub App、監査ログを確認します。

### 何をするか

GitHubの管理画面で、不要なアクセスを削除し、メンバーとAppができることを必要な範囲だけに制限します。

### 成功状態

必要な人とAppだけが、必要なリポジトリへアクセスできます。新しいリポジトリやGitHub Actionsにも、
同じ安全な設定が適用されます。

### 対象外・残余リスク

この対策だけでは、ソースコードの問題、漏れた認証情報、危険なworkflow、削除されたリポジトリは守れません。
READMEやscriptをコピーするだけでも効果はありません。GitHubの実際の設定を変更する必要があります。

## このcontrolの優先度

優先度の目安は「中」です。製品を直接守る対策ではなく、複数のリポジトリへ安全な初期設定を広げるための
管理上の対策です。

小さなチームが一つのprivateリポジトリだけを使い、外部メンバーやGitHub Appも使っていない場合は、
急いで導入する必要はありません。次のどれかに当てはまるなら導入を検討してください。

- リポジトリやチームが増えてきた。
- 業務委託先や社外メンバーを招待している。
- 複数のGitHub AppやOAuth Appを使っている。
- Organization共通のGitHub Actions設定を使っている。

認証情報の管理、workflowの権限、外部からのpull request対策、リポジトリの復旧方法を先に整える方が重要です。

## 最短の導入手順

1. GitHub OrganizationのOwnerと、設定を確認するSecurity担当者を決めます。
2. 次の「まず設定する7項目」を上から順に設定します。
3. 設定した人とは別の人が、同じ画面を開いて値を確認します。
4. 90日ごとに、Owner、社外メンバー、Appが今も必要か見直します。

専用ツール、collector、policy JSONは必要ありません。より詳しい画面操作やAPIでの確認方法が必要な場合だけ、
[導入runbook](docs/github-adoption-runbook.md)を使ってください。

## まず設定する7項目

| 順序 | GitHubの場所 | 設定する内容 |
|---|---|---|
| 1 | People | Ownerを、本人を特定できる2〜3名に絞ります。退職者、不要なメンバー、不要な社外メンバーを削除します。 |
| 2 | Settings > Security > Authentication security | 2要素認証を必須にします。会社のログイン基盤を使っている場合は、SAML SSOとSCIMまたはEMUも有効にします。 |
| 3 | Settings > Access > Member privileges | Base permissionsをNoneにします。メンバーによるリポジトリ作成とprivateリポジトリのforkを無効にします。 |
| 4 | Settings > Actions > General | 必要なリポジトリとActionだけを許可します。Actionを完全なcommit SHAで固定し、標準のGITHUB_TOKENを読み取り専用にします。forkからのworkflowへsecretを渡しません。 |
| 5 | Settings > Third-party Access | 使っていないAppを削除します。残すAppは、必要なリポジトリと権限だけに絞ります。 |
| 6 | Settings > Security > Advanced Security > Configurations | 全リポジトリでdependency graph、Dependabot alerts、secret scanning、push protectionを有効にします。 |
| 7 | Settings > Archive > Logs > Audit log | メンバー、App、Actionsなどの重要な設定変更を確認します。監査ログはOrganizationのOwnerだけでは消せない場所へ保存します。 |

GitHubの契約プランによって表示されない設定があります。その場合は安全だったことにせず、使えない機能と
代わりに行う確認を記録してください。

## 設定できたか確認する

GHO-001〜GHO-010は、作業を増やすための仕組みではありません。設定漏れを防ぐための確認表です。

| Check | 確認すること |
|---|---|
| [GHO-001](docs/github-adoption-runbook.md#gho-001-target-and-evidence) | 正しいOrganizationを確認しているか。確認結果は24時間以内のものか。 |
| [GHO-002](docs/github-adoption-runbook.md#gho-002-authentication-and-provisioning) | 2要素認証と会社のログインが機能し、退職者のアクセスが24時間以内に削除されるか。 |
| [GHO-003](docs/github-adoption-runbook.md#gho-003-organization-owners) | Ownerは本人を特定できる2〜3名だけか。 |
| [GHO-004](docs/github-adoption-runbook.md#gho-004-members-teams-and-outside-collaborators) | メンバー、チーム、社外メンバーのアクセスが必要なリポジトリだけに絞られているか。 |
| [GHO-005](docs/github-adoption-runbook.md#gho-005-repository-defaults) | Base permissionsがNoneで、メンバーのリポジトリ作成とprivate forkが禁止されているか。 |
| [GHO-006](docs/github-adoption-runbook.md#gho-006-github-actions) | GitHub Actions、GITHUB_TOKEN、forkへのsecret送信が制限されているか。 |
| [GHO-007](docs/github-adoption-runbook.md#gho-007-github-apps-and-oauth-apps) | 全Appに担当者と利用目的があり、アクセス先と権限が必要な範囲だけか。 |
| [GHO-008](docs/github-adoption-runbook.md#gho-008-security-configuration-coverage) | 全リポジトリへ共通のセキュリティ設定が適用されているか。 |
| [GHO-009](docs/github-adoption-runbook.md#gho-009-audit-drift-and-alerts) | 重要な設定変更を監査ログで確認でき、監視の停止にも気付けるか。 |
| [GHO-010](docs/github-adoption-runbook.md#gho-010-fail-closed-assessment) | 設定を確認できなかったときに、誤って「安全」と判断しないか。 |

GitHubの管理画面で一項目ずつ確認すれば十分です。Organizationが大きくなり、手作業が負担になってから
read-only APIによる確認を追加してください。

## セキュリティ向上の効果はどこから生まれるか

効果が生まれるのは、GitHubとログイン基盤の設定を実際に変更したときです。

- 不要なアカウントとAppを削除すると、使われていない入口が減ります。
- リポジトリの初期権限をNoneにすると、新しいリポジトリが意図せず共有されにくくなります。
- GitHub Actionsを制限すると、workflowが不要な書き込み権限やsecretを使いにくくなります。
- 監査ログを確認すると、重要な設定が後から変えられたことに気付きやすくなります。

secure/policy.json、sample JSON、verifierは説明と開発用テストのためのものです。これらをコピーしても、
GitHubの設定は変わりません。

## 誰が何をするcontrolなのか

| 担当 | やること |
|---|---|
| GitHub Organization Owner | メンバー、初期権限、Appの設定を変更します。 |
| ログイン基盤の管理者 | SAML SSO、SCIMまたはEMUを設定し、退職者のアクセスを止めます。 |
| CI担当 | Organization共通のGitHub Actions設定を変更します。 |
| Security担当 | App、共通セキュリティ設定、監査ログを確認します。 |
| 各リポジトリの管理者 | 必要なチームと社外メンバーだけにアクセスを付けます。 |

一般の開発者がOrganization全体を管理する必要はありません。必要なリポジトリ、Action、Appを管理者へ
申請できれば十分です。

## 安全な設定と危険な設定

| 項目 | 安全な設定 | 危険な設定 |
|---|---|---|
| Owner | 本人を特定できる2〜3名 | 共有アカウント、退職者、多すぎるOwner |
| メンバーの初期権限 | Base permissionsがNone | 全メンバーにRead、Write、Admin |
| リポジトリ作成 | メンバーによる作成を無効 | 全メンバーが確認なしで作成できる |
| Private fork | 無効 | 全メンバーがforkできる |
| GitHub Actions | 必要なリポジトリとActionだけ。標準tokenは読み取り専用 | 全リポジトリ、全Actionを許可。標準tokenが書き込み可能 |
| Forkからのworkflow | secretと書き込みtokenを渡さない | forkから実行されたworkflowへsecretを渡す |
| GitHub App | 必要なリポジトリと権限だけ | 全リポジトリと管理権限を与える |
| 共通セキュリティ設定 | 全リポジトリへ適用 | 一部のリポジトリが未適用、失敗、解除済み |
| 監査ログ | Security担当が確認できる場所へ保存 | Organization Ownerだけが管理し、停止に気付けない |

## 導入できたと判断する条件

次をすべて確認できたら導入完了です。

- 「まず設定する7項目」が設定されている。
- 設定した人とは別の人が、現在の値を確認した。
- Owner、社外メンバー、Appを90日以内ごとに見直す担当者がいる。
- 監査ログを180日以上保存し、重要な設定変更を確認できる。
- 設定や記録を確認できない場合は、確認済みとして扱わない。

確認結果には、Organization名、確認日、確認した人、確認した設定を残します。実際のユーザー名、token、
secretをこのrepositoryへ保存しないでください。

## 開発者向けの補助テスト

次のテストは、sampleの安全な設定を合格、危険な設定を不合格として判定できるか確認します。
GitHub Organizationの実際の設定は確認しません。

~~~bash
make verify-control CONTROL=PSB-SOURCE-006
~~~

| 終了status | 意味 |
|---|---|
| 0 | 安全なsampleを正しく合格にした。実際のGitHub設定は未確認 |
| 1 | 危険なsampleまたは弱いpolicyを検出した |
| 2 | sampleが古い、不完全、壊れているなどの理由で判定できなかった |

## 問題が起きたとき

- 2要素認証やSSOでログインできなくなった場合は、事前に決めた二人目のOwnerとGitHubの復旧手順を使います。
- Actionsを制限してworkflowが止まった場合は、必要なActionだけを確認して許可します。allへ戻しません。
- Appが止まった場合は、必要なリポジトリと権限だけを追加します。管理権限をまとめて与えません。
- 設定を元へ戻す場合は、設定ごとに影響を確認し、別の人の承認を得ます。

## 他のcontrolとの役割分担

| Control | 担当すること |
|---|---|
| [PSB-SOURCE-003](../public-repository-exposure/README.md) | Publicリポジトリから情報が公開されていないか確認する |
| [PSB-SOURCE-004](../source-access-credential-lifecycle/README.md) | PAT、SSH key、OAuth、GitHub Appの認証情報を管理する |
| [PSB-SOURCE-005](../repository-destruction-recovery/README.md) | リポジトリの削除を制限し、backupから復旧できるようにする |
| PSB-SOURCE-006 | GitHub Organization全体のメンバー、初期設定、Actions、Appを管理する |
| [PSB-CICD-001](../../cicd-security/action-sha-pinning/README.md) | Workflow内のActionをcommit SHAで固定する |
| [PSB-CICD-004](../../cicd-security/actions-least-privilege/README.md) | WorkflowごとのGITHUB_TOKEN権限を小さくする |
| [PSB-CICD-005](../../cicd-security/untrusted-pr-boundary/README.md) | 外部からのpull requestへsecretを渡さない |
| [PSB-CICD-008](../../cicd-security/privileged-control-plane-change/README.md) | 重要な設定変更を申請、承認、記録する |
| [PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md) | 一時的な例外に担当者と期限を付ける |

Publicリポジトリの中身や公開範囲はPSB-SOURCE-003が担当します。このbranchでは同packageを変更しません。

## 詳しい手順と参考資料

- [GitHub画面とread-only APIを使った導入runbook](docs/github-adoption-runbook.md)
- [将来、自動確認が必要になった場合の案](docs/governance-automation-options.md)
- [Machine-readable control metadata](control.yaml)
- [GitHub security guidance mapping](../../../frameworks/github-security-guidance/README.md)
- [OpenSSF OSPS Baseline mapping](../../../frameworks/openssf-osps-baseline/README.md)
- [MITRE ATT&CK mapping](../../../frameworks/mitre-attack/README.md)
- [REF-CICD-015: DS-202](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-015)
- [REF-CICD-017: Flatt Security](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-017)
- [REF-CICD-018: Allstar](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-018)

Frameworkとの対応は、このcontrolがどの考え方を参考にしているか示すものです。正式な準拠や、
Organization全体が安全であることを証明するものではありません。

## 制限事項

- GitHubの契約プランによって、SAML、SCIM、security configuration、監査ログの保存機能を利用できない場合があります。
- InternalリポジトリはBase permissionsがNoneでもOrganizationメンバーから見える場合があります。
- GitHub ActionsのOrganization設定だけでは、個々のworkflowの権限や処理内容までは確認できません。
- GitHubの管理画面が安全に見えても、実際のアカウント管理、Appの運用、監査担当者が適切とは限りません。
