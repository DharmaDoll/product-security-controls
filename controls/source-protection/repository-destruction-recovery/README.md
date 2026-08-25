# PSB-SOURCE-005: Critical repositoryの破壊を制限し、GitHub外から復旧できるようにする

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHub Organization Ownerやrepository administratorのsessionが侵害されると、製品の再ビルド、
security patch、incident investigationに必要なrepositoryや重要branch／tagを破壊される可能性が
ある。GitHub上のfork、同じOrganization内のmirror、未検証のbackupだけでは、同じ侵害や設定不備で
同時に失われる。

### 誰から、または何から守るか

侵害されたGitHub管理者session、過剰なrepository admin権限、誤った削除操作や自動化、GitHub障害、
backupの設定不備、復元したことのないbackupから守る。

### 何が対象か

製品の再ビルド、緊急security patch、incident investigationに不可欠とproduct ownerが指定した
critical repositoryを対象とする。短命なsandboxや他の正本から再生成できるrepositoryまで一律に
対象にはしない。

### 何をするか

GitHubでrepositoryの削除・移管権限をOrganization Ownerへ限定し、重要branch／tagの削除とforce
pushをrulesetで防ぐ。さらに、GitHub管理者が削除できない別accountのretention-locked storageへ
Git dataを定期退避し、隔離したrepositoryへ実際に復元する。

### 成功状態

通常のrepository adminはrepositoryを削除・移管できず、重要branch／tagを破壊できない。critical
repositoryごとにGitHubの管理境界外へ保存された新しいbackupがあり、そのbackupから全branch／tagと
必要なLFS objectをRPO／RTO内に復元し、製品を再ビルドまたは修正できる。

### 対象外・残余リスク

GitHub Organization Owner自身の侵害、GitHubとbackup accountの同時侵害、backup encryption keyの
喪失は残余riskである。`git clone --mirror`だけではIssues、Pull Requests、Discussions、Packages、
Actions artifacts、team permission、secret、外部integrationを復元しない。必要な対象は別途backup
製品またはprovider APIで追加する。

## セキュリティ向上の効果はどこから生まれるか

このcontrolの効果はscriptやchecklistを置くことからは生まれません。次の実設定と運用から生まれます。

1. GitHubの削除権限を狭め、repository adminの侵害だけではrepository全体を消せなくする。
2. rulesetで重要branch／tagの削除とforce pushを止め、source historyの破壊を難しくする。
3. GitHub Organization Ownerに削除権限がないstorageへbackupし、GitHub侵害時にもcopyを残す。
4. 実際に隔離環境へrestoreし、「保存した」ではなく「戻せる」ことを確認する。

GitHubの削除repository復元機能は補助策であり、このcontrolの独立backupではありません。削除後90日
以内という制約があり、team permissionも復元されず、復元操作もOrganization Ownerへ依存するためです。

## 誰が何をするcontrolなのか

このcontrolの主担当は一般のapplication developerではなく、product owner、GitHub Organization
Owner、platform／SREです。

- **Product owner**: 製品を再ビルド、修正、調査するために不可欠なrepositoryを指定し、RPOとRTOを
  決める。
- **GitHub Organization Owner**: memberによるrepository削除・移管を禁止し、critical repositoryへ
  rulesetを適用する。Owner人数とbreak-glass経路を最小化する。
- **Platform／SRE**: GitHubとは別のsecurity accountへbackupを定期保存し、retention lockと削除拒否を
  管理する。
- **Development team**: restore drillで戻したsourceからbuild、security patch、調査に必要な操作が
  できるか確認する。
- **Product Security**: 設定とrestore drillの結果をreviewし、例外にowner、理由、期限を持たせる。

## 最短の導入手順

このcontrolの導入にPython package、Docker、assessment JSONは不要です。採用時は
[`secure/README.md`](secure/README.md)を運用runbookへコピーし、以下を実施します。

### 1. Critical repositoryを決める

product ownerとrepository adminが、製品の再ビルド、security patch、incident investigationに必要な
repositoryを列挙します。renameに影響されないGitHub numeric repository IDも記録します。

Organization内のrepository一覧は、read-only権限のGitHub CLIで取得できます。

```bash
export GH_ORG="example-org"
gh api --paginate "/orgs/${GH_ORG}/repos?type=all&per_page=100" \
  --jq '.[] | [.id, .full_name, .visibility, .archived] | @tsv'
```

出力をそのまま「critical」とみなしてはいけません。product ownerが必要性を判断し、各対象にowner、
RPO、RTOを記録します。

### 2. Repositoryの削除・移管をOrganization Ownerへ限定する

GitHubで次を設定します。

1. Organizationの **Settings** を開く。
2. **Member privileges** を開く。
3. **Repository deletion and transfer** で、memberによるrepository削除・移管を許可する設定を
   無効にする。
4. GitHub Enterprise policyを利用できる場合は、全Organizationで削除・移管をOrganization Ownerへ
   限定する。
5. Organization Ownerを日常のrepository管理者と分離し、人数を必要最小限にする。

これにより、通常のrepository admin sessionが盗まれてもrepository全体の削除・移管はできなく
なります。Organization Ownerの侵害は防げないため、次の独立backupが必要です。

### 3. 重要branch／tagの破壊をrulesetで止める

critical repositoryを対象にOrganization rulesetまたはrepository rulesetを作成します。

- Enforcement status: **Active**
- Target repositories: 手順1で選んだcritical repositoryだけ
- Target refs: default branch、release branch、release tag
- **Restrict deletions**: 有効
- **Block force pushes**: 有効
- Bypass list: broadな`Repository admin`や全Ownerを入れず、review済みbreak-glass teamだけ

rulesetはbranch／tagを守りますが、repository全体の削除を止める機能ではありません。手順2と必ず
組み合わせます。

### 4. GitHub管理者から独立したbackupを作る

最低限、Git history、全local branch／tag、利用している場合はGit LFS objectを退避します。

```bash
git clone --mirror "https://github.com/${GH_ORG}/critical-repository.git"
git -C critical-repository.git fsck --full
git -C critical-repository.git for-each-ref \
  --format='%(refname) %(objectname)' refs/heads refs/tags
```

Git LFSを使用している場合は、mirror directoryで次も実行します。

```bash
git -C critical-repository.git lfs fetch --all
```

保存先は次の条件を満たす必要があります。

- GitHub Organization Ownerが管理者ではない別cloud account／projectである。
- backup jobのGitHub credentialはread-onlyであり、repository削除権限を持たない。
- backup writerは新しいobjectを書けるが、既存objectとretention policyを削除・短縮できない。
- object versioningとretention lockを有効にし、RPOより短い間隔でbackupする。
- storage accountのbreak-glass credentialとencryption keyをGitHub credentialから分離する。

具体例として、別AWS accountのS3 Object Lock `COMPLIANCE` modeを使用できます。providerは任意ですが、
「GitHub adminがbackupも削除できる」構成は不可です。

### 5. 隔離した場所へ実際にrestoreする

少なくとも四半期ごと、またはproduct ownerが定めた間隔で、productionとは異なるOrganizationまたは
Git serverへ復元します。既存production repositoryを上書きしてはいけません。

```bash
git -C critical-repository.git fsck --full
git -C critical-repository.git push --all \
  "https://github.com/example-recovery-org/restore-critical-repository.git"
git -C critical-repository.git push --tags \
  "https://github.com/example-recovery-org/restore-critical-repository.git"
```

復元後に次を確認します。

- 必要なbranch／tagとcommitがbackup時点と一致する。
- LFSを使用するrepositoryでは必要なLFS objectをcheckoutできる。
- ruleset、branch protection、default branchをrunbookから再設定できる。
- 開発チームがbuildまたはsecurity patchを実行できる。
- 復元開始から上記確認までがRTO以内である。

Issues、Pull Requests、Releases、Packages等が製品復旧に必要なら、mirror backupとは別に復元対象と
手順を追加します。

## 検証方法

このpackageはorganizationの状態をJSONへ自己申告させません。実環境では、GitHub設定を画面または
APIでreviewし、実backupを隔離先へrestoreして確認します。

repositoryに含まれるself-testは、Git mirrorがbranch／tagを保持して復元でき、不完全なrestoreを
検出できることだけをlocal temporary directoryで確認します。

```bash
make verify-control CONTROL=PSB-SOURCE-005
```

期待する出力は次です。

```text
PASS mirror backup preserves branches and tags after source loss
PASS incomplete restore is detected
```

このself-testの成功はGitHub設定、storage separation、organizationのbackup、RPO／RTO達成を証明しません。
それらは手順2から5の実施によってのみ確認できます。

## よくある不十分な実装

[`insecure/README.md`](insecure/README.md)に代表例を示します。特に次はbackupとして不十分です。

- 同じGitHub Organization内のprivate forkだけを保持する。
- GitHub Organization Ownerがbackup storageのadministratorでもある。
- `git clone`だけを取り、他branch、tag、LFS、必要なprovider metadataを対象外にしたままにする。
- backup jobへrepository admin／delete権限を与える。
- backup完了logだけを見て、一度もrestoreしない。

## 運用コストとfailure recovery

- backup storage、API利用、retention期間、定期restore用の隔離repositoryに費用がかかる。
- backup失敗時は前回成功を現在の成功として扱わず、RPO超過としてownerへ通知する。
- restore失敗時はbackup世代、LFS不足、permission、rate limit、settings runbookを切り分け、成功するまで
  recovery-readyとみなさない。
- critical repositoryの追加、rename、移管、archive時に対象一覧とbackup jobを更新する。

## Rollback

このreference guideやlocal self-testは削除できますが、導入済みの削除制限、ruleset、retention lockを
単なるrollbackとして弱めてはいけません。controlを廃止する場合は、代替の復旧手段、backup保管期限、
data disposal approvalをproduct ownerとsecurity ownerが先に決定します。

## 既存controlとの分担

- `PSB-CICD-008`はprivileged control-plane変更のapprovalとauditを扱う。
- `PSB-SOURCE-004`はGitHub App、PAT、SSH key等のcredential lifecycleを扱う。
- `PSB-SOURCE-006`はOrganization Owner、member／team／App、hosted defaults、Actions、
  repository security coverage、継続monitoringを扱う。
- `PSB-GOV-001`はincident時のcontainment、authorization、response runbookを扱う。
- 本controlはcritical sourceの削除制限、独立backup、実restoreだけを扱う。

## Framework relationship

SITF `1.0.0@d1d1536`の`T-V009 Mass Deletion of Repositories`とMITRE ATT&CK `v19.1`の
`T1485 Data Destruction`を限定的にmitigateする。これはattack behaviorとの関係であり、GitHub設定や
backupのorganization adoption、formal compliance、完全なdisaster recoveryを意味しない。

## 公式reference

- [GitHub: repositoryの削除・移管権限を設定する](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-organization-settings/setting-permissions-for-deleting-or-transferring-repositories)
- [GitHub: rulesetで利用できるrule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub: repositoryをbackupする](https://docs.github.com/en/repositories/archiving-a-github-repository/backing-up-a-repository)
- [GitHub: 削除したrepositoryを復元する際の制約](https://docs.github.com/en/enterprise-cloud@latest/repositories/creating-and-managing-repositories/restoring-a-deleted-repository)
- [AWS: S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
