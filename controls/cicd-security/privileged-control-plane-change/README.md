# PSB-CICD-008: CI/CDの特権control-plane変更を本人・承認・監査証跡へ結合する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | workflowを安全にしても、SCM、CI、cloud federation、registry、signing serviceの管理者がprovider画面やAPIからbranch protection、environment、runner登録、OIDC trust、release保護、signing policyを直接変更できれば、review済みpipelineの外側で供給網のtrust boundaryを弱められる。 |
| 誰から、または何から守るか | phished／stolen管理者sessionを使う外部攻撃者、単独で不正変更するinsider、共有owner account、誤ったautomation、provider audit収集の欠落、恒久化したbreak-glass bypassから守る。 |
| 何が対象か | SCMとCIの管理plane、cloud workload-identity trust、artifact registry保護、signing service policy、およびそれらを変更するhuman identity、session、request、approval、execution、provider audit event。 |
| 何をするか | 各特権変更を、named current human、phishing-resistantで短寿命かつrecently reauthenticatedなsession、exact targetとbefore／after digest、独立承認、実行結果、unique provider eventへ結合する。緊急変更は1時間以内の失効と独立事後reviewを要求する。 |
| 成功状態 | 全required serviceのfreshで完全なcollector evidenceがあり、通常変更は実行前に別人がexact digestを承認し、provider eventがactor／session／request／target／applied digestと一致する。緊急変更は期限内に別人がacceptまたはrevertし、欠落・stale・malformed・credential-bearing evidenceは`ERROR`になる。 |
| 対象外・残余リスク | このoffline fixtureはlive provider設定、管理者在籍、hardware authenticator、audit backendの耐改ざん性、provider自身の侵害を証明しない。machine OIDCは`PSB-CICD-006`、runner lifecycleは`PSB-CICD-007`、workflow権限とPR境界は`PSB-CICD-004／005`が所有する。 |

## Security problem

CI/CDの供給網には、repository内のworkflowとは別の管理面があります。攻撃者が
administrator sessionを得ると、pull requestを通さずにrequired reviewを外す、
production environmentを開く、malicious runnerを登録する、OIDC subjectを広げる、
release tagのimmutabilityを解除する、またはsigning authorityを広げることができます。

workflow lint、SHA pin、least privilege tokenはこの直接変更を止めません。本controlは、
「変更ticketがある」だけでなく、誰がどの認証sessionで、どの対象の何byte相当の設定を、
誰の承認を受け、providerが実際に何へ変更したかを一つのidentity chainとして検証します。

## Threat, target, and boundary

想定する攻撃者は、phishingやinfostealerで管理者sessionを盗んだ外部攻撃者、広いowner
権限を持つinsider、共有accountや長寿命sessionを誤用する運用者です。収集失敗、API
pagination漏れ、audit event遅延、emergency pathの放置もfailure sourceです。

対象と責務は次のように分離します。

- `PSB-CICD-004`: workflow／jobのtoken permissions;
- `PSB-CICD-005`: untrusted pull requestとprivileged runの分離;
- `PSB-CICD-006`: pipeline workloadがcloud authorityを得るOIDC claim;
- `PSB-CICD-007`: runner routing、registration、one-job lifecycleとteardown;
- `PSB-CICD-008`: human administratorによるprovider control-plane変更のidentity、
  exact configuration、approval、execution、audit、emergency reviewの連結。

## Insecure example

[`insecure/policy.json`](insecure/policy.json)はpassword-only、12時間session、mutable
policy、approvalなし、SCMのみのpartial collection、fail-openを許します。
[`insecure/change-evidence.json`](insecure/change-evidence.json)では、shared service
accountがwildcard targetを変更し、requestより先に別actor／sessionが実行し、provider
eventとpost-reviewが欠落しています。

これは意図的な危険fixtureです。providerへ適用する設定ではありません。

## Secure example

[`secure/policy.json`](secure/policy.json)は次を要求します。

- SCM、CI、cloud identity、registry、signing serviceの全inventory;
- digest-pinned policyとcollector identity;
- named current humanとphishing-resistant authentication;
- serviceごとの明示的administrator role allow-list;
- sessionは最大1時間、step-up後15分以内の実行;
- exact service、change type、target、before／after SHA-256、reason、ticket;
- ordinary changeのindependent pre-approval;
- provider execution／audit eventのrequestとapplied digestへの結合;
- emergency changeの1時間以内のexpiryとindependent post-review;
- collection failure、stale、malformed、secret fieldの`ERROR`。

[`secure/change-evidence.json`](secure/change-evidence.json)は通常のbranch rule変更と、
credential incident中の緊急OIDC trust縮小を別のpathとして示します。fixtureはreal user、
token、repository ID、production dataを含みません。

## Integration

各provider adapterはread-only APIまたは外部audit exportを使い、次の正規化recordを
secret-freeで作成します。

1. provider側のcurrent organization membershipとauthentication assuranceを取得する。
2. session IDとissuance／expiry／reauthentication timeをcontent-freeに記録する。
3. provider設定のcanonical representationから変更前後SHA-256を計算する。
4. requestとapprovalをexact target／after digestへ結合する。
5. providerのunique audit eventを取得し、actor、session、target、request、applied digestを
   照合する。
6. required serviceが一つでも未収集なら`complete: false`として終了する。
7. organization evidence storeへ保存する前にcredential fieldを除去する。

Provider固有adapterはこのcontrolに追加できますが、write APIをverification pathへ混ぜず、
version／integrity、pagination、rate limit、event lag、error stateを明示する必要があります。

### GitHub read-only normalization adapter

[`scripts/normalize_github.py`](scripts/normalize_github.py)は、GitHub organization audit
export、organization側のidentity／session export、review済みchange registerをjoinし、
本controlのcanonical change evidenceへ変換します。GitHub公式audit eventで確認できる
`_document_id`、stable `actor_id`、`request_id`、repository／environment／runner-group target、
`old_value`／`new_value`を利用します。runner-group変更はさらにread-only current-state
snapshotをstable group IDでjoinします。provider exportに含まれる`hashed_token`、IP、token
metadata等は出力しません。

```bash
make normalize-github-control-plane-evidence \
  GITHUB_AUDIT_EVENTS=organization-github-audit.json \
  GITHUB_ADMIN_SESSIONS=organization-admin-sessions.json \
  GITHUB_CHANGE_REGISTER=organization-reviewed-changes.json \
  GITHUB_RUNNER_GROUPS=organization-runner-group-state.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/github-control-plane-evidence.json
```

GitHub audit eventだけからphishing-resistant authentication、current membership、approvalを
推論しません。exact stable actor／requestで外部identity/session evidenceとchange registerへ
joinできないeventはnormalization `ERROR`です。またGitHub fragmentの`covered_services`は
`ci`だけであり、単独では5-service completenessをPASSにしません。cloud identity、registry、
signing service等のadapter outputとcross-service collectorでcomposeしてから本体verifierへ
渡します。

### GitHub live audit collector

[`scripts/collect_github_audit.py`](scripts/collect_github_audit.py)は、GitHub organization
audit REST APIをread-onlyで取得します。query windowは最大24時間、`include=all`、昇順、
100件／pageに固定し、GitHubが返す`after` cursorを同じHTTPS host／organization／queryへ
完全paginationします。途中の403／429、timeout、malformed response、cursor loop、100 page／
10,000 event超過では出力を公開しません。

```bash
# GITHUB_TOKEN is already injected by the approved secret boundary.
make collect-github-control-plane-audit \
  GITHUB_ORGANIZATION=example-org \
  AUDIT_WINDOW_START=2026-08-12T03:00:00Z \
  AUDIT_WINDOW_END=2026-08-12T04:00:00Z \
  GITHUB_AUDIT_OUTPUT=generated/assessments/github-audit.json
```

Tokenは環境からmemory内だけで利用し、command lineや出力へ書きません。collectorは
`environment.update_protection_rule`、`org.runner_group_updated`、`repository_ruleset.update`、
`protected_branch.update_allow_force_pushes_enforcement_level`を選択します。最初のeventはexact
`old_value`／`new_value`を持ちます。後者は完全な設定差分を持たないため、次のcurrent-state
collectorなしでは`CPC-003／005` evidenceへ昇格しません。ruleset eventはその次のhistory
collectorでexact before／after versionへ結合します。

### GitHub runner-group current-state collector

[`scripts/collect_github_runner_group.py`](scripts/collect_github_runner_group.py)は、stable
runner-group IDを指定してorganizationのread-only detail APIを取得します。visibilityが
`selected`ならrepository access APIも全page取得し、URL等の不要なprovider fieldを落として、
name、visibility、public repository許可、workflow制限、selected workflow、network設定、
stable repository IDをcanonical snapshotへ変換します。

```bash
make collect-github-runner-group-state \
  GITHUB_ORGANIZATION=example-org \
  GITHUB_RUNNER_GROUP_ID=42 \
  GITHUB_RUNNER_GROUP_OUTPUT=generated/assessments/github-runner-group-42.json
```

normalizerはaudit eventから5分以内のsnapshotだけを受け入れ、stable group ID、eventに含まれる
設定field、review済み`after_digest`を照合します。snapshot時刻までを含む完全なaudit windowに
同じgroupの後続更新があれば曖昧として`ERROR`にします。これにより現在の適用後設定は独立に
確認できますが、GitHub APIは過去状態を返さないため、`before_digest`はchange register側の
review済みassertionです。より強い保証には変更前snapshotの独立保存が必要です。

### GitHub repository／organization ruleset SCM adapter

[`scripts/collect_github_ruleset.py`](scripts/collect_github_ruleset.py)はrepositoryのstable ID／
node ID、repository-scoped branch／tag rulesetのstable ID／node ID、current state、全version history、
指定したbefore／after version stateをread-only REST APIで収集します。`includes_parents=false`を
固定し、organization rulesetをrepository rulesetと誤結合しません。

```bash
make collect-github-ruleset-state \
  GITHUB_ORGANIZATION=example-org \
  GITHUB_REPOSITORY=product-api \
  GITHUB_RULESET_ID=73 \
  GITHUB_RULESET_BEFORE_VERSION_ID=4 \
  GITHUB_RULESET_AFTER_VERSION_ID=5 \
  GITHUB_RULESET_OUTPUT=generated/assessments/github-ruleset-73.json
```

organization rulesetは同じcollectorをorganization endpoint modeで実行します。stable organization
ID／node ID、repository selectorを含むconditions、branch／tag selector、全version historyを一組として
取得するため、名前が同じ別organizationやrepository-scoped rulesetへ証跡を流用できません。

```bash
make collect-github-organization-ruleset-state \
  GITHUB_ORGANIZATION=example-org \
  GITHUB_RULESET_ID=74 \
  GITHUB_RULESET_BEFORE_VERSION_ID=8 \
  GITHUB_RULESET_AFTER_VERSION_ID=9 \
  GITHUB_RULESET_OUTPUT=generated/assessments/github-org-ruleset-74.json
```

[`scripts/normalize_github_ruleset.py`](scripts/normalize_github_ruleset.py)は、完全なorganization
audit exportの`repository_ruleset.update`、外部human session、review済みchange register、
上記snapshotを`scm` fragmentへ変換します。

```bash
make normalize-github-ruleset-control-plane-evidence \
  GITHUB_AUDIT_EVENTS=organization-github-audit.json \
  GITHUB_ADMIN_SESSIONS=organization-admin-sessions.json \
  GITHUB_CHANGE_REGISTER=organization-reviewed-scm-changes.json \
  GITHUB_RULESET_SNAPSHOT=github-ruleset-73.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/github-scm-evidence.json
```

event actorとhistoryのafter-version actor／時刻、stable repositoryまたはorganization／ruleset identity、auditの
old／new enforcementとname、before／after state digestをすべて一致させます。historyの最新versionが
review対象after versionより進んでいれば現在状態との対応が曖昧なので`ERROR`です。audit logが
持つadded／deleted／updated fieldだけを完全stateと誤認しません。

`target=branch`は`branch-protection`、`target=tag`は`tag-protection`として別の変更種別に正規化します。
tag rulesetではrelease tagの削除、non-fast-forward更新、署名要求を弱める変更が供給網のrelease
identityを差し替えるため、branch設定と同じ厳密なreview／history結合を要求します。beforeとafterで
targetが変わる証跡は`ERROR`です。

repository-scoped `target=push`はroot repositoryのfork network全体へ波及するため、ruleset snapshotに
加えて専用のfork-network snapshotを要求します。rootがforkでなくprivate／internalであること、rootの
stable ID／node ID、`network_count`、最大100件／pageで完全取得した各forkのstable IDとroot sourceを
照合し、review済み`network_digest`へ結合します。

```bash
make collect-github-fork-network-state \
  GITHUB_ORGANIZATION=example-org \
  GITHUB_REPOSITORY=product-api \
  GITHUB_FORK_NETWORK_OUTPUT=generated/assessments/github-product-api-network.json

make normalize-github-ruleset-control-plane-evidence \
  GITHUB_AUDIT_EVENTS=organization-github-audit.json \
  GITHUB_ADMIN_SESSIONS=organization-admin-sessions.json \
  GITHUB_CHANGE_REGISTER=organization-reviewed-push-ruleset.json \
  GITHUB_RULESET_SNAPSHOT=github-push-ruleset-76.json \
  GITHUB_FORK_NETWORK_SNAPSHOT=github-product-api-network.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/github-push-scm-evidence.json
```

fork名や一覧はnormalized outputへ残さず、root-bound network digestだけをtarget identityへ含めます。
ruleset変更後5分以内、かつ完全なaudit window内のnetwork snapshotだけを受け入れます。

GitHub公式audit event catalogはorganization ruleset専用の別actionを記載せず、
`repository_ruleset.update`に`ruleset_source_type`を載せています。本実装は
`ruleset_source_type=Organization`、stable `org_id`、repository field不在を組み合わせて
organization ruleset updateと判定します。これは公式fieldから導く実装上の推論であり、導入時は
実tenantのsanitized event shapeを確認してください。形が異なる場合は成功扱いにせずcollectorを
更新します。

GitHubはruleset history取得にrepositoryまたはorganization Administration write permissionを要求し、
bypass actorもwrite accessがなければ省略します。collectorはGETしか実行しませんがcredential自体は
write可能です。専用GitHub App installation、対象repository／organizationの限定、短寿命token、
collectorからwrite endpointへのegress拒否、利用監視を組み合わせてください。この残余権限を
「read-only token」と表現しません。organization credentialは多数repositoryへ影響できるため、
repository modeよりblast radiusが大きいものとして別管理します。

本adapterはrepository／organization-scoped branch／tagとrepository-scoped push ruleset updateの証跡を
所有します。ruleset内容の安全性要件、workflow token、untrusted PR executionは
`PSB-CICD-004／005`、create／delete、organization-wide push、repository transfer／rename／archiveは
将来adapterの対象です。
organization-wide pushはrepository selectorが示す全rootと各fork networkの完全列挙が必要なので、単一
repositoryのnetwork evidenceを流用せず`ERROR`にします。

### GitHub legacy branch-protection force-push adapter

[`scripts/collect_github_branch_protection.py`](scripts/collect_github_branch_protection.py)は、
stable repository ID／node IDと、wildcardを含まないexact branchのlegacy branch-protection
current stateをread-only REST APIから取得します。このsliceは
`allow_force_pushes.enabled`だけをcanonical stateへ残し、他のbranch-protection fieldを検証したとは
主張しません。

```bash
make collect-github-branch-protection-state \
  GITHUB_ORGANIZATION=example-org \
  GITHUB_REPOSITORY=product-api \
  GITHUB_BRANCH=main \
  GITHUB_BRANCH_PROTECTION_OUTPUT=generated/assessments/github-main-protection.json
```

[`scripts/normalize_github_branch_protection.py`](scripts/normalize_github_branch_protection.py)は、
`protected_branch.update_allow_force_pushes_enforcement_level`のunique audit event、外部human
session、review済みchange register、上記current-state snapshotを`scm` fragmentへ結合します。
adapter contractはaudit enforcement levelの`0`をdisabled、`1／2`をenabledとして扱い、それ以外や
booleanへの型置換を拒否します。導入時はsanitized tenant eventでこのprovider表現を確認してください。

```bash
make normalize-github-branch-protection-evidence \
  GITHUB_AUDIT_EVENTS=organization-github-audit.json \
  GITHUB_ADMIN_SESSIONS=organization-admin-sessions.json \
  GITHUB_CHANGE_REGISTER=organization-reviewed-legacy-branch-change.json \
  GITHUB_BRANCH_PROTECTION_SNAPSHOT=github-main-protection.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/github-legacy-branch-evidence.json
```

snapshotはeventから5分以内かつsnapshot後まで完全なaudit windowに含まれなければなりません。
同じrepository／branchへ後続force-push変更があればcurrent stateとの対応が曖昧なので`ERROR`です。
GitHub RESTはlegacy branch-protection historyを返さないため、`before_digest`はreview済みregisterの
before booleanから再計算します。高保証環境では変更直前snapshotを独立保存してください。

### AWS IAM trust-policy normalization adapter

[`scripts/normalize_aws.py`](scripts/normalize_aws.py)は、CI workloadが引き受けるAWS IAM
roleのtrust policy変更だけを`cloud-identity` fragmentへ変換します。次の4入力を結合します。

1. completeなorganization CloudTrail management-event exportの成功した
   `UpdateAssumeRolePolicy` event;
2. eventから5分以内にread-only `iam:GetRole`で取得したstable `RoleId`と現在のtrust policy;
3. assumed-role principal、issuer、`sourceIdentity`に結合されたorganization identity/session;
4. CloudTrail `eventID`／`requestID`、stable role ID、before／after digestを固定したreview済み
   change register。

```bash
make normalize-aws-control-plane-evidence \
  AWS_CLOUDTRAIL_EVENTS=organization-cloudtrail-events.json \
  AWS_ADMIN_SESSIONS=organization-aws-admin-sessions.json \
  AWS_CHANGE_REGISTER=organization-reviewed-aws-changes.json \
  AWS_IAM_ROLES=organization-iam-role-snapshot.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/aws-control-plane-evidence.json
```

CloudTrail windowはsnapshot後まで完全である必要があります。同じroleへsnapshot前の後続
`UpdateAssumeRolePolicy`があれば、どのeventが現在状態を作ったか曖昧なので`ERROR`です。
CloudTrail request policy、`GetRole` current policy、review済み`after_digest`は同一でなければ
なりません。`accessKeyId`、IP、user agent、policy本文はnormalized outputへ残しません。

CloudTrailだけからcurrent membershipやphishing-resistant MFAを推論せず、organization
session exportとのexact joinを要求します。AWS fragmentのcoverageは`cloud-identity`だけなので、
GitHubと同様、単独ではcross-service completenessをPASSにしません。

### AWS ECR repository-policy normalization adapter

[`scripts/normalize_aws_ecr.py`](scripts/normalize_aws_ecr.py)は、AWS ECR
repository access policyの直接変更だけを`artifact-registry` fragmentへ変換します。
CloudTrailの成功した`SetRepositoryPolicy`、`DescribeRepositories`のresource identity、
`GetRepositoryPolicy`の現在policy、外部human session、review済みchange registerを結合します。

```bash
make normalize-aws-ecr-control-plane-evidence \
  AWS_ECR_CLOUDTRAIL_EVENTS=organization-ecr-cloudtrail-events.json \
  AWS_ECR_ADMIN_SESSIONS=organization-ecr-admin-sessions.json \
  AWS_ECR_CHANGE_REGISTER=organization-reviewed-ecr-changes.json \
  AWS_ECR_REPOSITORIES=organization-ecr-repository-snapshot.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/ecr-control-plane-evidence.json
```

ECRにはIAM `RoleId`相当のimmutable repository IDがないため、account、region、repository
ARN、name、作成時刻を一つのrepository generationとして固定します。同名repositoryを削除・
再作成した場合、過去のapprovalを新しいresourceへ再利用できません。CloudTrail request policy、
`GetRepositoryPolicy` current policy、review済み`after_digest`を一致させ、snapshotまでの後続
policy updateがあれば曖昧として`ERROR`にします。

`force=true`は将来のpolicy更新を妨げる設定を強制できるため、通常変更として受け入れません。
利用する場合はexact force decision、break-glass authority、期限、post-reviewを所有する別の
emergency adapterが必要です。tag immutability、push／delete operation、lifecycle等は
`PSB-CONTAINER-002`が所有し、このadapterへ重複実装しません。

### AWS KMS signing-key policy normalization adapter

[`scripts/normalize_aws_kms.py`](scripts/normalize_aws_kms.py)は、AWS KMSのcustomer-managed
署名鍵に対する`default` key policyの直接変更だけを`signing-service` fragmentへ変換します。
CloudTrailの成功した`PutKeyPolicy`、`DescribeKey`のstable Key ID／ARNと`SIGN_VERIFY`用途、
`GetKeyPolicy`の現在policy、外部human session、review済みchange registerを結合します。

```bash
make normalize-aws-kms-control-plane-evidence \
  AWS_KMS_CLOUDTRAIL_EVENTS=organization-kms-cloudtrail-events.json \
  AWS_KMS_ADMIN_SESSIONS=organization-kms-admin-sessions.json \
  AWS_KMS_CHANGE_REGISTER=organization-reviewed-kms-changes.json \
  AWS_KMS_KEYS=organization-kms-key-snapshot.json \
  CONTROL_PLANE_EVIDENCE_OUTPUT=generated/assessments/kms-control-plane-evidence.json
```

eventから5分以内のcurrent snapshotを要求し、snapshot後までの完全なCloudTrail windowに
同じKey ID／ARNの後続`PutKeyPolicy`があれば曖昧として`ERROR`にします。request policy、
current policy、review済み`after_digest`が一致し、keyがenabled、customer-managed、
`SIGN_VERIFY`でなければ証跡を作りません。KMS APIは結果整合性を持つため、write直後の単発readを
無条件に信頼せず、collectorは収束を確認してから時刻付きsnapshotを発行する必要があります。

`BypassPolicyLockoutSafetyCheck=true`は鍵を管理不能にする危険があるため通常pathでは拒否します。
必要ならexact bypass decision、break-glass authority、期限、post-reviewを結合する別のemergency
adapterを設計します。署名要求・署名生成・鍵version・receiptは`PSB-REL-005`、artifact側の
署名検証は`PSB-REL-001`が所有し、本adapterはhumanによるkey-policy管理変更だけを扱います。

## Verification

```bash
make verify-control CONTROL=PSB-CICD-008
```

直接実行する場合:

```bash
python3 controls/cicd-security/privileged-control-plane-change/scripts/verify.py \
  --policy controls/cicd-security/privileged-control-plane-change/secure/policy.json \
  --change-evidence controls/cicd-security/privileged-control-plane-change/secure/change-evidence.json \
  --evaluation-time 2026-08-12T04:10:00Z
```

Verifierは`PASS`を0、semantic findingを1、評価不能を2で返します。negative testsは
shared identity、weak／broad session、wildcard、request substitution、approval欠落、
audit mismatch、unreviewed emergency、stale、malformed、unavailable、secret-bearing evidenceを
検証します。GitHub adapterについてもsession join欠落、old／new値改ざん、partial-service
bundle、sensitive provider field除去を検証します。
runner-group adapterはrepository pagination、stable ID mismatch、snapshot欠落、5分超過、
field改ざん、後続updateによる曖昧性もfail closedで検証します。
AWS adapterはidentity substitution、stable RoleId mismatch、trust-policy改ざん、snapshot遅延、
後続update、partial collection、provider error、secret-bearing provider fieldsを検証します。
ECR adapterはidentity substitution、同名repository再作成、policy改ざん、`force=true`、
snapshot遅延、後続update、partial collection、provider errorをfail closedで検証します。
GitHub SCM adapterはrepository／organization／ruleset／history actor差し替え、organization eventへの
repository field混入、digest改ざん、partial audit、stale snapshot、後続version、current/history不一致、
credential field残留をfail closedで検証します。
legacy branch adapterはrepository／branch／session差し替え、current force-push stateとaudit levelの
不一致、review済みdigest改ざん、5分超過、後続update、不完全またはcredential-bearing inputを
fail closedで検証します。

## Expected output

安全fixture:

```text
PASS PSB-CICD-008 privileged control-plane changes are identity and evidence bound
```

危険fixtureは`FAIL CPC-* ...`を返します。collector unavailable、stale、JSON parse failure、
credential fieldは`ERROR PSB-CICD-008 ...`になり、credential valueは出力しません。

## Operational notes and cost

- Providerごとにidentity、membership、audit、current configurationのread-only collectorが必要です。
- GitHub REST audit logは最大100件／pageです。collectorはAPI version、query window、page／
  event count、pagination完了を記録します。GitHub event retentionを超える欠損は復元できないため、
  schedule、checkpoint、外部保存と監視は組織側で必要です。
- provider eventの遅延を考慮しつつ、本例では15分以内のfreshnessを要求します。
- canonicalizationが変わるとdigestが変わるため、adapter versionもcollector identityへ固定します。
- Runner-group snapshotは変更eventから5分以内に取り、snapshot後までのaudit windowを再収集します。
  Audit logとstate APIはtransactionではないため、同じgroupの後続変更があれば証跡を作り直します。
- Ruleset snapshotも5分以内に取得し、snapshot後までaudit windowを再収集します。historyの全pageを
  取得し、最新versionが変わった場合は新しいbefore／after pairで証跡を作り直します。
- Legacy branch-protection snapshotも5分以内に取得し、snapshot後までaudit windowを再収集します。
  `allow_force_pushes`以外のlegacy setting変更は本sliceのPASSへ含めず、別adapterとして追加します。
- AWS IAM snapshotも変更eventから5分以内に取り、snapshot後までのCloudTrail windowを確定します。
  CloudTrail Event Historyだけに依存せず、organization trailの完全性、retention、独立保存を監視します。
- ECR snapshotも同じ5分境界で収集し、repository delete／createとpolicy updateを含むorganization
  trailを保持します。repository ARNだけでは同名再作成を区別できないため、作成時刻を失わないでください。
- KMS snapshotも5分以内に`DescribeKey`と`GetKeyPolicy`から作成し、snapshot後までの
  `PutKeyPolicy` management eventを保持します。CloudTrail trailからKMS eventを除外しないでください。
- 独立承認は日常変更の摩擦になります。対象をtrust-boundary変更へ限定し、read-only操作へ
  適用しないことでHITL頻度を抑えます。
- emergency pathはapprovalを省略できますが、失効と事後reviewは省略できません。
- Audit backendはcontrol-planeとは別のwrite boundaryとretentionを持たせます。

## Limitations and residual risk

- Normalized fixtureが通っても、実環境でcollectorが配備されている証拠にはなりません。
- Providerが侵害されればmembership、authentication、configuration、eventを同時に偽造する
  可能性があり、independent export、provider assurance、incident investigationが必要です。
- 本controlは変更内容のbusiness correctnessを証明しません。ownerとsecurity reviewerが
  exact diffの妥当性を判断します。
- Configuration canonicalization、eventual consistency、SCIM／IdP latencyはprovider adapterで
  個別に検証します。
- Runner-group current-state snapshotは適用後digestを確認しますが、変更前のprovider状態を
  復元しません。高保証環境ではwriteの直前にも同じcollectorでsnapshotを保存します。
- GitHub SCM sliceはrepository／organization-scoped branch／tag、repository-scoped push ruleset
  update、およびlegacy branchのforce-push enforcement updateを扱います。ruleset create／delete、
  その他のlegacy branch setting、organization-wide push、repository lifecycleは対象外です。
- Push rulesetはfork networkへ継承され、root repositoryのbypass権限がnetwork全体へ影響します。fork一覧と
  `network_count`はtransactional snapshotではなく、collection中のfork作成／削除やAPIの可視性欠損は残余
  リスクです。organization-wide selectorは全root networkを証明できないため拒否します。
- Ruleset historyとbypass actorの完全取得にrepository／organization Administration write permissionが
  必要なのはprovider上の制約です。GET-only実装でもtoken窃取時のmutation riskが残るため、credentialと
  egressを分離します。organization権限はより大きいblast radiusとして扱います。
- Organization ruleset audit分類は公式eventの`ruleset_source_type=Organization`等からの推論です。
  providerがtenantで異なるfieldを返す場合、本adapterは未検証であり、sanitized実eventを基に更新が必要です。
- Legacy branch REST snapshotはcurrent stateだけで、provider-side before historyを証明しません。
  audit enforcement levelの数値表現もtenantで検証し、不一致や未知の値を成功扱いにしないでください。
- AWS sliceはroot-path roleの直接`UpdateAssumeRolePolicy`に限定します。IaCによるreplacement、
  `CreateRole`、SAML、Azure／GCP、role permission policyはこのadapterの対象外です。
- IAM policyはstructural JSONとしてdigest化します。意味が同じでもstatementやarray順が変われば
  fail closedになるため、providerが並べ替える環境ではreview済みsemantic canonicalizerが必要です。
- ECR policyもstructural JSONとして扱い、`GetRepositoryPolicy`は過去のbefore stateを返しません。
  高保証環境では変更直前snapshotを独立保存し、force変更は通常pathから分離します。
- KMS sliceはenabled customer-managed `SIGN_VERIFY` keyの直接`PutKeyPolicy`に限定します。
  key create／disable／delete、grant、alias、key material、multi-Region操作と`Sign`実行は対象外です。
- `GetKeyPolicy`も過去のbefore stateを返さず、key policyをstructural JSONとしてdigest化するため、
  高保証環境では変更前snapshotを保存し、semantic上無害な配列順変更もreviewし直します。
- KMSの実効権限はkey policyだけでなくIAM policy、grant、VPC endpoint policyにも依存します。
  本adapterのPASSを「signing権限またはpolicy管理権限を完全に除去した証明」と解釈しないでください。

## Provider references

- [GitHub organization audit-log events](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [GitHub repository ruleset REST API and history](https://docs.github.com/en/rest/repos/rules)
- [GitHub organization ruleset REST API and history](https://docs.github.com/en/rest/orgs/rules)
- [GitHub protected-branch REST API](https://docs.github.com/en/rest/branches/branch-protection)
- [AWS IAM UpdateAssumeRolePolicy API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html)
- [AWS IAM GetRole API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRole.html)
- [AWS CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [AWS CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [AWS ECR SetRepositoryPolicy API](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_SetRepositoryPolicy.html)
- [AWS ECR GetRepositoryPolicy API](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetRepositoryPolicy.html)
- [AWS ECR Repository resource fields](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_Repository.html)
- [AWS ECR CloudTrail logging](https://docs.aws.amazon.com/AmazonECR/latest/userguide/logging-using-cloudtrail.html)
- [AWS KMS PutKeyPolicy API](https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html)
- [AWS KMS PutKeyPolicy CloudTrail event](https://docs.aws.amazon.com/kms/latest/developerguide/ct-put-key-policy.html)
- [AWS KMS GetKeyPolicy API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyPolicy.html)
- [AWS KMS KeyMetadata](https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html)
- [AWS KMS CloudTrail logging](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html)

## Framework mapping boundary

行単位mappingは[`control.yaml`](control.yaml)にあります。GitHub guidance、OpenSSF OSPS
Baseline、MITRE ATT&CKへのmappingは関連するevidenceを示すもので、GitHub設定完了、OSPS
compliance、ATT&CK coverage、NIST SP 800-204D complianceを意味しません。SP 800-204Dは
framework mappingとして重複登録せず、`SCIR-010` integration reconciliationからexact checkを
参照します。
