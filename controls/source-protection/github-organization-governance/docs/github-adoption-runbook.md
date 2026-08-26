# GitHub Organization governance adoption runbook

このrunbookは`PSB-SOURCE-006`の正式な最小導入手順です。対象はGitHub.com／GitHub Enterprise Cloudの
一つのOrganizationです。GitHub Enterprise Serverや他providerへ適用する場合は、同じsecurity outcomeを
満たす画面項目、API、evidenceをadopterが別途確認してください。

このfile、policy、verifierをcopyするだけではsecurity効果は発生しません。効果はGitHubとIdPのlive settingを
変更し、access review、audit export、drift detection、alert deliveryを継続運用することから生まれます。

## Prerequisites and trust assumptions

- 対象Organizationのloginとnumeric database IDを記録できること;
- Organization Owner、IdP administrator、repository administrator、CI platform、security reviewerを
  特定し、設定者とreviewerを同一人物だけで完結させないこと;
- 利用中のGitHub planでSAML／SCIMまたはEnterprise Managed Users、Actions policy、security
  configuration、audit API／exportの利用可否を確認すること;
- Organization Ownerが2名以上存在し、変更中に一人を失っても管理不能にならないこと;
- Current member、team、outside collaborator、repository、installed App、authorized OAuth Appのinventoryを
  変更前に取得できること;
- 特権変更を`PSB-CICD-008`のrequest、independent approval、before／after evidence、audit eventへ接続すること。

GitHub UIのlabelやplan availabilityは変わり得ます。Repositoryのpin済み
`github-security-guidance` baselineとlinked official GitHub Docsを確認し、label変更を理由にrequired stateを
弱めないでください。

## Responsibilities

| Role | Required action |
|---|---|
| Product owner | Public／internal／privateを含む対象repositoryと業務上必要なaccessを確定する |
| Organization Owner | 2FA、Owner、Member privileges、App installation policyを設定する |
| IdP administrator | SAML／SCIMまたはEMU、group assignment、offboardingを設定しhealthを確認する |
| Repository administrator | Team、outside collaborator、exact repository grant、permission、expiryを管理する |
| CI platform | Organization Actions policy、selected repository／Action、default token権限を設定する |
| Security | Owner／App review、security configuration coverage、audit、drift、alert、exceptionを独立reviewする |
| Platform／security operations | Read-only collection、独立evidence storage、alert receiverを運用する |

Development teamにはOrganization-wide設定の保守を要求しません。必要なrepository、Action、App accessを
exact scopeで申請し、縮小によるworkflow failureを担当者へ返すことだけを求めます。

## Before changing live settings

1. 変更ticketに対象Organization ID、setting、before state、実施者、reviewer、rollback ownerを記録する。
2. 2FA requirementで影響を受けるmember、outside collaborator、billing manager、botを確認する。
3. SAML enforcement前にtest sign-in、recovery code、二人目のOwner、IdP障害時手順を確認する。
4. OAuth App access restrictionを初めて有効化する場合は、既存OAuth App、SSH key、webhookへの影響を確認する。
5. Actions policyを狭める前に、使用中Actionとreusable workflowをexact source／revisionでinventoryする。
6. Security configurationを適用する前に、license consumptionと既存repository overrideを確認する。
7. 一括変更せず、代表repositoryで影響を確認してから対象集合を広げる。

Unreviewedなlockout回避としてOwnerを増やす、Actionsを`all`へ戻す、Appへ`administration: write`を与える、
security configurationをdetachすることは禁止します。

## Step 1: activate the repository-local reference

Repository rootで、既存pathを上書きしないことを確認して実行します。

```bash
test ! -e .security/github-organization-governance
mkdir -p .security/github-organization-governance
cp controls/source-protection/github-organization-governance/secure/policy.json \
  .security/github-organization-governance/policy.json
cp controls/source-protection/github-organization-governance/scripts/verify.py \
  .security/github-organization-governance/verify.py
```

この操作はGitHub、IdP、Git、shell、IDE、OSの設定を変更しません。Existing pathがある場合は停止し、
adopterが差分をreviewしてmergeしてください。

## Step 2: enforce authentication and provisioning

担当はOrganization OwnerとIdP administratorです。

1. Organizationの`Settings > Security > Authentication security`を開く。
2. `Require two-factor authentication for everyone in your organization`を有効にする。
3. 利用可能な場合は`Only allow secure two-factor methods`も有効にし、passkey、security key、
   authenticator app等へ限定する。
4. GitHub Enterprise CloudではSAML configurationをtestし、`Require SAML SSO authentication`を有効にする。
5. SCIMまたはEMUでIdP assignmentとGitHub membershipを同期し、unlinked identityを0にする。
6. Offboarding sampleを実施し、IdPで無効化してからGitHub accessが失われるまで24時間以内であることを確認する。

Successは、2FA／SSOが実際にrequiredで、provisioningがhealthy、unlinked identityがなく、offboarding sampleが
24時間以内に完了した状態です。SAML／SCIMを利用できないplanは`PASS`にせず、underlying resultと
`PSB-GOV-002`のbounded exceptionを分けて記録します。

公式手順:

- [Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [Enabling and testing SAML single sign-on](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/enabling-and-testing-saml-single-sign-on-for-your-organization)
- [About SCIM for organizations](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-scim-for-organizations)

## Step 3: bound Owners and repository access

1. Organizationの`People`でroleを`Owner`にfilterし、2～3名のcurrent humanだけにする。
2. 各Ownerについてcurrent employment、phishing-resistant authentication、review dateを確認する。
3. Member、team、outside collaboratorのgrantをcurrent sponsor、exact repository、必要最小permissionへ結ぶ。
4. Outside collaboratorは原則`pull`または`triage`、90日以内のexpiryとreviewを設定する。Write以上は
   exact business needとexceptionを必要とする。
5. Orphaned team、former worker、unknown owner、expired grantを削除する。

Successは、すべてのgrantがstable actor／team／repository IDへresolveし、90日以内のreviewを持ち、
expired、orphaned、unowned、unbounded admin grantがない状態です。

公式手順:

- [Roles in an organization](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization)
- [Managing outside collaborators](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators)
- [Repository roles for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization)

## Step 4: restrict Organization defaults

Organization Ownerが`Settings > Access > Member privileges`で次を設定します。

| Setting | Minimum value |
|---|---|
| `Base permissions` | `None` |
| `Repository creation` | MemberとGitHub Appによる作成を無効化 |
| `Repository forking` | `Allow forking of private repositories`を無効化 |

Internal repositoryはGitHubのvisibility semanticsにより、base permissionが`None`でもOrganization memberに
readableです。Internalをprivate相当として扱わず、対象repositoryのvisibility decisionを別にreviewします。
Base permission変更は既存private forkのpermissionを自動更新しないため、fork inventoryも確認します。

公式手順:

- [Setting base permissions for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization)
- [Restricting repository creation](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization)
- [Managing the forking policy](https://docs.github.com/en/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization)

## Step 5: constrain GitHub Actions

CI platformがOrganizationの`Settings > Actions > General`で次を設定します。

1. Actionsを必要なselected repositoriesだけで有効にする。
2. `Allow OWNER, and select non-OWNER, actions and reusable workflows`を選び、review済みsourceだけを許可する。
3. `Require actions to be pinned to a full-length commit SHA`を有効にする。
4. `Workflow permissions`を`Read repository contents and packages permissions`にする。
5. GitHub Actionsによるpull request作成／承認を通常baselineでは許可しない。
6. Public／private fork workflowへwrite tokenまたはsecretを渡さない。

Successは、`all repositories`、`allow all actions`、mutable Action reference、write default token、fork secretが
拒否される状態です。Full-length SHA requirementはActionには適用されますが、reusable workflowのtag参照を
同じ境界で完全には防ぎません。個別workflowは`PSB-CICD-001`、`PSB-CICD-004`、`PSB-CICD-005`で検証します。

公式手順:

- [Disabling or limiting GitHub Actions for your organization](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization)

## Step 6: restrict GitHub Apps and OAuth Apps

1. `Settings > Access > Member privileges`でrepository administratorによるGitHub App installationを禁止する。
2. App access requestをOrganization Ownerがreviewできるrequest flowへ限定する。
3. `Settings > Third-party Access`でinstalled GitHub Appsとauthorized OAuth Appsを全件reviewする。
4. 各Appをcurrent human owner、purpose、selected repository、必要最小permission、90日以内のreviewへ結ぶ。
5. `actions`、`administration`、`members`、`organization_administration`、`workflows`のwrite権限を通常baselineで
   許可しない。
6. OAuth App access restrictionを有効にし、unapproved AppがOrganization resourceへ到達しないようにする。

OAuth App access restrictionの初回有効化は既存authorizationや一部SSH keyへ影響し得るため、inventory、
communication、rollback ownerなしに実施しません。App permission不足時もall-repositoryやadmin writeへ
戻さず、exact operationだけを再reviewします。

公式手順:

- [Reviewing GitHub Apps installed in your organization](https://docs.github.com/organizations/managing-programmatic-access-to-your-organization/reviewing-your-organizations-installed-integrations)
- [Limiting OAuth app and GitHub App access requests and installations](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [Enabling OAuth app access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/enabling-oauth-app-access-restrictions-for-your-organization)

## Step 7: cover every repository with security configuration

Security managerまたはOrganization Ownerが`Settings > Security > Advanced Security > Configurations`を開き、
complete repository inventoryへreview済みconfigurationを適用します。

Minimum baselineは次を有効にします。

- dependency graph;
- Dependabot alerts;
- secret scanning;
- secret scanning push protection。

`Repositories` viewで`not applied`、`failed`、`detached`、unreviewed override、unknown repositoryが0であることを
確認します。Transferredまたは新規repositoryを自動的にcoveredと推測せず、inventoryとの差分を日次で確認します。
Planで利用できないfeatureは`PASS`にせず、featureごとのunderlying resultと例外を分離します。

公式手順:

- [Configuring security features in your organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security)
- [Applying a custom security configuration](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/establish-complete-coverage/apply-custom-configuration)

## Step 8: retain audit, detect drift, and test alerts

Security operationsが次を実施します。

1. `Settings > Archive > Logs > Audit log`またはsupported API／streamでrequired event categoryを収集する。
2. Membership、application access、repository visibility、Actions policy、ruleset、Organization settingを含める。
3. GitHub Organization Ownerが削除できないsecurity-owned accountへ180日以上保全する。
4. 少なくとも日次でcurrent postureを評価し、snapshotとdrift evaluationを24時間以内に保つ。
5. Partial pagination、rate limit、permission denial、exporter停止、sequence gapをclean resultではなく`ERROR`にする。
6. 30日以内ごとにharmless canaryを送信し、accountable receiverへのdeliveryを確認する。

GitHubのaudit logが0件であることは、不正操作がなかった証明ではありません。Collection health、coverage、
sequence、retention、alert deliveryを別々に確認します。

公式手順:

- [Reviewing the audit log for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
- [Audit log events for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)

## Step 9: run harmless self-tests

Repository rootで実行します。

```bash
python3 controls/source-protection/github-organization-governance/scripts/verify.py \
  --policy controls/source-protection/github-organization-governance/secure/policy.json \
  --snapshot controls/source-protection/github-organization-governance/secure/organization-snapshot.json \
  --evaluation-time 2026-08-26T12:00:00Z
```

Expected exitは`0`です。これはreference contractの成功であり、live Organizationの成功ではありません。

```bash
python3 controls/source-protection/github-organization-governance/scripts/verify.py \
  --policy controls/source-protection/github-organization-governance/secure/policy.json \
  --snapshot controls/source-protection/github-organization-governance/insecure/organization-snapshot.json \
  --evaluation-time 2026-08-26T12:00:00Z
```

Expected exitは`1`です。どちらもfixtureだけを読み、GitHubやIdPを変更しません。Malformed、stale、partial、
secret-bearing、adapter failureはexit `2`であり、findingやclean resultと区別します。

## Live verification and completion

Organization adoptionは、次のcurrent evidenceを組織のapproved evidence systemで確認して初めて完了します。
Repositoryへreal evidenceをcommitしません。

| Checks | Current evidence |
|---|---|
| `GHO-001` | Stable Organization ID、policy digest、取得時刻、complete pagination、source health |
| `GHO-002` | GitHub authentication setting、IdP assignment／SCIM health、offboarding sample |
| `GHO-003..004` | Complete principal／team／outside collaborator inventoryと90日以内のreview |
| `GHO-005..006` | Current Member privilegesとOrganization Actions setting |
| `GHO-007` | Complete installed GitHub App／authorized OAuth App inventory、permission、repository selection |
| `GHO-008` | Complete repository inventoryとsecurity configuration status |
| `GHO-009` | Audit coverage／retention／independent storage、drift result、alert canary receipt |
| `GHO-010` | Weak policyとcollection failureがcleanにならない実行結果 |

すべてのapplicable checkがcurrent required stateを満たし、ownerと次回review dateがあり、evidence failureが
fail closedになることが成功状態です。有効なexceptionもunderlying `FAIL`や`NOT_CHECKED`を`PASS`へ
書き換えません。

## Recovery and rollback

- 2FA／SAML変更でaccessを失った場合は、事前確認した二人目のOwnerとprovider recovery手順を使う。
- Actions restrictionでworkflowが止まった場合は、必要なexact Action／reusable workflowだけをreviewして
  allowlistへ追加し、`all`へ戻さない。
- Appが停止した場合は、必要なexact repository／permissionだけを再承認する。
- Collectorが失敗した場合はpartial outputを破棄して全件再収集し、古いsnapshotを再timestampしない。
- Alert deliveryが失敗した場合はreceiverを修復し、同じcanaryが届くまでmonitoringをcleanにしない。

Repository-local rollbackは`.security/github-organization-governance/`とCI参照だけをreview後に外します。
Hosted settingを戻す場合はsettingごとに影響を確認し、`PSB-CICD-008`の独立承認を得ます。広いOwner、
Actions `all`、write default token、fork secret、all-repository Appを一括復活させてはいけません。
