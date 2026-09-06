# PSB-CICD-006: GitHub ActionsのAWS OIDC federationをexact trustへ限定する

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHub ActionsをOIDCへ移行しても、AWS IAM roleのtrust policyがorganization wildcardや誤った
audienceを許すと、別repositoryの正規GitHub tokenまでproduction roleへ交換できる。OIDC導入後も
長期AWS access keyが残っていれば、攻撃者はfederationを迂回できる。

### 誰から、または何から守るか

別repositoryや未承認contextを操作する攻撃者、侵害されたworkflow step、利便性のためtrustやroleを
広げる管理者、OIDC移行後も残った長期credential、live設定を確認せずfixtureだけで安全と判断する運用から守る。

### 何が対象か

GitHub Actionsのdeploy job、GitHub OIDC issuerとimmutable subject、AWS IAM OIDC provider、IAM roleの
trust／permissions policy、GitHub repository／Environment secrets、AWS STS sessionを対象とする。

### 何をするか

AWS側でissuer、`sts.amazonaws.com` audience、immutable repository IDと`production` Environmentを含む
subjectを完全一致させる。専用roleのaction／resourceを限定し、STS sessionを900秒で要求し、長期AWS keyを削除する。

### 成功状態

`main`からprotected `production` Environmentを通るjobだけが期待するAWS roleを引き受け、別audienceや
別subjectのharmless testは拒否される。GitHubに長期AWS access keyがなく、live設定と試験結果が確認されている。

### 対象外・残余リスク

許可されたdeploy job自体が侵害されると、900秒以内のcredentialは盗まれ得る。Runner／egress保護、
untrusted PR分離、provider設定変更の承認、AWS以外のprovider、実deploymentの正当性は別controlまたは導入先で確認する。

## セキュリティ向上の効果はどこから生まれるか

このcontrolの効果は、採用先で次のlive状態を作ることから生まれる。

- AWS IAM roleがGitHub issuer、用途固有audience、exact subjectを検証する。
- GitHub Environmentが`main`以外からproduction jobを開始させない。
- Exchange後のroleが一つのdeployment用途とresourceだけを許可する。
- GitHubから長期AWS access keyを撤去する。
- 実際のAWS STSで、許可contextと拒否contextを試す。

このREADME、sample policy、workflowをcopyしただけではAWSやGitHubの設定は変わらず、導入済みにはならない。
JWT署名、issuer key rotation、token有効期間の検証はAWS federation serviceへ任せる。Repository内に
providerを模倣するtoken verifierやreplay ledgerを実装しない。

## 誰が何をするcontrolなのか

- **Development team**: deploymentに必要なAWS action／resource／実行時間を列挙し、既存deploy stepと
  [copy対象workflow](secure/aws/workflow.yml)を統合する。
- **Repository administrator**: repository ID、owner ID、`main`、`production` Environment、secret inventory、
  required reviewを設定・確認する。
- **Cloud／platform administrator**: AWS IAM OIDC provider、exact role trust、permissions policy、900秒session、
  CloudTrailを設定する。
- **Organization owner／CI platform**: immutable OIDC subject policyとorganization-level Actions設定を所有する。
- **Security**: GitHubとAWSのcurrent設定、wildcard不在、旧key撤去、positive／negative test、例外を独立reviewする。

同じworkflowや変更者だけに、trust変更、role付与、試験、最終承認を完結させない。

## 最短の導入手順

### 0. Reference profileと置換値を確認する

このsampleはGitHub.com／GitHub Enterprise Cloud、AWS標準partition、direct workflow、GitHub-hosted Ubuntu、
`main`、`production`、一つのAWS accountとIAM roleを対象とする。

| 置換対象 | Sample value | 確認元 |
|---|---|---|
| GitHub organization | `example-org` | Repository URL |
| GitHub organization ID | `123456` | GitHub API／organization管理画面 |
| GitHub repository | `secure-app` | Repository URL |
| GitHub repository ID | `987654` | GitHub API／repository情報 |
| GitHub Environment | `production` | Repository Settings |
| AWS account ID | `111122223333` | AWS account |
| AWS region | `ap-northeast-1` | Deployment target |
| IAM role | `github-oidc-secure-app-prod` | AWS IAM |
| Allowed action／resource | `s3:PutObject`と一つのprefix | 実deployment設計 |

GitHubの[OIDC REST API](https://docs.github.com/en/rest/actions/oidc)またはOIDC settings画面で、対象repositoryが
immutable subjectを使うことを確認する。作成時期やrepository名だけから推測しない。

このprofileが期待するsubject形式は次である。

```text
repo:example-org@123456/secure-app@987654:environment:production
```

Immutable subjectを新たに有効化する場合、先にAWS trustへ新subjectを追加し、GitHubを切り替え、成功確認後に
旧subjectを削除する。名前だけのsubjectやorganization wildcardを恒久的なfallbackとして残さない。

### 1. AWS IAM OIDC providerを登録する

AWS Consoleで`IAM → Identity providers → Add provider`を開き、次を設定する。

| Field | Value |
|---|---|
| Provider type | `OpenID Connect` |
| Provider URL | `https://token.actions.githubusercontent.com` |
| Audience | `sts.amazonaws.com` |

同じproviderが存在する場合は重複作成せず、URLとaudienceのcurrent値を確認する。詳細は
[AWSのGitHub OIDC role作成手順](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)を参照する。

### 2. Exact trustの専用IAM roleを作る

[secure/aws/role-trust-policy.json](secure/aws/role-trust-policy.json)をreviewし、sampleのaccount、organization、
repository、ID、Environmentを実値へ置換してIAM roleのtrust policyへ設定する。

中心となる条件は次である。

```json
"StringEquals": {
  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
  "token.actions.githubusercontent.com:sub":
    "repo:example-org@123456/secure-app@987654:environment:production"
}
```

`StringLike`、`repo:example-org/*`、`repo:example-org/secure-app:*`、audience省略へ弱めない。
[insecure/aws/wildcard-trust-policy.json](insecure/aws/wildcard-trust-policy.json)は比較専用であり、AWSへ適用しない。

### 3. Roleのactionとresourceを限定する

[secure/aws/role-permissions-policy.json](secure/aws/role-permissions-policy.json)は、一つのS3 release prefixへ
`s3:PutObject`だけを許可する例である。実deploymentが使うactionとresourceへ置換し、`Action: "*"`、
`Resource: "*"`、IAM管理権限、不要なrole chainingを追加しない。

[IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)で
grammarとAWSのsecurity warningを確認する。その結果だけではsemantic least privilegeを証明しないため、
development teamが列挙したoperationとpolicyを一対一でreviewする。

### 4. GitHub Environmentを保護する

`Repository Settings → Environments → production`で次を設定する。

- Deployment branches and tags: `Selected branches and tags`
- Allowed branch: `main`
- Required reviewers: 契約planで利用できる場合はdevelopment teamと異なる担当
- Prevent self-review: 利用できる場合は有効
- Administrator bypass: 無効化できる場合は無効

利用できないprotectionをsample JSONで代替せず、`NOT_CHECKED`または残余リスクとして記録する。
[GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)で
利用中planの挙動を確認する。

### 5. Workflowをcopyして明示的に有効化する

[secure/aws/workflow.yml](secure/aws/workflow.yml)をreviewし、既存fileを上書きしない新しいpathへcopyする。

```bash
mkdir -p .github/workflows
cp controls/cicd-security/audience-bound-oidc-federation/secure/aws/workflow.yml \
  .github/workflows/verify-aws-deployment-identity.yml
```

次を実値へ置換する。

- `111122223333`
- `github-oidc-secure-app-prod`
- `ap-northeast-1`
- 必要なら`production`

Workflowはtop-level `permissions: {}`とし、exchange jobだけへ`id-token: write`を与える。Repository checkoutが
必要になった場合だけ、同じjobへ`contents: read`を追加する。

AWS認証Actionは`v6.2.3`のcommit
[`e6de054238d6b7531b4efff3b6587d9aade6a06c`](https://github.com/aws-actions/configure-aws-credentials/commit/e6de054238d6b7531b4efff3b6587d9aade6a06c)
へ固定している。更新時はrelease差分をreviewし、新しいfull commit SHAへ明示的に変更する。

Workflowは安全なactivation testとして`aws sts get-caller-identity`までを行う。期待identityを確認してから、
既存のreview済みdeploy stepを後続へ追加する。

## Verification

このcontrolはlive GitHub／AWS設定を必要とする`manual` verificationである。Repository fixtureの存在を
organization adoptionの証拠にしない。

### Positive self-test

1. Copyしたworkflowをdefault branchへreview付きでmergeする。
2. GitHub Actions画面から`Verify exact AWS deployment identity`を選ぶ。
3. `main`を選択して`Run workflow`を実行する。
4. `production` Environmentのreviewを通す。
5. `Confirm the assumed identity`のsanitized出力を確認する。

期待出力の形は次である。Credential valueは出力しない。

```json
{
  "Account": "111122223333",
  "Arn": "arn:aws:sts::111122223333:assumed-role/github-oidc-secure-app-prod/gh-..."
}
```

Workflow runは成功する。CloudTrailの`AssumeRoleWithWebIdentity`でexpected role、GitHub issuer、subject、
`durationSeconds: 900`を確認する。[AWS STS API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)と
[CloudTrail user identity reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)を参照する。

### Harmless negative self-test

Production deploy commandを含まないreview branchでworkflowを一時的にcopyし、`environment`を
`oidc-negative-test`へ変更する。予期せずroleを取得した場合のauthorityを抑えるため、認証Actionへ次を追加する。

```yaml
inline-session-policy: >-
  {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}
```

次を一つずつ試す。

1. Production roleへ、`oidc-negative-test` subjectからexchangeする。
2. `audience`を`urn:psb:negative-test`へ変更してexchangeする。

どちらもAWS STSで拒否され、caller identity stepへ到達しないことが期待結果である。単なるnetwork failure、
YAML error、Environment未作成をtrust policyの拒否と誤認しない。試験後は一時workflowとEnvironmentを削除する。

### Stored credential removal

Positive test成功後、repository、`production` Environment、organizationのsecret-name inventoryで次を確認する。

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- 同じ用途の独自名access key

既知consumerをOIDCへ移行してから長期keyを削除し、positive testを再実行する。
[insecure/aws/stored-credentials-workflow.yml](insecure/aws/stored-credentials-workflow.yml)は、OIDC導入後も旧keyが
残る失敗例であり、`.github/workflows`へcopyしない。

### Decision semantics

| Result | Meaning |
|---|---|
| `PASS` | Current GitHub／AWS設定、positive test、negative test、旧key撤去をすべて確認した |
| `FAIL` | Wildcard、wrong audience／subject受理、過剰role、旧key、または期待外identityを確認した |
| `NOT_CHECKED` | Live設定または試験をまだ確認していない |
| `ERROR` | API失敗、権限不足、不完全inventory、取得失敗により判定できない |

Canonical commandはlive adoptionを推測せず、procedureを示して`NOT_CHECKED`／exit `2`を返す。

```bash
make verify-control CONTROL=PSB-CICD-006
```

## 導入完了の証拠

一つのreview recordで次を結び付ける。

- exact repository、revision、workflow、Environment
- current AWS OIDC providerとIAM role trust policy
- current role permissions policy
- 900秒を要求したpositive exchange
- wrong subjectとwrong audienceのprovider拒否
- CloudTrail eventの取得元、時刻、reviewer
- secret値を含まないcurrent secret-name inventory
- 旧AWS keyの削除と既知consumerの移行結果

Token、temporary credential、secret value、private payloadを保存しない。Fixtureや手書きreceiptはlive evidenceではない。

## よくある失敗と復旧

- **`AccessDenied`**: Workflowが実際に使うsubject、AWS trustのsubject、audience、role ARNを比較する。
  復旧のためにwildcardへ広げない。
- **Wrong account**: `role-to-assume`と`allowed-account-ids`を確認する。Account checkを削除しない。
- **Environmentで停止**: `main`のdeployment branch rule、reviewer、bypass設定を確認する。
- **古いrepository名のsubject**: Immutable subjectのcurrent状態を確認し、AWSを先、GitHubを後の順で移行する。
- **900秒ではdeployが終わらない**: Jobを小さく分ける。最初から長時間sessionへ広げず、必要時間と追加controlをreviewする。
- **証跡取得失敗**: `PASS`にせず`ERROR`とし、read-only権限またはCloudTrail deliveryを復旧する。

## Rollback

1. 新しいdeploy stepを停止し、最後のreview済みworkflow revisionへ戻す。
2. AWS trust policyを直前のexact revisionへ戻す。Organization wildcardは使わない。
3. OIDC providerは他roleの利用有無を確認してから削除する。
4. 長期access keyの恒久復活を既定rollbackにしない。緊急時は
   [PSB-GOV-002](../../governance-operations/time-bound-security-exceptions/README.md)の
   narrow、owned、time-boundな例外を使う。
5. Rollback後もGitHubとAWSのcurrent stateを再確認する。

## 自動検証できないこと

- Repository内のsampleからlive AWS trust／role／CloudTrailを証明できない。
- Workflow fileだけではGitHub Environment protectionやsecret inventoryを証明できない。
- `aws sts get-caller-identity`はprincipalを確認するが、deployment permissionsのsemantic minimumを証明しない。
- AWS STSはこのprofileで`jti` single-use ledgerを証明しない。盗まれた短期credentialのsession内replayは残余リスクである。
- IAM Access Analyzerの警告なしは、product固有の必要最小権限を保証しない。

README文字列test、自己申告JSON、synthetic JWT、常に成功するscriptは追加しない。

## IaCで管理する場合

Terraformを既に利用する組織は、このJSONを手作業で二重管理せず、既存moduleへexact conditionを移植できる。
初期sliceでは新しいTerraform module、provider dependency、OPA rule、Terraform専用testを追加しない。

概念例:

```hcl
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

# aws_iam_role.assume_role_policyでもaudとsubをStringEqualsで完全一致させる。
```

- [Terraform AWS OIDC provider resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_openid_connect_provider)
- [Terraform AWS IAM role resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)
- [Terraform AWS IAM role policy resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy)

`terraform validate`はsyntax確認であり、apply済みlive stateやnegative exchangeの証拠ではない。

## 既存controlとの分担

- [PSB-CICD-001: Action SHA pinning](../action-sha-pinning/README.md): AWS認証Actionのimmutable reference。
- [PSB-CICD-003: Actions static analysis](../actions-static-analysis/README.md): Workflow全体のscannerとerror semantics。
- [PSB-CICD-004: Actions least privilege](../actions-least-privilege/README.md): `GITHUB_TOKEN`と`id-token: write`のjob分離。
- [PSB-CICD-005: Untrusted PR boundary](../untrusted-pr-boundary/README.md): Untrusted codeとprivileged deployの分離。
- [PSB-CICD-007: Runner hardening](../runner-hardening/README.md): Runner image、network、credential exposure、teardown。
- [PSB-CICD-008: Privileged control-plane change](../privileged-control-plane-change/README.md): IAM trust変更のidentity、approval、audit。
- [PSB-BUILD-001: Build containment](../../build-security/build-containment/README.md): Approved job内のsandboxとegress。
- [PSB-SOURCE-004: Source credential lifecycle](../../source-protection/source-access-credential-lifecycle/README.md): Source-platform credential。
- [PSB-GOV-002: Time-bound exceptions](../../governance-operations/time-bound-security-exceptions/README.md): 例外のscope、owner、approval、expiry。

本controlはAWS cloud roleのexact federation、短期session、長期AWS key撤去を所有する。上記controlのscanner、
runner、PR policy、変更承認を複製しない。

## 関連フレームワーク

Mappingはrepository sampleとmanual verification procedureの関係を示す。Live採用やformal complianceを示さない。

| Framework／registry | ID | Relationship | このcontrolで扱う境界 |
|---|---|---|---|
| [GitHub Security Guidance](https://docs.github.com/en/actions/concepts/security/openid-connect) | `GHAS-CONCEPT-OIDC` | `verifies` | OIDC短期credentialと長期secret撤去 |
| [GitHub OIDC Reference](https://docs.github.com/en/actions/reference/security/oidc) | `GHAS-REF-OIDC` | `verifies` | Issuer、audience、subject、job context |
| [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19#osps-ac-0402) | `OSPS-AC-04.02` | `supports` | CI/CD credentialのleast privilege |
| [MITRE ATT&CK v19.1](https://attack.mitre.org/techniques/T1552/001/) | `T1552.001` | `mitigates` | Repository内の長期credential撤去 |

SLSA Build Level、OWASP ASVSのapplication OIDC requirements、NIST SSDFへは、このAWS deployment
federationだけで直接のrequirement evidenceを示せないためmappingしない。

## 関連ガイド

- [GitHub OpenID Connect concept](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [GitHub OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub Actions OIDC REST API](https://docs.github.com/en/rest/actions/oidc)
- [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [AWS: Configure a role for GitHub OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
- [AWS STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [AWS IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)
- [AWS CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [AWS configure-aws-credentials Action](https://github.com/aws-actions/configure-aws-credentials)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-18.html)

## Limitations and operational cost

- AWS標準partitionだけをreferenceにする。AWS China／GovCloudはaudienceとARNを別profileで確認する。
- GitHub Enterprise Serverでは同じimmutable subjectを利用できない場合がある。
- GitHub Environmentのreviewerやbypass機能はrepository visibilityとplanに依存する。
- `role-duration-seconds: 900`はAWS STSの最小requestである。Provider側のrole maximum sessionとは別に確認する。
- Approved job内の悪意あるstepは短期credentialを盗み得る。Job分離、egress制限、runner monitoringが必要である。
- AWS Actionの更新にはupstream差分、full SHA、Node runtime、input behaviorの再reviewが必要である。
- Manual verificationにはGitHub administrator、AWS IAM administrator、CloudTrail閲覧者の協力が必要である。
