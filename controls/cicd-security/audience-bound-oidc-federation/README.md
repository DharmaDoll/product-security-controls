# PSB-CICD-006: GitHub ActionsのAWS OIDC federationをexact trustへ限定する

## このcontrolを一枚で理解する

### セキュリティ上の問題

OIDCは、GitHub Actionsのjobが「自分はどのrepositoryの、どの実行contextか」を示す署名付きtokenを受け取り、
AWSがそれを一時credentialへ交換する仕組みである。長期AWS access keyをGitHubへ保存せずに済むが、
OIDCを有効にしただけでproductionへの経路が安全になるわけではない。

具体的な被害が成立するには、概ね次の三条件が揃う必要がある。

1. 攻撃者が、OIDC tokenを要求できるGitHub Actions jobを起動できるか、そのjobが実行するcodeやdependencyを
   変更・侵害できる。
2. AWS IAM roleのtrust policyが、そのjobの`aud`（tokenの利用先）と`sub`（どのworkloadかを示す識別子）を
   受理する。Organizationやrepository全体を許すwildcardがあると、意図していないjobまで一致し得る。
3. 交換後のAWS roleが、攻撃者にとって意味のあるactionとresourceを許し、短いsessionが失効する前に
   AWS APIを実行できる。

したがって、organization wildcardがあるだけで、internet上の任意の攻撃者が直ちにAWS accountを奪えるとは限らない。
例えば`repo:example-org/*`を悪用するには、攻撃者がそのorganization内の一致するrepositoryでOIDC許可jobを
動かせる必要がある。一方、その条件を満たす侵害repositoryや過剰権限jobが一つでもあれば、tokenはGitHubが
正規に発行したものなので、AWSは署名が正しいという理由だけでは攻撃を見分けられない。

被害範囲は、引き受けたroleの権限で決まる。このreferenceのように一つのS3 prefixへの`PutObject`だけなら、
その場所をreleaseやdeploymentが信用している場合に限り、artifactの差し替えや配布停止へつながり得る。
ECR、Lambda、ECS等の更新権限があれば実行codeを変更でき、IAM管理権限まであれば権限拡大へ進む可能性がある。
逆に、roleに対象dataの読取りも変更もできる権限がない、または書込み先を後続systemが利用しないなら、
roleを取得した事実だけからproduction被害を断定できない。

OIDC導入後も有効な長期AWS access keyが残る場合は、別の攻撃経路が残る。そのkeyを攻撃者が読めるjobや
accountがあり、keyに有効なAWS権限があると、exactなOIDC条件や900秒の有効期間を通らずに操作できる。
Secret名が存在するだけでは漏えいの証明にならないが、移行対象の有効なkeyは撤去する必要がある。

### 誰から、または何から守るか

AWS trustの範囲内にある別repositoryや未承認branch／Environmentでworkflowを動かせる攻撃者、正規deploy jobの
Actionやdependencyを侵害した攻撃者、利便性のためtrustやroleを広げる設定ミス、OIDC移行後も残った長期credential、
live設定を確認せずsample fileだけで安全と判断する運用から守る。

単に外部forkを作れるだけで、そのforkのtokenがexact repository／Environment subjectに一致せず、base repositoryの
OIDC許可jobでも攻撃者のcodeが動かない場合、このcontrolが扱うrole取得経路は成立しない。また、正規deploy jobを
侵害された場合はexact subjectにも一致するため、trust条件では防げず、roleの最小権限と短いsessionだけが被害を限定する。

### 何が対象か

GitHub Actionsのdeploy jobからAWS resourceへ届く認証・認可の経路全体を対象とする。具体的には、jobの
`id-token: write`、GitHub OIDC issuerとimmutable subject、GitHub Environmentのbranch protection、AWS IAM OIDC
provider、IAM roleのtrust policyとpermissions policy、AWS STS session、repository／Environment／organizationに
残る長期AWS credentialである。

### 何をするか

OIDC tokenを要求できるjob、AWSが受理するworkload、交換後に操作できるAWS resourceを、それぞれ独立して狭める。
AWS側ではissuer、`sts.amazonaws.com` audience、immutable repository IDと`production` Environmentを含むsubjectを
完全一致させる。Environment subject自体にはbranchが入らないため、GitHub Environment側で`main`だけを許可する。
専用roleのaction／resourceをdeploymentに必要な範囲へ限定し、STS sessionを最小の900秒で要求し、同じ用途の
長期AWS keyを既知consumerの移行後に削除する。

### 成功状態

`main`からprotected `production` Environmentを通るreview済みjobだけが、期待するAWS accountの専用roleを
900秒で引き受ける。別Environmentのsubjectと別audienceを使う無害な試験は、networkやYAMLの失敗ではなくAWS STSの
trust判定で拒否される。Role policyは列挙したdeployment operation以外を許さず、同じ用途の長期AWS access keyが
GitHubに残っていない。これらがsampleの見た目ではなく、current設定、actual run、CloudTrailで確認されている。

### 対象外・残余リスク

許可されたdeploy job自体が侵害されると、そのjobは正しいsubjectを持つため、900秒以内のcredentialは取得・窃取され得る。
このcontrolはsessionを一回限りにはせず、deployment内容やS3 objectの完全性も検証しない。Runner／egress保護、
untrusted PR分離、artifact provenance、provider設定変更の承認、AWS以外のproviderは別controlまたは導入先で確認する。
また、role policyが本当に業務上の必要最小権限かは、AWSのsyntax checkだけでは決まらず、deployment設計との人手reviewが残る。
900秒はsample Actionが要求して取得したsessionの長さであり、同じtokenで行われる全STS requestへの強制上限ではない。
OIDC tokenを要求できるjob全体を攻撃者が制御した場合、AWS roleのmaximum session durationまでの別sessionを直接要求し得る。

## まず、このcontrolの本質を理解する

AWSへのOIDC federationでは、GitHubのtokenとAWSの一時credentialは同じものではない。GitHub tokenはjobのidentityを
AWSへ伝える材料であり、AWS IAM roleのtrust policyが「そのidentityへroleを貸すか」を決める。貸した後に何ができるかは、
roleのpermissions policyが決める。

実害へ至る基本経路は次のとおりである。

```text
攻撃者が変更・起動できるjob
        ↓  id-token: writeがあり、OIDC tokenを要求できる
GitHubが正規tokenを発行
        ↓  AWS trustがaudienceとsubjectを受理する
AWS STSが一時credentialを発行
        ↓  roleが価値あるaction／resourceを許す
AWS resourceの読取り・変更・deployment
```

このうち一つでも成立しなければ、この経路によるAWS被害はそこで止まる。Exact trustは二番目の境界を狭めるcontrolであり、
未信頼codeの実行防止やrole権限の設計を代替しない。本controlは、token発行jobの限定、exact trust、最小role、短いsession、
旧key撤去を一つの導入単位として扱い、一つの対策だけを安全性の根拠にしない。

## 何が、どの条件で被害になるか

| 対象 | 被害が成立する主な条件 | 起こり得ること | 経路が成立しない、または限定される例 |
|---|---|---|---|
| OIDC token発行 | 攻撃者が変更・起動できるjobに`id-token: write`がある | AWSへ提示できる正規GitHub tokenを取得する | 未信頼jobにOIDC permissionがなく、protected jobは攻撃者のcodeを実行しない |
| AWS role trust | Tokenのissuerが登録済みで、`aud`と`sub`がbroadな条件に一致する | 意図しないrepository／Environmentからproduction roleを引き受ける | `StringEquals`のexact audience／immutable subjectが不一致tokenを拒否する |
| GitHub Environment | Environment subjectを使うが、deployment branch restrictionやreviewがない | 同じrepositoryの未承認branchから一致subjectを取得する | `production`が`main`だけを許可し、job開始前に必要なprotectionを通す |
| AWS role permissions | Roleが対象resourceの変更、機密dataの読取り、deployment、IAM操作等を許す | Artifact差替え、service変更、data取得、権限拡大。Exact impactはpolicy次第 | 一つのrelease prefix等へ限定され、無関係なAWS API／resourceが拒否される |
| 発行済み900秒sessionの窃取 | Approved job内の悪意あるstepがActionの取得した一時credentialを失効前に外部送信・利用する | Roleの許可範囲をjob外からsessionの残り時間だけ利用する | Egress／runner isolationが持出しを妨げ、900秒requestがそのcredentialの再利用時間を限定する |
| 残存する長期key | 有効なkeyがjobやaccountから読め、key policyが価値ある操作を許す | OIDC trustと短期TTLを迂回し、失効まで繰り返し利用する | 既知consumer移行後にkeyを無効化・削除し、secret storeから撤去する |

設定名やtokenが存在するだけでfindingとはしない。実際のjobからtoken、trust、role、resourceまでを順にたどり、
攻撃者が制御できる入力とAWSで得る実効権限がつながるかを確認する。

### 反証してから判断する

最初に見つけた設定だけで結論を出さず、少なくとも次の仮説を反証する。

- **仮説: organization wildcardがあれば侵害済みである。** 一致するorganization内で攻撃者がjobを動かせるか、
  そのjobに`id-token: write`があるか、roleに価値ある権限があるかを確認する。いずれかがなければ、設定は広すぎても
  記載した被害経路が既に使われたとは言えない。
- **仮説: exact subjectならproduction jobは安全である。** Approved job内のActionやdependencyが侵害されれば、
  正しいsubjectでroleを取得できる。Role policy、session時間、runner、egressを別々に確認する。
- **仮説: negative runが失敗したのでAWS trustが拒否した。** Environmentのbranch rule、approval待ち、YAML error、
  network障害でもrunは失敗する。AWS STSの拒否応答とCloudTrailを確認するまでtrust testの成功にしない。
- **仮説: OIDC workflowが動いたので長期keyはなくなった。** Repository以外のEnvironment／organization secret、
  独自名のkey、別consumer、AWS側でまだactiveなaccess keyを確認する。

## セキュリティ向上の効果はどこから生まれるか

このcontrolの効果は、採用先で次のlive状態を作ることから生まれる。

- AWS IAM roleがGitHub issuer、用途固有audience、exact subjectを検証し、別repository／Environmentの正規tokenを拒否する。
- GitHub Environmentが`main`以外からproduction jobを開始させず、Environment subjectに含まれないbranch条件を補う。
- OIDC permissionをproduction jobだけへ置き、無関係なtest／build codeがcandidate tokenを要求できないようにする。
- Exchange後のroleが一つのdeployment用途とresourceだけを許可し、認証に成功しても被害範囲をそのresourceへ限定する。
- Sample ActionがSTS sessionを900秒で要求し、そのActionが取得したcredentialの利用時間を短くする。ただしsingle-useや、
  同じOIDC tokenを使った別STS requestの900秒上限にはならない。
- GitHubから同じ用途の長期AWS access keyを撤去し、exact trustを通らない迂回経路を閉じる。
- 実際のAWS STSで、許可contextの成功と拒否contextの`AccessDenied`を確認する。

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

この最短手順が有効化する対象は、`main`から`production` Environmentを通る一つのdirect workflowと、
一つのAWS accountにある専用IAM roleである。最初はdeployment commandを入れず、`sts get-caller-identity`だけを行う。
変更する実設定は、AWS OIDC provider、role trust、role permissions、GitHub Environment、repository-local workflow、
旧AWS keyである。

完了時に観測する状態は、trusted runだけが期待account／roleを返し、別Environmentと別audienceのrunはAWS STSで
拒否され、roleが宣言したexact deployment resource（sampleでは一つのS3 prefix）以外を許さず、旧keyがsecret
inventoryと既知consumerから消えていることである。
この状態を確認する前に実deployment stepを追加しない。

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

AWSがGitHub tokenの署名を検証しても、それは「GitHubが発行したtoken」という確認にすぎない。`aud`はこのtokenを
AWS STS用として要求したこと、`sub`はこのrepository／Environmentのjobであることをrole引受け条件へ結び付ける。
Exact conditionは別workloadのtokenを拒否するが、許可済みproduction job内の悪意あるstepは拒否しない。

### 3. Roleのactionとresourceを限定する

[secure/aws/role-permissions-policy.json](secure/aws/role-permissions-policy.json)は、一つのS3 release prefixへ
`s3:PutObject`だけを許可する例である。実deploymentが使うactionとresourceへ置換し、`Action: "*"`、
`Resource: "*"`、IAM管理権限、不要なrole chainingを追加しない。

このsample権限で想定する価値は、release objectの書込みである。後続の配布・deploymentがそのprefixを信用する場合、
不正な書込みはartifact差替えにつながり得る。一方、sampleはobjectの読取り、削除、別bucket、compute、IAMを許可しない。
実装先でも「API名が少ない」だけでなく、各resourceを誰が何に使うかまで確認する。

[IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)で
grammarとAWSのsecurity warningを確認する。その結果だけではsemantic least privilegeを証明しないため、
development teamが列挙したoperationとpolicyを一対一でreviewする。

### 4. GitHub Environmentを保護する

`Repository Settings → Environments → production`で次を設定する。

[GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)にあるとおり、OIDC subjectはjobが
Environmentを参照するとEnvironment名を含む形式になり、branch名は同じsubjectへ同時には入らない。このためAWSで
`production` subjectをexact matchするだけでは、どのbranchがそのEnvironmentを使えるか決まらない。`main`制限は
この手順の必須境界である。

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

ここでいう「有効化」は、置換値とAWS側設定をreviewしたworkflowをdefault branchへmergeし、GitHub Actions画面から
手動実行できる状態にすることである。Fileを作業branchへ置いただけ、またはsample値のまま置いただけでは有効化されない。

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

この成功で確認できるのは、expected workflowからのtokenをAWSが受理し、Actionが要求した900秒sessionでexpected
account／roleを取得したことまでである。別contextが拒否されること、role権限が必要最小であること、長期keyがないことは
このrunだけでは分からないため、後続のnegative testと設定reviewを省略しない。

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

WorkflowがGitHub Environmentのbranch ruleやapprovalで停止し、AWS STSへrequestを送っていない場合は、AWS trustの
negative testとしては`NOT_CHECKED`である。対象runの時刻とroleをCloudTrailで照合し、`AssumeRoleWithWebIdentity`が
wrong subject／audienceにより拒否されたことを確認する。

### Stored credential removal

Positive test成功後、repository、`production` Environment、organizationのsecret-name inventoryで次を確認する。

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- 同じ用途の独自名access key

既知consumerをOIDCへ移行してから長期keyを削除し、positive testを再実行する。
[insecure/aws/stored-credentials-workflow.yml](insecure/aws/stored-credentials-workflow.yml)は、OIDC導入後も旧keyが
残る失敗例であり、`.github/workflows`へcopyしない。

Secret-name inventoryはcredential値を収集せず、GitHub上に候補が残っているかを調べるためのものである。候補があれば、
使用workflow、所有IAM principal、AWS側のactive／inactive状態、最終利用を確認してから削除する。逆にGitHubのinventoryが
空でも、外部secret managerや別CIに同じdeployment keyが残っていないことまでは証明しない。

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
- `role-duration-seconds: 900`は[AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)の
  最小requestであり、Actionが取得するsessionだけを900秒にする。AWS roleのmaximum session durationは最短でも1時間で、
  [`sts:DurationSeconds`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-sts)は
  STS assume-role operationに適用されない。許可jobを制御した攻撃者による別requestを900秒へ強制する境界ではない。
- Approved job内の悪意あるstepは短期credentialを盗み得る。Job分離、egress制限、runner monitoringが必要である。
- AWS Actionの更新にはupstream差分、full SHA、Node runtime、input behaviorの再reviewが必要である。
- Manual verificationにはGitHub administrator、AWS IAM administrator、CloudTrail閲覧者の協力が必要である。
