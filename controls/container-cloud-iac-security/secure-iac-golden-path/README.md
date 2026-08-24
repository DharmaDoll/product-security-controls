# PSB-IAC-001: Secure IaC golden path

## このcontrolを一枚で理解する

### セキュリティ上の問題

開発者が標準moduleやCI gateを迂回すると、暗号化なし、public exposure、過剰IAMなどのinfrastructureがdeployされ、後からの手動reviewだけでは防げない。

### 誰から、または何から守るか

悪意または誤設定のあるdeveloper、module差替え、policy bypass、CI障害、console変更によるdrift、過剰な自動修復から守る。

### 何が対象か

IaC source、versioned module registry、Terraform plan、Policy as Code engine、reusable CI、cloud identity、provider-side enforcement、deployed resource。

### 何をするか

Secure-by-default moduleをversion・digest固定で提供し、resolved planをfail-closed policy gateへ通し、provider hook・drift検知・bounded correctionを組み合わせる。

### 成功状態

Approved moduleとexact planが全policyを通過し、CI bypassもprovider側で拒否され、driftとevaluator errorがclean deploymentとして扱われない。

### 対象外・残余リスク

FixtureはTerraformやcloud APIを実行せず、module実装やpolicy自体の欠陥、provider compromise、すべてのmanual changeを単独では検出しない。

## Security problem

開発者へ長いsecurity手順を渡すだけでは、暗号化、private network、image、
IAM、tag、region、scanner、deployment identityの設定がrepositoryごとに
copyされ、時間とともにdriftします。このcontrolはplatform teamが
**secure-by-default module（正解の型）**を配布し、resolved planへの
**Policy as Code decision gate（型チェック）**とprovider側の強制を組み合わせ、
開発者が少ない設定で安全な状態を維持できるgolden pathを定義します。

対象はTerraform等のIaC module、plan、reusable CI workflow、cloud
provisioning boundary、deploy後のruntime stateです。application security、
build provenance、SBOM、artifact signingをこのcontrolへ複製せず、既存または
計画済みcontrolをgolden pathからcompositionします。

## Threat and failure scenario

- 開発者がsecure moduleを迂回し、暗号化なし、public IP、internet SSH、
  wildcard IAM、mutable imageを直接定義する。
- source text scannerは通るが、module展開後のresolved planに危険なresourceが
  現れる。
- PaC scannerが起動できない、unknown valueを評価できない、またはwarningだけを
  出す状態がcleanとして扱われる。
- console、API、別IaC toolがCI gateを迂回する。
- deploy後のmanual changeでgolden pathからdriftし、危険な設定が残る。
- corrective automationが安全確認なしにresourceを削除し、可用性や証跡を損なう。

## Runnable examples

- `secure/golden-path-policy.json`はversionとdigestを固定したmodule contract、
  resolved plan gate、CI composition、deploy-only OIDC、provider enforcement、
  drift検知、限定されたcorrective actionを宣言します。
- `secure/tfplan.json`はAWS、GCP、Azureのprovider profileを同じ
  secure-compute contractから生成した、sanitized Terraform plan JSON fixture
  です。
- `insecure/`はmutable module、暗号化なし、public IP、internet SSH、
  wildcard IAM、fail-open scanner、static cloud key、CI-only enforcement、
  destructive auto-remediationを意図的に含みます。

fixtureのhostname、digest、region、resourceは非productionの例です。
Terraform binary planや`terraform show -json`の出力にはsensitive valueが
含まれ得るため、実planをGitへcommitしてはいけません。

## Secure-by-default module contract

platform teamは、provider固有の実装を一つのreview済みinterfaceへ
カプセル化します。

| Provider profile | 暗号化 | Public access | 管理経路 | Image |
|---|---|---|---|---|
| AWS | customer-managed KMS | public IPなし、private subnet | Session Manager等の承認済み経路 | 承認済みdigest |
| GCP | Cloud KMS CMEK | external IPなし、private network | IAP + OS Login等 | 承認済みdigest |
| Azure | Key Vault CMK | public IPなし、private network | Entra ID + Bastion等 | 承認済みdigest |

これは各cloudの完全なhardening moduleではなく、共通contractの実行可能な
最小例です。実moduleではlogging、backup、metadata service、firewall、
service identity、availability、data residency等もthreat modelに応じて追加し、
provider testを個別に持たせます。CIS Hardened Imageを採用する場合も、
marketplace名や「CIS準拠」という自己申告ではなく、承認済みimage identity、
version、digest、更新責任を固定します。

moduleはprivate registry等からversioned artifactとして配布します。
Git URLを利用する場合はbranchやtagではなくimmutable commitへ固定し、
integrityとreview evidenceを保持します。

## PaC decision flow

```text
approved module + application inputs
                 |
                 v
         saved Terraform plan
                 |
       terraform show -json
                 |
                 v
      PaC deny decision on plan
         | pass          | finding / unknown / error
         v               v
   protected deploy    BLOCK / ERROR
         |
         v
 provider-side create/update enforcement
         |
         v
 scheduled drift comparison and bounded remediation
```

OPA/Rego、Conftest、Checkov、Sentinel、CloudFormation Guard/Hooks等は実装候補
です。このreference verifierは外部downloadを必要とせず、同じdecision contractを
Python標準libraryで検証します。productionで別engineへ移植しても、finding、
unknown、tool errorを区別し、block decisionを失わないことが要件です。

## CI golden-path composition

reusable workflowは次のcontrolを組み合わせます。表の状態を保つことで、
未実装機能を「templateに名前があるだけ」で達成済みにしません。

| Capability | Control | Status in this repository |
|---|---|---|
| Immutable Actions/reusable workflows | `PSB-CICD-001` | implemented |
| Workflow static analysis | `PSB-CICD-003` | implemented |
| Credential and privilege containment | `PSB-BUILD-001` | implemented |
| Platform-authenticated provenance generation | `PSB-BUILD-003` | implemented |
| Local secret prevention | `PSB-SOURCE-002` | implemented |
| Resolved IaC plan policy gate | `PSB-IAC-001` | implemented here |
| Pinned Trivy/SCA/IaC scan profile | `PSB-DETECT-001` | implemented |
| Dockerfile／Compose remediation feedback | `PSB-DETECT-001` DockSec profile | implemented as optional non-blocking feedback |
| Provenance distribution | `PSB-REL-002` | implemented |
| Exact artifact signing generation | `PSB-REL-005` | implemented as provider-neutral offline E3 contract |
| OCI provenance and workload admission | `PSB-CONTAINER-001` | implemented |
| Cloud OIDC federation profile | `PSB-CICD-006` | implemented as signed exact-claim offline E3 contract |
| Source／Build／Deployment SBOM identity plus artifact-bound Build SBOM publication | `PSB-REL-003` | implemented |
| SBOM portfolio and continuous analysis | `PSB-REL-003` Dependency-Track adapter | implemented as normalized fail-closed composition |

Artifact signing generationは`PSB-REL-005`が所有します。Golden Pathはexact artifact
digest、短寿命authorization、non-exportable sign-only signer、署名／publication receipt、
fail-closed gateの独立証跡を要求し、このcontrol内へ署名処理を複製しません。Repositoryの
状態はoffline E3 contractであり、live KMS／HSM／keyless、OIDC、transparency、release
storage adoptionを達成済みとは扱いません。`PSB-REL-001`は引き続きconsumer側の署名・
provenance検証を所有します。

DockSecはGolden Pathの独立したcontrolではなく、`PSB-DETECT-001`のoptional
adapterです。release gateは固定・ロック済みCLI環境で
`--scan-only --offline --fail-on high --json --no-cache`を実行し、status `2`
または`3`を`ERROR`としてblockします。AI説明は別の非blocking feedbackであり、
scoreや提案だけでdeployを許可しません。review済みupstream Actionは内部でmutable
downloadと`curl | sh`を使用するため、full commit SHAへ固定しても採用しません。

SBOM jobは`PSB-REL-003`をそのままcompositionします。Release artifactの実byte列と
CycloneDX root component、release manifestをSHA-256で結び付け、direct／transitive
component、relationship、complete compositionを検証してから公開します。その後、
事前作成したDependency-Track project UUIDとexact release versionへ
`BOM_UPLOAD`だけを持つidentityで登録し、API受付ではなく`BOM_PROCESSED`まで確認
します。`BOM_PROCESSING_FAILED`、`BOM_VALIDATION_FAILED`、timeout、stale analyzer
dataはすべて`ERROR`です。Golden Pathはこのcontrolを再実装せず、独立した
`make verify-control CONTROL=PSB-REL-003`の証跡を要求します。
Source observationはPR feedback、Build observationはrelease authority、
Deployment observationはartifact配置のoperational evidenceとして別serialで保持し、
Golden Pathが1つのSBOMへ上書きしないことも同controlへ委譲します。

OIDCの`id-token: write`はworkflow全体へ付与せず、protected deploy jobだけへ
明示的に付与します。`PSB-CICD-006`をcompositionし、cloud側trust policyで
immutable repository identity、ref、environment、audience、full-SHA reusable
workflow、JTIを限定します。provider別live federationとaudit evidenceは導入先で
追加し、権限を付けただけでcloud accessを安全と判断しません。

## Provider enforcement and drift

CIを通らないconsole/API/別toolの変更経路には、cloud provider側のpolicy、
admission hook、organization policy等を適用します。CloudFormation Hooksの
ように特定のprovisioning pathだけを対象とする機能は、対象外APIを別controlで
閉じなければ`all-provisioning-paths`の証跡になりません。

deploy後は24時間以内を例とする定期比較で、approved IaC revisionとruntime stateを
照合します。自動修復は「public IPを外す」「必須tagを戻す」等、review済みで
可逆かつ影響が限定されたactionだけをallowlist化します。resource削除、network
遮断、key変更等は、人の承認、impact確認、証跡保全を経て実施します。

## Verification

```bash
make verify-control CONTROL=PSB-IAC-001
```

secure fixtureは12のcheckを通過します。insecure fixtureは12行すべてで拒否され、
malformed inputはexit `2`の`ERROR`となります。外部PaC engineの実行失敗、
plan未取得、unknown valueをcleanとして扱ってはいけません。

## Source notes

この構成は、ユーザー提供のgolden-path guidanceと次の公式資料を基に
境界と注意点を整理しています。

- [ユーザー提供原文](docs/user-supplied-golden-path-guideline-ja.md)
- [Terraform `show -json`](https://developer.hashicorp.com/terraform/cli/commands/show):
  saved planをmachine-readable JSONへ変換できる一方、sensitive valueが平文で
  出力され得る。
- [OPA Terraform integration](https://www.openpolicyagent.org/docs/terraform):
  plan JSONをpolicy decisionへ渡す方法と、plan時点のunknown value等の限界。
- [Terraform private registry](https://developer.hashicorp.com/terraform/registry/private):
  reusable moduleのversioned distribution。
- [GitHub reusable workflow with OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows):
  reusable deployment workflowとcloud trust conditionの連携。
- [AWS CloudFormation Hooks](https://docs.aws.amazon.com/cloudformation-cli/latest/hooks-userguide/creating-and-managing-hooks.html):
  create/update等の前にresourceを評価し、failure modeでblockできる。
- [GCP Compute Engine disk encryption](https://docs.cloud.google.com/compute/docs/disks/disk-encryption):
  default encryptionとCloud KMS CMEKの選択肢。
- [Azure managed disk CMK](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-customer-managed-keys-portal):
  Key Vaultとdisk encryption setによるcustomer-managed key。

## Limitations and operational cost

- fixtureはTerraformやcloud providerを実行せず、production moduleやpolicyの
  実効性を証明しません。
- Terraform plan policyではunknown value、dynamic behavior、provider側で
  決まる値を完全に評価できない場合があります。
- plan JSONはsecretを含み得るため、artifact retention、access、encryption、
  redactionを設計する必要があります。
- multi-cloud共通interfaceは最低共通要件へ弱くなりやすく、provider固有controlを
  失ってはいけません。
- provider hookは全変更経路を必ずしも覆いません。
- drift scanner自体の停止や権限不足はcleanではなくERRORです。
- golden pathは例外をゼロにせず、例外を狭く、owned、justified、expiringにします。
- DockSec profileは開発者の修正体験を改善しますが、organization-built lock済み
  environment、Trivy／Hadolint integrity、DB freshnessのproduction証跡は外部です。
- Dependency-Track compositionは4.14.3 normalized fixture contractであり、live API、
  project ACL、notification delivery、analyzer freshness、5系migrationの証跡は外部です。
