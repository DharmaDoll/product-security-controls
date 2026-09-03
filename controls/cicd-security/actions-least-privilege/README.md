# PSB-CICD-004: GitHub Actionsのtoken権限をjob目的へ限定する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Workflowやjobが暗黙のdefaultまたは広いpermissionを使うと、侵害されたstepがsource、package、deployment、
attestation、OIDC tokenへjob目的を超えてアクセスできる。

### 誰から、または何から守るか

悪意あるcontributor、侵害されたAction／dependency、過剰な権限を付けるmaintainer、暗黙のdefaultを継承する
reusable workflow callerから守る。

### 何が対象か

GitHub Actions workflow、各jobの`GITHUB_TOKEN`、`id-token`発行権限、write-capable jobを起動できるref、
GitHub Environment。

### 何をするか

Workflow全体を原則無権限（deny-all）にし、各jobへ必要なpermissionだけを付ける。リポジトリを書き換えるjobや
クラウド認証を行うjobは、レビュー済みの`main`やrelease tagなど、決めたrefからだけ起動できるようにする。
release／deploy jobは承認者が必要なGitHub Environmentへ結び付け、承認されるまで処理を進めない。

ここでいう「trusted ref」は、branch protectionやrulesetで変更を制限したbranch、または発行手順を決めたtagを指す。
「protected Environment」はrequired reviewerやdeployment branch／tag ruleを設定したGitHub Environmentを指す。
どちらもworkflow fileを置くだけでは有効にならず、GitHub側の設定が必要である。

### 成功状態

全jobのpermissionと必要理由をreviewでき、暗黙権限や`write-all`がなく、privileged jobは意図したrefと
Environmentでだけ実行され、live GitHub settingも確認されている。

### 対象外・残余リスク

このcontrolはActionの安全性、shell injection、fork trust、cloud側OIDC trust、PAT／GitHub App token、runner host、
GitHub control planeの完全性を証明しない。

## 最短の導入手順

このcontrolはconfiguration-firstである。Security効果は、このdirectoryをcopyしたことではなく、採用先の
workflowとGitHub settingを実際に変更したときに生まれる。

### 前提とtrust assumption

- GitHub Actionsを利用している。
- Development teamが各jobの処理を説明できる。
- Repository administratorがActions setting、ruleset、Environmentを変更できる。
- Organization policyがrepository側のrestricted settingを緩めていないことを確認できる。
- Static analysisを導入する場合は、[`PSB-CICD-003`](../actions-static-analysis/README.md)のreview済みscannerを使う。

### Copyまたは参照するfile

- [`secure/workflow.yml`](secure/workflow.yml): job目的別permissionの例
- [`insecure/workflow.yml`](insecure/workflow.yml): copy／deploy禁止の比較用fixture

既存workflowを上書きせず、`secure/workflow.yml`のpatternをreviewしてmergeする。
`make test`は採用先の通常のtest commandへ置き換える。

### Activation

1. GitHub repositoryの`Settings` → `Actions` → `General` → `Workflow permissions`でrestricted optionを選ぶ。
2. `Allow GitHub Actions to create and approve pull requests`は、明確な必要性がなければ無効にする。
3. 全workflowのtop-levelへ`permissions: {}`を置く。
4. 全jobへ実際に必要なscopeだけを置く。API accessが不要ならjob-levelも`permissions: {}`にする。
5. Writeまたは`id-token: write`を持つjobをreview済みref conditionへ限定する。
6. Release／deploy jobをGitHub Environmentへ結び、required reviewer、deployment branch／tag、self-review、
   administrator bypassを組織方針に従って設定する。
7. [`PSB-CICD-003`](../actions-static-analysis/README.md)のscanner jobをrequired checkにする。

GitHubではworkflowまたはjobへ一つでもpermissionを指定すると、未指定scopeは`none`になる。`permissions: {}`は
全scopeを無効化する。現在のscopeと計算順序は
[GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
で確認する。

## まず理解するべきpermission model

```text
Enterprise／Organization／Repository default
                    ↓
          Workflow-level permissions
                    ↓
             Job-level permissions
                    ↓
        fork eventに対する追加の制限
```

Workflow top-levelのdeny-allは、repository defaultが将来変わってもjobへ暗黙のauthorityを渡さないために置く。
Job-level permissionは、そのjob内の全Actionとshell stepが共有する。同じtoken境界を共有させたくない処理はjobを分ける。

### 最小例

```yaml
permissions: {}

jobs:
  test:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: make test
```

外部Actionのcommit pinningは[`PSB-CICD-001`](../action-sha-pinning/README.md)の責務である。

## Job目的別の考え方

次は許可listではなく、reviewを始めるための最小例である。記載されたscopeでもjobが使わなければ削除する。

| Job目的 | Permission例 | Review point |
|---|---|---|
| Repository APIを使わないlint／test | `{}` | CheckoutもAPI accessも不要か |
| Sourceをcheckoutするtest | `contents: read` | Write scopeやOIDCが混ざっていないか |
| SARIF report | `contents: read`, `security-events: write` | Untrusted gateとprivileged uploadを別jobにしたか |
| GitHub Release作成 | `contents: write` | Package、deployment、OIDC権限を混ぜていないか |
| OIDC federation | `contents: read`, `id-token: write` | Token exchangeを行うexact jobだけか |
| Deployment記録 | `contents: read`, `deployments: write` | Protected Environmentとtrusted refがあるか |

`write`は多くのscopeで`read`を含む。`id-token: write`はrepository writeではないがOIDC token発行を可能にするため、
独立したprivilegeとしてreviewする。

### Privileged jobの最小pattern

GitHub Releaseを作成するjobは、package publishやOIDCを同じjobへ混ぜない。

```yaml
release:
  if: github.ref == 'refs/tags/v1.0.0'
  environment: release
  permissions:
    contents: write
  steps:
    - env:
        GH_TOKEN: ${{ github.token }}
      run: gh release create "$GITHUB_REF_NAME" --generate-notes
```

OIDC federationは別jobにし、cloud側のclaim／audience policyを
[`PSB-CICD-006`](../audience-bound-oidc-federation/README.md)で検証する。Copy可能なprovider別のtoken exchangeは
同controlの[`secure/workflow.yml`](../audience-bound-oidc-federation/secure/workflow.yml)を使い、ここではpermission boundaryだけを示す。

```yaml
publish-with-oidc:
  if: github.ref == 'refs/tags/v1.0.0'
  environment: release
  permissions:
    contents: read
    id-token: write
  # stepsはPSB-CICD-006のprovider別実装を参照する。
```

Reusable workflow callerもdefaultへ依存しない。External referenceのpinningは
[`PSB-CICD-001`](../action-sha-pinning/README.md)に従う。

```yaml
reusable-check:
  permissions:
    contents: read
  uses: example-org/ci/.github/workflows/check.yml@0123456789abcdef0123456789abcdef01234567
```

## Secureとinsecureの違い

[`secure/workflow.yml`](secure/workflow.yml)は次を一つの比較用fixtureで示す。

- top-level deny-all;
- checkoutを行うtest jobだけの`contents: read`;
- third-party Actionのimmutable commit reference。

[`insecure/workflow.yml`](insecure/workflow.yml)はimplicit permissionと`write-all`を意図的に含む。
Privileged job、OIDC、reusable workflowの安全な分離は上のpurpose別patternで示す。Fixtureは
`.github/workflows`外に隔離され、実行されない。

## 誰が何をするcontrolか

- Development team: jobが行うAPI operationを列挙し、不要なscopeを削る。
- Repository administrator: 全workflowをreviewし、restricted default、required check、ruleset、Environmentを設定する。
- CI platform／organization owner: organization-wide Actions defaultとreusable workflow policyを管理する。
- Security: write／OIDC permissionの必要性、trust condition、Environment、例外、live evidenceをreviewする。

同じworkflowだけにpermission決定、enforcement、evidence、最終判定を完結させない。

## Verification

このcontrolはmanual verificationである。Fixture testや自己申告JSONは、jobの権限が本当に必要最小限であることや
GitHub上の設定を証明できないため提供しない。

### 1. Static check

[`PSB-CICD-003`](../actions-static-analysis/README.md)のzizmor `excessive-permissions` auditで、implicit permission、
broad workflow-level permission、明白なover-permissionを検出する。Scannerの取得、pinning、finding／error分離は
`PSB-CICD-003`が所有し、このcontrolで複製しない。

Blueprint repositoryでreference scannerを確認する場合:

```bash
make verify-control CONTROL=PSB-CICD-003
```

### 2. Semantic review

各jobについて、次をworkflow diffと同じreviewで確認する。

- 実行するGitHub API operationは何か。
- そのoperationに必要なscopeとaccessは何か。
- 同じjob内の全stepへそのpermissionを共有してよいか。
- Write／OIDC jobを別jobへ分離できないか。
- Trusted refとEnvironmentがpermissionを行使できる条件を狭めているか。
- Reusable workflow callerがpermissionを明示しているか。

### 3. Live setting review

Repository administratorはGitHub UIで次を確認する。

- `Settings` → `Actions` → `General` → `Workflow permissions`がrestricted。
- Actionsによるpull request作成・承認が不要なら無効。
- Release／deploy jobが参照するEnvironmentに必要なprotection ruleがある。
- Scanner jobがrulesetまたはbranch protectionのrequired checkである。

既に承認されたGitHub CLIを利用できる場合、default permissionはread-only APIでも確認できる。これはnetwork accessと
repository `Administration: read` authorityを必要とする。

```bash
gh api repos/OWNER/REPOSITORY/actions/permissions/workflow
```

期待する主要field:

```json
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": false
}
```

API仕様は[GitHub Actions permissions REST API](https://docs.github.com/en/rest/actions/permissions)を参照する。

### Harmless positive／negative self-test

- Positive: reviewed branchでread-only test jobを実行し、正常終了とjob log上の`GITHUB_TOKEN Permissions`を確認する。
- Negative: review用branchで`permissions: write-all`を一時的に置き、required scannerがmergeを拒否することを確認して
  変更を破棄する。Insecure fixtureを実行しない。
- Environment: 実処理を`printf`だけに置き換えたreview済みdry-runで、未許可refからprivileged jobが開始せず、
  required reviewer承認前にはEnvironment jobが進まないことを確認する。

Expected stateは`PASS`、不適切なpermissionは`FAIL`、未確認は`NOT_CHECKED`、API／scanner／inventory failureは`ERROR`とする。
`make verify-control CONTROL=PSB-CICD-004`はlive reviewなしでは`NOT_CHECKED`を表示してexit `2`となる。

## 導入完了の判定

次の4点を、対象repository・revision・確認日時・reviewer付きで記録できれば導入完了とする。

1. 全workflow／jobのpermissionと、それぞれが行うoperationの対応表。
2. GitHub Actionsのrestricted default、required check、Environment protectionの現在値。
3. read-only jobの成功と、未許可refまたは未承認Environmentでprivileged jobが進まない確認。
4. 未確認項目、例外、次回review日。

これは採用組織のlive設定を示すための記録であり、fixtureやREADMEの存在を証明にしてはいけない。Secret、token、
private payloadは保存しない。live確認ができない項目は`NOT_CHECKED`とする。

## Failure recovery

- Scanner finding: broad permissionを削り、必要なscopeをjob-levelへ移す。
- Job failure: 失敗したoperationとGitHubのpermission referenceを照合し、そのoperationに必要な一つのscopeだけを追加する。
- Environmentで停止: Environment名、deployment branch／tag、required reviewer、bypass設定を確認する。
- API failure: credential、repository scope、pagination、rate limitを確認し、取得不能をcleanにしない。
- Unsupported syntax: scannerを無効化せず、review可能なsyntaxへ簡素化するか`PSB-CICD-003`で対応する。

## Rollback

Workflow変更をrevertし、追加したrequired checkやEnvironment wiringをrepository administratorがreviewして外す。
Global Git、shell、IDE、Python、OS settingは変更しない。Rollback後もorganization／repositoryのrestricted defaultは維持する。
Controlを外すとjob-level driftのreview可能性が下がるため、server-side scannerとCODEOWNER reviewは残す。

## 既存controlとの分担

- [`PSB-CICD-001`](../action-sha-pinning/README.md): Action／reusable workflowのimmutable reference。
- [`PSB-CICD-002`](../actions-command-injection/README.md): Actions expressionからshellへのcommand injection。
- [`PSB-CICD-003`](../actions-static-analysis/README.md): pinned scanner、static findings、scanner failure、required gate。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): fork／untrusted PRからprivileged contextを分離する。
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): OIDC claims、audience、cloud trust、exchangeを検証する。
- [`PSB-CICD-007`](../runner-hardening/README.md): runner image、network、lifecycle、teardown。
- [`PSB-CICD-008`](../privileged-control-plane-change/README.md): GitHub setting変更のhuman identity、approval、audit。
- [`PSB-SOURCE-004`](../../source-protection/source-access-credential-lifecycle/README.md): PAT、GitHub App、OAuth、SSH credential lifecycle。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): organization-wide Actions policyとrepository coverage。

本controlが所有するのはjob-visibleな`GITHUB_TOKEN`／OIDC発行permissionの明示と最小化である。

## Framework mappings

Mappingはformal complianceやorganization adoptionの証明ではない。

| Framework | Requirement | Relationship | このcontrolが提供するもの |
|---|---|---|---|
| [GitHub Security Guidance](https://docs.github.com/en/actions/concepts/security/github_token) | `GHAS-CONCEPT-GITHUB-TOKEN` | `addresses` | Job tokenの明示的なpermission boundary |
| [GitHub Secure Use Reference](https://docs.github.com/en/actions/reference/security/secure-use) | `GHAS-REF-SECURE-USE` | `supports` | Default denyとjob-level least privilegeの導入手順 |
| [GitHub repository Actions administration](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository) | `GH-ADMIN-ACTIONS-REPOSITORY` | `related-to` | Workflow設定と組み合わせるrepository default |
| [GitHub organization Actions administration](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization) | `GH-ADMIN-ACTIONS-ORGANIZATION` | `related-to` | Repositoryへ継承・overrideされるorganization policy |
| [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19.html#osps-ac-0401) | `OSPS-AC-04.01` | `supports` | Permission未指定時の最低権限化をworkflow deny-allで支援 |
| [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19.html#osps-ac-0402) | `OSPS-AC-04.02` | `addresses` | Job目的ごとの必要最小permissionを設定・reviewする手順 |

SLSA、NIST SSDF、MITRE ATT&CKは一般的な関連性だけでは追加しない。Exact requirement／techniqueへの直接的な
evidenceがreviewできた場合に限り、[`control.yaml`](control.yaml)へrow-level mappingを追加する。

## Guides and references

- [GitHub Actions workflow syntax: permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [GitHub: GITHUB_TOKEN](https://docs.github.com/en/actions/concepts/security/github_token)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub repository Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [GitHub organization Actions settings](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization)
- [GitHub reusable workflow configuration](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations)
- [GitHub deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [GitHub Actions permissions REST API](https://docs.github.com/en/rest/actions/permissions)
- [zizmor excessive-permissions audit](https://docs.zizmor.sh/audits/#excessive-permissions)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19.html)
