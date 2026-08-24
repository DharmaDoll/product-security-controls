# PSB-CICD-004: GitHub Actionsのtoken権限をjob目的へ限定する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Workflowやjobが暗黙のrepository defaultを継承すると、reviewerに見えない過剰な`GITHUB_TOKEN`やOIDC権限がcode executionへ付与される。

### 誰から、または何から守るか

Workflow injection、侵害されたdependency、誤設定、reusable workflow caller、untrusted refからのprivileged job起動から守る。

### 何が対象か

GitHub Actions workflow、job、`GITHUB_TOKEN`、`id-token`、protected environment、trusted ref condition、reusable workflow caller。

### 何をするか

Top-levelをdeny-allにし、job目的別のexact permission map、trusted ref、environment protection、OIDC job分離を明示して検証する。

### 成功状態

全jobが明示的な最小権限を持ち、write・OIDC権限は目的とtrusted contextへ限定され、暗黙・broad・評価不能な権限は拒否される。

### 対象外・残余リスク

最小権限として承認した権限自体の妥当性はsemantic reviewが必要で、GitHub App・cloud IAM・runner host権限までは直接評価しない。

## Security problem

GitHub Actionsはjobごとにrepository-scopedの`GITHUB_TOKEN`を発行します。
workflowが`permissions`を省略すると、organization／repository defaultに結果が
依存します。`write-all`や不要な`contents: write`、`id-token: write`が付いた
jobでthird-party Actionや侵害されたbuild stepが実行されると、source、package、
deployment、attestation、cloud federationへ被害が拡大します。

## Threat, target, and why this control exists

想定する脅威は、悪意あるcontributor、侵害されたAction／dependency、workflowを
誤設定するmaintainerです。対象は各workflow jobへ発行される`GITHUB_TOKEN`と
OIDC token発行権限です。

GitHubではworkflow-level権限がjob-level設定で調整され、いずれかのpermissionを
指定すると未指定scopeは`none`になります。このcontrolは、その仕組みを利用して
top-levelを`permissions: {}`に固定し、全jobへ明示的な最小権限を設定します。
repository defaultだけに依存せず、review差分からjobの実効権限を判断できることが
目的です。

## Secure and insecure examples

`secure/workflow.yml`は次を示します。

- top-level deny-allと全jobの明示的な権限;
- test、report、release、deployの目的別permission ceiling;
- write-capable jobのreview済みref条件;
- release／deploy jobのprotected environment;
- federationするjobだけの`id-token: write`;
- reusable workflow callerの明示的なread-only権限。

`insecure/workflow.yml`は隔離された非実行fixtureです。暗黙権限、
`write-all`、test／reusable callerの`contents: write`、不要なOIDC権限、
ref条件とenvironmentの欠落を含みます。

Sidecar policyは各jobの目的、完全一致すべきpermission set、ref条件、
environmentをreview可能なJSONとして固定します。policyにないworkflowやjobは
cleanとして扱わず`ERROR`になります。

## Verification

```bash
make verify-control CONTROL=PSB-CICD-004
```

repository workflowを直接確認する場合:

```bash
python3 controls/cicd-security/actions-least-privilege/scripts/verify.py \
  --policy controls/cicd-security/actions-least-privilege/secure/repository-policy.json \
  --root .
```

終了コードは`0=accepted`、`1=permission policy finding`、
`2=policy／workflow欠落、未対応YAML、parse不能`です。scanner／parser失敗を
権限なしと解釈しません。

## Integration guidance

1. Organization／repositoryの既定`GITHUB_TOKEN`権限もrestrictedへ設定します。
2. workflow top-levelを`permissions: {}`にします。
3. jobごとに実際に使用するscopeだけを指定します。
4. write権限を持つjobをtrusted ref条件へ限定します。
5. release／deploy jobはapproval rulesを持つGitHub Environmentへ結びます。
6. `id-token: write`はOIDC federationまたはattestationに必要なjobだけへ付与します。
7. workflowまたはjob追加時にsidecar policyもreviewします。
8. reusable workflow callerでも`permissions`を明記します。called workflowは
   callerから権限を昇格できませんが、callerの省略はdefault依存になります。

## Limitations and operational cost

- Sidecar policyのjob目的とpermission setは人がreviewする必要があります。
- ref条件の文字列一致は、branch protectionやGitHub Environmentのapproval ruleが
  実際に有効かをAPIで検証しません。
- `GITHUB_TOKEN`を絞っても、別途渡されたPAT、GitHub App token、cloud secretの
  権限は縮小しません。
- 同一job内のActionとshell stepはそのjob tokenを共有します。信頼境界が異なる
  処理はjobを分ける必要があります。
- fork／`pull_request_target`のcredential隔離は`PSB-CICD-005`、OIDC trust
  conditionは`PSB-CICD-006`の対象です。
- GitHubがpermission scopeやYAML構文を追加した場合、verifierをreviewして更新する
  まで未知の形式を`ERROR`として拒否します。

## References

- [GitHub Actions workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub reusable workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations)
- [GitHub OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19#osps-ac-04)
- [GitHub Actions Best Practice 2025 source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-005)
- [OIDC and Trusted Publishing residual-risk source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-009)
