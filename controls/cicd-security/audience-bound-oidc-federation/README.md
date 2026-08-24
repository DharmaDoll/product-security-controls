# PSB-CICD-006: GitHub Actionsのcloud OIDC federationをexact claimへ限定する

## このcontrolを一枚で理解する

### セキュリティ上の問題

OIDCへ移行して長期cloud keyをなくしても、cloud側のtrust policyがorganization wildcard、誤ったaudience、可変workflow refを許すと、別repositoryや侵害jobが短期credentialを取得できる。

### 誰から、または何から守るか

fork／PR作成者、侵害されたActionやdependency、悪意あるrepository、差し替えられたreusable workflow、期限切れ・replay token、過剰なcloud role設定から守る。

### 何が対象か

GitHub Actions OIDC JWT、cloud trust policy、protected deploy job、repository secret inventory、reusable workflow identity、交換後の一時credential。

### 何をするか

JWT署名とissuer、audience、不変ID付きsubject、repository、ref、environment、workflowを完全一致で検証し、発行jobとcloud権限・寿命・replayを制限する。

### 成功状態

protected deploy jobだけが署名済みtokenを一度交換でき、15分以下かつ対象resource・action限定のcredentialを得て、静的cloud keyは存在しない。

### 対象外・残余リスク

短期credentialも同じjob内の悪意あるcodeには窃取され得る。provider固有IAM、GitHub Environment設定、鍵取得・rotation、live auditは導入先で追加確認する。

## Security problem

OIDCはGitHubに長期cloud keyを保存せず、jobごとに短期credentialを交換できる
仕組みです。ただし`id-token: write`を付けただけでは安全になりません。cloud側が
`repo:example-org/*`のような広いsubjectを信頼したり、audienceを照合しなかったり、
reusable workflowを`@main`で信頼したりすると、攻撃者が正規に署名された別contextの
tokenをcloud roleへ交換できます。

このcontrolは`PSB-CICD-004`のjob-level token発行権限と、`PSB-CICD-005`の
untrusted PR分離の後段に位置します。今回確認するのは「cloud側がそのOIDC tokenを
受理してよいか」と「交換後のcredentialが十分に狭いか」です。

## Threat, target, and why this control exists

攻撃者はforkや別repositoryでworkflowを起動する、侵害したstepからOIDC tokenを
要求する、可変refのreusable workflowを差し替える、盗んだJWTを再利用する、といった
経路を狙います。対象はsource codeそのものではなく、GitHub OIDC issuerとcloud IAM
の間にあるworkload identity境界です。

GitHubのJWTは`iss`、`aud`、`sub`に加えてrepository ID、ref、environment、
`workflow_ref`、`job_workflow_ref`等を持ちます。名前は移管・再利用され得るため、
fixtureではowner IDとrepository IDを含むimmutable subjectも要求します。reusable
workflowはfull commit SHAへ固定し、PR context、期限切れ、署名不正、replayを拒否します。

## Secure and insecure examples

`secure/`には次を収録しています。

- deny-allを既定とし、`deploy` jobだけへ`id-token: write`を与えるworkflow;
- exact claim、10分以下のJWT、15分以下のcloud credentialを定義するtrust policy;
- private keyを含まない、RS256署名済みsynthetic JWTと公開鍵;
- 完全なrepository secret inventory、未使用JTI state、secret値を含まない交換receipt。

`insecure/`は隔離された非実行fixtureです。organization wildcard、誤ったaudience、
PR trigger、self-hosted runner、複数jobのOIDC権限、stored cloud key、replay済みJTI、
wildcard action/resource、12時間credentialを含みます。

`tests/fixtures/`のfork／PR、別repository、`@main` reusable workflow、期限切れtokenは
すべて同じsynthetic issuer鍵で正しく署名されています。単なる署名改ざんテストでは
なく、「正規に署名されていてもclaimが違えば拒否する」ことを確認できます。

## Verification

```bash
make verify-control CONTROL=PSB-CICD-006
```

直接実行する場合:

```bash
python3 controls/cicd-security/audience-bound-oidc-federation/scripts/verify.py \
  --policy controls/cicd-security/audience-bound-oidc-federation/secure/policy.json \
  --workflow controls/cicd-security/audience-bound-oidc-federation/secure/workflow.yml \
  --token controls/cicd-security/audience-bound-oidc-federation/secure/token.jwt \
  --secret-inventory controls/cicd-security/audience-bound-oidc-federation/secure/secret-inventory.json \
  --replay-state controls/cicd-security/audience-bound-oidc-federation/secure/replay-state.json \
  --receipt controls/cicd-security/audience-bound-oidc-federation/secure/credential-receipt.json \
  --now 1785823200
```

終了コードは`0=全条件を受理`、`1=security finding`、`2=入力・署名検証・証跡を
評価不能`です。cloud exchangeが`denied`になった場合も「deploy checkをskipしたので
clean」とせず`1`です。OpenSSLやsecret inventoryが利用不能なら`2`になります。

期待されるsecure出力は`expected-results/secure.txt`、複数の脆弱な設定をまとめた
出力は`expected-results/insecure.txt`に固定しています。

## Integration guidance

1. cloud providerへGitHub issuerを登録し、audienceをdeploy用途のexact valueへ固定します。
2. organization/repository名だけでなくstable IDをtrust条件へ含めます。既存repositoryで
   immutable default subjectを使わない場合はGitHubのsubject customizationとprovider
   対応状況を確認します。
3. protected Environment名、trusted branch、caller workflow、full-SHA reusable
   workflowを条件へ追加します。providerがclaimを扱えない場合、条件を黙って落とさず
   provider固有adapterと補完controlをreviewします。
4. top-levelを`permissions: {}`とし、実際にexchangeするjobだけへ
   `id-token: write`を付けます。build/testとdeployを同じjobへ混在させません。
5. repository／environment secret一覧からAWS、Azure、GCP等の長期cloud keyを削除し、
   削除前に依存workflowがないことと、削除後にOIDC exchangeが成功することを確認します。
6. cloud roleはdeploy actionと対象serviceだけへ絞り、credential TTLを15分以下にします。
7. provider audit logへJTI、repository ID、run ID、role、resource、decisionを残し、同じJTIの
   再利用を拒否します。fixtureのJSON stateはproduction用の排他ledgerではありません。

## Limitations and operational cost

- この第一sliceはprovider-neutralなoffline evaluatorです。AWS IAM、Azure federated
  credential、GCP Workload Identity Federation等の構文へ変換するadapterは別途必要です。
- GitHubの実token検証では固定公開鍵ではなくissuer discovery/JWKS、TLS、cache、key
  rotationをfail closedで実装します。この公開鍵はsynthetic fixture専用です。
- providerによって利用可能なclaimとcredential最小TTLが異なります。15分以下を提供
  できないproviderでは、最大限短いTTLと追加のnetwork／approval制御を記録します。
- GitHub Environmentのreviewer、deployment branch rule、protection ruleが有効かは
  repository API証跡で別途確認します。
- `jti` replay拒否には原子的で可用性のあるprovider-side ledgerが必要です。静的JSONは
  検証contractを示すだけです。
- OIDCはcredential exposureをなくしません。token交換後の悪意あるstep、runner memory、
  outbound通信は`PSB-BUILD-001`等のcontainmentとruntime monitoringで補います。

## References

- [GitHub OpenID Connect concept](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [GitHub OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub OIDC with reusable workflows](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19#osps-ac-0402)
- [MITRE ATT&CK T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001)
- [OIDC／Trusted Publishing residual-risk source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-009)
