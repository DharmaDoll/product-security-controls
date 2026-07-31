# PSB-CICD-005: forkと未信頼PRをprivileged CIから分離する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Forkや未信頼PRのcodeをsecret、write token、protected environment、self-hosted runnerがあるcontextで実行すると、contributorが権限を奪取できる。 |
| 誰から、または何から守るか | 悪意あるfork contributor、改変されたPR code、`pull_request_target` misuse、cache poisoning、trusted jobへの同一run内elevationから守る。 |
| 何が対象か | Pull request workflow、checkout revision、GitHub token、secret、environment、runner group、cache、workflow triggerとrun間handoff。 |
| 何をするか | Untrusted validationをcredential-free hosted jobへ限定し、privileged処理はreview済みrevisionを使う新しいtrusted runとして開始する。 |
| 成功状態 | PR jobはread-only・secretなし・protected environmentなしで動き、head codeをprivileged contextへ持ち込まず、trusted phaseは独立triggerとartifact identityを検証する。 |
| 対象外・残余リスク | Static fixtureはorganizationのfork approval、branch・environment protection、runner-group policyのlive enforcementを証明しない。 |

## Security problem

forkまたは未レビューbranchのpull requestは、workflow、build script、test、
dependency、cache keyを攻撃者が変更できる未信頼入力です。このコードをsecret、
write可能な`GITHUB_TOKEN`、GitHub Environment、OIDC、self-hosted runnerと同じ
jobで実行すると、repository改ざん、credential窃取、runner残留、cloudへの侵入に
つながります。

特に`pull_request_target`はdefault branch側のworkflowとして動作する一方、
attacker-controlledなhead revisionをcheckoutして実行するとprivileged contextと
未信頼コードが同居します。`workflow_run`で後段をprivileged化しても、前段の
artifactやcache、実行結果を無条件に信頼すれば同じ境界越えが起きます。

## Threat, target, and why this control exists

想定する攻撃者は、forkを作成できる外部contributor、侵害されたcontributor
account、悪意あるdependencyです。対象はpull requestを処理するGitHub Actions
job、runner、checkout revision、secret、token、cache、reusable workflow、
trusted reporting jobです。

このcontrolは「actor名やlabelを確認して同じrunを昇格する」のではなく、PRでは
credential-freeの検証だけを行い、reviewとmerge後のtrusted branch `push`を新しい
runとして開始します。PRで変更されたworkflow自体が実行されても、到達可能な資産を
read-onlyのsourceとephemeralなGitHub-hosted runnerへ限定するためです。

## Secure and insecure examples

`secure/workflow.yml`は次を示します。

- `pull_request`検証jobは明示的read-onlyでsecretとenvironmentを持たない;
- GitHub-hosted runnerを使用する;
- checkout credentialを保存せず、eventが選んだmerge revisionを検証する;
- PR jobではshared cacheとreusable workflowを使用しない;
- privileged reportingはmerge後の`push`条件を持つ独立jobで実行する;
- trusted jobはPR jobを`needs`で引き継がない。

`insecure/workflow.yml`は隔離された非実行fixtureです。
`pull_request_target`、`workflow_run`、attacker head checkout、secret、
write token、production environment、self-hosted runner、shared cache、
`secrets: inherit`付きreusable workflow、actor名による同一run昇格を含みます。

Sidecar policyはworkflow event、各jobのtrust分類、runner、trusted jobの条件を
review可能なJSONとして固定します。policyにないworkflow／jobやevent差分は
cleanではなく`ERROR`です。

## Verification

```bash
make verify-control CONTROL=PSB-CICD-005
```

repository workflowを直接確認する場合:

```bash
python3 controls/cicd-security/untrusted-pr-boundary/scripts/verify.py \
  --policy controls/cicd-security/untrusted-pr-boundary/secure/repository-policy.json \
  --root .
```

終了コードは`0=accepted`、`1=trust-boundary finding`、
`2=policy／workflow欠落、未対応YAML、parse不能`です。eventやrevisionを評価
できない状態をtrustedと解釈しません。

## Integration guidance

1. PR validationは`pull_request`とGitHub-hosted runnerで実行します。
2. workflow top-levelをdeny-allにし、PR jobは`contents: read`以下へ限定します。
3. PR jobへrepository／organization／environment secretを渡しません。
4. checkoutは`persist-credentials: false`とし、PR eventのmerge revisionを使います。
5. untrusted jobではshared cache、self-hosted runner、privileged reusable
   workflowを使用しません。
6. reporting、release、deployはmerge後のtrusted branch eventから新規実行します。
7. 同一run内のactor、label、author associationを権限昇格の根拠にしません。
8. repository policyを全workflowへ適用し、追加workflowを未登録のままにしません。
9. GitHub repository設定側でもfork workflow approval、default token permission、
   Environment approval、runner group制限を確認します。

## Limitations and operational cost

- このstatic verifierはGitHub repository／organizationのfork approval設定、
  Environment protection、runner group実設定をAPIで確認しません。
- `pull_request_target`と`workflow_run`を全面拒否する保守的なfirst sliceです。
  metadata-only用途が必要な場合は、untrusted revisionを一切実行・復元しない
  専用profileとnegative testを追加してから例外化します。
- PRでshared cacheとreusable workflowを禁止するため、build時間とworkflow重複が
  増える場合があります。安全な一方向artifact promotionは今後の独立profileです。
- GitHub-hosted runnerを使っても、悪意あるtestが公開ネットワークへ送信すること
  自体は防ぎません。credentialを渡さないことが主要な境界です。
- job内部のsandbox、egress、telemetryは`PSB-BUILD-001`、正確なtoken最小権限は
  `PSB-CICD-004`、OIDC trust conditionは`PSB-CICD-006`の対象です。
- restricted YAML parserが未知の構文を検出した場合、reviewされるまで`ERROR`に
  なります。

## References

- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub self-hosted runner access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19#osps-br-0103)
- [GitHub Security Lab pwn-request source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-010)
- [Practitioner best-practice source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-005)
- [Mercari internal-guideline case-study source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-007)
