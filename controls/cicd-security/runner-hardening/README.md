# PSB-CICD-007: CI runnerをjobごとに隔離し、使用後に破棄する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | 長寿命または共有runnerは、以前のjobが残したprocess、workspace、credentialや改変されたimageを次のjobへ引き継ぎ、cloud metadata、host socket、management networkへの到達点にもなり得る。 |
| 誰から、または何から守るか | 悪意あるcontributor、侵害されたdependency／workflow、runner imageへのimplant、運用者の設定誤り、teardown／evidence collectorの失敗から守る。 |
| 何が対象か | GitHub-hosted runnerの選択、self-hosted runner fleet、runner group、provisioning image、registration authority、startup state、network境界、job終了後のderegistration・破棄・log。 |
| 何をするか | 未信頼jobをreview済みhosted profileへroutingし、self-hostedはtrusted scopeだけのJIT one-job instanceに限定する。digest検証済みimageからcleanに起動し、host資産を遮断し、外部logを残して期限内に破棄する。 |
| 成功状態 | 全dispatchがexact profileへ一致し、self-hostedは1 jobだけ処理する。prior stateとhost credentialがなく、metadata／management／host socketへ到達せず、jobとrunner generationに紐づくteardown receiptと外部logがfreshかつ完全である。collector欠落やstale evidenceは`ERROR`になる。 |
| 対象外・残余リスク | Providerのcontrol plane、GitHub-hosted VMの実破棄、job内部のapplication egress、workflow token、build sandboxをこのfixtureだけでは証明しない。live provider／provisioner adapterとnetwork probeが別途必要である。 |

## Security problem

CI jobはsourceだけでなくdependency install、build script、test、Actionも実行します。
runnerを再利用すると、先行jobのworkspace、process、credential file、tool cacheや
implantが後続jobへ残ります。self-hosted runnerがcloud VMやcontainer hostと同じ
network／identity boundaryにいる場合、metadata endpoint、runtime socket、管理用
serviceを経由してCIの権限を越える可能性もあります。

tokenをread-onlyにしても、host上のSSH key、cloud identity、internal service、
runner registration authorityは消えません。そのためrunner lifecycle自体をjob単位の
security boundaryとして設計し、起動前・実行時・終了後を同じjob identityで検証します。

## Threat, target, and control boundary

想定する攻撃者は、未信頼PRを送る外部contributor、侵害されたdependency／Action、
runner imageやprovisionerを改変するsupply-chain attackerです。対象はrunnerの選択、
image、registration、workspace／process、host credential、network、teardownとlogです。

責務の重複を避けるため、次の境界を固定します。

- `PSB-CICD-005`: 未信頼PRをself-hosted runnerへ載せないworkflow trust boundary;
- `PSB-BUILD-001`: job開始後のcredential、privilege、build egress、sandbox、telemetry;
- `PSB-CICD-007`: runnerのimage、startup、group／registration、one-job lifecycle、
  host／metadata／management isolation、deregistration、破棄とlog export;
- providerのCI control planeとGitHub-hosted VM破棄の実装: external assurance boundary。

Hostedとself-hostedを同じ証跡でPASSにしません。hosted profileはproviderが公開する
job image／lifecycle contractを正規化し、organization側でuntrusted routingとinternal
network不許可を確認します。self-hosted profileはorganization-owned provisionerが
runner generation、network probe、deregistration、compute／storage破棄をreceiptとして
発行します。

## Secure and insecure examples

`secure/runner-policy.json`は、未信頼jobをreview済みmanaged-hosted profileへ限定し、
self-hosted release runnerをexact repository、workflow commit、event、runner groupに
限定します。self-hosted runnerはJIT、ephemeral、one job、underlying host非再利用で、
imageはdigestとprovenance evidenceを持ちます。

`secure/fleet-snapshot.json`、`image-evidence.json`、`teardown-receipts.json`は、
clean startup、IPv4／IPv6 metadataとmanagement networkの遮断、registration TTL、
job終了後のderegistration・破棄、外部log correlationを示すsynthetic evidenceです。
実環境の適合を主張するものではありません。

`insecure/`は、未信頼PRをpersistent self-hosted runnerへroutingし、mutable image、
prior-job state、host credential、metadata、management network、runtime socket、SSH、
再利用、local-only logを意図的に含む非deploy fixtureです。

## Verification

```bash
make verify-control CONTROL=PSB-CICD-007
```

直接実行する場合:

```bash
python3 controls/cicd-security/runner-hardening/scripts/verify.py \
  --policy controls/cicd-security/runner-hardening/secure/runner-policy.json \
  --fleet-snapshot controls/cicd-security/runner-hardening/secure/fleet-snapshot.json \
  --image-evidence controls/cicd-security/runner-hardening/secure/image-evidence.json \
  --teardown-receipts controls/cicd-security/runner-hardening/secure/teardown-receipts.json \
  --evidence-health controls/cicd-security/runner-hardening/secure/evidence-health.json \
  --evaluation-time 2026-08-11T03:10:00Z
```

終了codeは`0=accepted`、`1=runner hardening finding`、
`2=input／collector／freshness error`です。scanner／collector failureをcleanと
解釈しません。

Expected output:

```text
PASS RNR-001 trust-class routing and exact runner scope
...
PASS RNR-009 complete fresh fail-closed evidence
ACCEPT PSB-CICD-007 runner fleet evidence satisfies the reference policy
```

## Integration guidance

1. `PSB-CICD-005`でuntrustedを分類し、review済みGitHub-hosted profileだけへroutingする。
2. self-hosted runner groupをexact repositoryへ限定し、workflow commitとeventを
   provisioner requestへ含める。
3. JIT registrationをjob直前に一度だけ発行し、短いTTLにして保存しない。
4. signed／provenance-verified imageをdigestで起動し、runner binary更新はmutable hostへ
   任せずimage replacementとして行う。
5. startup probeでprevious job、foreign process、workspace、host／cloud credential、
   SSH keyがないことを確認する。
6. runner namespaceからmetadataのIPv4／IPv6、management CIDR、host runtime socketを
   denyし、control-plane originだけを許可する。
7. job完了後に外部logをexportし、runnerをderegisterしてcompute、workspace、
   ephemeral storage keyを期限内に破棄する。
8. dispatch、runner generation、image digest、teardown、logを同じjob IDで相関する。
9. fleet snapshot、network probe、image pipeline、teardown、log exporterのhealthを
   一緒に評価し、欠落・stale・parse errorを`ERROR`にする。

GitHubはself-hosted runnerのautoscalingにephemeral runnerを推奨し、ephemeral runnerは
1 jobだけを受け取った後に自動deregisterされると説明しています。ただしunderlying
machineのwipeとlog転送は利用組織のautomation責務です。JIT runnerを使っても同じ
hardwareを再利用すればclean environmentは保証されないため、このcontrolはcomputeと
storage keyの破棄まで要求します。

## Operational notes and limitations

- GitHub-hosted imageとlifecycleはprovider-ownedです。reference fixtureはprovider contractを
  正規化した例であり、provider内部のVM破棄を独立attestationしていません。
- Self-hosted runnerの起動時間とimage build／patch運用costが増えます。pre-warmed poolを
  使う場合もjob assignment前にidentityを確定し、job後はinstanceをpoolへ戻しません。
- External logにはcommand output由来のsecretが含まれ得ます。metadata-only receipt、
  masking、access control、retentionを別途適用します。
- GitHub runner serviceのavailability、control-plane侵害、provider内部のtenant isolationは
  対象外です。
- `runner_version_supported`はlive adapterがGitHubのsupport window／critical updateを
  判定して投入するnormalized resultです。このoffline verifierはInternetへ問い合わせません。
- Job内部のpublic egress、credential mount、non-root／read-only sandboxは
  `PSB-BUILD-001`で検証します。

## References

- [GitHub self-hosted runners reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub monitoring and troubleshooting self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/monitor-and-troubleshoot)
- [GitHub self-hosted runner access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access)
- [Pinned GitHub guidance registry](../../../frameworks/github-security-guidance/README.md)
- [CI/CD threat-matrix reconciliation](../../../docs/CICD_THREAT_MATRIX_RECONCILIATION.md)
- [Source adoption record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-014)
