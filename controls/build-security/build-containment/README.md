# PSB-BUILD-001: dependency buildを権限・credential・networkから隔離する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Dependencyやuntrusted sourceを実行するbuild jobにcredential、deploy権限、広いnetworkやhost権限があると、build compromiseが組織侵害へ直結する。 |
| 誰から、または何から守るか | 侵害されたdependency、悪意あるbuild script、untrusted contributor、runner設定ミス、telemetry停止から守る。 |
| 何が対象か | CI build environment、runner filesystem、credential、source、artifact、egress network、deploy pipeline、runtime telemetry。 |
| 何をするか | Buildをephemeral・non-root・read-only・credential-free環境へ隔離し、default-deny egressとtelemetryを要求し、deployをartifactだけ受け取る別境界に分ける。 |
| 成功状態 | Untrusted buildはread-only control-plane accessだけを持ち、credential・deploy権限・runtime socket・broad egressを持たず、検証不能時は停止する。 |
| 対象外・残余リスク | JSON fixtureは実runner sandboxやfirewallを構築せず、許可先domainの侵害、DNS・proxy・artifact smugglingはplatform側の追加対策が必要である。 |

## Goal

dependencyやuntrusted sourceを実行し得るbuild jobからdeploy権限とcredentialを除去し、
ephemeral sandbox、read-only root、non-root、default-deny egress、process／network
telemetryを強制します。deployはartifactだけを受け取る別trust boundaryにします。

## 安全な構成

`secure/build-plan.json`は、provider非依存の実行可能policy fixtureです。

- `build`
  - untrusted sourceを実行可能
  - credentialなし
  - `contents: read`だけ
  - ephemeral、non-root、read-only root
  - Docker socketなし
  - HTTPS origin allowlist以外のegressを拒否
  - process／network telemetry必須
- `deploy`
  - source codeを実行しない
  - build artifactだけを入力にする
  - protected release triggerとproduction environment
  - audience固定、15分以下のOIDC credential
  - job単位で必要な`id-token: write`だけを追加

## 検証

```bash
make verify-control CONTROL=PSB-BUILD-001
```

終了コードは`0=適合`、`1=policy違反`、`2=入力欠落・parse不能`です。

negative testは、buildとdeployの混在、long-lived secret、write permission、
wildcard egress、root実行、Docker socket、telemetry欠落、untrusted triggerからのdeployを
拒否します。

## GitHub Actionsへの変換

- workflow top-levelを`permissions: contents: read`以下にする
- build jobでは`id-token: write`、environment secret、deploy keyを付与しない
- deploy jobだけにenvironment protectionと短命OIDCを付与する
- untrusted PR codeを`pull_request_target`やprivileged reusable workflowで実行しない
- job間は署名・digest検証済みartifactだけを渡す
- runner egress enforcementはworkflow記述だけでなくrunner／network control planeで行う

## Runtime sensor adapterの評価

このcontrolはprocess／network telemetryを必須にしますが、現在のJSON fixtureは
telemetry backend自体を実装しません。`cicd-sensor`は、CI jobのprocess、file、
network activityをeBPFで観測するprovider adapter候補として記録しています。

ただし、upstreamがpre-releaseかつactive developmentと明記しているため、現時点では
採用workflowへ追加しません。採用判断には次の証跡が必要です。

1. immutable releaseまたはcommitと、取得artifactのchecksumまたは署名
2. eBPF loadingに必要なkernel capabilityとprivilegeの最小化レビュー
3. synthetic process、file、network eventのpositive／negative fixture
4. credential、path、network destinationを必要以上に残さないredactionとretention
5. sensorまたはbackend停止を`clean`ではなく`ERROR`にするhealth evidence
6. GitHub-hosted／self-hosted runnerごとの対応範囲と、未対応環境の`NOT_CHECKED`

Runtime sensorは検知と調査証跡を補完します。ephemeral sandbox、credential分離、
read-only root、non-root、default-deny egressの代替にはしません。固定sourceと
採用保留理由は
[`REF-BUILD-001`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-build-001)
に記録します。

## 制限事項

- JSON fixtureはOS sandboxやfirewallそのものではなく、platform adapterが必要
- GitHub-hosted runnerのnetwork enforcement範囲はself-hosted runnerと異なる
- 許可domainの侵害、DNS、proxy、artifact smugglingは別途対策が必要
- `id-token: write`はtoken発行能力なのでdeploy job内でもclaimとaudience検証が必要
- telemetry backend停止をcleanと扱ってはいけない

## 公式リファレンス

- [GitHub: GITHUB_TOKENの最小権限](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication)
- [SLSA v1.2 Build Track Basics](https://slsa.dev/spec/v1.2/build-track-basics)
- [cicd-sensor reviewed source snapshot](https://github.com/cicd-sensor/cicd-sensor/tree/6e08deb2221c19a854d8d3be7ce37c659c15bce9)
