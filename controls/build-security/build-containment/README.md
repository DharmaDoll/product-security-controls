# PSB-BUILD-001: dependency buildを権限・credential・networkから隔離する

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

## 制限事項

- JSON fixtureはOS sandboxやfirewallそのものではなく、platform adapterが必要
- GitHub-hosted runnerのnetwork enforcement範囲はself-hosted runnerと異なる
- 許可domainの侵害、DNS、proxy、artifact smugglingは別途対策が必要
- `id-token: write`はtoken発行能力なのでdeploy job内でもclaimとaudience検証が必要
- telemetry backend停止をcleanと扱ってはいけない

## 公式リファレンス

- [GitHub: GITHUB_TOKENの最小権限](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication)
- [SLSA v1.2 Build Track Basics](https://slsa.dev/spec/v1.2/build-track-basics)
