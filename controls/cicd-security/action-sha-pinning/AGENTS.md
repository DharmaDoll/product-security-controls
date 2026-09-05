# PSB-CICD-001 implementation instructions

このfileは`PSB-CICD-001`（`cicd-security`）に固有の実装境界を定める。作業前に
[repository rootのAGENTS.md](../../../AGENTS.md)、[controlsのAGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、[ROADMAP](../../../docs/ROADMAP.md)、関連ADR、
[README.md](README.md)と[control.yaml](control.yaml)を読むこと。

## Control essence

- 外部Actionと外部reusable workflowはfull 40-character Git commit SHA、`docker://` Actionは
  `sha256` digestへ固定する。
- Security効果は、実際の`.github/workflows`を変更し、CI required checkと利用可能なGitHub policyで
  mutable referenceを拒否したときに生まれる。READMEやfixtureをcopyしただけでは効果は発生しない。
- Full SHAが固定するのは直接参照されたGit objectである。Action内部のcontainer、package、nested Action、
  外部download等の推移的依存までimmutableになるとは主張しない。
- 推移的依存は、このcontrolでは完全解決せず、固定commitを確認してmutable runtime dependencyの有無を
  review結果として明示する。架空のevidenceや自動的な総合`PASS`を作らない。

## Assumptions and roles

- Primary providerはGitHub.com／GitHub Enterprise Cloud、developer環境はmacOSまたはLinuxとPython 3.10+である。
- Developerはcanonical upstreamのreleaseとexact SHAを確認してworkflowを変更する。
- Repository administratorはverifierをCI required checkにし、同じPRでgateを無効化できないreview境界を設ける。
- Organization ownerは利用可能なfull-length SHA policyを有効化する。ただしreusable workflowを含むlocal gateを残す。
- Security reviewerは高権限jobで使うActionの固定commitと明白な推移的mutabilityをreviewする。
- General dependency graph、cooldown、workflow permission、untrusted PR、runner、OIDC、exception lifecycleは関連controlの
  責務とし、このpackageへ複製しない。

## Implementation contract

主実装は小さく保つ。

1. [`scripts/verify.py`](scripts/verify.py)がworkflow textをnetwork-freeで検査する。
2. [`secure/workflow.yml`](secure/workflow.yml)と[`insecure/workflow.yml`](insecure/workflow.yml)は実行されない
   positive／negative exampleである。
3. [`secure/verify-action-pinning.yml`](secure/verify-action-pinning.yml)はadopterがcopyするCI gateである。
4. [`tests/test.sh`](tests/test.sh)はsafe fixture、inert finding、missing input、repository workflowだけを確認する。
5. [`docs/transitive-dependency-review.md`](docs/transitive-dependency-review.md)はmanual reviewの正式なverificationである。

Verifierは次を守る。

- Remote `owner/repository[/path]@ref`はfull 40-character SHAだけをacceptedにする。
- `docker://`は`@sha256:<64 hex>`だけをacceptedにする。
- Repository-local `./...`はpinning対象外だが、untrusted checkoutで安全になるとは扱わない。
- Tag、branch、short SHA、missing ref、expressionはfindingにする。
- Missing input、読めないfile、unsupported syntax、`uses:`なしはerrorにし、cleanへ丸めない。
- Exit statusは`0=accepted`、`1=policy finding`、`2=input／parser／tool error`を維持する。
- GitHub API、remote SHAの存在、upstream ownership、release binding、推移的依存を推測しない。

## pinact boundary

[pinact](https://github.com/suzuki-shunsuke/pinact)は、mutableなAction／reusable workflow参照をSHAへ直すための
推奨remediation toolとして使う。採用version、source commit、release artifact checksumを固定し、downloadは
[公式installation guide](https://github.com/suzuki-shunsuke/pinact/blob/main/INSTALL.md)に従って検証する。

- pinactをこのcontrolの唯一のgateにはしない。v4.1.1は`docker://` Actionをpinning対象として扱わないためである。
- pinactのdefault実行はfileを変更しGitHub APIへ接続する。READMEでnetwork accessと`git diff` reviewを明示する。
- pinactによるauto-commit、write permission、SARIF、reviewdog、`min-age`は初期実装へ含めない。
- `min-age`は[`PSB-DEPS-001`](../../dependency-security/release-cooldown/README.md)の責務である。
- pinactのparserをfixtureで再テストしない。独自gapであるDocker digestと、repository-owned gateだけを検証する。

## Transitive dependency review

[Palo Alto NetworksのUnpinnable Actions解説](https://www.paloaltonetworks.com/blog/cloud-security/unpinnable-actions-github-security/)
を境界理解の参考にする。数値を現在のecosystem全体へ一般化せず、次の技術的な問題を説明するために使う。

- SHA固定後もAction内部のcontainer tag、base image、package install、nested `uses:`、checksumなしdownloadは変わり得る。
- Direct reference結果とtransitive review結果を分離する。
- `NO_OBVIOUS_MUTABILITY`は完全性や安全性の証明ではない。
- 高権限jobで`MUTABLE_RUNTIME_OBSERVED`なら、より小さなAction、repository-owned script、review済みfork、
  least privilege、または[`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)を検討する。

## Verification and evidence

- Testはpinact自身を再検証せず、secure fixtureのexit `0`、insecure fixtureのexit `1`、missing inputのexit `2`、
  実際のrepository workflowのexit `0`だけを確認する。
- Fixture successはorganization adoption、GitHub setting、required check、upstream trust、推移的依存の安全性を証明しない。
- Live evidenceはexact repository revision、sanitized verifier output、required-check適用、current provider settingを含める。
- Transitive review evidenceは固定commit permalinkとreview記録にし、手書きの`secure: true` JSONを作らない。
- README文字列検査、no-op test、real Action実行、provider-valid token、synthetic adoption evidenceを追加しない。

## Metadata and completion

[`control.yaml`](control.yaml)がcanonical metadataである。`check_context_version: "1.0"`と既存check IDを維持する。
推移的mutability reviewは`ACT-007`とし、廃止済みIDを別の意味へ再利用しない。

変更後はrepository rootから次を実行する。

```bash
bash controls/cicd-security/action-sha-pinning/tests/test.sh
make verify-control CONTROL=PSB-CICD-001
make validate-controls
```

Generated index、mapping、checklistはcanonical metadataから再生成できることだけを確認し、このtaskのcommit対象には
含めない。Full SHA、Docker digest、reusable workflow coverage、fail-closed behaviorをtest通過のために弱めない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
