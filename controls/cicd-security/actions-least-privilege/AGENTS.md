# PSB-CICD-004 implementation instructions

このfileは`PSB-CICD-004`（`cicd-security`）固有の実装境界を定める。変更前に
[repository rootのAGENTS.md](../../../AGENTS.md)、[controlsのAGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、[ROADMAP](../../../docs/ROADMAP.md)、関連ADR、
[README.md](README.md)、[control.yaml](control.yaml)を読むこと。

## Control essence

- 対象はGitHub Actionsの各jobへ発行される`GITHUB_TOKEN`と`id-token: write`によるOIDC token発行権限である。
- Workflow top-levelを`permissions: {}`にし、全jobへ実際のoperationに必要なpermissionだけを明示する。
- Write／OIDC jobはtrusted refへ限定し、release／deployはlive protected Environmentへ結び付ける。
- Security効果は採用先の実workflow、restricted default、required check、Environmentから生まれる。
  READMEやfixtureをcopyしただけではorganization adoptionにならない。
- Job intentはYAMLから機械的に証明できない。人間のsemantic reviewをcontrolの欠陥として隠さず、正式な実装に含める。

## Implementation mode

本controlはconfiguration-first／guidance-firstで実装する。

- [`secure/workflow.yml`](secure/workflow.yml)と[`insecure/workflow.yml`](insecure/workflow.yml)を比較可能な最小例にする。
- 導入、self-test、live verification、evidence、recovery、rollbackは[`README.md`](README.md)にまとめる。
- 明白なover-permissionのstatic detectionは[`PSB-CICD-003`](../actions-static-analysis/README.md)のzizmorへ委譲する。
- Control-local YAML parser、sidecar permission policy、expected-output fixture、`tests/test.sh`を追加しない。
- 手書きpolicyとworkflowの一致だけを検査して、semantic least privilegeまたはlive adoptionを証明したと主張しない。
- Provider設定を変更するautomationはbaselineに含めない。Read-only APIは取得元、authority、failure stateが明確な場合だけ
  optional verificationとして案内する。

## Supported assumptions and roles

- Reference providerはGitHub Actions、developer環境はmacOSまたはLinuxである。
- Development teamは各jobが使うGitHub API operationを説明し、不要なscopeを削る。
- Repository administratorは全workflow inventory、restricted default、required check、ruleset、Environmentを所有する。
- CI platform／organization ownerはorganization-wide Actions defaultとreusable workflow policyを所有する。
- Securityはwrite／OIDC permission、trust condition、Environment、例外、live evidenceをreviewする。
- GitHub Enterprise Serverまたはprovider plan固有差分を追加するときは、対象version、利用可能なsetting、検証方法を先に確認する。

## 実装前に確認するcontrol固有入力

1. 対象repositoryの全workflow、全job、reusable workflow callerを列挙できるか。
2. 各jobが実行するGitHub API operationと、そのoperationに必要なscope／accessは何か。
3. Write-capable jobを起動できるexact refとprotected Environmentは何か。
4. `id-token: write`を必要とするexact token exchange jobはどれか。
5. Organization／repository default、required check、Environmentを誰がliveで確認するか。
6. PAT、GitHub App token、cloud secret等、`GITHUB_TOKEN`以外のauthorityが同じjobへ入るか。

情報がない場合は架空のrepository、Environment、evidenceを作らない。Provider-neutral guidanceだけを変更し、live resultは
`NOT_CHECKED`のままにする。

## Required configuration

- 全workflowのtop-levelは`permissions: {}`。
- 全jobはexplicit permission mapを持つ。API accessが不要ならjob-levelも`{}`。
- `read-all`と`write-all`を使用しない。
- Scopeは利用箇所に最も近いjobへ置き、異なるauthorityを必要とする処理はjobを分ける。
- `id-token: write`は実際にOIDC tokenをexchangeするjobだけへ置く。
- Write／OIDC jobはreview済みref conditionを持つ。
- Release／deploy jobはlive protection ruleを持つEnvironmentを参照する。
- Reusable workflow callerもpermissionを明示する。Called workflowがcallerの暗黙または広い権限を最小化すると想定しない。

## Atomic checks

[`control.yaml`](control.yaml)がcanonical metadataである。既存IDを不要にrenumberせず、次の意味を維持する。

- `PERM-001`: top-level deny-allと全jobのexplicit opt-in。
- `PERM-002`: 各permissionがjobの一つの必要operationへ対応する。
- `PERM-003`: OIDC token発行をexact federation jobへ限定する。
- `PERM-004`: Privileged jobをtrusted refとlive protected Environmentへ限定する。
- `PERM-005`: Reusable workflow callerもexplicitでpurpose-boundなpermissionを渡す。
- `PERM-006`: Missing／partial／stale／failed verificationを`PASS`へ丸めない。

Check変更時は`check_context_version: "1.0"`、`applies_to`、responsible role、check固有のthreat actor／scenario／
why required、verification、evidence、mappingを同時にreviewする。

## Verification boundary

本controlのtop-level verificationは`manual`である。

- Static: `PSB-CICD-003`の`excessive-permissions` auditで明白な構造上の問題を検出する。
- Semantic: Reviewerがjob operationとpermissionを一対一で照合する。
- Live: GitHub UIまたはapproved read-only APIでdefault、required check、Environmentを確認する。
- Harmless drill: read-only jobの成功、`write-all`変更のscanner拒否、未許可ref／未承認Environmentの停止を確認する。

`make verify-control CONTROL=PSB-CICD-004`はlive reviewがないため`NOT_CHECKED`を表示してexit `2`となる。
これをtool failureやPASSへ変換しない。Fixture、README、secure YAMLの存在をlive evidenceとして扱わない。

Evidenceにはtarget repository、exact revision、取得元、取得時刻、reviewer、workflow inventory、permission review、
current provider setting、harmless drill resultを含める。Token、secret、private payload、provider-valid credentialを保存しない。

## Relationship to other controls

- [`PSB-CICD-001`](../action-sha-pinning/README.md): Action／reusable workflowのimmutable reference。
- [`PSB-CICD-002`](../actions-command-injection/README.md): Expressionからshellへのinjection。
- [`PSB-CICD-003`](../actions-static-analysis/README.md): Pinned scannerとstatic finding／error semantics。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): Fork／untrusted PRのcredential-free boundary。
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): OIDC claims、audience、cloud trust、exchange。
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner image、network、lifecycle、teardown。
- [`PSB-CICD-008`](../privileged-control-plane-change/README.md): Provider setting変更のidentity、approval、audit。
- [`PSB-SOURCE-004`](../../source-protection/source-access-credential-lifecycle/README.md): External source credential lifecycle。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): Organization-wide Actions policy。

別controlの実装をcopyして見かけ上self-containedにしない。

## Framework and guide rules

READMEは関連するframeworkとguideをリンク形式で一覧化する。Current reviewed mappingはGitHub Security Guidanceの
`GHAS-CONCEPT-GITHUB-TOKEN`、`GHAS-REF-SECURE-USE`、repository／organization Actions administrationと、
OpenSSF OSPS Baseline `2026.02.19`の`OSPS-AC-04.01`／`OSPS-AC-04.02`である。

Mappingはrepository configurationとreview procedureの関係を示すだけで、organization adoptionやformal complianceを
示さない。SLSA、SSDF、MITRE ATT&CK等はexact requirementへのdirect evidenceをreviewできない限り追加しない。

## Required verification after changes

Repository rootから次を実行する。

```bash
python3 -m unittest tests.test_control_metadata tests.test_run_controls
make validate-controls
make verify-control CONTROL=PSB-CICD-004
```

最初の二つはexit `0`、最後は`NOT_CHECKED`を表示してexit `2`である。Generated index、mapping、checklistはcanonical
metadataから再生成可能であることを確認するが、task指示どおりcommit対象へ含めない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
