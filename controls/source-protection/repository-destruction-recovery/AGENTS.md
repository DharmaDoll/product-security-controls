# PSB-SOURCE-005 implementation instructions

このfileは`PSB-SOURCE-005`固有の実装境界を定める。repository rootと`controls/`の`AGENTS.md`を
先に読むこと。

## Control essence

- Domainは`source-protection`である。
- 対象は製品の再ビルド、security patch、incident investigationに不可欠なcritical repositoryである。
- 実効性は、GitHubの削除制限、重要refのruleset、GitHub管理者から独立したretention-locked backup、
  隔離restore drillから生まれる。
- JSONへの自己申告、synthetic evidence、fixtureのPASSをorganizationの安全性として扱わない。

## Atomic checks

既存参照を安定させるためIDをrenumberしない。

- `RDR-001`: product ownerがcritical repositoryをGitHub numeric IDで特定する。
- `RDR-002`: memberのrepository削除・移管を禁止し、重要branch／tagの削除とforce pushをrulesetで
  制限する。
- `RDR-003`: GitHub Organization Ownerが削除できない別security accountにcurrent backupを保持する。
- `RDR-006`: 隔離先への実restoreとproduct build／patch確認をRPO／RTO内に行う。

checkを変更する場合は`control.yaml`の`applies_to`、context、verification、mappingも更新する。

## Implementation rules

- READMEはGitHub管理者が実施する画面設定、backup boundary、restore手順を具体的に示す。
- provider-neutralな架空のpolicy、evidence schema、assessment adapterを追加しない。
- GitHub設定を自動変更するscriptを追加しない。read-only commandまたは明示的な管理者操作にする。
- backup credentialへrepository admin、delete、Organization Owner権限を与えない。
- production repositoryをself-testで削除、上書き、renameしない。
- GitHub live state、backup storage、restore結果を見ていない場合は、導入済み・検証済みと主張しない。

## Verification boundary

`tests/test.sh`はtemporary local Git repositoryをmirror backupし、source消失後にbranch／tagを復元できる
ことと、不完全なrestoreを検出できることだけを確認する。GitHub organization setting、storage lock、
RPO／RTO、Issues／PR等の復元を証明するtestへ見せかけない。

変更後は次を実行する。

```bash
bash controls/source-protection/repository-destruction-recovery/tests/test.sh
make verify-control CONTROL=PSB-SOURCE-005
make validate-controls
```

metadata変更後はrepository generatorを実行し、PSB-SOURCE-005に由来する生成差分をreviewする。
