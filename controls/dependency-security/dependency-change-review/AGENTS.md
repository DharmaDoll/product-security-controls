# PSB-DEPS-004 implementation instructions

このfileは`PSB-DEPS-004`に固有の実装境界だけを定める。
[repository instructions](../../../AGENTS.md)と
[control instructions](../../AGENTS.md)にある共通規約をここへ複製しない。

## Control essence

Dependency変更はcode変更である。このcontrolが所有する成果は、pull requestで新しく追加・更新される
direct／transitive dependencyをmerge前に可視化し、既知の重大な脆弱性をrequired checkで止めることだけである。

次の3つを一読で確認できる状態を保つ。

1. `Dependency diff`: supported manifest／lockfileのbase-to-head dependency差分が表示される。
2. `Risk gate`: changed dependencyにhigh以上の既知脆弱性があればjobが失敗する。
3. `Merge enforcement`: failed、error、cancelled、missing checkではmergeできない。

Workflow fileやREADMEをcopyしただけではsecurity効果は発生しない。実repositoryでdependency graphと
active rulesetを有効にし、live pull requestで3つの成果を確認して初めて導入済みとする。

## When this control is needed

- PRでdependency差分を評価するrequired SCA／dependency reviewがないrepositoryには必要である。
- 既存のSCAが上記3成果をすべて満たす場合、別workflowを追加しない。そのexisting checkを
  `PSB-DEPS-004`の実装として記録する。
- Merge後または定期実行だけのSCAは、このcontrolの代替ではない。

## Deliberately delegated concerns

このpackageへ次を実装しない。

- Registry route、release cooldown: [`PSB-DEPS-001`](../release-cooldown/README.md)
- Install script／source build: [`PSB-DEPS-002`](../install-script-execution/README.md)
- Exact version、frozen lockfile、artifact hash: [`PSB-DEPS-003`](../lockfile-integrity/README.md)
- General SCA／artifact scanning: [`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md)
- Action SHA管理: [`PSB-CICD-001`](../../cicd-security/action-sha-pinning/README.md)
- Workflow permission: [`PSB-CICD-004`](../../cicd-security/actions-least-privilege/README.md)
- Untrusted PR境界: [`PSB-CICD-005`](../../cicd-security/untrusted-pr-boundary/README.md)
- Provenance: [`PSB-REL-001`](../../release-integrity/signature-provenance-verification/README.md)
- Exception lifecycle: [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)

License policy、CODEOWNER approval、provider-neutral lockfile normalization、synthetic evidenceを基本profileへ
追加しない。具体的なadopter要件がある場合だけ、別profileとして責任者とlive testを定義する。

## Reference implementation

Referenceは[`secure/github/dependency-review.yml`](secure/github/dependency-review.yml)だけである。

- Triggerは`pull_request`だけにする。
- Workflow-levelは`permissions: {}`、job-levelは`contents: read`だけにする。
- Dependency Review Actionをreview済みfull commit SHAへ固定する。
- `vulnerability-check: true`、`fail-on-severity: high`、`warn-only: false`を明示する。
- Runtime、development、unknown scopeを除外しない。
- Snapshot warningをbounded retryする。
- Checkout、PR comment、write permission、scorecard、broad allow、package exclusionを追加しない。

Pinned Action:

- [`actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294`](https://github.com/actions/dependency-review-action/commit/a1d282b36b6f3519aa1f3fc636f609c47dddb294)
  (`v5.0.0`)

Action更新時はrelease、exact commit、runtime、input behaviorを再reviewする。Floating tagを入れない。

## Verification contract

Repository testはreference workflowの次だけを確認する。

- `pull_request`、deny-all top permission、`contents: read`
- Full SHA-pinned Dependency Review Action
- Vulnerability check、high threshold、全scope、blocking mode
- Insecure fixtureの`warn-only: true`を拒否
- Missing workflowをclean resultにしない

これはlive GitHub settingを証明しない。導入先では次の4ケースを必ず試す。

1. Safe lockfile-only updateでdependency差分が表示される。
2. Installせずに記録した既知high vulnerabilityでjobが失敗する。
3. Failed jobのままmergeできない。
4. Jobをcancelまたはrequired checkをmissingにしてもmergeできない。

Unsupported ecosystem、empty diff、snapshot warningのままでは導入済みとしない。Providerの仕様上
評価できない状態は`NOT_CHECKED`、実行失敗は`ERROR`であり、どちらも`PASS`ではない。

## Metadata

[`control.yaml`](control.yaml)には`DCR-001`、`DCR-004`、`DCR-009`の3 checkだけを置く。
各checkは固有のactor、scenario、target、why-requiredを持つ。Framework mappingはsupporting
relationshipであり、dependencyの安全性、organization adoption、formal complianceを主張しない。

## References

- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [Configure the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- [Supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
- [GitHub ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19#osps-vm-05)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATT&CK T1195.001](https://attack.mitre.org/techniques/T1195/001/)

## Required local test

Repository rootから実行する。

```bash
make verify-control CONTROL=PSB-DEPS-004
make validate-controls
```

`control.yaml`変更後はcanonical generatorを実行して参照切れがないことを確認する。Testを通すために
threshold、scope、required check、fail-closed behaviorを弱めない。
