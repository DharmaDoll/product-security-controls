# Protected manual dependency review fallback

このrunbookは、GitHub Dependency Review Actionを利用できないrepositoryのfallbackです。Human checklistを
automationと呼ばず、protected branchとnon-author reviewが実際に有効な場合だけmanual controlとして扱います。

## Use this fallback only when

- GitHub以外のSCM／CI providerを使う
- Repository planがDependency Review Actionを提供しない
- Manifest／lockfileが
  [GitHub dependency graphのsupported ecosystem](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
  にない
- Transitive graphがproviderから取得できず、package managerのreview可能な標準出力を使う必要がある

具体的なprovider APIやpackage-manager adapterが承認された場合は、その実装を別profileとしてtestしてから
このfallbackを置き換えます。

## Roles

- Developer／update bot: dependency-only PR、manifest、lockfile、base-to-head diffを提出する。
- Dependency reviewer: exact package、version、direct／transitive path、scope、advisory、licenseを確認する。
- Repository administrator: protected branch、最低1 approval、latest diffの再承認、direct push denyを設定する。
- Security／Legal: threshold、license policy、exceptionをreviewする。

## Required PR contents

1. Base commit full SHAとhead commit full SHA
2. 変更したmanifest／lockfile path
3. Added、removed、updated dependencyのexact package／version
4. Direct／transitive分類と、transitiveの場合の親dependency path
5. Runtime／development／unknown scope
6. Current advisory lookup sourceと取得時刻
7. SPDX license identifierまたは`UNKNOWN`
8. Reviewer、decision、未解決事項
9. Exceptionがある場合は`PSB-GOV-002`のexact decision reference

PR authorが書いた表だけを信用せず、reviewerはlockfile diff、package manager output、advisory sourceをread-onlyで
再確認します。Dependency code、install script、build pluginをreview前のprivileged environmentで実行しません。

## Decision

- `PASS`: 全変更を確認し、threshold以上のknown vulnerability、unapproved license、unknown itemがなく、
  author以外が最新差分を承認した。
- `FAIL`: Vulnerability、license、scope、source、review policyの未解決findingがある。
- `ERROR`: Manifest、lockfile、graph、advisory、license、tool、providerを評価できない。
- `NOT_CHECKED`: Live設定またはrequired evidenceをまだ確認していない。

`ERROR`と`NOT_CHECKED`を`PASS`へ変換しません。Missing transitive dataを「変更なし」と扱いません。

## Harmless self-test

1. Disposable branchでapproved dependencyのlockfile-only updateを作る。
2. Reviewerがbase-to-head差分を再生成し、author作成の一覧と一致することを確認する。
3. Authorだけではprotected branchへmergeできないことを確認する。
4. Review後にcommitを追加し、以前のapprovalだけではmergeできないことを確認する。
5. Advisory sourceまたはdiff commandを意図的に利用不能にしたtestで、review decisionが`ERROR`になることを確認する。

Known-vulnerability negative testを行う場合は、disposable repositoryで修正済みのaffected versionをmanifest／lockfileへ
記録するだけにし、packageをinstall、import、executeしません。

## Evidence and limitations

Evidenceにはrepository、base／head SHA、取得時刻、source、reviewer、protected-branch resultだけを残し、credential、
private package名、source code、raw provider responseを含めません。

Manual reviewはreviewer error、advisory publication delay、package-manager outputの不完全性を防ぎません。Fixtureや
checklistの記入はorganization adoptionを証明しません。継続利用する場合はprovider-native required checkまたは
具体的なread-only adapterへの移行をownerと期限付きで計画します。

## References

- [GitHub dependency review concepts](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [OpenSSF OSPS Baseline 2026.02.19, OSPS-VM-05](https://baseline.openssf.org/versions/2026-02-19#osps-vm-05)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [SPDX License List](https://spdx.org/licenses/)
- [`PSB-GOV-002` exception contract](../../../governance-operations/time-bound-security-exceptions/README.md)
