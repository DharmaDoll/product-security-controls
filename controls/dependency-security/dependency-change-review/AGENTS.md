# PSB-DEPS-004 implementation instructions

このfileは`PSB-DEPS-004`（`dependency-security`）に固有の実装境界を定める。
[repository root instructions](../../../AGENTS.md)と
[control implementation instructions](../../AGENTS.md)を先に読み、共通規約をここへ複製しない。

## Control essence

- このcontrolの本質は、pull requestのbaseからheadで新たに導入されるdependency差分を
  reviewerへ提示し、documented vulnerability／license policy違反と未review状態をmerge前に止めることにある。
- 対象はdirect／transitive dependencyの追加、削除、version、scope、dependency pathである。
  Repository全体の定期scanや、変更されていないdependencyの継続監視を主実装にしない。
- Security効果は、実repositoryでdependency graphを有効にし、review workflowを実行し、
  そのcheckとnon-author approvalをactive rulesetのmerge条件にすることから生まれる。
  Workflow、README、fixtureをcopyしただけではenforcementにならない。
- Advisory、license、graphの取得失敗、unsupported manifest、partial dataを「findingなし」と
  推測しない。評価不能は`ERROR`または`NOT_CHECKED`としてmergeを止める。
- Known-vulnerabilityの不在はdependencyが無害であることを意味しない。未知脆弱性、malicious-but-
  unadvised code、runtime behavior、maintainer intentは残余riskである。

## Chosen implementation profile

このcontrolは次の順序で実装する。

1. **Reference implementation**: GitHub Dependency Review Actionとactive repository／organization
   rulesetを使うGitHub-native profile。
2. **Fallback**: GitHubの対応ecosystem、plan、provider機能を利用できない場合のprotected manual review。
3. **Deferred**: Provider-neutral verifierとpackage-manager adapterは、GitLab、自前CI、または具体的な
   unsupported ecosystem要件が提示されるまで追加しない。

既存のnormalized JSON verifierはoffline decision contractとnegative-test fixtureであり、最短導入経路ではない。
実lockfileをparseしないfixtureの成功をlive adoptionとして扱わず、generic schemaやadapterを増やさない。

## Supported profile and prerequisites

- Primary platformはGitHub.comとGitHub Actionsである。GitHub Enterprise Serverは、対象versionの
  dependency review、license API、Action runtime、GitHub Connect要件を確認してから別profileとして追加する。
- Public repository、またはdependency reviewに必要なGitHub Code Security機能を利用できるprivate
  repositoryを対象にする。
- GitHub dependency graphを有効にし、対象manifest／lockfileが
  [supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
  に含まれることを確認する。対応表にない形式やtransitive graphを取得できない形式をsilent passにしない。
- Repository administratorはworkflow、ruleset、required check、review ruleを変更できる必要がある。
- Securityとproduct ownerはvulnerability threshold、対象scope、license policy、exception authorityを決める。
- Dependency Review Action v5はNode 24を使用する。Self-hosted runnerを選ぶ場合は
  [v5.0.0 release requirements](https://github.com/actions/dependency-review-action/releases/tag/v5.0.0)
  を満たすrunner versionとisolationを先に確認する。ReferenceはGitHub-hosted runnerを使う。
- Reference development environmentはmacOS、VS Code、Python 3.10+、standard shellである。
  Windows-specific sampleは具体要件とtestが揃ってから追加する。

## GitHub reference workflow

Copy元は[`secure/github/dependency-review.yml`](secure/github/dependency-review.yml)とする。
Adopterは既存workflowを上書きせず、`.github/workflows/dependency-review.yml`へcopyまたはreview済みmergeを行う。

Reference workflowは次を満たす。

- Triggerは`pull_request`だけとし、`pull_request_target`でuntrusted headを処理しない。
- Workflow-levelは`permissions: {}`、dependency-review jobは`contents: read`だけにする。
- External Actionはfull 40-character commit SHAへ固定し、version commentを残す。
- `vulnerability-check: true`、`license-check: true`、`warn-only: false`を明示する。
- Reference thresholdは`high`、対象scopeは`runtime, development, unknown`とする。
- `comment-summary-in-pr: never`とし、単なる表示のために`pull-requests: write`を付けない。
- `show-openssf-scorecard: false`とし、このcontrolのblocking decisionに使わない追加signal／API callを増やさない。
- Snapshot warningはbounded retryする。Retry後もpartialな場合のAction conclusionをlive testし、成功扱いに
  なるprovider behaviorを確認した場合は、minimal fail-closed checkを追加するかprofileを`NOT_CHECKED`にする。
- Reference baselineに`allow-ghsas`、wildcard package exclusion、broad group exclusion、permanent license
  exceptionを置かない。

計画時点でreview済みのAction identityは次である。

- [`actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294`](https://github.com/actions/dependency-review-action/commit/a1d282b36b6f3519aa1f3fc636f609c47dddb294)
  (`v5.0.0`)

Action update時はrelease note、exact commit、runtime、input schema、license behavior、snapshot warning、
minimum runner versionをsemantic reviewする。Tagをそのままworkflowへ入れない。

## Vulnerability and license policy

- Reference vulnerability thresholdは`high`以上である。これはadopterが明示reviewできるbaselineであり、
  lower severityを安全と断定するものではない。
- Runtime、development、unknown scopeを対象にする。Test dependencyもbuild、code generation、developer
  endpointで実行され得るため、referenceから除外しない。
- LicenseはSPDX identifierでallowlistを定義する。Reference allowlistは導入例であり、製品license、link方式、
  配布形態、契約、法務判断に合わせてSecurity／Legalがactivation前にreviewする。
- `deny-licenses`はupstreamでdeprecatedとされているため、新しいreferenceの主設定にしない。
- [Dependency Review Action configuration](https://github.com/actions/dependency-review-action#configuration-options)
  はlicense不明を通知しても必ずしもjobをfailさせない。Unknown licenseを自動block済みと主張せず、
  non-author reviewerが確認し、解消またはexactなtime-bound exceptionがない限りmergeしない。
- `allow-dependencies-licenses`をname-only、namespace-wide、恒久例外として使わない。例外lifecycleは
  [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)へ委譲する。

## Roles and live enforcement

- Developer／update bot: manifestとlockfileを同じPRで変更し、通常installではfrozen／locked modeを使う。
  Actionやrulesetを同じdependency updateで弱めない。
- Dependency reviewer: Action summary、direct／transitive path、scope、known vulnerability、license unknown、
  release contextを確認し、最新pushをauthor以外として承認する。
- Repository administrator: dependency graph、workflow、required workflow／status check、CODEOWNERS、stale
  approval dismissal、bypass制限を有効化する。
- Security／Legal: vulnerability threshold、SPDX allowlist、exception、unsupported ecosystem、live negative
  resultをreviewする。
- Platform／SRE: Organization-wide required workflow、runner compatibility、provider outage handling、audit
  availabilityを管理する。Outage時にrequired checkを外さない。

GitHubでは[required workflowによるorganization enforcement](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)
または[protected branch／ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
を使う。最低1 approval、latest pushへのnon-author approvalまたはstale approval dismissal、dependency
fileのCODEOWNER、required dependency review checkを同じdefault branchへ適用する。

## Minimal adoption path

READMEと[`docs/github-adoption.md`](docs/github-adoption.md)は次の最短経路を先に示す。

1. Repository plan、dependency graph、supported manifest／lockfile、runner、admin authorityを確認する。
2. Reference workflowを`.github/workflows/dependency-review.yml`へcopyする。既存fileは上書きしない。
3. Product固有のSPDX allowlistをreviewし、example値のまま採用しない。
4. Harmlessなdependency-only PRを作り、workflowとstatus check名を確定する。
5. Default branchのactive rulesetでworkflow／checkをrequiredにする。
6. Non-author approval、latest push review、dependency CODEOWNERを有効にする。
7. Safe positive、inert vulnerable negative、provider error、unsupported manifest、license unknownを確認する。

Expected stateは「Actionが存在する」ではなく、対象branchでfailure、error、missing check、review欠落がmergeを
止めることである。Recoveryはgraph、plan、runner、API、manifest coverage、policyを修復して再実行することであり、
`warn-only`、threshold緩和、required check解除で通さない。

Rollbackはcopyしたworkflowとそのrequired-check entryだけをreviewの上で外す。Dependency graph、branch
protection、他security workflow、organization rulesetを一括無効化しない。Rollback後はこのcontrolを
`NOT_CHECKED`として記録し、manual fallbackを明示的に有効化する。

## Guidance-first fallback

GitHub-native profileを利用できない場合は[`docs/manual-review-fallback.md`](docs/manual-review-fallback.md)
を正式fallbackとする。

- Dependency変更を機能変更から分離する。
- Manifestとlockfileを同じPRへ含める。
- Package manager／providerの標準commandでbase-to-head direct／transitive差分を取得する。
- Exact version、dependency path、scope、advisory、licenseをauthor以外がreviewする。
- 判定不能、unsupported、partial outputはmergeしない。
- Protected branchでreviewなしのmergeを拒否する。

Manual checklist、PR本文、自己申告JSONをautomation済みevidenceにしない。Provider settingを実確認できない場合は
`NOT_CHECKED`、tool／API／permission failureは`ERROR`である。

## Relationship to other controls

- [`PSB-DEPS-001`](../release-cooldown/README.md)はmanaged registry routeとrelease cooldownを所有する。
- [`PSB-DEPS-002`](../install-script-execution/README.md)はlifecycle script／source buildのdefault denyを所有する。
- [`PSB-DEPS-003`](../lockfile-integrity/README.md)はmanifest、frozen graph、registry origin、artifact hashを所有する。
- [`PSB-CICD-001`](../../cicd-security/action-sha-pinning/README.md)はAction SHA pinとAction advisoryを所有する。
- [`PSB-CICD-004`](../../cicd-security/actions-least-privilege/README.md)はworkflow token permissionを所有する。
- [`PSB-CICD-005`](../../cicd-security/untrusted-pr-boundary/README.md)はfork／untrusted PR境界を所有する。
- [`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md)はrepository／artifact全体の
  vulnerability scanを所有する。
- [`PSB-REL-001`](../../release-integrity/signature-provenance-verification/README.md)はsignature／provenance
  expectation verificationを所有する。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)はshared exception
  lifecycleを所有する。

このpackageでregistry verifier、artifact hash、provenance verifier、exception register、general-purpose SCA、
CODEOWNERS engine、ruleset mutatorを複製しない。

## Verification strategy

Repository testは次のsecurity propertyだけを自動検証する。

- Reference workflowが`pull_request`、deny-all top permission、job-level `contents: read`を使う。
- External Actionsがfull commit SHAである。
- Vulnerability／license checksが有効で、threshold、scope、`warn-only`がbaselineを弱めない。
- Broad allow、PR write permission、privileged triggerがない。
- Insecure workflow fixtureがpolicy findingとして拒否される。
- Missing、unreadable、unsupported workflow inputはexit `2`の`ERROR`である。
- 既存normalized graph verifierのsafe、inert finding、stale／partial／malformed evidence testが維持される。

Workflow pin検査は[`PSB-CICD-001` verifier](../../cicd-security/action-sha-pinning/scripts/verify.py)を再利用する。
Dependency-review固有設定だけを小さなstandard-library verifierで確認し、general YAML engineを作らない。

Live verificationはsandbox repositoryで次を確認する。

- Safe dependency-only PRが成功する。
- Dependency codeをinstallせず、known-vulnerable versionを示すinert lockfile PRが失敗する。
- Author approvalだけ、最新push未承認、required check failure、missing checkがmergeできない。
- Graph／API／runner failureがmergeできない。
- Unsupported manifestがempty safe diffと誤解されない。
- Unknown licenseがmanual reviewへ送られ、自動PASS evidenceにならない。

## Evidence boundary

- Repository fixtureはreference behaviorのregression evidenceであり、live GitHub adoptionではない。
- Organization adoption evidenceは、stable repository identity、取得時刻、dependency graph setting、active
  ruleset、required workflow／check、review rule、supported manifest、safe／negative run URLまたはsanitized
  receiptを含むread-only recordに限る。
- Token、private package名、raw dependency output、source code、PR本文、license legal adviceをpublic evidenceへ
  copyしない。
- Provider evidenceを取得できない状態は`NOT_CHECKED`、collector／permission／API failureは`ERROR`とする。
- Synthetic `PASS`、手書き`secure: true`、README文字列だけをorganization security stateとして扱わない。

## Metadata and documentation

- [`control.yaml`](control.yaml)をatomic checkのcanonical sourceとし、`check_context_version: "1.0"`と
  row固有のactor、scenario、target、why-requiredを保つ。
- `DCR-001`、`DCR-002`、`DCR-004`、`DCR-005`、`DCR-007`、`DCR-009`を本controlの中心とする。
  Source integrity、provenance、exception lifecycleの重複checkを残す場合は、owning controlにない独自の
  review outcomeを説明できなければならない。
- READMEのmandatory one-page summary直後に、security effect、roles、prerequisites、copy、activation、
  self-test、expected status、recovery、server-side enforcement、rollback、residual riskを置く。
- Framework mappingはcheck-specificなsupporting relationshipであり、compliance、package safety、complete
  supply-chain coverage、organization adoptionの主張ではない。
- Mapping versionは自動更新しない。Source version変更時はidentifier、requirement text、relationship、
  confidence、rationaleを再reviewする。

## Framework references

- [OpenSSF OSPS Baseline 2026.02.19, OSPS-VM-05.01／05.02／05.03](https://baseline.openssf.org/versions/2026-02-19#osps-vm-05)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATT&CK T1195.001: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [SPDX License List](https://spdx.org/licenses/)

## Implementation guidance references

- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [Configure the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- [Dependency Review Action](https://github.com/actions/dependency-review-action)
- [GitHub dependency graph](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph)
- [Supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
- [Enforce dependency review across an organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)
- [Available rules for GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Repository-owned dependency review source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-deps-002)
- [Software supply-chain implementation principles](../../../docs/SUPPLY_CHAIN_PRINCIPLES.md)

## Required verification after changes

Repository rootから少なくとも次を実行する。

```bash
bash controls/dependency-security/dependency-change-review/tests/test.sh
make verify-control CONTROL=PSB-DEPS-004
make validate-controls
```

`control.yaml`のcheck、mapping、status、implementation pathを変更した場合はcanonical generatorを実行し、
`PSB-DEPS-004`由来のindex、mapping、checklist差分だけをreviewする。Testを通すためにAction pin、threshold、
scope、review、required check、fail-closed behaviorを弱めない。
