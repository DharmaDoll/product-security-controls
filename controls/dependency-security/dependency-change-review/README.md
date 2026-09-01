# PSB-DEPS-004: Dependency change review

## このcontrolを一枚で理解する

### セキュリティ上の問題

Pull requestでdirect／transitive dependency、version、scope、licenseが変わっても、通常のcode reviewだけでは
base-to-headの変更範囲や既知脆弱性を見落とし、未reviewのcomponentをmergeしやすい。

### 誰から、または何から守るか

侵害されたmaintainer／registry、malicious dependency、dependency confusion、既知脆弱性、license不適合、
不完全なdependency graph、review bot／provider障害、authorによる自己承認から守る。

### 何が対象か

Default branchをbaseとするpull request、supported manifest／lockfile、direct／transitive dependency差分、
GitHub dependency graph、Dependency Review Action、required check、non-author approval、license policy。

### 何をするか

GitHub Dependency Review Actionでbase-to-head dependency差分を取得し、high以上の既知脆弱性と明示的な
SPDX license policyを評価する。そのworkflowとauthor以外のreviewをactive rulesetのmerge条件にする。

### 成功状態

Supported graphの変更がPRに表示され、policy違反、Action／graph error、missing required check、最新差分の
non-author approval欠落がmergeを止める。Unsupportedまたはlive未確認は`NOT_CHECKED`として残る。

### 対象外・残余リスク

Clean resultはdependencyが無害であることを保証しない。未知脆弱性、advisory未登録のmalicious code、
artifact hash、registry origin、install script、provenance、runtime behaviorは別controlの対象である。

## セキュリティ向上の効果はどこから生まれるか

このcontrolはGitHub-nativeなhybrid implementationです。Security効果は次の実設定から生まれます。

1. GitHub dependency graphが実repositoryのsupported manifest／lockfileを解析する。
2. Pull requestでDependency Review Actionがbase-to-head差分を評価する。
3. Active rulesetが`Dependency Review`をrequired workflow／status checkにする。
4. RulesetとCODEOWNERSが最新差分へのnon-author approvalを要求する。
5. Failure、error、missing check、unsupported coverageをmerge許可へ変換しない。

[`secure/github/dependency-review.yml`](secure/github/dependency-review.yml)、このREADME、fixtureをcopyしただけでは
enforcementになりません。Live repositoryでdependency graph、ruleset、required check、review ruleを有効にし、
positive／negative self-testを実行してください。

## 誰が何をするcontrolなのか

| Role | Action | Completion state |
|---|---|---|
| Developer／update bot | Manifestとlockfileを同じdependency-only PRで変更する | Base-to-head diffが生成可能 |
| Dependency reviewer | Direct／transitive path、scope、advisory、license unknownを確認する | Author以外が最新差分を承認 |
| Repository administrator | Graph、workflow、ruleset、required check、CODEOWNERSを設定する | Failure／missing reviewではmerge不可 |
| Security／Legal | Severity threshold、SPDX allowlist、例外をreviewする | Policy ownerと根拠が明確 |
| Platform／SRE | Organization required workflow、runner、provider outageを管理する | Outage時もrequired checkを外さない |

## 最短の導入手順

### Prerequisites

- GitHub.com public repository、またはdependency reviewを利用できるprivate repository
- Repository administrator権限
- GitHub dependency graphが有効
- 対象fileが
  [supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
  に含まれる
- GitHub-hosted runner
- Product固有のreview済みvulnerability／license policy

### 1. Workflowをcopyする

Adopter repository rootから実行します。既存workflowを上書きしません。

```bash
test ! -e .github/workflows/dependency-review.yml
mkdir -p .github/workflows
cp controls/dependency-security/dependency-change-review/secure/github/dependency-review.yml \
  .github/workflows/dependency-review.yml
```

Workflowは次を明示します。

- `pull_request`
- Workflow-level `permissions: {}`
- Job-level `contents: read`
- Full SHA-pinned Dependency Review Action
- `high`以上、`runtime, development, unknown`
- Vulnerability／license check有効
- `warn-only: false`
- PRへのwrite permissionなし

Referenceの`allow-licenses`は導入例です。[SPDX License List](https://spdx.org/licenses/)を使い、製品license、
link方式、配布形態、契約に合わせてSecurity／Legalがactivation前にreviewしてください。

### 2. Rulesetを有効にする

1. Harmlessなdependency-only PRを作り、`Dependency Review` jobを1回実行する。
2. `Settings` → `Rules` → `Rulesets`でdefault branch向けbranch rulesetを作る。
3. `Enforcement status`を`Active`にする。
4. Pull requestと最低1名のapprovalを必須にする。
5. Stale approval dismissalまたはlatest pushへのnon-author approvalを有効にする。
6. `Dependency Review` workflow／status checkをrequiredにする。
7. Dependency manifest／lockfileを既存CODEOWNERSへ割り当てる。
8. Bypass主体を必要最小限にする。

GitHub Organizationへ一括適用する場合は
[Enforcing dependency review across an organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)
を使います。詳細なcopy、設定、evidence、rollbackは
[`docs/github-adoption.md`](docs/github-adoption.md)にあります。

## Safe self-test

### Positive

Disposable branchで、既に承認済みでcurrent advisory findingがないdependencyのexact versionだけを更新します。
Manifestとlockfileを同じPRへ含め、dependency codeは実行しません。

期待結果:

- `Dependency Review`が`success`
- Base-to-head dependency差分がsummaryへ表示される
- Author以外のrequired approvalがない間はmergeできない

### Inert negative

Disposable test repositoryまたは削除予定test branchで、
[GitHub Advisory Database](https://github.com/advisories)にある修正済みのknown-vulnerable versionを
manifest／lockfileへ記録します。Packageをinstall、import、executeしません。npmのlockfile-only例は次です。

```bash
npm install --package-lock-only --ignore-scripts --save-exact PACKAGE@AFFECTED_VERSION
```

`high`以上ならjobがfailureとなり、required checkがmergeを止めることが期待結果です。実在malware、credential、
production repositoryをtestに使いません。

### Error and coverage

- Missing、cancelled、timed out、action-required checkでmergeできない。
- Graph／API／runner failureをsuccessへ変換しない。
- Unsupported manifestのempty diffをcontrol successとして記録しない。
- Snapshot warningがretry後も残る場合はAction conclusionを確認する。
- License unknownはmanual reviewへ送り、自動license approvalとして記録しない。

Dependency Review Actionはlicenseを判定できないdependencyを通知しますが、公式仕様上は必ずしもjobをfailさせません。
[Action configuration](https://github.com/actions/dependency-review-action#configuration-options)の境界を保持し、
unknown licenseを自動block済みと主張しません。

## Expected status and recovery

| State | Meaning | Merge |
|---|---|---|
| `PASS` | Supported graphを評価し、threshold／license findingなし | Required review後の候補 |
| `FAIL` | Vulnerability、license、review policy違反 | Block |
| `ERROR` | Action、API、runner、graph、workflow評価失敗 | Block |
| `NOT_CHECKED` | Unsupported ecosystem、live setting未確認、evidenceなし | Blockまたはmanual fallback |

Recoveryはgraph、repository plan、runner、API、manifest coverage、policyを修復して再実行します。Threshold低下、
`warn-only`、required check解除、broad allowで通しません。

## Rollback

1. [`manual review fallback`](docs/manual-review-fallback.md)とownerを先に有効化する。
2. Required workflow／status check entryだけをrulesetからreview付きで外す。
3. Copyした`.github/workflows/dependency-review.yml`だけを通常PRで削除する。
4. Dependency graph、branch protection、他security workflowを一括無効化しない。
5. Adoption stateを`NOT_CHECKED`へ戻し、manual reviewと移行期限を記録する。

## Guidance-first fallback

GitHub機能、plan、supported ecosystemを利用できない場合は
[`docs/manual-review-fallback.md`](docs/manual-review-fallback.md)を正式fallbackとします。

- Dependency-only PR
- Manifestとlockfileの同時提出
- Package manager／provider標準出力によるbase-to-head diff
- Exact version、direct／transitive path、scope、advisory、licenseのreview
- Author以外の最新差分承認
- Protected branch
- 判定不能時のmerge拒否

ChecklistやPR本文をautomation evidenceにしません。GitLab、自前CI、unsupported package manager向けの
provider-neutral adapterは、具体要件とharmless testが揃うまで追加しません。

## Repository verification

Repository rootから実行します。

```bash
make verify-control CONTROL=PSB-DEPS-004
```

直接実行する場合:

```bash
python3 controls/dependency-security/dependency-change-review/scripts/verify_github_workflow.py \
  controls/dependency-security/dependency-change-review/secure/github/dependency-review.yml
```

Local verifierは`0=accepted`、`1=policy finding`、`2=input／parse／tool error`を返します。

Automated testは次を確認します。

- Secure workflowのevent、permission、Action identity、threshold、scope、license policy
- Insecure workflowのprivileged trigger、broad permission、disabled checks、`warn-only`
- Missing workflowが`ERROR`
- 既存offline contractのdirect／transitive delta、advisory freshness、non-author approval、malformed input

既存[`scripts/verify.py`](scripts/verify.py)とnormalized JSONはprovider-neutralなoffline decision contractです。
実lockfileをparseせず、GitHub settingやorganization adoptionを証明しません。

## 6つのatomic check

| Check | Required outcome | Verification boundary |
|---|---|---|
| `DCR-001` | Required checkがexact PR base／headとstable identityへ結び付く | Static＋live |
| `DCR-002` | Supported direct／transitive graph差分が完全に表示される | Hybrid |
| `DCR-004` | High以上のknown vulnerabilityをblockする | Automated＋live |
| `DCR-005` | SPDX allowlistを適用し、unknownをmanual reviewする | Hybrid |
| `DCR-007` | Author以外が最新差分を承認する | Live ruleset |
| `DCR-009` | Action／graph／provider failureをapprovalにしない | Automated＋live |

Source、provenance、exception lifecycleはこの一覧へ重複させず、owning controlをcomposeします。

## 既存controlとの分担

| Control | Responsibility |
|---|---|
| [`PSB-DEPS-001`](../release-cooldown/README.md) | Managed registry routeとrelease cooldown |
| [`PSB-DEPS-002`](../install-script-execution/README.md) | Install-time code executionのdefault deny |
| [`PSB-DEPS-003`](../lockfile-integrity/README.md) | Frozen graph、registry origin、artifact hash |
| `PSB-DEPS-004` | Base-to-head dependency risk reviewとmerge gate |
| [`PSB-CICD-001`](../../cicd-security/action-sha-pinning/README.md) | External Actionのimmutable SHA |
| [`PSB-CICD-004`](../../cicd-security/actions-least-privilege/README.md) | Workflow token permission |
| [`PSB-CICD-005`](../../cicd-security/untrusted-pr-boundary/README.md) | Fork／untrusted PR boundary |
| [`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md) | Repository／artifact全体のSCA |
| [`PSB-REL-001`](../../release-integrity/signature-provenance-verification/README.md) | Signature／provenance expectation |
| [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md) | Exact、owned、time-bound exception lifecycle |

## Evidence boundary

Live adoption evidenceはstable repository identity、取得時刻、dependency graph setting、supported manifest、
workflow path／Action SHA、active ruleset、required check、review rule、positive／negative／error runを含む
organization-owned sanitized recordです。

Fixtureの`PASS`、手書きJSON、workflow fileの存在、framework mapping、catalog statusをlive adoptionへ変換しません。
Token、private package名、source code、raw provider response、license legal adviceをpublic evidenceへ保存しません。

## Limitations

- GitHubのsupported ecosystem、plan、dependency graph data qualityへ依存する。
- Ecosystemによってtransitive relationshipやlicense metadataのcoverageが異なる。
- Action v5はunknown licenseを必ずしもfailさせないため、manual reviewが必要である。
- Snapshot warning retryはprovider dataの完全性を自動的に証明しない。
- Known advisoryがないmalicious package、未知脆弱性、maintainer intentは検出できない。
- Required rulesetとCODEOWNERSのlive enforcementはrepository fixtureで証明できない。
- Offline normalized graphは実package-manager parserではない。
- Framework mappingはsupporting relationshipであり、formal complianceやcomplete coverageではない。

## Frameworks

- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-VM-05.01／05.02／05.03](https://baseline.openssf.org/versions/2026-02-19#osps-vm-05)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATT&CK T1195.001](https://attack.mitre.org/techniques/T1195/001/)
- [SPDX License List](https://spdx.org/licenses/)

Mappingsは[`control.yaml`](control.yaml)のcheck-specific relationshipがcanonical sourceです。

## Implementation guides

- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [Configure the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- [Dependency Review Action](https://github.com/actions/dependency-review-action)
- [GitHub dependency graph](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph)
- [Supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
- [GitHub ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [`REF-DEPS-002` source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-deps-002)
- [Software supply-chain implementation principles](../../../docs/SUPPLY_CHAIN_PRINCIPLES.md)
