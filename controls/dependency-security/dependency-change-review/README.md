# PSB-DEPS-004: Dependency change review

## このcontrolを一枚で理解する

### セキュリティ上の問題

Dependency更新は外部codeを製品へ取り込む変更だが、通常のcode reviewでは新しいdirect／transitive
dependencyや既知脆弱性を見落としやすい。

### 誰から、または何から守るか

侵害されたmaintainer／update account、既知の脆弱なversion、意図せず追加されたtransitive dependency、
dependency review serviceの失敗から守る。

### 何が対象か

Default branchへmergeするpull requestのsupported manifest／lockfileと、そのbase-to-head dependency差分。

### 何をするか

Dependency変更をPR上で表示し、changed dependencyにhigh以上の既知脆弱性があればrequired checkを失敗させる。

### 成功状態

Dependency差分が表示され、known-high finding、job error、cancelled job、missing checkのいずれでもmergeできない。

### 対象外・残余リスク

未知脆弱性、advisory未登録のmalicious package、registry origin、artifact hash、install script、provenance、
merge後に発見された脆弱性は別controlの対象である。

## そもそもこのcontrolは必要か

必要性は、現在のPR gateで次の3点を満たしているかだけで判断します。

| Question | Yes | No |
|---|---|---|
| Dependency変更PRでdirect／transitive差分が表示されるか | 既存結果を利用 | このcontrolが必要 |
| 基準以上の既知脆弱性でcheckが失敗するか | 既存結果を利用 | このcontrolが必要 |
| Failed／error／missing checkでmergeできないか | 別workflowは不要 | Ruleset設定が必要 |

既存SCAが3点すべてを満たすなら、このworkflowを追加しません。既存check名、対象branch、negative test結果を
このcontrolのadoption evidenceとして記録します。Merge後または定期実行だけのSCAは代替になりません。

## 重要なのは3点だけ

| Check | 確認すること | 導入完了の判断 |
|---|---|---|
| `DCR-001` Dependency diff | PRで追加・更新されたdirect／transitive dependencyが表示される | Safe updateの実差分を確認 |
| `DCR-004` Risk gate | Changed dependencyのhigh／critical known vulnerabilityでjobが失敗する | Inert negative PRがfailure |
| `DCR-009` Merge enforcement | Failure、error、cancel、missing checkをmerge許可にしない | Rulesetによる拒否を確認 |

Workflow fileの存在やlocal testの`PASS`だけでは導入完了ではありません。

## 最短の導入手順

### Prerequisites

- GitHub dependency reviewを利用できるrepository plan
- GitHub dependency graphが有効
- 対象manifest／lockfileが
  [supported package ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems)
  に含まれる
- GitHub-hosted runnerとrepository administrator権限

Unsupported manifestまたはtransitive dependencyを取得できないecosystemでは、このprofileを導入済みとしません。

### 1. Workflowをcopyする

Adopter repository rootから実行します。既存workflowは上書きしません。

```bash
test ! -e .github/workflows/dependency-review.yml
mkdir -p .github/workflows
cp controls/dependency-security/dependency-change-review/secure/github/dependency-review.yml \
  .github/workflows/dependency-review.yml
```

Referenceは`high`以上をblockします。基準変更はSecurity ownerが明示的にreviewしてください。

### 2. Required checkにする

1. Workflowをdefault branchへ通常PRで追加する。
2. Dependency-only PRを1回作り、job名`Dependency Review`を確定する。
3. `Settings` → `Rules` → `Rulesets`でdefault branch向けbranch rulesetを作る。
4. `Enforcement status`を`Active`にする。
5. `Require status checks to pass`または`Require workflows to pass before merging`で
   `Dependency Review`を必須にする。
6. Bypass主体を必要最小限にする。

Organization-wide設定は
[Enforcing dependency review across an organization](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/enforce-dependency-review)、
ruleset項目は
[Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
を参照します。

## 具体的に何を試すか

Sandbox repositoryまたは削除予定test branchで、次の順番どおり確認します。

| Test | 操作 | Expected result |
|---|---|---|
| 1. Safe diff | 承認済みdependencyをlockfile-onlyで更新 | Direct／transitive差分が表示されjob成功 |
| 2. Known vulnerable | 修正済みのknown-high versionをinstallせずlockfileへ記録 | Job failure |
| 3. Failed merge | Test 2のfailureを残してmergeを試す | Rulesetが拒否 |
| 4. Missing/error | Jobをcancel、またはrequired checkが未生成の状態にする | Rulesetが拒否 |

Negative testでは[GitHub Advisory Database](https://github.com/advisories)から対象ecosystemの修正済みversionを選び、
dependency codeをinstall、import、executeしません。npmの例:

```bash
npm install --package-lock-only --ignore-scripts --save-exact PACKAGE@AFFECTED_VERSION
```

Test用PRとbranchは結果を記録した後に削除します。実在malware、credential、production dependencyを使いません。

## 判定

| State | Meaning | Merge |
|---|---|---|
| `PASS` | Supported diffを評価しthreshold findingなし | 他の条件を満たせば候補 |
| `FAIL` | Threshold以上のknown vulnerability | Block |
| `ERROR` | Action、API、runner、graphの実行失敗 | Block |
| `NOT_CHECKED` | Unsupported ecosystem、empty coverage、live未確認 | 導入済みとしない |

Snapshot warningがretry後も残る場合は、successを完全な評価と推測しません。Action conclusionと表示された差分を確認し、
完全性を判断できなければ`NOT_CHECKED`とします。Recoveryはgraph、plan、runner、API、manifest coverageを修復して
再実行します。`warn-only`やrequired check解除で通しません。

## Local regression test

Repository rootから実行します。

```bash
make verify-control CONTROL=PSB-DEPS-004
```

このtestは[`secure/github/dependency-review.yml`](secure/github/dependency-review.yml)について次を確認します。

- `pull_request`、read-only permission、full SHA-pinned Action
- Vulnerability check、high threshold、runtime／development／unknown scope、blocking mode
- [`insecure fixture`](insecure/github/dependency-review.yml)の`warn-only: true`を拒否
- Missing workflowをclean resultにしない

Local testはGitHub dependency graph、ruleset、provider health、実PRのmerge拒否を証明しません。

Expected outputと終了状態:

```text
PASS pull-request dependency review is SHA-pinned and read-only
PASS high-severity changed dependencies use blocking mode across all scopes
PASS warn-only configuration is rejected and missing workflow remains ERROR
NOT_CHECKED live dependency diff and required-ruleset merge rejection
```

このreferenceが保たれていればexit `0`、workflow policy違反はnon-zero、input unavailableはtest内部で
`ERROR`として区別されます。`NOT_CHECKED`はlocal testの失敗ではなく、live verificationが別途必要という境界です。

## 誰が何をするか

- Developer: Manifestとlockfileを同じdependency-only PRへ含める。
- Repository administrator: Dependency graph、workflow、active ruleset、required checkを設定する。
- Security: Severity threshold、negative test結果、unsupported coverageをreviewする。
- Platform／SRE: Runnerとprovider outageを復旧し、障害時にrequired checkを外さない。

## 他controlとの分担

- [`PSB-DEPS-001`](../release-cooldown/README.md): Registry routeとrelease cooldown
- [`PSB-DEPS-002`](../install-script-execution/README.md): Install時のcode execution
- [`PSB-DEPS-003`](../lockfile-integrity/README.md): Exact version、frozen graph、artifact hash
- [`PSB-DETECT-001`](../../detection-verification/integrity-verified-scanner/README.md): Repository／artifact全体の継続SCA
- [`PSB-CICD-001`](../../cicd-security/action-sha-pinning/README.md): Action SHA pin
- [`PSB-CICD-004`](../../cicd-security/actions-least-privilege/README.md): Workflow permission
- [`PSB-CICD-005`](../../cicd-security/untrusted-pr-boundary/README.md): Untrusted PR境界
- [`PSB-REL-001`](../../release-integrity/signature-provenance-verification/README.md): Provenance verification
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Exception lifecycle

License policy、non-author approval、provider-neutral lockfile parserをこの基本profileへ含めません。

## Evidence and rollback

導入証跡にはrepository、default branch、取得時刻、supported manifest、workflow SHA、active ruleset、required check、
4つのlive test結果を残します。Token、private package名、source code、raw logは公開証跡へ保存しません。

Rollback時は代替のPR dependency gateを先に有効化し、rulesetの該当required checkとcopyしたworkflowだけを
review付きで外します。Dependency graph、branch protection、他のsecurity workflowは無効化しません。

## Limitations

- GitHub plan、dependency graph、supported ecosystem、advisory dataへ依存する。
- Clean resultは未知脆弱性やmalicious packageがないことを保証しない。
- Snapshot warningのretryはprovider dataの完全性を証明しない。
- Static repository testはlive merge enforcementを証明しない。
- Mappingはformal complianceやcomplete supply-chain coverageを意味しない。

## Frameworks and guides

- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-VM-05](https://baseline.openssf.org/versions/2026-02-19#osps-vm-05)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATT&CK T1195.001](https://attack.mitre.org/techniques/T1195/001/)
- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [Configure the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- [Dependency Review Action](https://github.com/actions/dependency-review-action)
- [GitHub dependency graph](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [`REF-DEPS-002` source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-deps-002)
