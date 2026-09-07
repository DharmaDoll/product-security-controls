# PSB-CICD-009: GitHub Actions cacheをtrusted writerと非特権consumerへ隔離する

## このcontrolを一枚で理解する

### セキュリティ上の問題

CI cacheはrunをまたいでbytesを渡す共有channelです。Cacheを書ける低信頼または侵害されたjobと、
cacheからtoolやdependencyを実行するrelease／deploy jobがつながると、tokenやsecretを直接渡していなくても
後続の高権限jobへcode executionを持ち込めます。GitHub Actions cacheはworkflow identityでは隔離されません。

### 誰から、または何から守るか

Untrusted PR作成者、侵害されたdependencyやAction、cacheを書ける低権限job、広すぎるkeyとprefix fallback、
cache内容を検証済みdependencyだと誤認する実装、cache serviceや確認手順の失敗から守ります。

### 何が対象か

GitHub Actionsのcache producer／consumer、workflow trigger、cache key、cache path、default branch scope、
dependency lockfile、package managerのintegrity verification、release／deploy／signing jobです。

### 何をするか

Protected default branchへの`push`だけにcache保存を許し、`pull_request`はrestore-onlyにします。
Package download cacheだけをexact keyで復元し、non-exact restoreを削除してからhash-locked installを行います。
Release、deploy、signing jobはcacheを利用しません。

### 成功状態

Default branch runだけがcacheを保存し、PRはexact cacheまたは空のdownload cacheから同じintegrity verificationを
実行します。Lockfile変更時に旧cacheは使用されず、PRはdefault branch cacheを作成・更新せず、privileged jobは
cacheをconsumeしません。未確認または取得失敗は`NOT_CHECKED`／`ERROR`です。

### 対象外・残余リスク

Repository fileだけではlive GitHub設定やrun結果を証明できません。Trusted default-branch workflow自体の侵害、
GitHub cache serviceやarchive展開処理の侵害、package managerのintegrity defect、self-hosted runnerの永続状態、
cacheの可用性とquotaは別の対策または残余リスクです。

## セキュリティ向上の効果はどこから生まれるか

効果は[`secure/workflow.yml`](secure/workflow.yml)を置いたことではなく、採用repositoryで次の状態を実際に作ることから
生まれます。

- Cache writerをreview済みdefault branchへの`push`へ限定する。
- PRとforkをrestore-onlyにし、default branch cacheへ書かせない。
- Cacheをcredential-freeなtest jobだけで利用し、privileged jobへ渡さない。
- Cache pathをpackage download storeへ限定し、secretや直接実行されるstateを保存しない。
- Lockfile digestをkeyへ含め、non-exact restoreを破棄する。
- Cache hit時もpackage managerのartifact hash verificationを省略しない。

GitHubはcacheをkey、version、branchでscopeしますが、同じrepository／branchの複数workflowはcacheを共有できます。
また、default branch cacheはPRからread可能です。したがってbranch scopeだけではなく、writer、consumer、path、
dependency verificationを一つのdata flowとして確認します。

## 誰が何をするcontrolなのか

| 担当 | 作業 |
| --- | --- |
| Development team | Cache path、lockfile、Python versionを選び、cache hit時もhash-locked installを実行する |
| Repository administrator | Default branch protection、cache利用workflow inventory、trusted save condition、live runを確認する |
| CI platform／organization owner | GitHub plan、runner種別、cache scopeとlow-trust triggerの現行仕様を確認する |
| Release／platform owner | Release、deploy、signing workflowがcacheを使用しないことを確認する |
| Security | Producerからconsumerへのdata flow、negative test、例外、live evidenceをreviewする |

## 最短の導入手順

### 前提条件とtrust assumptions

- GitHub.com ActionsとGitHub-hosted Linux runnerを使用する。
- Default branchは`main`で、変更はreview後にmergeされる。
- ProjectはPython `3.13.15`と、全direct／transitive wheel hashを持つ`requirements.lock`を使用する。
- Cache miss時に`pip`がdependencyを取得できるnetwork accessがある。
- Cache利用jobにはsecret、write permission、OIDC、protected Environmentを与えない。
- Release、deploy、signing jobはcacheを使用しない。

Python version、default branch、lockfile名が異なる場合は、その3点だけを採用先に合わせて変更します。
GitHub Enterprise Server、self-hosted runner、他providerへそのまま適用しません。

### Copyとactivation

1. [`secure/workflow.yml`](secure/workflow.yml)を採用repositoryの`.github/workflows/dependency-cache.yml`へcopyする。
2. `requirements.lock`をrepository rootへ置く。作成と検証は
   [`PSB-DEPS-003`](../../dependency-security/lockfile-integrity/README.md)を使用する。
3. Default branchが`main`でなければ、`push.branches`とsave stepの`github.ref`を同時に変更する。
4. Python versionを変更した場合は、`python-version`と二つのcache keyを同時に変更する。
5. Pull requestでworkflowをreviewし、protected default branchへmergeする。

Global Git、shell、IDE、package manager設定は変更しません。Activationはworkflow fileのmergeだけです。

### Reference data flow

```text
protected main push
  -> exact restore or empty download cache
  -> pip --require-hashes --only-binary=:all:
  -> pip check
  -> main scopeへsave

pull_request / fork
  -> mainまたはPR scopeからrestore-only
  -> non-exact／failed restoreを削除
  -> pip --require-hashes --only-binary=:all:
  -> saveなし

release / deploy / signing
  -> cacheなし
```

## Secure implementation

[`secure/workflow.yml`](secure/workflow.yml)は`actions/cache/restore`と`actions/cache/save`を分離します。
全Actionはreview済みreleaseのfull commit SHAへpinしています。

Cache keyは次のidentityを持ちます。

```text
pip-download / schema v1 / runner OS / runner architecture /
Python 3.13.15 / requirements.lock SHA-256
```

`restore-keys`は指定しません。GitHubのlookupがprimary keyのpartial matchを返す場合にも、`cache-hit`が`true`でなければ
`.cache/pip-downloads`を削除します。Restore自体が失敗した場合も同じclean pathへ戻します。Cacheはperformance optimization
なので、service unavailableはclean downloadへfallbackできます。一方、`pip --require-hashes`、`pip check`、lockfile不在の失敗を
cache missとして継続しません。

Save stepは次の条件を同時に満たす場合だけ実行されます。

```text
event == push
ref == refs/heads/main
exact cache hitではない
dependency integrity verificationが成功済み
```

## Insecure implementation

[`insecure/workflow.yml`](insecure/workflow.yml)は実行されない隔離fixtureです。次の危険なdata flowを示します。
Fixtureの`simulated-release`には実credentialやwrite permissionを与えていません。

- `.venv`という直接実行されるstateをcacheする。
- Lockfile、runtime version、workflow purposeをkeyへ結合しない。
- `restore-keys: python-`で別contextへfallbackする。
- `push` producerとEnvironmentを参照するmanual releaseが同じcache namespaceを使用する。
- Release phaseがrestoreしたPython interpreterをそのまま実行する。

GitHubのlow-trust trigger制限だけでは、侵害されたtrusted producerや別workflowからのpoisoningを防げません。
高権限consumerからcacheを除くことが、このreference profileの最も単純な境界です。

## Verification

Repository fileだけではlive GitHub cache stateを証明できないため、このcontrolは`manual` verificationです。

```bash
make verify-control CONTROL=PSB-CICD-009
```

Live evidenceを入力しないcanonical commandは次を返します。

```text
NOT_CHECKED PSB-CICD-009: manual verification; follow controls/cicd-security/cache-provenance-isolation/README.md#verification
verified 0 control(s); 1 control(s) NOT_CHECKED
```

終了statusは`2`です。これはtool failureでもPASSでもなく、採用先のlive確認が必要という意味です。

### Harmless positive self-test

1. Reviewed `requirements.lock`とworkflowをdefault branchへmergeする。
2. Default branch runで`LOCKFILE_READY`、hash-locked install成功、cache saveを確認する。
3. Lockfileを変更しないPRを作り、restore stepの`cache-hit`が`true`になることを確認する。
4. PRでも同じhash-locked installと`pip check`が成功し、save stepがskippedであることを確認する。

### Harmless negative self-test

1. Test PRで`requirements.lock`をreview可能な別digestへ変更する。
2. Restoreがexact hitにならず、`CACHE_NOT_EXACT clean download cache initialized`が出ることを確認する。
3. Hash-locked clean installを実行し、save stepがskippedであることを確認する。
4. Test前後のdefault branch cache listを比較し、PRが作成・更新していないことを確認する。
5. Release、deploy、signing workflowを検索し、cache-aware Actionまたは同じcache pathを使用していないことを確認する。

Read-only確認例:

```bash
gh run list --workflow dependency-cache.yml --limit 10
gh cache list --ref refs/heads/main --limit 100
```

Live shared cacheを改ざんするnegative testは行いません。Isolated test repositoryがある場合だけ、cache内artifactを変更し、
`pip --require-hashes`が拒否することを追加確認できます。

### 判定

| 状態 | 意味 |
| --- | --- |
| `PASS` | 全workflow inventoryとcurrent provider stateを確認し、positive／negative runが期待どおりだった |
| `FAIL` | Unauthorized save、broad fallback、unsafe path、integrity bypass、またはprivileged cache consumerが存在する |
| `NOT_CHECKED` | Live workflow、setting、run、cache listの一部または全部を確認していない |
| `ERROR` | API、権限、取得、pagination、log parsing等の失敗で状態を評価できない |

## Evidence

Evidenceにはrepository、default branch、workflow path、exact workflow revision、run ID、event、ref、取得時刻、
restore／save実行状態、sanitized key、cache `ref`、consumer permission、runner種別、reviewerを含めます。

Cache listだけではwriter identityや内容の安全性を証明できません。Workflow revision、run log、cache recordを結合します。
Token、secret、cache payload、private source、provider-valid credentialは保存しません。Synthetic fixtureをorganization adoptionの
evidenceとして扱いません。

## Common failure recovery

- `requirements.lock is missing`: lockfile pathを修正し、hash付きlockfileをcommitする。
- Restore action error: workflowはdownload cacheを削除してclean installを続行する。繰り返す場合はGitHub statusとAction pinを確認する。
- `pip --require-hashes` failure: cacheを信用せず、lockfileと取得artifactのdigestをreviewしてから再生成する。
- Unexpected partial hit: `restore-keys`がないこと、key末尾にlockfile digestがあること、non-exact cleanupが実行されたことを確認する。
- PR save warning: PRでsave actionが実行されている。Referenceのevent／ref conditionへ戻す。
- Release scanner finding: release／deploy／signing workflowからcache-aware actionを除去する。

## Rollback

1. `.github/workflows/dependency-cache.yml`からrestore／save stepを削除し、通常のhash-locked installは残す。
2. RepositoryのActions cache画面またはread-only確認後のapproved管理操作で、該当purpose prefixのcacheだけを削除する。
3. Cleanup完了まではrelease／deploy／signingでcacheを有効化しない。

Rollback後はbuild時間とnetwork使用量が増えますが、application buildはcacheなしで成功できなければなりません。

## CI／server-side enforcement

- Default branchのworkflow変更をreview必須にする。Branch／ruleset enforcementは
  [`PSB-CICD-005`](../untrusted-pr-boundary/README.md)のlive verificationで確認する。
- [`PSB-CICD-003`](../actions-static-analysis/README.md)のpinned `zizmor`をrequired checkとして実行し、
  `cache-poisoning` finding、とくにrelease workflowのcache利用をblockする。
- Action full-SHA pinは[`PSB-CICD-001`](../action-sha-pinning/README.md)、job permissionは
  [`PSB-CICD-004`](../actions-least-privilege/README.md)で検証する。

Static scannerはlive cache ACL、実際のsave結果、cache内容、全dynamic data flowを証明しません。

## Limitations and operational cost

- GitHub.comのcurrent behaviorを前提とし、GitHub Enterprise Serverや他providerには再評価が必要です。
- GitHub cache内容は署名されず、trusted producer侵害を完全には防ぎません。Consumerを非特権にし、artifact hashを再検証します。
- Fork PRはdefault branch cacheをreadできるため、cacheへsecretや機密sourceを保存できません。
- `pip --require-hashes --only-binary=:all:`には全transitive wheel hashが必要で、sdist-only dependencyは別のbuild設計が必要です。
- Cache service障害時はdownload時間とnetwork使用量が増えます。Security gate失敗とcache可用性を同じ状態にしません。
- Protected branch、CODEOWNERS、runner lifecycle、dependency review、release provenanceは関連controlの責任です。
- `zizmor`の`cache-poisoning` auditはrelease patternを静的に検出しますが、すべてのcustom cache clientを識別するとは限りません。

## Related controls

- [`PSB-CICD-001`: Action SHA pinning](../action-sha-pinning/README.md)
- [`PSB-CICD-003`: GitHub Actions static analysis](../actions-static-analysis/README.md)
- [`PSB-CICD-004`: Least-privilege workflow permissions](../actions-least-privilege/README.md)
- [`PSB-CICD-005`: Untrusted PR boundary](../untrusted-pr-boundary/README.md)
- [`PSB-CICD-007`: Runner hardening](../runner-hardening/README.md)
- [`PSB-BUILD-001`: Build containment](../../build-security/build-containment/README.md)
- [`PSB-DEPS-002`: Install-script execution control](../../dependency-security/install-script-execution/README.md)
- [`PSB-DEPS-003`: Lockfile and dependency artifact integrity](../../dependency-security/lockfile-integrity/README.md)
- [`PSB-REL-001`: Release signature and provenance verification](../../release-integrity/signature-provenance-verification/README.md)

## Framework relationships

- [SITF 1.0.0 `T-C007` Action Cache Poisoning](https://github.com/wiz-sec-public/SITF/blob/d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59/techniques.json):
  trusted save、exact lookup、unsafe path除外、privileged consumer禁止によって攻撃behaviorを`mitigates`します。Live adoptionや完全なmitigationを意味しません。
- [GitHub Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use):
  cache-aware workflowを非特権にし、release pathから除くprovider guidanceを`supports`します。
- [OpenSSF OSPS Baseline 2026.02.19 `OSPS-BR-01.03`](https://baseline.openssf.org/versions/2026-02-19#osps-br-0103):
  untrusted executable stateをprivileged CI/CD assetから分離する要件をcache channelについて`supports`します。
- [OWASP `CICD-SEC-9` Improper Artifact Integrity Validation](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation):
  関連riskと理解補助であり、registry mappingやformal compliance claimには使用しません。
- [SLSA v1.2 Build Track](https://slsa.dev/spec/v1.2/build-track-basics):
  Build provenanceは関連しますが、本controlはcache authorizationを扱うため直接mappingしません。
- [NIST SSDF SP 800-218 Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final):
  Secure build lifecycleの参考であり、本control単独のSSDF適合を主張しません。

## Provider and implementation guides

- [GitHub: Dependency caching concept and cache security](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching)
- [GitHub: Dependency caching reference and access restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [GitHub: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: REST API endpoints for Actions cache](https://docs.github.com/en/rest/actions/cache)
- [GitHub: `actions/cache` source and release documentation](https://github.com/actions/cache)
- [zizmor: `cache-poisoning` audit](https://docs.zizmor.sh/audits/#cache-poisoning)
- [pip: Secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [Python 3.13.15 release](https://www.python.org/downloads/release/python-31315/)

Provider仕様の確認日: `2026-09-07`。GitHub.comの仕様変更時は、reference workflow、verification、limitationsを再reviewします。
