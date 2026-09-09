# PSB-CICD-009: GitHub Actions cacheをtrusted writerと非特権consumerへ隔離する

## このcontrolを一枚で理解する

| 項目 | 内容 |
| --- | --- |
| セキュリティ上の問題 | CI cacheはrunをまたいでbytesを渡す共有channelであり、poisonされた内容を後続jobが実行すると、secretを直接渡さなくても権限を横断できる。 |
| 誰から、または何から守るか | Untrusted PR作成者、侵害されたAction／dependency／trusted job、広すぎるcache key、破損cache、cacheを検証済みartifactと誤認する設計から守る。 |
| 何が対象か | GitHub Actionsのcache writer／consumer、trigger、key、path、dependency lockfile、およびrelease／deploy／signing jobとの境界。 |
| 何をするか | Protected default branchへの`push`だけがdownload cacheを保存し、PRはrestore-onlyにする。Exact hit以外を破棄し、restore後もdependency hashを検証する。高権限jobではcacheを使わない。 |
| 成功状態 | PRはdefault branch cacheを作成・更新せず、lockfile変更時はclean downloadになり、cache hit時も同じintegrity checkが実行され、privileged jobがcacheをconsumeしない。 |
| 対象外・残余リスク | Repository fileだけではlive設定を証明できない。Trusted writer、GitHub cache service、archive展開、package manager、self-hosted runner自体の侵害は別の境界または残余リスク。 |

## 適用判断

このcontrolは、GitHub Actionsでdependency download cacheをPRとdefault branchのtestに再利用したい場合に使います。
Cacheは高速化手段であり、artifact、provenance、承認済みbuild outputではありません。

次の場合は、このreferenceをそのまま使いません。

- Release、deploy、signing jobでcacheが必要: cacheを除去するか、展開前に認証できるartifact flowを別途設計する。
- `.venv`、`node_modules`、compiler、plugin、build outputを再利用したい: 直接実行されるstateなので本controlの対象外とする。
- Self-hosted runner、GitHub Enterprise Server、他CI provider: cache ACL、保存先、展開処理、runner永続状態を再評価する。
- Hash付きlockfileを用意できない: cache設計より先にdependency integrityを整備する。

## 設計の羅針盤

実装方式が変わっても、次の判断を一つのdata flowとして行います。

| 判断軸 | 最小要件 | 理由 |
| --- | --- | --- |
| Writer | Review済みdefault branchへの`push`だけがsaveする | Actor-influenced runからtrusted namespaceへの永続化を防ぐ |
| Consumer | Cacheを使うjobにsecret、write token、OIDC、protected Environmentを与えない | Poisoningが成功しても高権限へ到達させない |
| Content | Credential-freeなpackage download storeだけをcacheする | Cacheはread可能で、内容は署名・検証されない |
| Identity | Purpose、schema、OS、architecture、runtime、lockfile SHAをkeyへ含める | 別目的・別platform・別dependency graphとの混同を防ぐ |
| Restore | `restore-keys`を使わず、exact hit以外のpathを削除する | GitHubはprimary keyでもprefix matchを行う |
| Validation | Hit／missに関係なくpackage hashとdependency graphを検証する | Keyは内容の完全性を保証しない |

迷った場合の最終原則は単純です。低信頼writerと高権限consumerの間にcache経路を作らないでください。

## 最短の導入手順

### 前提条件

- GitHub.com Actions、GitHub-hosted Linux runner、default branch `main`を使用する。
- Python `3.13.15`と、全direct／transitive wheel hashを持つ`requirements.lock`を使用する。
- Cache miss時に`pip`がdependencyを取得できる。
- Release、deploy、signing workflowはcacheを使用しない。

### Copyとactivation

1. [`secure/workflow.yml`](secure/workflow.yml)を採用repositoryの`.github/workflows/dependency-cache.yml`へcopyする。
2. [`PSB-DEPS-003`](../../dependency-security/lockfile-integrity/README.md)に従い、hash付き`requirements.lock`をrepository rootへ置く。
3. Python versionを変える場合は、`python-version`と2か所のcache keyを同時に変える。
4. Default branchが異なる場合は、`push.branches`とsave条件の`github.ref`を同時に変える。
5. GitHubの`Settings > Rules > Rulesets`で`main`を対象にし、`Require a pull request before merging`を有効化して最低1 approvalを要求する。
6. Workflow変更をreviewしてmergeする。これが明示的なactivationです。

既存の`.github/workflows/dependency-cache.yml`は上書きせず、差分を採用者がmergeします。Global Git、shell、IDE、OS設定は変更しません。

### 期待する動作

| Run | Restore | Validation | Save | 結果 |
| --- | --- | --- | --- | --- |
| `push` to `main` | Exact hitまたはclean cache | `pip --require-hashes --only-binary=:all:`と`pip check` | Miss時だけ実行 | 成功時exit `0` |
| `pull_request` | Exact hitまたはclean cache | `push`と同じ | Skipped | 成功時exit `0` |
| Lockfile不在 | 実行前に停止 | 実行しない | 実行しない | `ERROR requirements.lock is missing or did not hash`、exit `2` |
| Hash不一致 | Cacheを信用しない | `pip`が拒否 | 実行しない | Job failure |

[`insecure/cache-fragment.yml`](insecure/cache-fragment.yml)は、broad keyで`.venv`を共有し、cache済みinterpreterを実行する最小の比較snippetです。
完全なworkflowではなく、`.github/workflows/`へcopyしないでください。

## 誰が何をするか

| 担当 | 必要な判断と作業 |
| --- | --- |
| Development team | Cache path、purpose、runtime、lockfileを決め、hit時も通常のinstallとtestを実行する |
| Repository administrator | Default branch rulesetとsave条件を保護し、cache利用workflowを漏れなく把握する |
| Release／platform owner | Secret、OIDC、write権限、Environmentを持つjobからcache actionとcached pathを除く |
| Product Security | Writer、consumer、content、identityのdata flowをreviewし、例外と未確認事項を明示する |

## Verification

次が本controlの導入完了条件です。Live確認がすべて完了するまで、導入済みとは扱いません。

1. **Positive**: Lockfileを変えないPRでexact hitまたはclean installとなり、hash検証が成功し、save stepがskippedになる。
2. **Negative**: 無害なlockfile変更PRで`CACHE_NOT_EXACT clean download cache initialized`が出て、旧cacheを利用せず、saveがskippedになる。
3. Test前後のdefault branch cache listを比較し、PRがcacheを作成・更新していない。
4. Release、deploy、signing workflowにcache action、setup actionのcache機能、同じcached pathがない。
5. Workflow revision、run ID、event、ref、確認時刻、判定者を記録する。Cache payload、token、private sourceは保存しない。

Read-only確認には次を使用できます。

```bash
gh run list --workflow dependency-cache.yml --limit 10
gh cache list --ref refs/heads/main --limit 100
```

Repository内のreferenceだけではlive状態を検証できないため、canonical commandは意図的にPASSを返しません。

```bash
make verify-control CONTROL=PSB-CICD-009
# NOT_CHECKED PSB-CICD-009: manual verification; follow controls/cicd-security/cache-provenance-isolation/README.md#verification
# exit 2
```

未確認は`NOT_CHECKED`、API・権限・pagination・log取得の失敗は`ERROR`、要件違反は`FAIL`です。

## 障害対応とrollback

| 状態 | 対応 |
| --- | --- |
| Cache restore failure | 対象pathを削除してclean installを続ける。繰り返す場合はGitHub statusとAction pinを確認する |
| Hash／dependency check failure | Cache missへ読み替えずjobを失敗させ、lockfileと取得artifactをreviewする |
| PRでsave warning | Save actionがPRから到達可能。Referenceのevent／ref条件へ戻す |
| Privileged jobでcacheを発見 | Cacheを除去し、clean installまたはverified artifactへ切り替える |

Rollbackはrestore／save stepだけを削除し、hash-locked installを残します。必要ならGitHub Actions cache画面で
`pip-download-v1-` prefixのcacheを削除します。Rollback後は遅くなりますが、buildはcacheなしで成功できなければなりません。

## CIと自動検証の境界

- [`PSB-CICD-003`](../actions-static-analysis/README.md)のpinned `zizmor`をrequired checkにし、`cache-poisoning` findingをblockする。
- Action pinは[`PSB-CICD-001`](../action-sha-pinning/README.md)、permissionは[`PSB-CICD-004`](../actions-least-privilege/README.md)、PR境界は[`PSB-CICD-005`](../untrusted-pr-boundary/README.md)で扱う。
- Static checkはYAMLの既知patternを検出できるが、live cache ACL、writer identity、cache内容、全workflow inventoryを証明できない。
- README文字列、自己申告JSON、synthetic evidenceのPASSをorganization adoptionとして扱わない。

## 限界と運用コスト

- GitHub native cacheは展開前に署名検証されない。Trusted writer侵害を完全には防げないため、consumerを非特権に保つ。
- Fork PRはdefault branch cacheをreadできる。Secret、credential、private sourceをcacheへ入れない。
- `--require-hashes --only-binary=:all:`は全transitive wheel hashを必要とする。Sdist-only dependencyには別のisolated build設計が必要。
- Cache障害・eviction・quota超過ではbuild時間とnetwork利用が増える。可用性低下とintegrity failureを混同しない。
- Branch protection、runner lifecycle、install hook、release provenanceは関連controlの責任範囲とする。

## 関連control

- [`PSB-CICD-001`: Action SHA pinning](../action-sha-pinning/README.md)
- [`PSB-CICD-003`: GitHub Actions static analysis](../actions-static-analysis/README.md)
- [`PSB-CICD-004`: Least-privilege workflow permissions](../actions-least-privilege/README.md)
- [`PSB-CICD-005`: Untrusted PR boundary](../untrusted-pr-boundary/README.md)
- [`PSB-CICD-007`: Runner hardening](../runner-hardening/README.md)
- [`PSB-BUILD-001`: Build containment](../../build-security/build-containment/README.md)
- [`PSB-DEPS-002`: Install-script execution control](../../dependency-security/install-script-execution/README.md)
- [`PSB-DEPS-003`: Lockfile and dependency artifact integrity](../../dependency-security/lockfile-integrity/README.md)
- [`PSB-REL-001`: Release signature and provenance verification](../../release-integrity/signature-provenance-verification/README.md)

## Frameworkとguide

- [SITF 1.0.0 `T-C007` Action Cache Poisoning](https://github.com/wiz-sec-public/SITF/blob/d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59/techniques.json): `mitigates`。完全なmitigationやlive adoptionを意味しない。
- [GitHub Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use): Provider固有の安全なworkflow設計を`supports`する。
- [OpenSSF OSPS Baseline 2026.02.19 `OSPS-BR-01.03`](https://baseline.openssf.org/versions/2026-02-19#osps-br-0103): Untrusted codeとprivileged assetの分離を`supports`する。
- [OWASP `CICD-SEC-9`](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation): 関連riskの理解補助。Formal mappingには使用しない。
- [SLSA v1.2 Build Track](https://slsa.dev/spec/v1.2/build-track-basics)と[NIST SSDF SP 800-218 v1.1](https://csrc.nist.gov/pubs/sp/800/218/final): 関連guideだが、本control単独の適合は主張しない。
- [GitHub dependency cache security](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching)
- [GitHub cache access and key matching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [GitHub Actions cache REST API](https://docs.github.com/en/rest/actions/cache)
- [`actions/cache` source](https://github.com/actions/cache)
- [`zizmor` cache-poisoning audit](https://docs.zizmor.sh/audits/#cache-poisoning)
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [Python 3.13.15](https://www.python.org/downloads/release/python-31315/)

Provider仕様の確認日: `2026-09-07`。
