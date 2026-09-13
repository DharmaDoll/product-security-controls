# PSB-CICD-009: GitHub Actions cacheをtrusted writerと非特権consumerへ隔離する

## このcontrolを一枚で理解する

### セキュリティ上の問題

CI cacheは、あるrunで作ったfileを別のrunが再利用する仕組みです。GitHub Actionsでは、cacheはworkflowやjobの名前だけで分離されず、同じrepositoryのbranch scopeを使う別workflowからも読めます。Default branchのcacheは、forkからのPRでも読めます。復元されたfileは署名済みとは限らず、readできるrunはその内容をそのまま取得できます。[GitHubのcache security仕様](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)も、cacheをuntrusted inputとして扱うよう説明しています。

ただし、cacheが存在するだけでrepositoryやcloudが直ちに侵害されるわけではありません。実害には、次の三条件が同時に必要です。

1. 攻撃者が、cacheへ新しい内容を保存できる。例えば、PR runのsave、侵害されたdefault-branch job、またはcacheを書ける別workflowがある。
2. 後のrunが、そのcacheを同じscopeまたはfallbackから復元できる。branch scopeだけではworkflowの目的やproducerの信頼度を区別できない。
3. 復元したfileを、install、build、script、interpreter、plugin、または未検証のdependencyとして実行・採用する。高権限jobなら、そのjobのsecret、write token、OIDC、Environment、内部networkを利用できる。

例えば`.venv`や`node_modules`、compiler、build toolをcacheし、後続のrelease jobがその中の実行fileを使うと、cacheへ混入したcodeがrelease権限で動く可能性があります。download cacheでも、hash検証を省略してinstallしたり、package hookを無制限に実行したりすれば、悪意あるdependencyへ置き換わる余地があります。Cache pathにsecretやcredentialが入っていれば、cacheを読めるPRへ漏えいします。

一方、PRがcacheを保存できず、consumerがprivilegedでなく、restore後にlockfileのhashを毎回検証してclean installするなら、cache poisoningだけで高権限へ到達する経路は成立しません。このcontrolは「cacheを使うな」という一般論ではなく、三条件の接続を切るものです。被害範囲も、侵害されたconsumerの実効権限が許すrepository、package、cloud role、deployment targetに限定されます。

### 誰から、または何から守るか

Cacheを書けるPR作成者、侵害されたActionやdependency、既に侵害されたtrusted job、cacheを読むfork contributor、広すぎるkeyやprefix fallback、破損cacheを成功扱いする運用から守ります。Cache writerがtrusted branchだけにあり、consumerがcacheを実行せず、独立したhash検証も行う場合は、このattack pathの主な被害は成立しません。

### 何が対象か

GitHub Actionsのcache writer／consumer、trigger、branch scope、key、restore path、dependency lockfile、package managerのintegrity check、およびrelease／deploy／signing jobとの境界です。`actions/cache`だけでなく、`setup-python`などの自動cache、custom upload／download、別workflowの同一pathもinventoryに含めます。

### 何をするか

Protected default branchへのreview済み`push`だけがdownload cacheを保存し、PRはrestore-onlyにします。Keyへpurpose、schema、OS、architecture、runtime、lockfile digestを含め、exact hit以外の復元結果は削除します。Restore後もdependency hashを検証し、secret、installed tree、tool、build outputをcacheしません。高権限jobはcacheを使わず、verified artifactまたはclean buildから開始します。

### 成功状態

PRはdefault branch cacheを作成・更新せず、lockfile変更時は旧cacheを使わずclean downloadになります。Exact hitでも同じhash-locked installとdependency checkが実行され、release、deploy、signing jobはcacheをconsumeしません。Live設定やrunを確認できない部分は、成功扱いではなく`NOT_CHECKED`または`ERROR`です。

### 対象外・残余リスク

Repository fileだけではbranch protection、全workflow inventory、cache ACL、実際のwriter、run結果を証明できません。Trusted writer、GitHub cache service、archive展開、package manager、self-hosted runner自体の侵害も完全には防げません。Cache障害やevictionによるbuild遅延はavailabilityの問題であり、security PASSとは別に扱います。

## 適用判断

このcontrolは、GitHub Actionsでdependency download cacheをPRとdefault branchのtestに再利用したい場合に使います。
Cacheは高速化手段であり、artifact、provenance、承認済みbuild outputではありません。

次の場合は、このreferenceをそのまま使いません。

- Release、deploy、signing jobでcacheが必要: cacheを除去するか、展開前に認証できるartifact flowを別途設計する。
- `.venv`、`node_modules`、compiler、plugin、build outputを再利用したい: 直接実行されるstateなので本controlの対象外とする。
- Self-hosted runner、GitHub Enterprise Server、他CI provider: cache ACL、保存先、展開処理、runner永続状態を再評価する。
- Hash付きlockfileを用意できない: cache設計より先にdependency integrityを整備する。

## 本当に被害になる条件

次の表は、対象があるだけでFAILとするためのものではありません。採用repositoryのworkflowで、左から右へdata flowがつながるかを確認します。

| 状況 | 被害が成立する条件 | 起こり得ること | 条件が欠ける場合 |
| --- | --- | --- | --- |
| 実行可能stateをcacheする | 攻撃者がsaveでき、後続jobが同じcacheをrestoreして実行する | そのjobの権限でcode injection、release汚染、deploy操作 | PRがsaveできない、またはconsumerがcacheを実行しない |
| Download cacheをcacheする | Restore後のhash検証を省略し、取得fileやinstall hookを信頼する | 悪意あるdependency、install時のcode execution | `--require-hashes`等でlockfileとartifactを照合し、失敗時はjobを止める |
| Cache pathにsecretを置く | Fork PRなどcacheを読めるrunが存在する | Token、credential、private sourceの漏えい | Cache pathにsecretがなく、cacheを公開可能なdataだけに限定する |
| Broad key／prefix fallbackを使う | 別目的・別runtime・別dependencyのcacheを選び、後続処理が採用する | 古い、異なる、または意図しないbytesの混入 | Purposeとlockfile identityをkeyへ含め、exact hit以外を削除する |

Cache poisoning単独でorganization administrator権限が得られるわけではありません。高権限consumerのeffective permission、secret配送、OIDCのcloud側trust policy、Environment protection、runnerの到達性を合わせて被害を見積もります。

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

## GitHub Actionsのcache分離を有効にする最短手順

ここでいう「最短」は、既存の全workflowを作り直す手順ではありません。Review済みのreference workflowを1本配置し、`main`へのpushとPRで「誰がcacheを保存できるか」「何を復元するか」を確認する、最小の導入経路です。既に別のcache workflowがある場合は、そのworkflowも同じ確認対象になります。

### 前提条件

- GitHub.com Actions、GitHub-hosted Linux runner、default branch `main`を使用する。
- Python `3.13.15`と、全direct／transitive wheel hashを持つ`requirements.lock`を使用する。
- Cache miss時に`pip`がdependencyを取得できる。
- Release、deploy、signing workflowはcacheを使用しない。

### 実施すること

1. [`secure/workflow.yml`](secure/workflow.yml)を採用repositoryの`.github/workflows/dependency-cache.yml`として配置する。これにより、dependency download cacheのrestoreとsaveの条件がworkflowへ追加される。
2. [`PSB-DEPS-003`](../../dependency-security/lockfile-integrity/README.md)に従い、hash付き`requirements.lock`をrepository rootへ置く。これがcache keyとinstall時のartifact identityになる。
3. Python versionを変える場合は、`python-version`と2か所のcache keyを同時に変える。
4. Default branchが異なる場合は、`push.branches`とsave条件の`github.ref`を同時に変える。
5. GitHubの`Settings > Rules > Rulesets`で`main`を対象にし、`Require a pull request before merging`を有効化して最低1 approvalを要求する。これでcache save条件を変更するworkflow自体をreview対象にする。
6. Workflow変更をreviewして`main`へmergeする。merge後の`main` runがcacheを保存し、PR runはrestoreだけを行えば、このreferenceの設定が実際に有効になった状態です。

既存の`.github/workflows/dependency-cache.yml`は上書きせず、差分を採用者がmergeします。Global Git、shell、IDE、OS設定は変更しません。

### 期待する動作

| Run | Restore | Validation | Save | 結果 |
| --- | --- | --- | --- | --- |
| `push` to `main` | Exact hitまたはclean cache | `pip --require-hashes --only-binary=:all:`と`pip check` | Miss時だけ実行 | 成功時exit `0` |
| `pull_request` | Exact hitまたはclean cache | `push`と同じ | Skipped | 成功時exit `0` |
| Lockfile不在 | 実行前に停止 | 実行しない | 実行しない | `ERROR requirements.lock is missing or did not hash`、exit `2` |
| Hash不一致 | Cacheを信用しない | `pip`が拒否 | 実行しない | Job failure |

[`insecure/cache-fragment.yml`](insecure/cache-fragment.yml)は、broad keyで`.venv`を共有し、cache済みinterpreterを実行する最小の比較snippetです。
完全なworkflowではなく、`.github/workflows/`へ配置しないでください。

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
