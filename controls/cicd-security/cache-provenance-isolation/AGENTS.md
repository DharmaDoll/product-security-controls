# PSB-CICD-009 implementation instructions

このfileは`PSB-CICD-009`（`cicd-security`）固有の実装境界を定める。変更前に
[repository rootのAGENTS.md](../../../AGENTS.md)、[controlsのAGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、[ROADMAP](../../../docs/ROADMAP.md)、関連ADR、
[README.md](README.md)、[control.yaml](control.yaml)を読むこと。

## Control essence

- CI cacheはperformance optimizationであり、artifact、provenance、承認、または信頼済みbuild outputではない。
- 防ぐべき中心的な遷移は、untrustedまたは低権限のrunが保存したcacheを、secret、write token、OIDC、
  protected Environment、release／deploy authorityを持つjobがrestoreして実行する`low trust -> high trust`である。
- GitHub Actionsのcacheはworkflow identityでは隔離されない。同一repository／branchの別workflowもcacheを
  restoreできるため、keyのpurpose namespaceとproducer／consumerのtriggerを明示する。
- Cache内容は署名済みとはみなさない。restore後もpackage managerのlockfile／integrity verificationを通し、
  privileged jobではprovider cacheをrestoreしない。
- Cacheにはsecret、credential、source tree、installed dependency tree、tool、binary、compiler plugin、startup file、
  shell profileを保存しない。Baselineはpackage managerのdownload cacheだけを対象とする。
- Security効果はlive workflowのsave条件、cache path、key、consumer authority、package integrity checkから生まれる。
  README、fixture、署名recordをcopyしただけでは効果は発生しない。

本controlを単なる「cache key naming rule」に縮小しない。一方、cache providerが保存・復元する実archiveへ接続されない
独自provenance schemaや署名器を中心実装にしない。

## 仮説と反証

実装前に最低でも次の仮説を比較し、最初の案をそのまま採用しない。

1. **独自署名が必須**: provider archiveを展開前にhash／署名検証できるadapterがなく、synthetic blobだけを署名するなら、
   live cache poisoningを防いだ証拠にならない。Baselineから外し、advanced profileまたは将来課題とする。
2. **providerのbranch scopeだけで十分**: GitHub Actions cacheは同一branchの複数workflowから利用でき、default branch cacheは
   PRからread可能である。Writer制約、purpose-bound key、safe path、privileged consumer禁止がなければ反証される。
3. **commit SHAをkeyへ含めれば安全**: 毎commitでmissし、cacheの採用目的をほぼ失う。Lockfile、platform、runtime、
   cache schemaが同じなら再利用可能とし、source revision exact bindingはbaseline要件にしない。
4. **download cacheなら常に安全**: download cacheも改ざん可能である。Lockfileやartifact hashを再検証しないpackage manager、
   install hookを無制限に実行する構成、cache hitを理由にverificationを省く構成では成立しない。

新しい複雑さを追加する前に、それがlive provider上の攻撃経路を実際に閉じるか、既存controlが所有する問題を重複して
実装していないかを確認する。

## Reference profile and assumptions

Baseline referenceはGitHub.com ActionsとGitHub-hosted Linux runnerである。

- Trusted cache writerは、review済み変更が入ったprotected default branchへの`push`だけとする。
- `pull_request`（forkを含む）はrestore-onlyとし、save actionを実行しない。
- Baselineでは`pull_request_target`、`workflow_run`、`issue_comment`、`repository_dispatch`、`schedule`、
  `workflow_dispatch`をcache writerにしない。追加する場合はactor、checked-out bytes、ref、credential、approvalを別途reviewする。
- Untrusted consumerがtrusted default-branch cacheを読むことは、cacheにsecretがなく、restoreしたbytesをuntrustedとして
  再検証する場合に限り許容できる。禁止対象は`untrusted -> trusted`の昇格であり、same-classだけを形式的に要求しない。
- Release、signing、deployment、production migration等のprivileged jobはcacheを使わず、clean environmentから
  integrity-verified dependenciesまたはverified release artifactを取得する。
- macOS runner、self-hosted runner、GitHub Enterprise Server、他CI providerはbaseline外である。追加時はprovider version、
  cache scope、低信頼triggerのwrite制限、archive extraction、eviction、API evidenceの差分を確認する。

GitHubのprovider仕様は変わり得る。実装時点の公式documentationを一次資料として確認し、確認日と対象serviceをREADMEへ記録する。

## 実装前に確認するcontrol固有入力

1. Cacheを使用する全workflow、job、triggerと、default branch名を列挙できるか。
2. 各cache producerはどのevent、ref、actor-controlled input、checked-out revisionで動くか。
3. 各cache consumerはsecret、write token、`id-token: write`、protected Environment、self-hosted runner、内部networkの
   いずれへ到達できるか。
4. Cache pathには何が入り、その中に実行物、installed tree、source、hook、credential、設定fileが混ざらないか。
5. Cache keyへ含めるpurpose、schema version、OS、architecture、runtime／package-manager version、exact lockfile digestは何か。
6. Lockfileがartifact hashまたはregistry integrity metadataを保持し、cache hit時にもpackage managerが検証するか。
7. Default branchへのcache saveを許可するworkflow fileと、その変更を保護するreview／rulesetは何か。
8. Privileged jobからcacheを除去できるか。除去できない場合、なぜ必要で、実archiveを展開前に認証する仕組みは何か。
9. Live positive／negative runとcurrent cache listを誰が確認し、どこへ機密情報を除いた証跡を保存するか。

これらが不明なら架空のrepository、cache key、run result、署名、evidenceを作らない。Reference exampleだけを提供し、
organization adoptionは`NOT_CHECKED`のままにする。

## Implementation mode

本controlはconfiguration-first／guidance-firstをbaselineとする。

- `secure/`にはそのままcopyして最小変更で使えるGitHub Actions workflowを置く。
- `insecure/`は低信頼runからsaveする、broad fallbackを使う、またはprivileged jobでcacheをrestoreする最小比較例に限定する。
- READMEの早い位置で、実際のsecurity効果がlive workflow設定から生まれ、file copyだけでは導入完了でないと明記する。
- READMEにはprerequisite、copy対象、activation、positive／negative self-test、expected result、failure recovery、
  server-side enforcement、rollback、residual riskを順に示す。
- Organization固有のretention、quota、cache cleanup、追加triggerは、動く最小構成の後へ分離する。
- Provider設定を変更するwrite automationは追加しない。Read-only API確認はoptional adapterとしてよい。
- YAMLを正規表現で判定するscanner、自己申告JSON、synthetic adoption evidence、no-op testを追加しない。

既存のEd25519 verifier、policy、record、signature、fixtureは「実provider archiveを展開前に認証する」というsecurity propertyを
満たす場合だけ主実装として維持する。Synthetic blobだけを検証する場合はlive adoptionの証拠にせず、advanced design exampleへ
明確に降格するか、不要なら関連README、metadata、test、expected outputと一緒に削除する。過去のE3表示を維持する目的だけで残さない。

## Required GitHub Actions configuration

Secure reference workflowは次を満たす。

- Third-party Actionsは`PSB-CICD-001`に従いfull commit SHAへpinする。
- Workflow／job permissionsは`PSB-CICD-004`に従い明示し、cache利用jobへsecret、write permission、OIDC、Environmentを渡さない。
- Restoreには`actions/cache/restore`、saveには`actions/cache/save`を分けて使う。
- Save stepは`github.event_name == 'push'`かつ`github.ref == 'refs/heads/<default-branch>'`の場合だけ実行する。
- PR専用workflowにはsave actionを置かない。`pull_request`と`push`を同じworkflowで扱う場合は、上記のstep conditionで
  PR runからsave actionを実行不能にする。
- Keyは少なくとも`purpose`、cache schema version、`runner.os`、`runner.arch`、runtime major／minor、lockfile SHA-256を含む。
- `hashFiles()`が空になるlockfile不在を拒否する。Repository名はprovider scopeに含まれるが、異なるworkflow purposeは
  固定namespaceで分ける。
- `restore-keys`を指定しない。Restore outputがexact hitを示さない場合、またはrestore stepが失敗した場合は、部分展開を含む
  restore対象pathを削除してからclean downloadへfallbackする。
- Cache missまたはservice unavailableは、cacheなしのintegrity-verified installへfallbackできる。破損、hash mismatch、
  package verification failureはcache hitやclean resultとして継続しない。
- Cache pathは`~/.npm`、pip download cache等のreview済みdownload storeに限定する。`node_modules`、`.venv`、`vendor/`、
  build output、workspace、`PATH`上のdirectoryはcacheしない。
- Cache hit時も`npm ci`、hash-locked install等の通常のdependency integrity verificationを実行する。
- Cacheへsecretを保存しない。Fork PRがdefault branch cacheをreadできる前提で内容を分類する。
- Release／deploy／signing jobはcache actionもcached directoryもconsumerにしない。

Actionのexact SHAやruntime要件は実装時点でreviewし、floating tagをexampleへ残さない。

## Roles

- Development team: cache対象、purpose namespace、lockfile、clean fallbackを選び、cache hit時も通常のinstall／testを実行する。
- Repository administrator: protected default branch、workflow変更review、全cache workflow inventory、live runを確認する。
- CI platform／organization owner: GitHub plan／Enterprise policy、runner種別、cache serviceのscopeと低信頼trigger制約を確認する。
- Security: producer／consumer data flow、privileged authority、cache内容、negative drill、例外、live evidenceをreviewする。
- Release／platform owner: privileged release pathがCI cacheを使用せず、verified artifactまたはclean dependency resolutionから始まることを確認する。

Cache writerとprivileged consumerの両方を、review不能な同一workflow変更だけで許可しない。

## Verification boundary

自動化するのは、実workflowまたは必要なevaluatorのsecurity propertyを意味のある方法で検証できる部分だけとする。

### Harmless positive self-test

1. Reviewed dependency lockfileをdefault branchへpushし、trusted jobがexact keyでdownload cacheを保存する。
2. Lockfileを変更しないPRでrestore-only jobを実行し、exact hit、通常のintegrity-verified install、test成功を確認する。
3. PR jobにsave step、write token、secret、OIDC、protected Environmentがないことをworkflowとrun logの両方で確認する。

### Harmless negative self-test

1. PRでlockfileを無害な別digestへ変更し、旧cacheをpartial restoreせずclean downloadになることを確認する。
2. Default branch cache listを前後比較し、PR runがdefault branch scopeへcacheを作成・更新していないことを確認する。
3. Release／deploy workflow inventoryを確認し、cache actionまたはcached pathを使用していないことを確認する。
4. Cache内容を一時的に変更できるisolated test環境がある場合、package integrity verificationが拒否することを確認する。
   Live shared cacheを破壊するtestは行わない。

Expected stateは、trusted default-branch runだけがsaveし、PRはexact restoreまたはclean fallbackだけを行い、privileged jobが
cacheをconsumeしないことである。Cache save denial warning、API permission不足、partial inventory、missing log、provider failureを
`PASS`へ丸めない。

Static verificationに既存のstructured parser／scannerが使える場合は、full-SHA pin、save condition、`restore-keys`不在、
forbidden path、privileged authorityとの同居を検証してよい。README文字列検索、別の自己申告policyとの比較、常時成功testは不可とする。

Live provider stateが本質で、meaningful local checkerがない場合はtop-level verificationを`manual`とし、`tests/test.sh`を置かない。
その場合`make verify-control CONTROL=PSB-CICD-009`は`NOT_CHECKED`とprocedure linkを表示してexit `2`とする。Meaningful static checkと
live procedureの両方がある場合だけ`hybrid`とし、fixture PASSとorganization adoptionを分ける。

## Evidence

Live evidenceには次を含める。

- repository、default branch、workflow path、exact workflow revision、run ID、event、ref、取得時刻
- restore／save actionの実行有無、sanitized exact key、cache hit種別、cache path分類
- GitHub UIまたはread-only APIから取得したcache `ref`、key、作成時刻
- PR negative run前後でdefault branch cacheが作成・更新されていない結果
- consumer jobのeffective permission、secret／OIDC／Environment有無、runner種別
- reviewerと、未確認項目の`NOT_CHECKED`または取得失敗の`ERROR`

Token、secret、cache payload、private source、provider-valid credentialは保存しない。Repositoryにsynthetic run evidenceを置いて
live adoptionと主張しない。Cache listだけではwriter identityや内容の安全性を証明できないため、workflow revisionとrun logを結合する。

## Atomic checks and metadata

[`control.yaml`](control.yaml)がcanonical metadataである。既存`CAC-001..007`はgenerated profileから参照され得るため、削除や
renumberの前にrepository全体を検索する。ただし、過去のsynthetic署名modelを守るために誤ったclaimを維持しない。

Check setは最終的に、少なくとも次のatomic outcomeを一読で区別できるようにする。

- cache saveはtrusted default-branch producerだけに限定される。
- keyはpurpose、schema、platform、runtime、exact dependency identityへ結合され、broad fallbackを使わない。
- `untrusted -> privileged`のcache遷移が存在しない。
- cache pathはsecretと直接実行されるstateを含まず、dependency integrityが毎回再検証される。
- exact hit以外はclean stateへ戻り、privileged jobはcacheをconsumeしない。
- live inventory、provider evidence、failure stateを`PASS`、`FAIL`、`NOT_CHECKED`、`ERROR`として区別する。

既存checkのtitle／required stateを変える場合は、context、responsible role、verification、evidence、mapping rationale、README、
limitationsを同時に更新する。署名、exact source revision、24時間TTLをbaselineから外す場合は、control title／summaryにも古いclaimを残さない。
Framework mappingはattack behaviorとの限定的な関係であり、live adoption、完全なmitigation、またはcomplianceを示さない。

## Relationship to other controls

- [`PSB-CICD-001`](../action-sha-pinning/README.md): cache Action／reusable workflowのimmutable reference。
- [`PSB-CICD-003`](../actions-static-analysis/README.md): GitHub Actions workflowの汎用static analysis。
- [`PSB-CICD-004`](../actions-least-privilege/README.md): token permission、OIDC、Environment authority。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): fork／PR executionとprivileged phaseの全体境界。
- [`PSB-CICD-007`](../runner-hardening/README.md): runner filesystem persistence、image、network、teardown。
- [`PSB-BUILD-001`](../../build-security/build-containment/README.md): build sandbox、credential、egress、deploy分離。
- [`PSB-DEPS-003`](../../dependency-security/lockfile-integrity/README.md): lockfileと取得dependency artifactのintegrity。
- [`PSB-DEPS-002`](../../dependency-security/install-script-execution/README.md): dependency install hookによるcode execution。
- [`PSB-REL-001`](../../release-integrity/signature-provenance-verification/README.md): release artifactのsignature／provenance verification。

本controlはcache固有のwriter、lookup、path、consumer data flowだけを所有する。Token policy、runner hardening、dependency review、
release provenanceをcopyして見かけ上self-containedにしない。

## Required verification after changes

Repository rootから、変更内容に応じて次を実行する。

```bash
python3 -m unittest tests.test_control_metadata tests.test_run_controls
make validate-controls
make verify-control CONTROL=PSB-CICD-009
```

Manual modeでは最後のcommandは`NOT_CHECKED`とexit `2`が期待値である。Automated／hybrid modeではpositive、negative、redaction、
tool unavailableを実際に検証し、exit `0`をfixtureの範囲を超えたadoption claimにしない。Generated index、mapping、checklistは
taskで必要な場合だけcanonical metadataから再生成し、無関係な差分を混ぜない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
