# Privileged control-plane change runbook

このrunbookは、SCM、CI、cloud identity、artifact registry、signing serviceのsecurity-impacting settingを
変更する管理者、approver、reviewer向けである。Developerにprovider-wide admin権限を要求しない。

Completed change recordやlive evidenceは、public repositoryではなくapproved ticket／evidence systemへ保存する。

## Reference defaults

| 項目 | 最小値 |
|---|---|
| Actor | Shared accountではないnamed current human |
| Authentication | Phishing-resistant |
| Session | 最大1時間 |
| Step-up | 実行前15分以内 |
| Ordinary approval | Requester／executor以外の1名以上、実行前 |
| Emergency expiry | 実行から最大1時間 |
| Post-change review | Executor以外 |
| Result | `PASS`／`FAIL`／`NOT_CHECKED`／`ERROR`／review済み`N/A` |

Provider／IdPがsessionやstep-upを確認できない場合、値を自己申告で補わず`CPC-002: NOT_CHECKED`とする。

## Before first use

1. Security-impacting serviceとchange typeのinventoryを作る。
2. Serviceごとにexecutor、approver、audit reviewer、failure ownerを割り当てる。
3. Shared administrator accountを廃止し、current membershipとroleをreviewする。
4. ProviderまたはIdPでphishing-resistant authenticationを有効にする。
5. Approved ticket systemへ[`change-record-template.md`](change-record-template.md)を登録する。
6. Provider auditを閲覧できるreviewerを用意する。
7. 可能ならauditをcontrol-plane administratorとは別のwrite boundaryへexportする。
8. Harmless drill用のnon-production targetを用意する。

一つでも未確認なら導入済みとせず`NOT_CHECKED`を記録する。

## Ordinary change

### Requester

1. Templateのclassificationとexact targetを埋める。
2. Provider画面またはapproved read-only APIからbeforeを取得する。
3. Afterを人が読める具体的な値で記述する。
4. 変更によって実際に利用可能になるauthorityと後続経路を説明する。
5. Rollbackと変更後のbuild／release確認を記述する。

### Independent approver

1. Requester／executorと別人であることを確認する。
2. Stable targetが別resourceを指していないことを確認する。
3. Before／afterと添付内容を読む。
4. Secure required stateを所有する関連controlと比較する。
5. Side effectとrollbackを確認する。
6. Exact targetとafterへ結び付く形で、実行前にapproveまたはrejectする。

### Executor

1. Approval済みのtargetとafterを再確認する。
2. 強い認証で再authenticationする。
3. 承認後、時間を空けずにprovider UI／APIで変更する。
4. 承認されていない追加変更を同じ作業へ含めない。
5. Provider resultと実行時刻をrecordへ記入する。

### Independent reviewer

1. Provider audit eventのactor、action、time、targetを確認する。
2. Provider画面またはapproved read-only APIからcurrent settingを取得する。
3. Current settingとapproved afterを比較する。
4. `CPC-001..007`を一つずつ評価する。
5. 不一致は`FAIL`、未確認は`NOT_CHECKED`、取得不能は`ERROR`とする。
6. Cleanにcloseできない結果にはfailure ownerと期限を付ける。

## GitHub ruleset reference

最初の対象は専用private sandbox repositoryの`control-test` branchとする。

Referenceの初期状態は、rulesetが`Active`、targetが`control-test`、pull request必須、required approving
review数が`1`である。Rulesetがない場合は、`before: absent`からこの初期状態を作る最初のordinary changeとして扱う。

1. Repositoryの`Settings > Rules > Rulesets`を開く。
2. 対象rulesetのURLまたはstable ID、enforcement、target branch、required review数をrecordへ記載する。
3. Positive drillではrequired approving review数を`1`から`2`へ強化する変更を申請する。
4. 別人の承認後にexecutorが変更する。
5. Organization audit logで対象時刻、actor、action（referenceでは`repository_ruleset.update`）、repository／rulesetを確認する。
6. Rulesetを再表示し、current required review数が`2`であることを確認する。
7. 戻す必要がある場合、`2`から`1`への変更を別のapproved changeとして実施する。

Production repositoryのprotectionを弱めてtestしない。

## Negative drill

### Missing approval

1. Sandbox向けchange recordを作る。
2. Approval sectionを空欄のままexecutorへ渡す。
3. Executorがprovider変更を開始せず`CPC-004: FAIL`として返すことを確認する。

### Direct change detection

Provider-native approval gateがない構成でのみ、sandboxで実施する。

1. Ticketを作らず、rulesetを`1`から`2`へ強化する方向で変更する。
2. Audit reviewerがreview cadence内にeventを発見する。
3. 対応するapproved recordがないため`CPC-003／004: FAIL`とする。
4. Incidentまたはfollow-up changeを起票する。
5. Revertが必要なら、別のapproved changeとして実施する。

これは事前防止のtestではない。Direct changeをaudit reviewで発見できることだけを確認する。

## Emergency change

1. Incident ID、reason、exact target、intended after、executor、開始時刻、expiryを変更前に記録する。
2. Expiryを開始から最大1時間にする。
3. Named administratorが必要最小限の変更だけを行う。
4. Provider audit eventとcurrent settingを直ちに記録する。
5. Executorとは別のreviewerがexpiryまでに確認する。
6. `accepted`または`reverted`を記録する。
7. 恒久化が必要なら通常変更または`PSB-GOV-002`のtime-bound exceptionへ移す。

Expiryまでにreviewできなければ`FAIL`であり、同じrecordを無期限延長しない。

## Failure handling

| 状況 | 処理 |
|---|---|
| Target、before、afterが曖昧 | 変更を開始せず`NOT_CHECKED`としてrequesterへ戻す |
| Approvalがない／self-approval | `FAIL`、provider変更を開始しない |
| Audit eventが見つからない | `ERROR`、追加変更を止めてcollector scopeとprovider healthを確認する |
| Current settingを取得できない | `ERROR`、executorの自己申告でcloseしない |
| Approved afterとcurrentが違う | `FAIL`、impactを確認し、必要ならemergency revert |
| Unauthorized direct change | `FAIL`、後続workflow／artifact／cloud operationを調査する |
| Evidenceへcredentialが混入 | 保存・共有を止め、隔離し、実credentialなら失効する |

Last-known-good evidenceをcurrent `PASS`として再利用しない。

## Rollback

- Hosted settingを戻す操作も新しいprivileged changeとして扱う。
- 安全設定を無承認で弱めるautomatic rollbackを用意しない。
- Emergency revertを使用した場合もprovider eventとcurrent stateを確認する。
- Repository-localなrunbook導入を外す場合は、copyしたdocumentとprocess referenceだけを削除する。
- Global Git、shell、IDE、OS settingを変更しない。

## Adoption completion

次が揃ったときだけ、宣言したscopeを導入済みとする。

- Scope inventoryとownerがcurrentである。
- Named administrator、strong authentication、role separationがliveで有効である。
- Ordinary changeでindependent pre-approvalが運用されている。
- Harmless positive drillでrequestからcurrent stateまで一致する。
- Missing approvalとdirect changeを`FAIL`として扱える。
- Emergency drillが期限内の独立decisionを残す。
- Missing／failed evidenceがcleanにならない。
- Audit review cadence、retention、failure ownerが割り当てられている。

一つのsandbox ruleset drillから、Organization全体や他providerの採用を推論しない。
