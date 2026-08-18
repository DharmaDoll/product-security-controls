# PSB-SOURCE-005: Repository mass deletionを防止し復旧可能性を検証する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | source-platformのowner権限を奪われると、多数repository、branch／tag、設定、監査証跡を短時間で削除され得る。同じ管理境界のmutable backupや未検証mirrorは攻撃者と一緒に消され、存在するだけでは復旧可能性を証明しない。 |
| 誰から、または何から守るか | stolen／phished administrator sessionを使う外部攻撃者、単独の悪意ある管理者、誤ったbulk automation、partial inventory、backup corruption、audit／alert障害、試していないrestore手順から守る。 |
| 何が対象か | critical repositoryのstable inventory、repository deletion API、管理session、Git objectsとrefs、保護設定、backup security domain、audit event、alert、containment、restore drill。 |
| 何をするか | 1 requestの削除を1 repositoryへ制限し、許可時は独立承認とrecent reauthenticationを要求する。全critical repositoryを別security domainの30日compliance-lock backupへ保存し、5分以内alert、actor authority失効、30日以内の全件isolated restore drillを検証する。 |
| 成功状態 | 完全な2-repository fixtureでbulk requestが拒否され、backup、audit、alert、containment、RPO 24時間／RTO 4時間以内のcontent／refs／settings digest一致restoreが7チェックを通過する。評価不能はERRORになる。 |
| 対象外・残余リスク | fixtureはlive provider設定やstorage object lockを証明せず、issues、PR、LFS、wiki、release、hook等すべてのprovider objectを網羅しない。実削除を行わないisolated drillであり、product固有RPO／RTOとprovider adapterが必要。 |

## Security problem and boundary

repository deletionはsource treeだけでなく、branch／tag、review history、保護設定、
release metadata、CIとのidentity relationshipを失わせます。branch deletion protectionや
CODEOWNER reviewが有効でも、organization ownerまたはprovider control planeがrepository
全体を削除できれば境界が異なります。

`PSB-CICD-008`はselected branch／ruleset設定変更のhuman approvalとaudit correlationを
所有します。本controlはcritical repository全体のdestructive blast radius、別authorityの
backup、削除attempt後のcontainment、実際に戻せることのdrillを所有します。
`PSB-GOV-001`のincident scopeやpreservation-first runbookを置き換えません。

## Secure and insecure examples

`secure/policy.json`はcontent-derived SHA-256 policy IDを持ち、次を固定します。

- stable IDで列挙した2つのcritical repository;
- 1 request最大1 repository、default deny、独立承認、15分以内のphishing-resistant reauthentication;
- RPO 24時間、別security domain、compliance object lock、30日retention、source admin delete denial;
- complete auditと5分以内のexternal alert;
- actor sessionとtoken失効後のrecovery authorization;
- 30日以内、RTO 4時間以内、全scopeのisolated restore drill。

`secure/evidence.json`は2 repositoryへのbulk deletion requestを`DENIED`とし、exact audit、
外部alert、authority containment、backupと同じcontent／refs／settings digestを持つ2件の
restore receiptを記録します。repository内容、credential値、内部endpointは含みません。

`insecure/evidence.json`は隔離された非実行fixtureです。bulk deletionをself-approveして
許可し、same-domainで削除可能なstale backup、partial audit、failed／late alert、未失効
session、in-place partial restore、digest mismatchを示します。

## Verification

```bash
make verify-control CONTROL=PSB-SOURCE-005
```

直接実行する場合:

```bash
python3 controls/source-protection/repository-destruction-recovery/scripts/verify.py \
  --policy controls/source-protection/repository-destruction-recovery/secure/policy.json \
  --evidence controls/source-protection/repository-destruction-recovery/secure/evidence.json \
  --as-of 2026-08-18T14:00:00Z
```

| 終了コード | 意味 |
|---|---|
| `0` | 全7チェックが成立し、repository recovery assuranceを受理した。 |
| `1` | trustworthy evidenceがunsafe stateを示したため拒否した。 |
| `2` | stale、partial、unavailable、malformed、symbolic、policy不整合、sensitive evidence等で評価不能。 |

終了`2`を「削除なし」「backupあり」「drill成功」と読み替えてはいけません。secureと
insecureの完全出力は`expected-results/`へ固定しています。testはpolicy tamper、weakened
policy、collector staleness／partial coverage、audit outage、restore digest mismatch、
malformed JSON、symlink、credential-bearing fieldも確認します。

## Integration guidance

1. organization内のactive、archived、disabled、transferred、forkをprovider stable IDで完全列挙し、product criticalityとownerを割り当てます。
2. repository deletion APIをdefault denyにし、bulk operationを禁止します。単一削除もrecent phishing-resistant reauthenticationとrequester以外の承認へ結合します。
3. Git object／refだけでなく、保護設定、ruleset、default branch、team access、deploy key、hook等をcanonical manifestへ正規化します。provider非対応objectはgapとして明示します。
4. source administratorが管理できない別account／tenant／credentialへbackupし、object lockとretentionをprovider API evidenceで確認します。backup encryptionだけでは削除耐性になりません。
5. deletion attemptのactor、session、stable repository IDs、decisionをcomplete auditから取得し、source control plane外のreceiverへ5分以内に配送します。
6. compromised actor session、PAT、OAuth grant、SSH key、App token等を失効してからrecoveryをauthorizeします。復旧先へ旧authorityを復元しません。
7. 30日ごとにisolated targetへ全critical scopeをrestoreし、content、全refs、保護settingsのdigestとRPO／RTOを比較します。実environmentへ上書きしません。
8. production adapterではAPI pagination、rate limit、event lag、deleted repository IDの保持、provider retention window、backup export completenessをfail closedで扱います。

## Expected behavior

secure fixtureは`RDR-001..007`をPASSし、2 repositoryのbulk deletion拒否とcomplete
restore drillをACCEPTします。insecure fixtureはinventory classification、authorization、
backup、audit／alert、containment、restoreに31 findingを出してREJECTします。

collectorがstaleまたはpartial、auditがunavailable、JSONが壊れている、inputがsymlink、
sensitive fieldが含まれる場合はfindingを数える前にERRORで停止します。error outputはfield
pathだけを示し、値を表示しません。

## Limitations and operational cost

- provider-neutral E3 fixtureであり、GitHub／GitLab／Bitbucketやbackup storageのlive設定を証明しません。
- providerごとにrepository export対象が異なります。Issues、PR、discussion、wiki、LFS、release assets、packages、Actions artifacts、secret値、environment、hook等の対応表が必要です。
- compliance object-lockの文字列はprovider enforcement、root account、key custody、legal hold、control-plane compromise耐性を証明しません。
- restore drillはstorage、API、network、operator時間を消費します。productionと隔離したquota、naming、cleanup、cost budgetを用意します。
- digest一致は完全な意味的復旧を保証しません。access control、notification、external integration、branch ruleのbehavior testを追加します。
- referenceの24時間RPO、4時間RTO、30日retention／drill intervalは最低baselineです。product impact analysisからより厳しくできます。

## Framework relationship

SITF `T-V009 Mass Deletion of Repositories`へ`mitigates`、MITRE ATT&CK
`T1485 Data Destruction`へ限定的な`mitigates`として関連付けます。どちらもattack behavior
との関係であり、complete mitigation、live organization adoption、complianceを意味しません。

## References

- [Pinned SITF source and coverage boundary](../../../docs/SITF_COVERAGE.md)
- [Repository threat model](../../../docs/THREAT_MODEL.md)
- [Control-plane change boundary](../../cicd-security/privileged-control-plane-change/README.md)
- [Supply-chain incident readiness boundary](../../governance-operations/supply-chain-incident-readiness/README.md)
