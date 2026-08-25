# PSB-SOURCE-005: Critical repositoryの破壊耐性と独立復旧を検証する

## このcontrolを一枚で理解する

### セキュリティ上の問題

source-platformの強い管理権限を奪われると、製品の再ビルド、セキュリティ修正、
incident investigationに必要なrepository、refs、履歴、保護設定をまとめて失い得る。
同じ管理権限で消せるmirrorや、実際に戻したことのないbackupは復旧保証にならない。

### 誰から、または何から守るか

stolen administrator sessionを使う攻撃者、悪意ある管理者、誤ったbulk automation、
不完全なrepository inventory、同一authorityのmutable copy、破損したexport、試されて
いないrestore手順から守る。

### 何が対象か

製品の再ビルド、security patch、incident responseに必要と分類したcritical repository
だけを対象とする。stable provider ID、destructive-action control、独立したrecovery copy、
Git objects／refs／protected settings、isolated restore drillを確認する。

### 何をするか

critical scopeを完全に列挙し、一度の破壊操作を1 repositoryへ制限する。source
administratorが削除できない別security domainへcurrent recovery copyを保持し、全scopeを
isolated targetへ戻してRPO、RTO、content／refs／settings digestを比較する。

### 成功状態

全critical repositoryがstable IDで一意に確認され、bulk destructive actionが拒否され、
各repositoryに独立したcurrent recovery copyがあり、期限内のisolated restore drillで
選択したcopyと同じcontent、refs、protected settingsを復元できる。

### 対象外・残余リスク

本controlはprovider、backup製品、IdP、alert基盤を構築せず、organization全体のdisaster
recoveryを証明しない。Issues、PR、LFS、release assets等の復元対象はproviderごとに定義が
必要であり、provider control-planeやbackup root authorityの侵害リスクは残る。

## 最短の導入手順

### 前提とtrust assumption

- Python 3.10以上を使用する。Docker、追加package、network接続は不要。
- critical repositoryの選定、RPO、RTO、retentionはproduct ownerとrepository adminが
  合意する。
- source provider、backup storage、restore drillから取得する証跡が正本であることは、
  adopter側のcollectorとreviewに依存する。
- fixtureはsynthetic exampleであり、organization adoptionの証跡ではない。

### コピーするもの

最も簡単な方法は、このcontrol directoryをreviewしてそのままコピーすることです。
最低限必要なのは次です。

- `secure/policy.json`
- `scripts/verify.py`
- `scripts/policy_id.py`
- `assessment/assess.py`
- `docs/check-implementation-guide.md`

`secure/evidence.json`と`insecure/evidence.json`はschemaとself-testの例としてだけ使います。

### 明示的なactivation

1. `secure/policy.json`のcritical repository IDと組織固有のRPO／RTOをreviewする。
2. `docs/check-implementation-guide.md`に従い、provider、backup、restoreからsecretを含まない
   normalized evidenceを作る。
3. evidence fileを明示してread-only assessmentを実行する。

```bash
python3 assessment/assess.py \
  --workspace . \
  --policy secure/policy.json \
  --evidence organization-recovery-evidence.json \
  --json-output /tmp/PSB-SOURCE-005.json \
  --csv-output /tmp/PSB-SOURCE-005.csv
```

この手順はGit、shell、IDE、OS、source provider、backup storageの設定を変更しません。

### Harmless self-test

repository rootから次を実行します。

```bash
make verify-control CONTROL=PSB-SOURCE-005
```

control directoryから直接実行する場合:

```bash
bash tests/test.sh
```

self-testはsynthetic metadataだけを使い、実repositoryの削除、credential失効、network access、
production restoreを行いません。

### 結果と終了status

- exit `0`: 全中核checkが`PASS`
- exit `1`: authoritative evidenceでunsafe stateを確認した`FAIL`
- exit `2`: collector、parser、schema、policy identity等の評価に失敗した`ERROR`
- exit `3`: 必要なorganization evidenceが未提供の`NOT_CHECKED`

`NOT_CHECKED`と`ERROR`を「問題なし」に読み替えてはいけません。

### よくある失敗と回復

- `NOT_CHECKED`: 表示されたcheckのprovider／backup／drill evidenceを接続する。
- `ERROR`: malformed JSON、unknown field、stale collector、partial pagination、policy ID、
  symlink、sensitive fieldを修正して再実行する。
- `FAIL`: policyを弱めず、対象scope、destructive-action control、recovery copy、restore
  procedureを修正する。
- policyを変更した場合は、次でcontent-derived `policy_id`を計算してfileへ反映し、変更をreviewする。

```bash
python3 scripts/policy_id.py secure/policy.json
```

### CI／server-side enforcement

local assessmentだけではdestructive actionを止められません。source provider側の権限制御、
backup側のretentionとdelete denial、定期restore drill、audit／incident integrationを別途
強制してください。assessmentはそれらのsanitized evidenceを検証する役割です。

### Rollback

コピーしたcontrol directory、生成したassessment結果、adopterが明示的に追加した定期実行
設定だけを削除します。source providerやbackup storageの保護設定をrollbackで弱めては
いけません。

## このcontrolの位置付け

このcontrolはrepository backup製品でもincident response platformでもありません。
critical product sourceについて、次の4つのsecurity outcomeを小さなpolicy、実装ガイド、
sanitized read-only assessmentで確認するreference implementationです。

1. `RDR-001`: critical repository scopeが完全である。
2. `RDR-002`: 一つの侵害authorityや操作によるdestructive blast radiusが限定される。
3. `RDR-003`: 同じsource authorityでは消せないcurrent recovery copyがある。
4. `RDR-006`: 全critical scopeをisolated targetへ期限内に正確に戻せる。

全repositoryへ一律適用するcontrolではありません。短命なsandbox、他の正本から再生成できる
mirror、製品復旧に不要なrepositoryは、ownerのreviewにより対象外にできます。

## Check実装ガイド

各checkの最小構成、組織実装、必要証跡、`NOT_CHECKED`条件、限界は
[`docs/check-implementation-guide.md`](docs/check-implementation-guide.md)にまとめています。

provider固有の設定値をfixtureから推測しません。live adapterがない場合はsanitized exportを
入力し、証跡がなければ`NOT_CHECKED`を返します。外部systemをmockして架空の`PASS`を作りません。

## Policyとevidence

`secure/policy.json`はreference baselineです。24時間RPO、4時間RTO、30日retention／drill
interval、15分以内のreauthenticationを例示します。より厳しい値へ変更できます。弱める場合は
product impact analysisとowner、理由、期限を持つexceptionが必要です。

Normalized evidenceは次だけを含みます。

- stable repository ID、criticality、collector identity、freshness、pagination completeness
- destructive-action controlのnormalized stateとharmless dry-run decision
- recovery-copy identity、security domain、retention、lock、delete authority、digest
- isolated restoreのscope、duration、copy identity、content／refs／settings digest

repository content、credential、token、username、内部endpoint、raw audit payload、production
dataは含めません。

## Verificationとassessmentの違い

fixture verificationは、reference implementationとnegative testが意図どおり動くことを確認
します。organization assessmentは、adopterが与えた外部証跡の範囲だけを評価します。

```bash
make verify-control CONTROL=PSB-SOURCE-005
make assess-control CONTROL=PSB-SOURCE-005
```

evidenceを指定しないcanonical assessmentは、外部証跡を勝手に発見せず、4 checkすべてを
`NOT_CHECKED`としてsanitized JSON／CSVへ出力します。

## 既存controlとの分担

- `PSB-CICD-008`はprivileged control-plane変更のapprovalとaudit correlationを所有する。
- `PSB-SOURCE-004`はOAuth、PAT、SSH、App credentialのinventory、lifecycle、revocationを
  所有する。
- `PSB-GOV-001`はincident scope、証跡保全、containmentとresponse runbookを所有する。
- 本controlはそれらを再実装せず、critical sourceのdestructive-action limit、独立copy、
  restore assuranceだけを所有する。

Audit delivery、actor authority containment、recovery authorizationはproduction recoveryの
重要な前提ですが、本controlのfixtureで導入済みと主張しません。

## Limitations and operational cost

- provider-neutral evidence contractであり、live GitHub／GitLab／Bitbucket設定を証明しない。
- providerごとにIssue、PR、Discussion、Wiki、LFS、Release、Package、Actions artifact、hook、
  key、environment等の復元対象表が必要になる。
- lock metadataだけではstorage enforcement、root account、key custody、legal holdを証明しない。
- digest一致だけではaccess control、notification、external integration等のbehaviorを完全に
  証明しない。
- restore drillにはstorage、API、operator時間、isolated quota、cleanup、cost budgetが必要。
- source providerとbackup providerの両control planeが同時に侵害されるriskは残る。

## Framework relationship

SITF `1.0.0@d1d1536`の`T-V009 Mass Deletion of Repositories`へ`mitigates`、MITRE
ATT&CK `v19.1`の`T1485 Data Destruction`へ限定的な`mitigates`として関連付けます。
どちらもattack behaviorとの関係であり、compliance、complete mitigation、organization
adoptionを意味しません。SSDF、SLSA、ASVS、OWASP Top 10へのmappingは主張しません。

## References

- [Pinned SITF source and coverage boundary](../../../docs/SITF_COVERAGE.md)
- [Repository threat model](../../../docs/THREAT_MODEL.md)
- [Control-plane change boundary](../../cicd-security/privileged-control-plane-change/README.md)
- [Source credential lifecycle boundary](../source-access-credential-lifecycle/README.md)
- [Supply-chain incident readiness boundary](../../governance-operations/supply-chain-incident-readiness/README.md)
