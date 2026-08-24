# PSB-GOV-005: 稼働artifactの脆弱性をrebuildと置換完了まで追跡する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Build時には安全だったartifactも、dependency・base imageの新規脆弱性、support終了、registry lifecycleの時間変化により危険になる。検出だけしても、再build・再deploy・旧digest除去まで追跡しなければ本番riskは残る。

### 誰から、または何から守るか

侵害dependency、古いbase image、既知脆弱性、support終了、partial rollout、mutable tag、inventory欠落、運用放置、scanner／registry／deployment collector障害から守る。

### 何が対象か

Active deployment、artifact digest、SBOM serial、vulnerability／support／registry evidence、rebuild decision、source revision、build／provenance／signature、registry publication、admission receipt。

### 何をするか

Exactな稼働digestを起点にcurrent evidenceを評価し、policyでownerと期限を決め、clean rebuildのnew digestをrelease・admitし、全environmentからold digestが消えたことを別に検証する。

### 成功状態

`REMEDIATED`は、新digestのevidence-completeなbuild、immutable publication、全targetのadmission、fresh inventoryによるold digestゼロが揃った場合だけ成立する。検査不能は`ERROR`、期限超過は`OVERDUE`となる。

### 対象外・残余リスク

Offline fixtureはlive scanner、全cluster inventory、build platform、registry、admission controllerを証明しない。新build自体の安全性は既存build／release／container controlが担う。

## Goal

「影響するartifactが分かった」を「本番から危険なbytesが消えた」まで閉じます。
署名やprovenanceはartifactのidentityとoriginを検証しますが、時間経過後も安全かは
証明しません。本controlは`PSB-GOV-001`のruntime inventory、`PSB-GOV-003`の
vulnerability priority、build／release evidence、registry、admissionを一つの
refresh caseへ結びます。

## Control境界

- `PSB-GOV-001`: component、artifact、SBOM、active deploymentのimpact inventory
- `PSB-GOV-003`: exact vulnerability、applicability、priority、response deadline
- `PSB-BUILD-002..003`: hosted build invocationとplatform provenance
- `PSB-REL-002..005`: provenance、SBOM、supplier trust、signatureの生成・公開
- `PSB-CONTAINER-001..002`: exact digest admissionとregistry lifecycle
- `PSB-GOV-005`: current riskからrebuild decision、replacement deployment、old digest除去までのclosure

本controlはscanner、builder、registry、deployment systemを再実装しません。

## 判断状態

| 状態 | 意味 |
|---|---|
| `NOT_AFFECTED` | Completeでfreshなevidenceがexact deployed digestを非該当と判断した。将来の安全を保証しない。 |
| `IN_PROGRESS` | Rebuildが必要で期限内だが、replacementまたはold digest除去が未完了。 |
| `OVERDUE` | Rebuild期限を過ぎてもclosure条件が揃っていない。 |
| `REMEDIATED` | New digestがbuild・release・admitされ、全original scopeでold digestがinactive。 |
| `FINDING` | Policy弱体化、same-digest rebuild、identity mismatch、partial rolloutなどのsemantic failure。 |
| `ERROR` | Evidenceがmissing、stale、partial、malformed、unavailable、またはsensitiveで評価不能。 |

## 安全な例と危険な例

[`secure/case-remediated.json`](secure/case-remediated.json)は、二つのproduction
deploymentをold digestからnew digestへ置換し、build／release／admission identityと
post-deployment inventoryを一致させます。

[`secure/case-in-progress.json`](secure/case-in-progress.json)は、期限内の未完了を
`IN_PROGRESS`として保持します。これはPASSではなく、運用上のopen stateです。
[`secure/case-not-affected.json`](secure/case-not-affected.json)はcompleteなcurrent
evidenceでのみ`NOT_AFFECTED`になります。

[`insecure/case.json`](insecure/case.json)は、old digestをnew tagで再利用し、一つの
environmentに旧artifactを残したまま`REMEDIATED`を要求します。verifierは拒否します。

## 実行方法

```bash
make verify-control CONTROL=PSB-GOV-005
```

直接実行する場合:

```bash
python3 controls/governance-operations/deployed-artifact-refresh/scripts/verify.py \
  --policy controls/governance-operations/deployed-artifact-refresh/secure/policy.json \
  --case controls/governance-operations/deployed-artifact-refresh/secure/case-remediated.json
```

終了codeは`0`がverified state、`1`がsecurity findingまたはopen／overdue state、`2`が
evidence／execution errorです。`IN_PROGRESS`をcleanやremediatedとして扱いません。

## Expected output

```text
REMEDIATED case=REFRESH-2026-0001 old_digest_instances=0 replacement_targets=2
```

出力にはcase ID、state、countだけを残し、digest、CVE、endpoint、credential、raw
scanner finding、customer情報は記録しません。

## Integration

1. `PSB-GOV-001`でexact active deployment scopeを固定する。
2. Scanner、support、base image、registry lifecycleのcomplete receiptを収集する。
3. Affectedならpolicyからowner、priority、deadlineを導出する。
4. `PSB-BUILD-002..003`と`PSB-REL-002..005`を通るclean rebuildを作る。
5. `PSB-CONTAINER-002`へimmutable publishし、`PSB-CONTAINER-001`で全targetへadmitする。
6. Fresh inventoryでold digestがゼロになったことを確認してからcloseする。

Provider adapterはraw evidenceをこのcontractへ正規化し、collector outageやpartial
paginationを`ERROR`にします。Destructive rolloutやrollbackはこのoffline verifierから
実行しません。

## Operational notes

- Deadlineは組織policyで定め、fixture値をSLAとして流用しない。
- Emergency rollbackでold digestを使う場合は、別の期限付き承認と再refresh caseが必要。
- Replacement成功とold digest denial／absenceは独立して収集する。
- Inventory scopeを縮めてclosureすることは禁止する。
- Evidenceにはraw exploit、credential、customer data、internal endpointを保存しない。

## Framework mapping

- NIST SSDF `RV.1.1`: current evidenceからaffected deployed artifactを確認する支援関係
- NIST SSDF `RV.2.1`: bounded response、rebuild、replacement closureを計画・検証する支援関係
- OpenSSF OSPS `OSPS-DO-04.01`: support scope evidenceとの関連。文書公開の達成主張ではない
- MITRE ATT&CK `T1195.002`: supply-chain compromiseが稼働し続ける時間を縮めるmitigation

これらはformal complianceや完全なattack preventionを意味しません。

## Limitations

- Live adoptionにはscanner、SBOM platform、registry、builder、cluster inventory、admissionのadapterが必要です。
- Clean rebuildにも新たな脆弱性やmalicious changeが入り得ます。
- Signed artifactであることとcurrent／safeであることは別です。
- Full rollout後もmemory resident processやexternal cacheが残る場合は別のruntime responseが必要です。
