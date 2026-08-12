# PSB-GOV-004: supply-chain credential漏洩を封じ込めてrotation完了を検証する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | 漏洩したcredentialを置換しただけでは、旧credential、派生session、忘れられたconsumer、侵害時間帯の不正操作が残り、source改変、package公開、artifact差し替え、deploymentが継続し得る。 |
| 誰から、または何から守るか | Secret-harvesting bot、phisher、infostealer、malicious dependency・Action、侵害されたmaintainer・build job、insider、不完全なprovider responseやrotation automationから守る。 |
| 何が対象か | Source access、CI secret、package publishing、container registry、cloud deployment、SSH、artifact signingのcredential identifier、consumer、resource、派生authority、release・artifact・deployment影響。 |
| 何をするか | Secretを含まない関係inventoryから全consumerを特定し、credential種別ごとに旧authorityを封じ込め、必要なら狭いreplacementへ移行し、旧authority拒否と影響レビューを独立確認してからcloseする。 |
| 成功状態 | Evidence保全、承認、旧authority無効化、派生authority失効、consumer移行、旧authority拒否、影響レビューが順序どおり完了し、不完全・stale・adapter失敗は`CLOSED`やclean結果にならない。 |
| 対象外・残余リスク | E3 fixtureはprovider-neutralなdry-runであり、live credentialを失効・発行せず、全provider sessionや未観測consumer、侵害中に行われた操作を完全に発見したことを証明しない。 |

## セキュリティ上の問題

Credential漏洩時の「rotation」は、新しいcredentialを発行して設定を1か所更新する作業では
ありません。旧credentialがまだ使用可能、派生sessionが有効、緊急用consumerが更新漏れ、
signerのtrustが残存、またはauditとartifact影響が未確認でも、新credentialの疎通だけを見て
完了扱いすると、攻撃者のauthorityが残ります。

このcontrolは、supply chain全体のcredential incidentを次のclosure条件へ分解します。

1. secret値を取得しないstable credential identifierと関係graphを確定する
2. 証跡を保全し、独立したownerが具体的なresponse scopeを承認する
3. credential classに合ったcontainmentを実施したというsanitized receiptを確認する
4. 全consumerをmigrate、remove、quarantine、またはowner-approved N/Aへ決定する
5. replacementの成功とは別に、旧authorityを使用できないことをnegative probeで確認する
6. exposure windowのauditをsource、workflow、package、image、attestation、release、artifact、deploymentへ結び付ける
7. これらが揃った場合だけ`CLOSED`とする

## Control境界

| Control | 所有する責務 |
|---|---|
| `PSB-SOURCE-003` | Public sourceとGit historyを含む露出検出、credential-first remediation |
| `PSB-SOURCE-004` | GitHub OAuth、PAT、SSH key、GitHub App等の通常lifecycle、storage、review、revoke trigger |
| `PSB-CICD-006` | OIDC exact claim、短寿命cloud federation、static deployment credential排除 |
| `PSB-GOV-001` | Package／SBOMからbuild、artifact、active deploymentへの影響逆引き |
| `PSB-GOV-004` | Incident横断のconsumer集約、class別containment、replacement移行、旧authority拒否、closure判定 |

Secret scanning、通常のcredential hygiene、application runtime secret injection、artifact
provenance生成をこのcontrolへ重複実装しません。

## Credential classごとのresponse

| Credential class | 必須response | Replacementの扱い |
|---|---|---|
| Reusable bearer token | 旧authority revoke、派生session・downstream authority失効 | Owner、purpose、scope、resource、consumerを狭く保ち、有効期間を短縮して再bind |
| SSH key | 旧key削除、関連session失効 | 新keyを再enrollしてexact consumerへbind |
| Signing key | Signer trust revoke、fresh status公開、署名済みartifact review | Replacement trustを意図的に配布し、旧署名が新trustへ混入しないことを確認 |
| Short-lived OIDC／session | Replayまたはissuer経路を遮断し、trust policyを修復 | 通常の期限切れだけをincident解決の証拠にせず、不要ならreplacementは`NOT_REQUIRED` |

## 安全な例と安全でない例

`secure/response-bundle.json`は、実credential値を含まないsynthetic fixtureです。

- package publishing tokenのrevoke、狭いreplacement、2 consumerの移行;
- signing keyのtrust revoke、signer status、artifact review、replacement trust;
- short-lived cloud sessionのreplay／issuer遮断とtrust policy修復;
- exact exposure window auditとrelease、artifact、deployment等のimpact reference;
- independent old-authority denial probe;
- live provider mutationを`NOT_CHECKED`に残すdry-run receipt。

`insecure/`は、長すぎるauthorization、自己承認に近いrole、不完全なsurface inventory、
replacement-only response、wildcard scope、未解決consumer、旧authorityが`ALLOWED`、証跡保全前の
cleanup、empty auditを「不正なし」と誤認する状態を隔離して示します。

## 状態機械

状態遷移は次のexact orderです。

```text
SUSPECTED
  -> CONTAINMENT_AUTHORIZED
  -> OLD_AUTHORITY_DISABLED
  -> DEPENDENT_AUTHORITY_INVALIDATED
  -> REPLACEMENT_BOUND
  -> CONSUMERS_MIGRATED
  -> OLD_AUTHORITY_DENIED
  -> IMPACT_REVIEWED
  -> CLOSED
```

Short-lived credentialでreplacementが不要な場合も`REPLACEMENT_BOUND`を飛ばさず、
`NOT_REQUIRED`というreview済みdecisionを記録します。Repository cleanupは
`OLD_AUTHORITY_DENIED`以後、artifact quarantine／delete／republishとclosureは
`IMPACT_REVIEWED`以後にしか計画できません。

## 検証

```bash
make verify-control CONTROL=PSB-GOV-004
```

直接実行する場合:

```bash
python3 controls/governance-operations/credential-exposure-containment/scripts/verify.py \
  --policy controls/governance-operations/credential-exposure-containment/secure/policy.json \
  --bundle controls/governance-operations/credential-exposure-containment/secure/response-bundle.json \
  --evaluation-time 2026-08-10T12:00:00Z
```

| 終了コード | 意味 |
|---|---|
| `0` | Provider-neutral contractとsynthetic closure evidenceが成立。Live mutationは引き続き`NOT_CHECKED` |
| `1` | Unsafe policy、過大replacement、未解決consumer、旧authority有効等を検出 |
| `2` | Missing consumer、stale inventory、partial receipt、denial test未実施、順序不正、secret-bearing evidence、adapter・parser失敗で検証不能 |

Negative testはsuccessful leaked-secret response、signer、short-lived token、missing consumer、
stale inventory、partial revocation、replacement-only、old authority still valid、out-of-order、
malformed、secret-bearing、adapter errorを区別します。Error messageへfixtureの値をechoしません。

## 導入方法

1. Providerごとのcredential inventory collectorをread-onlyで実装し、secret値を返さずstable ID、owner、class、scope、resource、consumerだけを正規化する。
2. `PSB-SOURCE-003`等のdetection evidence digestとexposure windowをincidentへbindする。
3. Live mutation adapterはresponse planと分離し、least privilege、idempotency、rate limit、rollback、audit、independent authorizationをreviewする。
4. Provider receiptがpartial、outage、unknownの場合は成功へfallbackせず`ERROR`にする。
5. Replacement疎通とold-authority denialを別probeとして実行する。
6. Package、artifact、deployment影響は`PSB-GOV-001`へhandoffし、exact identityをclosure recordへ戻す。
7. Live adoption evidenceが得られるまで、fixture PASSをproduction rotation完了とみなさない。

## 制限事項

- Local verifierはlive providerへ接続せず、credentialの失効、発行、session invalidation、signer distrustを実行しない。
- Stable identifierの発行元が不完全なら、同じsecretから派生した別sessionやcredentialを見落とし得る。
- Audit eventが0件でも不正利用がなかったことを証明しない。
- Replacementのscope比較はnormalized exact setであり、provider固有のimplicit permissionやresource hierarchyはlive adapterで追加評価する必要がある。
- Signing incidentではtimestamp、transparency、revocation propagation、consumer trust-store更新のlive evidenceが別途必要である。
- Short-lived credentialの自然失効は、issuer trust修復、replay防止、impact reviewの代替にならない。
- Destructive response、history rewrite、artifact deletion、republishは本controlのdry-run対象であり、自動実行しない。

## 参考資料

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATT&CK T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [OpenSSF Security Baseline](https://baseline.openssf.org/)
