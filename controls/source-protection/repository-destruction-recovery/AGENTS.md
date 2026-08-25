# PSB-SOURCE-005 implementation instructions

このcontrolを変更するagent向けの局所指示です。repository rootの`AGENTS.md`と
`controls/AGENTS.md`を先に読み、このfileでは`PSB-SOURCE-005`固有の境界を補足します。

## Control essence

- Domainは`source-protection`です。
- 目的は、単一のsource-platform管理権限ではcritical repositoryを不可逆に消失させられず、
  独立したrecovery copyからproduct固有のRPO／RTO内に復旧できることを実証することです。
- 対象は、製品の再ビルド、security patch、incident investigationに必要なcritical
  repositoryです。全repositoryへの一律適用を要求しません。
- 本packageはbackup製品、source-platform管理製品、IdP、alert system、incident response
  platformではありません。provider-neutralなpolicy、実装ガイド、sanitized read-only
  assessmentを提供します。

## Atomic checks

中核checkは4つだけです。既存参照を安定させるためIDをrenumberしません。

- `RDR-001`: critical repository scopeの完全性とstable provider ID。
- `RDR-002`: bulk destructive actionの拒否、単一操作のdefault deny、独立承認、recent
  phishing-resistant reauthentication。
- `RDR-003`: source administratorが削除できない別security domainのcurrent retained
  recovery copy。
- `RDR-006`: 全critical scopeのisolated restore、RPO／RTO、content／refs／protected
  settingsのexact comparison。

旧`RDR-004`のaudit／alert実装と旧`RDR-005`のcredential containmentは、本controlの
production integration prerequisiteですがatomic checkとして再実装しません。旧`RDR-007`の
strict parsing、policy identity、redaction、fail-closed semanticsはverifier invariantとtestで
維持します。

checkを追加・変更する場合は、`control.yaml`の`applies_to`、`context.threat_actor`、
`context.attack_or_failure_scenario`、`context.why_required`、mappingを同じ変更で更新します。
大きなchecklistを維持するためだけにcheckを追加しないでください。

## Relationship to other controls

- `PSB-CICD-008`はprivileged control-plane変更のapprovalとaudit correlationを所有します。
- `PSB-SOURCE-004`はOAuth、PAT、SSH、App credentialのinventory、lifecycle、revocationを
  所有します。
- `PSB-GOV-001`はincident scope、証跡保全、containment、response authorizationを所有します。
- 本controlはcritical sourceのdestructive-action limit、independent recovery copy、restore
  assuranceだけを所有し、上記controlのscriptやschemaを複製しません。

SITF `T-V009`とMITRE ATT&CK `T1485`はattack behaviorとのrelationshipです。SSDF、SLSA、
ASVS、OWASP Top 10、formal complianceとの関係を追加する場合は、check単位の直接的な根拠を
別途reviewしてください。

## Adoption-first implementation

- READMEの一枚要約直後に、prerequisites、copy対象、明示的activation、harmless self-test、
  exit status、failure recovery、server-side enforcement、rollbackを置きます。
- 最短pathはPython 3.10以上のstandard libraryだけで動作させます。Docker、package manager、
  network access、sudoを要求しません。
- provider-specific API clientやbackup SDKは、documented gapと具体的adopter requirementが
  ない限り追加しません。
- local activationはglobal Git、shell、IDE、OS、source provider、backup storageを変更しません。
- 実削除、実credential revoke、production restore、in-place overwrite、auto-remediationを
  fixtureやself-testへ入れません。
- provider固有のthresholdやobject coverageは、working minimal pathの後にadopter tuningとして
  記録します。

## Evidence and assessment

Assessmentはorganization systemを変更せず、adopterが明示的に渡したsanitized evidenceだけを
評価します。evidenceを指定しないcanonical assessmentは全checkを`NOT_CHECKED`にします。

- `PASS`: freshでauthoritativeなevidenceがrequired stateを示す。
- `FAIL`: 評価可能なevidenceがunsafe stateを示す。
- `NOT_CHECKED`: provider、backup、restore等の外部証跡が未提供。
- `ERROR`: collector、parser、schema、freshness、policy identity等により評価不能。

`NOT_CHECKED`と`ERROR`をclean、問題なし、導入済みとして扱ってはいけません。fixture successも
organization adoption evidenceではありません。

Evidenceにはstable repository ID、security-domain ID、snapshot identity、timestamps、decision、
digest等のmetadataだけを入れます。repository content、credential、token、username、内部endpoint、
raw audit payload、production dataを保存または出力しません。

`scripts/verify.py`は次をfail closedで扱います。

- content-derived policy identity mismatch
- unknown／missing field、wrong type、malformed JSON、size超過
- staleまたはfuture evidence、partial pagination
- duplicate／missing stable ID
- symlink input
- sensitive field
- recovery-copy／restore digest mismatch

Error outputはsanitized field pathまたはreason codeだけを示し、入力値をechoしません。

## Policy tuning

`secure/policy.json`の24時間RPO、4時間RTO、30日retention／drill interval、15分以内の
reauthenticationはreference baselineです。より厳しい値を許容します。弱める場合はproduct impact
analysis、owner、理由、期限を持つreview済みexceptionを要求します。

Policy contentを変更したらcanonical SHA-256の`policy_id`を更新し、fixtureのbindingとpolicy
tamper testを同時に更新します。単にtestを通すためにbaselineやverifier safeguardを弱めては
いけません。

`python3 scripts/policy_id.py secure/policy.json`でcandidate IDを表示し、
`--check`でembedded IDとの一致を検証します。helperはpolicyを自動上書きしません。

## Verification strategy

人間が読める次のケースを維持します。

- secure evidence: exit `0`、4 checkが`PASS`
- unsafe evidence: exit `1`、具体的な`FAIL`
- evidence not connected: exit `3`、`NOT_CHECKED`
- collector／parser failure: exit `2`、`ERROR`
- missing repositoryとpartial paginationを別ケースとして扱う
- same-domain mutable recovery copy、bulk dry-run許可、partial／in-place restore、digest mismatch
- malformed、stale、symbolic、policy tamper、sensitive evidenceのfail-closed behavior
- sensitive markerがtext、JSON、CSVへ出ないこと

固定した`--as-of`をfixture testに使い、wall clockに依存させません。live/no-evidence smoke testは
schema、sanitization、supported exitだけを確認し、実行環境のorganization complianceを要求しません。

変更後はcontrol directoryから実行します。

```bash
bash tests/test.sh
```

repository rootからも実行します。

```bash
make verify-control CONTROL=PSB-SOURCE-005
make validate-controls
```

Assessment contractを変更した場合は、`make assess-control CONTROL=PSB-SOURCE-005`も実行し、
生成されたorganization-specific resultをcommitしません。indexやmappingに影響するmetadata変更では
repository generatorを実行し、review済みの生成差分だけを更新します。
