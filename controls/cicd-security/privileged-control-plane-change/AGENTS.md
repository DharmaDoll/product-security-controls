# PSB-CICD-008 implementation instructions

このfileは`PSB-CICD-008`（`cicd-security`）固有の実装境界を定める。変更前に
[repository rootのAGENTS.md](../../../AGENTS.md)、[controlsのAGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、[ROADMAP](../../../docs/ROADMAP.md)、関連ADR、
[README.md](README.md)、[control.yaml](control.yaml)を読むこと。

## Control essence

- 対象は、SCM、CI、cloud identity、artifact registry、signing serviceのsecurity-impactingな管理設定変更である。
- 本質は、一つの変更を、named current human、exact targetと人が読めるbefore／after、独立事前承認、
  provider上の実行記録、変更後current stateへ結び付けることである。
- 通常変更はrequester／executorとは別の人物が実行前に承認する。
- 緊急変更はincident-owned、最大1時間で、executorとは別の人物が期限内に`accepted`または`reverted`を判断する。
- Security効果はlive provider／IdP setting、role separation、approval operation、audit review、rollbackから生まれる。
  Repository documentをcopyしただけでは導入済みにならない。
- Providerがadmin settingの二者承認を強制しない場合、このreferenceは直接変更を完全にはpreventしない。
  無承認変更をaudit review cadence内にdetectし、影響確認とrevertへつなぐcontrolである。
- 本controlは変更内容のsecure baselineを重複して所有しない。各settingの正しい値は関連domain controlが所有する。

## Implementation mode

本controlはguidance-first／manual verificationで実装する。

- Copy可能な実装は[`secure/privileged-change-runbook.md`](secure/privileged-change-runbook.md)と
  [`secure/change-record-template.md`](secure/change-record-template.md)の二つに保つ。
- [README.md](README.md)はsecurity problem、被害条件、役割、最短導入、通常／緊急手順、harmless drill、
  recovery、rollback、residual riskを具体的に説明する。
- [`insecure/uncontrolled-change.md`](insecure/uncontrolled-change.md)は、危険な運用と実害が成立する条件を示す。
  Providerへ適用する設定やcredentialを置かない。
- Control-local verifier、normalizer、collector、policy JSON、synthetic evidence、expected-output fixture、
  `tests/test.sh`を追加しない。
- README文字列test、`secure: true`を検査するscript、常に成功するtest、形式的schema validationを追加しない。
- Real organizationのcompleted record、audit export、screenshot、provider responseをrepositoryへcommitしない。
- Provider settingを変更するautomationやautomatic rollbackをverificationに混ぜない。
- Read-only automationを将来追加するのは、対象数が人手reviewを超え、actual provider evidenceの完全性を
  明確に改善するときだけとする。その場合はauthority、pagination、failure state、redaction、live boundaryを先に
  設計し、top-level verificationをmanualのままにできるか再評価する。

## 実装前の仮説と反証

最初の案へanchoringせず、少なくとも次を確認する。

1. **管理者権限があるだけで直ちに製品侵害になる。** 変更可能なsetting、変更後に利用できるauthority、
   downstream workflow／consumerまでの経路がなければ反証される。
2. **IaCとpull request reviewだけで十分である。** Direct UI／API changeやprovider driftが残るなら反証される。
3. **Hashと共通JSONがなければexactな変更を承認できない。** 人が読める小さなsettingをprovider画面で
   before／after比較できるなら反証される。Hashは大きなmachine-readable policyだけに使う。
4. **Sandbox drillが通れば全providerで導入済みである。** Scope inventoryの他targetを確認していなければ反証される。
5. **Repository testを増やせばcontrol assuranceが上がる。** Live MFA、membership、approval、provider event、
   current stateを確認しないself-authored fixtureなら反証される。

READMEの`セキュリティ上の問題`とrisk説明は、単に「管理者が設定を変えられて危険」と書かない。各例について次を示す。

1. 誰が何を変更できるか。
2. 変更後にどのauthorityまたはtrust boundaryが変わるか。
3. どのworkflow、actor、consumerがそのauthorityを利用できるか。
4. 起こり得る具体的な被害。
5. どの条件がなければ、その被害経路が成立しないか。

Severityやimpactを最大値だけで語らず、実効権限とdata flowを確認する。一方で、現在のdownstream経路が不明だからと
無承認変更を安全扱いせず、`NOT_CHECKED`としてownerを割り当てる。

## Supported reference and prerequisites

- Reference providerはGitHub.com／GitHub Enterprise Cloudである。
- 最初の対象は専用private sandbox repositoryの`control-test` branch rulesetである。
- Developer環境はmacOSまたはLinux、repository-local documentのcopyには標準shellを使う。
- Requester／executorとは別に、変更内容を理解できるapproverが1名以上必要である。
- Shared administratorを使わず、provider auditでactorを一人のcurrent humanへ結び付けられる必要がある。
- ProviderまたはIdPでphishing-resistant authenticationを使う。
- Approved ticket／change system、provider audit access、current-setting確認、non-production drill targetが必要である。

Provider plan、GitHub Enterprise Server、GitLab、AWS、Azure、GCP等へ拡張する前に、stable target、audit event、
current-state確認方法、必要権限、history、retentionを確認する。確認できないpropertyを架空のevidenceで埋めず
`NOT_CHECKED`とする。

Reference defaultはsession最大1時間、実行前15分以内のstep-up、emergency review最大1時間である。
Provider／IdPがsession evidenceを提供しない場合、自己申告だけで`CPC-002`を`PASS`にしない。

## Roles

- **Product owner／Development team:** 対象、変更理由、期待結果、downstream authority、変更後のbuild／release確認を説明する。
- **Repository administrator／Organization owner:** Named roleと認証を整備し、承認済みsettingをproviderへ適用する。
- **CI platform／Platform／SRE:** Scope inventory、audit export、保管、review cadence、failure ownerを運用する。
- **Security／Independent approver:** Exact target、before／after、被害条件、side effect、rollbackを実行前にreviewする。
- **Independent reviewer:** Provider eventとcurrent settingを実行後に確認し、checkごとのresultを記録する。
- **Incident response:** Emergency scope、expiry、独立post-review、revertを完了する。

Developerにorganization-wide admin、collector credential、evidence retentionを担当させない。

## Atomic checks

[control.yaml](control.yaml)がcanonical metadataである。既存IDを不要にrenumberせず、次の意味を維持する。

- `CPC-001`: Actorはshared accountでないnamed current humanで、対象serviceのauthorized roleを持つ。
- `CPC-002`: Phishing-resistant authenticationとbounded session／recent step-upをliveで確認する。
- `CPC-003`: Requestはstable target、人が読めるbefore／after、reason、impact conditions、rollbackを実行前に持つ。
- `CPC-004`: Ordinary changeはrequester／executor以外がexact targetとafterを実行前に承認する。
- `CPC-005`: Provider auditのactor／action／time／targetとcurrent settingがapproved requestに一致する。
- `CPC-006`: Emergency changeはincident-owned、最大1時間、独立したtimelyな`accepted`／`reverted`判断を持つ。
- `CPC-007`: 宣言したscopeの全targetにowner、verification path、明示的resultがあり、不足をcleanにしない。

Check変更時は`check_context_version: "1.0"`、`applies_to`、responsible role、check固有の
`context.threat_actor`、`context.attack_or_failure_scenario`、`context.why_required`、verification、
evidence、mappingを同時にreviewする。

## Verification and evidence boundary

Top-level verificationは`manual`である。

- Positive drillはprivate sandbox rulesetを弱めず、required review数を`1`から`2`へ強化する。
- Negative drillはapprovalなしでexecutorが停止することと、ticketなしのsandbox強化変更がaudit reviewで
  `FAIL`になることを確認する。
- Production protectionを弱めるtest、実credential、provider-valid tokenを使用しない。
- Completed evidenceはapproved ticket／evidence systemへ保存し、public repositoryへcommitしない。
- `PASS`はcurrent authoritative evidenceが期待状態と一致するときだけ使う。
- `FAIL`はself-approval、無申請変更、target／value不一致、期限超過等、評価できた違反に使う。
- `NOT_CHECKED`はscope、setting、role、provider機能、live evidenceの未確認に使う。
- `ERROR`はaudit／API／画面取得失敗、partial export、時刻不整合、読めない記録に使う。
- `N/A`はscopeに存在しない対象についてownerが理由をreviewした場合だけ使う。

`make verify-control CONTROL=PSB-CICD-008`は`NOT_CHECKED`とexit `2`を返す。これをtest failureや
repository controlの欠陥と扱わず、live手順への誘導を維持する。

## Relationship to other controls

他controlのpolicy、fixture、verifierをこのpackageへcopyしない。

- [`PSB-CICD-004`](../actions-least-privilege/README.md): Workflow／job token permission。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): Untrusted PR codeとprivileged executionの分離。
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): Machine OIDC claimとcloud trustのrequired state。
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner routing、registration、image、network、lifecycle。
- [`PSB-SOURCE-004`](../../source-protection/source-access-credential-lifecycle/README.md): Human／App credential lifecycle。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): GitHub Organization current posture。
- [`PSB-SOURCE-005`](../../source-protection/repository-destruction-recovery/README.md): Destruction制限、backup、restore。
- [`PSB-CONTAINER-002`](../../container-cloud-iac-security/container-registry-security/README.md): Registry required state。
- [`PSB-REL-005`](../../release-integrity/artifact-signing-generation/README.md): Signing authorizationとgeneration。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Time-bound exception lifecycle。

本controlは、これらのrequired stateを変更するときのactor、approval、execution、provider observationだけを所有する。

## Framework and claim rules

- Mappingはexact framework version、identifier、relationship、confidence、rationale、reviewer、review date、
  `applies_to`を持つ。
- Manual guidanceとの関係だけを示し、live GitHub setting、organization adoption、formal compliance、
  complete mitigationを主張しない。
- Existing adapterの削除後も、adapterが検証したという古いrationaleを残さない。

## Required verification after changes

Repository rootから実行する。

```bash
make validate-controls
python3 -m unittest tests.test_control_metadata tests.test_run_controls
```

次は`NOT_CHECKED`を表示してexit `2`になることを個別に確認する。

```bash
make verify-control CONTROL=PSB-CICD-008
```

`tests/test.sh`を追加してexit `0`へ変えない。Generated index、mapping、checklistは再生成可能性を確認しても、
taskで明示されない限りcommit対象へ含めない。Testsを通すためにlive verification boundaryを弱めない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
