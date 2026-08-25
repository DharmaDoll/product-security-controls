# PSB-SOURCE-005 check実装ガイド

このガイドは、critical repositoryの破壊耐性と復旧可能性を、特定providerやbackup製品に
固定せず実装するための最小手順を示します。製品名は選択肢でありsecurity outcomeでは
ありません。

各checkは次の順序で読みます。

- **目的**：そのcheckが独立して必要な理由。
- **最小構成**：小規模なadopterが最初に実施できる方法。
- **組織実装**：source／backup control planeへ接続する場合の方法。
- **必要証跡**：assessmentへ渡すmetadata-only evidence。
- **Harmless self-test**：実削除やproduction overwriteを伴わない確認。
- **NOT_CHECKED**：unsafeと断定せず、外部証跡待ちにする条件。
- **限界**：そのcheckだけでは証明できないこと。

## RDR-001：Critical repository scopeを完全にする

- **目的**：保護対象から一つでもrepositoryが漏れると、他のrepositoryのbackupやrestoreが
  完全でも製品を再ビルド、修正、調査できないため。
- **最小構成**：製品ごとに、再ビルド、security patch、incident investigationに必要な
  repositoryをprovider stable IDで列挙し、ownerとcriticalityをreviewする。mutableな
  `owner/name`だけをidentityにしない。
- **組織実装**：provider APIの全pageからactive、archived、disabled、transferred、forkを
  inventory化し、product catalogとexact joinする。対象外repositoryにはownerと理由を持たせる。
- **必要証跡**：collector identity、capture time、pagination completeness、stable repository
  ID、criticality。repository名や内部URLは必須ではない。
- **Harmless self-test**：synthetic inventoryから一つのIDを削除し、`FAIL`になることを確認する。
- **NOT_CHECKED**：provider inventoryまたはproduct-criticality sourceが未接続で、完全scopeを
  判断できない場合。
- **限界**：完全なrepository一覧だけでは、各repositoryの内容やbackupの完全性を証明しない。

## RDR-002：Destructive actionのblast radiusを限定する

- **目的**：一つのstolen owner sessionや誤ったautomationが、短時間に複数のcritical
  repositoryを破壊することを防ぐため。
- **最小構成**：bulk deletionを禁止し、単一repositoryの削除にもdefault deny、requester以外の
  承認、recent phishing-resistant reauthenticationを要求する。providerが直接強制できない
  場合は、削除権限を通常roleから外し、review済みの管理手順だけへ限定する。
- **組織実装**：source-platform role、IdP session policy、privileged workflowを結合し、
  destructive requestの最大target数を1にする。approvalとauditの実装は`PSB-CICD-008`、
  credential lifecycleは`PSB-SOURCE-004`とcomposeする。
- **必要証跡**：default-deny state、最大target数、independent approval requirement、
  reauthentication requirementと有効時間、harmless dry-run decision。
- **Harmless self-test**：syntheticな2-target requestをpolicy evaluatorへ渡し、実APIを呼ばずに
  `DENIED`となることを確認する。
- **NOT_CHECKED**：providerやprivileged workflowのcurrent state、または安全なdry-run decisionを
  取得できない場合。
- **限界**：provider root、support channel、control-plane compromise、複数の連続した単一削除を
  完全には防がない。audit deliveryとincident responseも別途必要である。

## RDR-003：Source authorityから独立したrecovery copyを保持する

- **目的**：source administratorと同じaccount、tenant、credentialで削除できるcopyは、
  repository destructionと同時に失われるため。
- **最小構成**：critical repositoryごとにcontent、全refs、選択したprotected settingsをexportし、
  source administratorが削除できない別security domainへ保存する。retention lockとRPOを定める。
- **組織実装**：source inventoryとbackup inventoryをstable IDでexact joinし、backup account、
  role、key custody、retention、object lock、delete denialをそれぞれreviewする。backup encryption
  だけをdeletion resistanceとみなさない。
- **必要証跡**：stable repository ID、source／backup security-domain ID、snapshot ID、capture time、
  retained-until、lock mode、source-admin delete decision、content／refs／settings digest。
- **Harmless self-test**：synthetic evidenceのbackup domainをsource domainと同じ値へ変更し、
  `FAIL`になることを確認する。
- **NOT_CHECKED**：backup providerのcurrent retention、delete authority、snapshot completenessを
  authoritative sourceから取得できない場合。
- **限界**：metadataはstorage provider enforcement、root account、legal hold、key custody、
  provider control-plane compromiseへの耐性を単独では証明しない。

## RDR-006：Isolated restore drillで復旧可能性を実証する

- **目的**：backup receiptは保存を示すだけで、product sourceを期限内かつ正確に再構成できることを
  示さないため。
- **最小構成**：productionと異なるisolated targetへ全critical repositoryをrestoreし、duration、
  snapshot ID、content、全refs、protected settingsを選択したrecovery copyと比較する。
- **組織実装**：product impact analysisでRTOとdrill cadenceを定め、quota、naming、network、cleanup、
  evidence retentionを用意する。実incidentでは`PSB-GOV-001`のcontainmentとauthorizationを先に行う。
- **必要証跡**：drill identity、started／completed time、isolated target domain、stable repository
  scope、各restoreのsnapshot ID、content／refs／settings digest、refs completeness、settings state。
- **Harmless self-test**：synthetic restore receiptのcontent digestを変更し、`FAIL`になることを
  確認する。self-testでproduction repositoryを削除または上書きしない。
- **NOT_CHECKED**：current full-scope drill receipt、RPO／RTO、または比較対象のrecovery-copy evidenceが
  提供されない場合。
- **限界**：digest一致はIssue、PR、Discussion、Wiki、LFS、Release、Package、hook、key、environment、
  notification、external integrationの意味的な動作を自動では証明しない。

## Evidence statusの扱い

- `AVAILABLE`: authoritative evidenceとして評価可能。安全なら`PASS`、unsafeなら`FAIL`。
- `NOT_PROVIDED`: 必要な外部証跡が未接続。`NOT_CHECKED`でありcleanではない。
- `ERROR`: collectorやsource systemが評価可能な証跡を作れなかった。assessmentでは`ERROR`。

Unknown field、malformed JSON、stale collector、partial pagination、policy identity mismatch、
symlink、size超過、sensitive fieldはassessment failureです。値をstdoutやJSON／CSVへ出力せず、
field pathまたはsanitized reason codeだけを示します。

## 導入の進め方

最初に`RDR-001`でcritical scopeを確定し、次に`RDR-003`の独立copy、`RDR-006`のrestore drillを
接続します。`RDR-002`はprovider capabilityに応じてsource-platform roleまたはprivileged
workflowで強制します。各checkにowner、evidence source、review cadence、exception expiryを
記録し、証跡がない期間は`NOT_CHECKED`のまま維持します。
