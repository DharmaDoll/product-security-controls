# PSB-SOURCE-006 implementation instructions

このfileは`PSB-SOURCE-006`固有の実装境界を定める。作業前に
[repository rootのAGENTS.md](../../../AGENTS.md)、[controlsのAGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、[ROADMAP](../../../docs/ROADMAP.md)、このpackageの
[README.md](README.md)と[control.yaml](control.yaml)を読むこと。

## Control essence

- Control IDは`PSB-SOURCE-006`、domainは`source-protection`である。
- 対象は一つのGitHub Organization全体のidentity、access relationship、repository既定値、
  Actions policy、installed App、repository security configuration、audit／drift／alertである。
- 実効性はGitHubとIdPの実設定、権限分離、定期access review、完全なread-only inventory、
  独立した監査保全、drift対応から生まれる。
- `secure/policy.json`、synthetic snapshot、verifierをcopyするだけではlive settingは変わらず、
  organization adoptionも証明されない。
- このcontrolは、個別repositoryが安全でもOrganization側の広い権限や設定漏れから迂回される
  cross-repository governance gapだけを所有する。

## Supported profile and assumptions

- 基準profileはGitHub.com／GitHub Enterprise Cloudとする。他providerは具体的なadopter要件、
  current-state取得方法、stable identity、失敗時の扱いが定義できる場合だけ追加する。
- GitHub planによりSAML／SCIM、Enterprise Managed Users、Actions policy、security configuration、
  audit APIとretentionが異なる。利用不能な機能を安全と推測せず、組織が調整するbounded fallbackか
  `PSB-GOV-002`の例外として明示する。
- 開発環境はmacOS、VS Code、Python 3.10+を基本とし、既存verifierはstandard libraryだけで
  動作させる。このcontrolのためにpackage manager、framework、Dockerを追加しない。
- Providerの管理権限、IdP、audit保管先、alert receiverはorganization-owned authorityである。
  Repository fixtureからこれらの実在、完全性、運用状態を推測しない。
- Live collectorはadopterが用意するread-only integrationである。Repository内のreference
  implementationはcollector credentialの発行やGitHub設定の変更を行わない。

## 実装方式を選ぶ前の問い

変更を設計する前に、次を判断する。

1. Security向上を生むGitHub／IdPの実設定または運用は何か。
2. Repositoryへfileやscriptを追加するだけで、その効果が本当に発生するか。
3. Organization owner、identity administrator、repository administrator、CI platform、security、
   product ownerのうち、誰が実施し誰が独立reviewするか。
4. Fixtureで検証できるpolicy contractと、live environmentでしか確認できないsettingをどう分けるか。
5. Synthetic fixtureの`PASS`がorganization adoptionと誤解されないか。
6. Evidenceがproviderから取得したcurrent state、取得時刻、対象、権限境界、完全性を本当に示すか。

自己申告JSONを検査するだけ、または常に成功するscriptは主実装にしない。

## このcontrolで採用する方式

このcontrolはguidance-firstのGitHub Organization baselineと、小さなprovider-neutral検証contractを
組み合わせる。

- 主実装は、GitHub／IdPで変更する設定、担当者、実施順序、access review、monitoring、
  live verificationを具体化したadoption guidanceである。
- `secure/policy.json`、`scripts/verify.py`、fixtureはmaintainer向けのsecondary regression contractである。
  Adopter向けの主実装や導入完了条件として前面に出さない。
- Live collectionを追加する場合はread-only assessmentとして分離する。Collectionとremediationを
  同じprocess、credential、commandへ混ぜない。
- GitHub settingを自動変更するscript、Organization Owner権限を持つcollector、広範な自動是正は追加しない。

READMEでは早い位置に、少なくとも次を一読で分かる形で保つ。

- セキュリティ向上の効果が生まれる実設定と運用。
- 担当者ごとの作業と独立reviewの境界。
- Provider名、画面項目またはAPI property、最小推奨値、順序、成功状態を含む最短導入手順。
- Documentationやfixtureをcopyしただけでは効果が出ないこと。

「組織に合わせて適切に設定する」だけで終わらせず、現在のsecure policyをminimum baselineとして先に
示し、planや組織固有の調整を後段へ分離する。

## Setting-first documentation contract

Human-facing Markdownの主役は、policy file、snapshot schema、fixture、verifierではなく、GitHub／IdPで
実際に設定すべきminimum baselineである。READMEまたはadoption runbookに`GHO-001`から`GHO-010`を
一つずつexact IDで表示し、`GHO-003..004`や`GHO-005..006`のようにまとめない。

各checkには、少なくともtarget、担当者、GitHub／IdPの画面pathまたはread-only API property、minimum
value、危険なvalue／状態、何が防げるか、live verification、期待結果、plan制約を記載する。
`control.yaml`がcanonical metadataであっても、adopterに必要な設定をMarkdownから省略してよい理由には
ならない。設定表をcopy手順やself-testより先に置く。

`GHO-005`では最低でも`Settings > Access > Member privileges`、`Base permissions: None`、memberによる
repository creationの無効化、private repository forkingの無効化、current settingの確認方法を明記する。

「安全な例／安全でない例」はsynthetic JSONの説明だけにしない。実際のUI settingまたはAPI propertyについて、
危険値、minimum secure value、security consequenceを同じ表で比較する。Fixtureはその後にmaintainer向け
regression sampleとして短くリンクするだけにする。

## Reference link rules

- Framework、provider guidance、repository guidance、他controlはplain text名だけで置かず、Markdown linkにする。
- GitHub設定の根拠は、設定行の近くから該当する公式GitHub Docsへ直接linkする。
- Frameworkは[framework mapping rules](../../../docs/FRAMEWORK_MAPPING.md)と各registry README、設計資料は
  [security guidance sources](../../../docs/SECURITY_GUIDANCE_SOURCES.md)の該当entryへlinkする。
- `REF-*`やframework IDだけを記載して読者に検索させない。Machine-readable mappingの正本は引き続き
  [control.yaml](control.yaml)とし、linkは調査導線、mappingはrelationshipの根拠として役割を分ける。

## 誰が何をするcontrolなのか

- Product owner: public／internal／privateを含む保護対象repositoryと業務上必要なaccessを確定する。
- Organization owner／identity administrator: 2FA、SSO、SAML／SCIMまたはEMU、offboarding、
  Organization Owner、Member privilegesとrepository作成／fork既定値をprovider側で設定する。
- Repository administrator: member、team、outside collaboratorのexact repository grant、permission、
  sponsor、expiryを管理し、90日以内に棚卸しする。
- CI platform: Actionsをselected repository／selected Actionへ限定し、full commit SHA、read-only default
  token、fork credential denyを維持する。
- Security: Owner、App、OAuth authorization、全repositoryへのsecurity configuration coverage、例外、
  drift findingを独立reviewする。
- Platform／security operations: complete paginationのread-only collector、24時間以内のsnapshot、
  独立audit export、alert receiverとharmless canaryを運用する。
- Development team: Organization-wide settingを自己変更せず、必要なrepository／Action／App accessを
  exact scopeで申請し、削除や縮小で壊れたworkflowを報告する。

同一人物だけでOrganization Owner変更、access承認、evidence収集、security reviewを完結させない。

## Minimum secure outcome

実装またはguidanceを変更するときは、次のoutcomeを維持する。

- 2FAとSSOを強制し、approved provisioningがhealthyで、unlinked identityがなく、offboarding SLAが
  24時間以内である。
- Organization Ownerは2～3名の記名humanで、phishing-resistant authenticationと90日以内のreviewを持つ。
- Member、team、outside collaboratorはcurrent owner、exact repository、bounded permission、expiry、
  90日以内のreviewへ結び付く。
- Base permissionは`none`で、memberのrepository作成とprivate forkはdeny-orientedである。
- Actionsはselected repository／selected Action、full SHA、read-only default token、PR approval deny、
  forkへのwrite token／secret denyである。
- Installed GitHub App／authorized OAuth App inventoryは完全で、owner、selected repository、最小permission、
  90日以内のreviewを持つ。High-risk administration writeを通常baselineで許可しない。
- 完全なrepository inventoryへrequired security configurationが適用され、public repositoryは
  `PSB-SOURCE-003`のcurrent reviewへ接続する。
- Auditは180日以上保持しGitHub Organization管理者から独立したboundaryへexportする。Required event
  categories、sequence health、24時間以内のdrift evaluation、30日以内のalert delivery testを確認する。
- Local exceptionをpolicyやsnapshotへ埋めず、`PSB-GOV-002`のexact、owned、approved、time-boundな
  contractへ接続する。

## Relationship to other controls

このpackageへ他controlの実装を複製しない。

- `PSB-SOURCE-003`: Public repository、Git history、issue／wiki等の露出検出とcredential-first remediation。
- `PSB-SOURCE-004`: OAuth、PAT、SSH、GitHub App credentialの発行、保管、期限、失効、通常lifecycle。
- `PSB-SOURCE-005`: Critical repositoryの削除／移管／ref破壊制限、独立backup、restore drill。
- `PSB-CICD-001`: 個別workflowのthird-party Action SHA pinning。このcontrolはOrganization-wide
  allowed Actions policyだけを所有する。
- `PSB-CICD-004／005`: Workflow／job permissionとuntrusted PR safety。このcontrolのActions設定だけで
  workflow内容が安全だと判定しない。
- `PSB-CICD-008`: 特権設定変更のactor、session、approval、before／after、execution、audit eventの結合。
  このcontrolはcurrent postureと完全な対象集合を所有する。
- `PSB-GOV-002`: Security exception lifecycle。独自のlocal exception formatを作らない。
- `PSB-GOV-004`: 漏洩後の横断credential containmentとrotation。

Compositionはexact control／check IDとcanonical commandで参照する。他controlのfixtureやverifierを
copyして見かけ上self-containedにしない。

## Atomic checks

`control.yaml`がcanonical sourceである。既存IDは生成済みchecklist参照を安定させるため不要に
renumberしない。

- `GHO-001`: 完全・fresh・stable organization ID・exact policy digestのsnapshot。
- `GHO-002`: Organization authentication、approved provisioning、offboarding。
- `GHO-003`: 2～3名のattributable human Ownerとphishing-resistant authentication。
- `GHO-004`: Member、team、outside collaborator grantのowner、scope、permission、expiry、review。
- `GHO-005`: Ambient authorityを与えないrepository defaults。
- `GHO-006`: Organization Actions execution／token trust policy。
- `GHO-007`: 完全で限定されreview済みのGitHub App／OAuth App access。
- `GHO-008`: 完全なrepository inventoryへのsecurity configuration coverage。
- `GHO-009`: 独立保全されたaudit、drift evaluation、alert delivery。
- `GHO-010`: Weak policy、local exception、evidence failureのfail-closed handling。

Markdown変更時はこの10 IDすべてを検索し、各IDからそのrequired setting／operationとlive確認手順へ直接
到達できることをreviewする。Verifier outputにIDが出るだけではMarkdown coverageとみなさない。

Checkを追加するのは、Organization-wide postureに固有で他check／controlが所有しないatomic stateだけと
する。変更時は`applies_to`、`responsible_role`、check固有の`context.threat_actor`、
`context.attack_or_failure_scenario`、`context.why_required`、verification、evidence、mappingを一緒に
reviewする。`check_context_version: "1.0"`を維持する。

## Implementation and verification rules

Primary verificationは各`GHO-*`のlive setting／operation確認である。UI確認ならexact画面path、表示される
setting名、期待値を示す。安全なread-only APIがある場合はendpoint／property、必要なread permission、
pagination、期待値を示し、copy可能なcommandはsecretを引数や出力へ残さない場合だけ載せる。APIで確認
できない項目はmanual verificationと必要なcurrent evidenceを正式な方法として記載する。

Live resultは`PASS`、`FAIL`、`NOT_CHECKED`、`ERROR`を分ける。Permission denial、partial pagination、stale
state、schema change、count mismatch、collector failureをclean resultへ丸めず、last-known-goodをcurrent
`PASS`として再利用しない。Evidenceには取得元、時刻、stable Organization target、collector authorityを
含め、credential、不要な個人情報、private repository名を含めない。

Verifierを維持する場合だけ、Python 3.10+ standard library、network-free、`0=accepted`、`1=finding`、
`2=input／evidence error`を保つ。Positive／negative fixture、weak policy、evidence error、redaction testは
verifier自身のregressionに限定し、organization adoption testと呼ばない。README文字列test、自己申告
`secure: true`、no-op、実際のsettingと無関係なschema testは追加しない。

Hosted settingを変更するscript、automatic remediation、Owner／member変更、App uninstallをverificationへ
混ぜない。Live変更はOrganization ownerが影響を確認し`PSB-CICD-008`の承認境界で行う。

## Adoption and completion criteria

最短導入手順は、少なくとも次を含める。

1. Prerequisite、trust assumption、担当者、利用可能なGitHub plan機能を確認する。
2. Organization ownerとIdP administratorがcheckごとのminimum baselineをlive settingへ反映する。
3. 各`GHO-*`をUIまたはread-only APIで確認し、current valueと期待値を照合する。
4. Audit export、drift detection、alert canary、90日以内のaccess／App reviewを運用へ載せる。
5. Current provider evidenceをapproved systemへ保存し、未確認項目を`NOT_CHECKED`、取得失敗を`ERROR`にする。
6. Normalized collectorを採用する場合だけpolicy／verifierをreview済みpathから参照し、fixture self-testを行う。
7. Recovery、server-side enforcement、rollback、plan制約、residual riskを明記する。

導入完了はlocal fixtureの成功ではない。対象Organizationで実設定が有効で、current complete evidenceが
GHO-001からGHO-009を満たし、evidence failureがGHO-010でfail closedになり、ownerとreview cadenceが
割り当てられた状態をいう。

Rollbackはcopy／参照したrepository-local fileとCI参照だけを外す。Hosted security settingを弱める
rollbackは自動化せず、setting単位の影響確認と独立承認を必要とする。

## Required verification after changes

Repository rootから実行する。

```bash
bash controls/source-protection/github-organization-governance/tests/test.sh
make verify-control CONTROL=PSB-SOURCE-006
make validate-controls
```

`control.yaml`のcheck、mapping、statusを変更した場合はcanonical Make targetでindex、mapping、checklistを
再生成し、`PSB-SOURCE-006`に由来する差分だけをreviewする。Fixture PASSをlive adoptionへ昇格させず、
security requirementを弱めてtestを通さない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
