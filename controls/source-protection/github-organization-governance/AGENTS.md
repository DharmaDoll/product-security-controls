# PSB-SOURCE-006 implementation instructions

このfileは`PSB-SOURCE-006`固有の実装境界を定める。作業前にrepository rootの`AGENTS.md`、
`controls/AGENTS.md`、必読の設計文書、このpackageの`README.md`と`control.yaml`を読むこと。

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
- `secure/policy.json`はcopy可能なminimum security floorであり、組織の安全性を自己宣言するfileではない。
- `scripts/verify.py`とsecure／insecure fixtureは、policyとnormalized snapshot contractのregression、
  insecure stateの拒否、evidence failureのfail-closed behaviorを確認する補助実装である。
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

Checkを追加するのは、Organization-wide postureに固有で他check／controlが所有しないatomic stateだけと
する。変更時は`applies_to`、`responsible_role`、check固有の`context.threat_actor`、
`context.attack_or_failure_scenario`、`context.why_required`、verification、evidence、mappingを一緒に
reviewする。`check_context_version: "1.0"`を維持する。

## Implementation rules

- VerifierはPython 3.10+ standard library、single-purpose、決定的、network-freeに保つ。
- `0=accepted`、`1=security finding`、`2=input／parser／evidence error`のexit contractを維持する。
- Policy floorをadopter convenienceやtest通過のために弱めない。Plan制約はsilent downgradeではなく、
  external evidence、bounded fallback、または`PSB-GOV-002`の例外として扱う。
- Organization、actor、team、repository、Appはrename可能な名前だけでなくstable provider IDへbindする。
- Collectorにはread-only最小権限を使い、固定API version、complete pagination、field allow-list、
  count reconciliation、source health、observed time、target identity、policy SHA-256を必須とする。
- Rate limit、permission denial、API／schema change、partial page、stale cache、count mismatch、adapter failureを
  `ERROR`として扱い、last-known-goodをcurrent `PASS`として再利用しない。
- Real secret、provider-valid token、authorization header、personal data、private repository名、production
  evidenceをfixture、log、expected resultへ入れない。必要fieldだけをsecret-freeにnormalizeする。
- Existing adopter configurationを上書きしない。Local activationは明示的なrepository-local copy／reference
  とし、global Git、shell、IDE、OS設定やGitHub hosted settingを暗黙に変更しない。
- Automatic remediation、member removal、Owner変更、App uninstall、Actions policy変更をself-testや
  verifierから実行しない。Live変更はOrganization ownerが影響を確認し`PSB-CICD-008`の承認境界で行う。

## Verification boundary

意味のある自動検証だけを追加する。

- Secure fixtureがacceptedになるpositive case。
- Inert insecure fixtureが具体的な`GHO-*` findingになるnegative case。
- Weak policyとungoverned local exceptionの拒否。
- Stale、partial pagination、count mismatch、adapter error、malformed、secret-bearing inputがexit `2`になる
  fail-closed case。
- Sensitive fixture valueがoutputへ複製されないredaction case。

READMEに文字列があることだけを確認するtest、`secure: true`を信頼する判定、常に成功するtest、
security outcomeと無関係なschema validation、live adoptionを装うsynthetic evidenceは追加しない。

Live assessmentを追加する場合はfixture verificationと分離し、次を使い分ける。

- `PASS`: Completeでfreshなsupported current stateがrequired stateを満たす。
- `FAIL`: Current stateが具体的にrequired stateを満たさない。
- `NOT_CHECKED`: Provider planや別authorityのため、そのassessmentでは確認していない。
- `ERROR`: Collection、permission、pagination、parser、freshness、identity、evidence healthの失敗。

Unsupported stateやcollection failureを`PASS`または`NOT_CHECKED`へ丸めない。

## Evidence rules

- Secure fixture、expected output、synthetic snapshotの`PASS`はreference contractのevidenceであり、
  organization adoption evidenceではない。
- Live adoptionに使えるのは、provider APIから取得したcurrent setting、IdPのcurrent assignment／SCIM health、
  実audit export、current drift result、実際のharmless alert delivery receipt等である。
- Evidenceは収集元、取得時刻、stable organization target、完全pagination、collector authority、policy identityを
  明示し、credential valueと不要な個人情報を含めない。
- Live evidenceを用意できない場合は架空のfileを作らず、READMEまたは`control.yaml`へorganization-owned
  verificationと導入完了条件を記述する。
- Host-specific live outputをrepositoryへcommitしない。Repositoryのignored assessment directoryまたは
  組織のapproved evidence systemへ保存する。

## Adoption and completion criteria

最短導入手順は、少なくとも次を含める。

1. Prerequisite、trust assumption、担当者、利用可能なGitHub plan機能を確認する。
2. `secure/policy.json`と`scripts/verify.py`だけをreview済みdirectoryへcopyまたは参照する。
3. Existing pathを上書きせずrepository-localにactivationする。
4. Synthetic secure／insecure fixtureでharmless self-testとexit statusを確認する。
5. Organization ownerとIdP administratorがlive settingsをminimum secure outcomeへ変更する。
6. Read-only collectorまたはmanual provider reviewで完全なcurrent stateを確認する。
7. Audit export、drift detection、alert canary、90日以内のaccess／App reviewを運用へ載せる。
8. Recovery、CI／server-side enforcement、rollback、residual riskを明記する。

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
