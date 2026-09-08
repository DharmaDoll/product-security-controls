# PSB-CICD-008: CI/CDの特権control-plane変更を本人・承認・監査証跡へ結合する

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHubやcloudの管理者権限があるだけで、直ちに製品へ被害が出るわけではない。実害につながるのは、概ね次の条件がつながったときである。

1. 管理者または盗まれた管理者sessionが、branch ruleset、protected Environment、runner group、OIDC trust、
   artifact registry、signing policyなど、softwareの作成・承認・公開を支える設定を変更できる。
2. その変更を別人が事前確認する仕組みがない、またはprovider画面やAPIから承認経路を迂回できる。
3. 変更後の設定によって、未review codeのmerge、権限あるrunnerの利用、広いcloud roleの取得、artifactの
   差し替え、または本来許可されない署名など、後続の攻撃経路が実際に開く。
4. Audit logと変更後設定を確認していないため、不正変更を悪用前に発見・復元できない。

例えば、required reviewを外しただけではproduction侵害は確定しない。しかし、そのrepositoryのdefault branchから
release workflowが起動し、package公開権限を持つなら、攻撃者または不正な管理者が未review codeをmergeして
不正packageを公開できる可能性が生まれる。OIDC trustのsubjectを広げた場合も、対象workflowがtokenを発行でき、
cloud roleが重要resourceへの権限を持つ場合に初めてcloud変更へ進める。Runner groupをpublic repositoryへ広げても、
runnerにinternal networkやcredentialがなければ被害は限定的だが、それらがあればcredential窃取や横展開につながり得る。

逆に、変更権限が少数の記名管理者に限定され、別人がexactな変更内容を事前承認し、変更直後にprovider auditと
current settingを確認できるなら、一つの盗難sessionや操作ミスだけでtrust boundaryを静かに弱めることは難しくなる。
本controlは、この条件を満たす変更手順とlive確認を提供する。

### 誰から、または何から守るか

Phishingや端末侵害で管理者sessionを得た外部攻撃者、単独で設定を弱めるinsider、共有管理者account、対象や値を
取り違えたoperator、承認後に別の設定を適用するautomation、緊急権限を戻し忘れるincident対応、audit確認の欠落から
守る。変更権限がなく、後続で利用できるauthorityもなく、変更が速やかに検知・復元される場合は、想定する被害経路は
成立しにくい。

### 何が対象か

SCM／CIの管理画面とAPI、branch／tag ruleset、protected Environment、runner access、CI-to-cloud trust、
artifact registryの保護、signing service policy、およびそれらを変更するhuman identity、session、申請、承認、
provider audit event、変更後のcurrent setting。

### 何をするか

対象をsecurity-impacting changeへ絞り、通常変更では「誰が、何を、どの値からどの値へ、なぜ変更するか」を
別人が実行前に承認する。記名管理者が変更し、別のreviewerがprovider audit eventとcurrent settingを確認する。
緊急変更には期限とincident reasonを付け、1時間以内に別人が継続またはrevertを判断する。確認不能や収集失敗は
`PASS`にしない。

### 成功状態

採用scope内の全対象について、管理者が記名され強い認証を使い、通常変更には独立した事前承認があり、実行後の
provider記録とcurrent settingが承認内容に一致している。緊急変更は期限内に追認またはrevertされている。
Harmless drillでこの一連の手順と無承認変更の検知を確認し、未確認は`NOT_CHECKED`、不一致は`FAIL`、取得失敗は
`ERROR`として記録できる。

### 対象外・残余リスク

このrepositoryのtemplateをcopyしてもprovider設定は変わらず、organization adoptionの証明にはならない。
GitHubが管理設定の二者承認を強制できない構成では、本controlは無承認の直接変更を必ず事前阻止するものではなく、
運用上の抑止と事後検知が中心になる。Provider、IdP、approverが同時に侵害された場合、audit log自体の欠落、
変更内容のbusiness上の正しさ、各settingのsecure baselineは別途確認が必要である。

## このcontrolの本質

本controlが要求するのは、すべてのproviderを一つの判定器へ接続することではない。次の五つが一つの変更について
確認できることである。

```text
記名された変更者
      +
対象と変更前後が分かる申請
      +
別人による事前承認
      +
provider上の実行記録
      +
変更後のcurrent setting
      =
誰が何を承認どおり変更したかを説明できる
```

Hashや自動collectorは、この結合を正確かつ低負担にできる場合の補助である。Provider画面から取得した設定値を
人間が十分に比較できるなら、SHA-256や共通JSON schemaを導入する必要はない。反対に、対象が多く人手では漏れる場合は、
read-only APIによる収集を追加できるが、そのcollector自体をcontrol導入の証明にはしない。

本controlは変更内容のsecure baselineを重複して定義しない。例えばworkflow permissionは`PSB-CICD-004`、
OIDC trustの内容は`PSB-CICD-006`、runnerの安全な状態は`PSB-CICD-007`、GitHub Organizationのcurrent postureは
`PSB-SOURCE-006`が所有する。本controlは、それらの設定を変更するときの人、承認、実行、確認を所有する。

## 何が、どの条件で被害になるか

| 変更対象 | 被害が成立する主な条件 | 起こり得ること | 条件が揃わない例 |
|---|---|---|---|
| Branch／tag ruleset | Reviewやdeletion／non-fast-forward保護が弱まり、変更者がbranchやtagを書き換えられ、後続CIがそれを信頼する | 未review codeのmerge、release tagやsource identityの差し替え | 変更者にwrite権限がなく、releaseがexact commit／artifact digestを別途検証する |
| Protected Environment | Required reviewerやdeployment branch制限を外し、対象jobがsecretやdeploy権限を持つ | 未承認deployment、Environment secretの利用 | JobがEnvironmentを参照せず、実効deploy権限もない |
| Runner group | 未信頼workflowがinternal network、host credential、persistent stateへ到達できるrunnerを選べる | Credential窃取、internal serviceへの横展開、後続jobへの永続化 | Runnerがone-jobで破棄され、credentialやinternal routeを持たない |
| OIDC trust | 広げたissuer／audience／subjectをCIが発行でき、cloud roleが重要操作を許す | Cloud resource変更、artifactやdeployment authorityの取得 | Cloud側conditionが拒否する、またはroleが対象操作を許可しない |
| Registry protection | Tag immutabilityや削除制限を弱め、変更者が同じ名前へ別artifactをpushでき、consumerが名前だけを信頼する | Release artifactの差し替え、誤ったimageのdeployment | Consumerがverified immutable digestだけを使用する |
| Signing policy | 新しいprincipalがsigning operationを呼べ、consumerがその署名を信頼する | 未承認artifactへの正規署名 | Principalにsign権限がなく、release authorizationも別途必要 |

「設定が変更された」という事実だけでseverityを決めない。変更者が実際に利用できるauthorityと、後続consumerまでの
経路を確認する。一方、直接の被害経路がまだ見つからなくても、重要な保護を無承認で変更できる状態は、
将来の構成変更と組み合わさるため、未管理のまま放置しない。

## Guidance-first implementation

Security効果は、次のlive settingと運用から生まれる。

- Shared accountを使わず、対象serviceの変更権限を少数のnamed humanへ限定する。
- ProviderまたはIdPでphishing-resistant authenticationを要求する。
- 通常変更は、変更者とは別の人物がexactなtargetとbefore／afterを実行前に確認する。
- 変更直後にprovider auditとcurrent settingを、変更者以外が確認する。
- Audit記録をcontrol-plane administratorだけでは消せない場所へ保管する。
- Emergency pathへincident reason、期限、独立事後reviewを付ける。

このrepositoryは、copy可能なrunbookとchange record templateを提供する。Templateをcopyしただけでは、MFA、
権限分離、audit export、承認経路は有効にならない。Organization ownerとPlatform／SREが実際のproviderへ反映する。

## 誰が何をするcontrolか

| 担当 | 作業 |
|---|---|
| Product owner／Development team | 変更対象、必要な理由、期待する結果、変更後に確認するbuild／release behaviorを説明する |
| Repository administrator／Organization owner | Named roleと認証を整備し、承認済み内容をproviderへ適用する |
| CI platform／Platform／SRE | 対象inventory、session policy、audit export、保管先、時刻同期、収集失敗時の対応を運用する |
| Security／Independent approver | Exact target、before／after、被害条件、rollbackを事前reviewし、実行後のprovider記録を確認する |
| Incident response | Emergency changeのscopeと期限を管理し、別人による`accepted`／`reverted`判断を完了させる |

Developerへorganization-wide admin権限、audit collector credential、provider evidence保管の責任を持たせない。

## Prerequisites and trust assumptions

最小構成は次のとおり。

- 対象providerとsecurity-impacting settingのownerが決まっている。
- Requester／executorとは別に、変更内容を理解できるapproverが1名以上いる。
- Shared administrator accountを使わず、audit logで個人を識別できる。
- ProviderまたはIdPでphishing-resistant authenticationを利用できる。
- Ticket、issue、change-management systemのいずれかに承認と実行結果を残せる。
- Provider audit logと変更後settingを、変更者以外が閲覧できる。
- Harmless drillに使用できるnon-production organization、account、repository、branchのいずれかがある。

Reference providerはGitHub.com／GitHub Enterprise Cloudである。最初の導入対象は、専用private sandbox
repositoryのbranch rulesetとする。GitHub Enterprise Server、GitLab、AWS、Azure、GCP等へ適用するときは、
同じ手順をそのまま信用せず、providerが提供するstable target、audit event、current-state確認方法、必要権限を
確認する。

Session最大1時間、実行前15分以内のstep-up、emergency review最大1時間をreference defaultとする。
Provider／IdPがsession evidenceを提供しない場合は架空の時刻を記録せず、`CPC-002`を`NOT_CHECKED`とする。

## Insecure example

[`insecure/uncontrolled-change.md`](insecure/uncontrolled-change.md)は、共有Owner accountからbranch rulesetを
直接弱め、承認、変更前後、audit review、rollbackが残らない例である。危険なのは「Ownerが設定を変更した」という
一文ではなく、その後に未review codeをmergeでき、権限あるrelease workflowが動く条件までつながる点である。

これは意図的な危険例であり、providerへ適用する設定ではない。

## Secure reference

採用先へcopyするfileは二つだけである。

- [`secure/privileged-change-runbook.md`](secure/privileged-change-runbook.md): 通常／緊急変更とfailure recoveryの手順。
- [`secure/change-record-template.md`](secure/change-record-template.md): Ticketへ貼り付ける申請、承認、実行、確認記録。

既存fileを上書きせず、repository-localな運用資料としてcopyする。

```bash
mkdir -p docs/security/privileged-changes
test ! -e docs/security/privileged-changes/runbook.md
test ! -e docs/security/privileged-changes/change-record-template.md
cp controls/cicd-security/privileged-control-plane-change/secure/privileged-change-runbook.md \
  docs/security/privileged-changes/runbook.md
cp controls/cicd-security/privileged-control-plane-change/secure/change-record-template.md \
  docs/security/privileged-changes/change-record-template.md
```

Copy後は、対象provider、担当group、ticket system、audit保存先、sandbox targetをreviewしてからmergeする。
このcopyはglobal Git、shell、IDE、OS、provider settingを変更しない。Actual activationは次の手順で行う。

## 最短の導入手順

### 1. 対象を小さく決める

最初はGitHubの専用private sandbox repositoryと、その`control-test` branchを対象にする。Repository
administratorが`Settings > Rules > Rulesets`で対象rulesetを確認し、stableなrepository／rulesetのURLまたはID、
current enforcement、target branch、required review数をchange recordへ記録する。

Referenceの初期状態は、rulesetが`Active`、targetが`control-test`、pull request必須、required approving
review数が`1`である。Rulesetがまだない場合は、`before: absent`、`after: この初期状態`として最初の通常変更を
申請・承認し、作成eventとcurrent settingまで確認する。

Production repository、全Organization、AWS IAM、registry、signing serviceを最初から一括導入しない。
未導入scopeは`NOT_CHECKED`として残す。

### 2. 人と権限を分ける

Organization ownerは次をliveで確認する。

1. Shared administrator accountがない。
2. Executorとapproverが別のnamed humanである。
3. Executorがcurrent memberで、対象serviceに必要なroleだけを持つ。Approverはstable identityと変更を判断できる知識を持つが、providerの管理権限は必須にしない。
4. Phishing-resistant authenticationが有効である。
5. Audit reviewerは、変更者に依存せずaudit logとcurrent settingを確認できる。

GitHubのorganization全体のOwner数、2FA／SSO、membership、audit運用は
[`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md)と組み合わせる。

### 3. 通常変更経路を有効にする

[`secure/change-record-template.md`](secure/change-record-template.md)をapproved ticket systemへ登録する。
通常変更は次の順序を必須にする。

1. Requesterがexact target、before、after、理由、被害条件、rollbackを記入する。
2. Independent approverがtargetとafterを確認し、実行前に承認時刻を記録する。
3. Executorが承認済みの値だけをproviderへ適用する。
4. Executor以外のreviewerがprovider audit eventとcurrent settingを確認する。
5. 一致すれば`PASS`、不一致なら`FAIL`としてticketを閉じずに対応する。

GitHubには、すべてのadministrative setting changeへ汎用の二者承認を強制できない構成がある。その場合、
このreferenceは直接変更の完全なpreventive gateではない。Named roleの限定、事前承認、audit reviewを組み合わせ、
無承認の直接変更を検知する。事前阻止が必須なら、provider-native approvalまたは別途reviewしたchange gatewayが必要である。

### 4. Auditを別境界へ残す

GitHub organization audit logで、対象時刻、actor、action、repository／rulesetを確認する。可能なら、
Organization ownerだけでは上書きできないlogging／SIEM accountへexportする。

Audit eventが設定全体を示さない場合は、`Settings > Rules > Rulesets`またはapproved read-only APIから変更後の
current settingを取得する。Audit eventだけからMFA強度、current membership、承認を推測しない。

### 5. Harmless drillを実行する

[Verification](#verification)のpositive／negative drillをsandboxで実行する。Production settingを弱めて
テストしない。結果と不足項目をchange recordへ記録し、review cadenceとfailure ownerを決める。

## Ordinary change procedure

1. 対象serviceとsettingが採用scopeに含まれるか確認する。
2. Provider画面またはread-only APIからbefore stateを取得する。
3. After stateを具体的な値で記述する。Export可能なら同じ形式を添付する。
4. 被害が成立する条件、想定impact、rollback、利用者への影響を記録する。
5. Requester／executorではないapproverがexact after stateを承認する。
6. Executorが再認証し、承認から時間を空けずに変更する。
7. Reviewerがprovider audit eventのactor、time、action、targetを確認する。
8. Reviewerがcurrent settingを取得し、approved after stateと比較する。
9. `PASS`、`FAIL`、`NOT_CHECKED`、`ERROR`のいずれかをcheckごとに記録する。

Hashは必須ではない。大きなJSON policyなど、人間が比較すると取り違えやすい場合だけ、approved attachmentと
current exportを同じ規則でcanonicalizeしSHA-256を併記する。Hash文字列だけを残して内容をreviewしない運用は不可とする。

## Emergency change procedure

Production incidentのcontainmentで事前承認を待てない場合だけ使用する。

1. Incident ID、緊急理由、target、予定するafter state、executor、開始時刻、expiryを変更前に記録する。
2. Expiryは実行から最大1時間とする。
3. Named administratorが必要最小限の変更を行う。
4. Provider audit eventとcurrent settingを直ちに保存する。
5. Executorとは別のreviewerがexpiryまでに内容を確認する。
6. 必要かつ妥当なら`accepted`、不要または不適切なら`reverted`を記録する。
7. `accepted`した一時変更を恒久化する場合は、通常変更または
   [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)へ移す。

Expiryまでにreviewできなければ`FAIL`である。Incidentが継続中であることを理由に、同じemergency recordを
無期限延長しない。

## Verification

本controlのverificationはmanual／live external evidenceである。Repository内のfixtureやREADME文字列から
organization adoptionを判定しない。

### Harmless positive drill

専用private sandbox repositoryと`control-test` branchで実施する。

1. Current rulesetのrequired approving review数を記録する。
2. 例えば`1`から`2`へ強化する変更を、通常変更templateで申請する。
3. Executorとは別の人物がexact targetと`after: 2`を承認する。
4. ExecutorがGitHubの`Settings > Rules > Rulesets`で変更する。
5. Reviewerがorganization audit logのactor、action（referenceでは`repository_ruleset.update`）、time、targetを確認する。
6. Reviewerがrulesetを再表示し、required approving review数が`2`であることを確認する。
7. `CPC-001..007`を評価し、current evidenceに基づく`PASS`またはownerが理由をreviewした`N/A`だけを完了扱いにする。
8. 元へ戻す必要があれば、`2`から`1`への変更を別の通常変更として承認・実行する。

### Harmless negative drill

Production protectionを弱めず、次の二つを確認する。

1. **事前承認の停止確認:** Sandbox変更を申請するがapprovalを空欄にする。Executorがprovider変更を開始せず、
   `CPC-004: FAIL`として返すことを確認する。
2. **直接変更の検知確認:** Sandbox rulesetを、例えばreview数`1`から`2`へ強化する方向でticketなしに変更する。
   次回audit reviewが対応するapproved requestを見つけられず、`CPC-003／004: FAIL`としてincidentを起票することを
   確認する。検知後のrevertも新しい承認済み変更として行う。

Provider-native gateがない場合、二つ目のdrillは「変更前に止める」ことを証明しない。Audit review cadenceの範囲で
直接変更を発見できることだけを証明する。

### Result semantics

| Result | 使用条件 |
|---|---|
| `PASS` | 対象checkについてcurrentなauthoritative evidenceがあり、期待状態と一致する |
| `FAIL` | Evidenceを確認でき、self-approval、無申請変更、target／value不一致、期限超過等がある |
| `NOT_CHECKED` | Provider機能、権限、担当者、対象inventory、live evidenceのいずれかが未確認 |
| `ERROR` | API／画面取得失敗、audit欠落、partial export、時刻不整合、読めない記録等で安全に判定できない |
| `N/A` | 採用scopeに存在しない対象で、ownerが理由とscopeをreviewした |

一つのGitHub ruleset drillが通っても、Organization全体、AWS、registry、signing serviceを`PASS`にしない。

### Required evidence

Completed recordはrepositoryへcommitせず、approved ticket／evidence systemへ保存する。最低限次を含める。

- Providerとstable target
- 取得元と取得時刻
- Requester、executor、approver、reviewerのstable identity
- Before／afterの人が読める値
- Approvalとexecutionの時刻
- Provider audit event IDまたは直接参照
- 変更後current setting
- Collection scopeと欠落の有無
- Resultとfailure owner

Token、cookie、authorization header、private key、secret value、不要なIP／個人情報を保存しない。

### Canonical command

Repository rootで実行する。

```bash
make verify-control CONTROL=PSB-CICD-008
```

期待結果は`NOT_CHECKED`とexit `2`である。非zero exitは自動検証済みとして先へ進ませないためのもので、
repositoryの文書だけではlive providerとorganization evidenceを確認できないことを示す。

```text
NOT_CHECKED PSB-CICD-008: manual verification; follow controls/cicd-security/privileged-control-plane-change/README.md#verification
```

## Failure recovery

- Approval前に情報が不足した場合は変更を開始せず、`NOT_CHECKED`としてrequesterへ戻す。
- Audit eventまたはcurrent settingを取得できない場合は`ERROR`とし、last-known-goodをcurrent evidenceとして使わない。
- Approved afterとcurrent settingが違う場合は`FAIL`とし、追加変更を止め、影響を確認する。
- 不正または誤った変更を戻す場合も、緊急経路または新しい通常変更としてactor、target、resultを記録する。
- Evidenceへcredentialが混入した場合は共有を止め、保存先から隔離し、実credentialなら
  [`PSB-GOV-004`](../../governance-operations/credential-exposure-containment/README.md)に従って失効する。
- Direct changeを検知した場合は、変更者が正規管理者でも「問題なし」とせず、被害条件、後続run、artifact、
  cloud operationを確認する。

## Rollback

Repository-localな導入を外す場合は、copyしたrunbookとtemplateへの参照だけを削除する。Global Git、shell、IDE、
provider settingを自動変更しない。

Hosted security settingを以前の値へ戻す操作は、それ自体がprivileged changeである。安全設定を無承認で弱める
rollback scriptは提供しない。通常変更またはemergency procedureを通し、変更後stateとauditを再確認する。

## Operational notes and cost

- Developerの日常作業は、変更理由と期待結果の記載、変更後のbuild／release確認に限る。
- Organization owner、Platform／SRE、Securityには、approver availability、audit review、evidence retentionの
  運用負担が生じる。
- Provider-native approvalがない場合、検知までの時間はaudit review cadenceに依存する。高impact scopeでは
  alertまたは短いreview cadenceを用意する。
- 少人数teamでexecutorとapproverを分けられない場合、controlを`PASS`にせず、対象を限定し、期限付き例外と
  強いaudit／rollbackを`PSB-GOV-002`で管理する。
- Hash、collector、SIEM連携は対象数と取り違えriskが人手確認を超えたときに追加する。最初から必須にしない。

## Limitations and residual risk

- Manual approvalは、approverが変更の意味を誤解するriskを残す。
- Providerが直接変更を許す場合、無承認変更を事前阻止できず、検知まで一時的に弱い状態が残り得る。
- Provider／IdP／audit backendが同時に侵害されると、actorやeventを偽装・欠落できる。
- Current settingは変更後の状態を示すが、providerがhistoryを持たなければbefore stateを独立に証明できない。
- Phishing-resistant authenticationの設定だけでは、既にunlockされた端末や悪意あるauthorized administratorを
  防げない。
- 本controlは設定内容のsecure baseline、workflow permission、untrusted PR、machine OIDC、runner lifecycle、
  registry運用、signing authorizationを全面的には評価しない。
- GitHubの画面、event、利用可能な保護はplanとversionで異なり得る。導入時に公式documentationとlive tenantで
  再確認する。

## Relationship to other controls

- [`PSB-CICD-004`](../actions-least-privilege/README.md): Workflow／job tokenのexact permission。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): Untrusted PR codeとprivileged executionの分離。
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): Machine OIDC claimとcloud trustのrequired content。
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner routing、registration、image、network、lifecycle。
- [`PSB-SOURCE-004`](../../source-protection/source-access-credential-lifecycle/README.md): Human／App credentialの
  発行、保管、scope、期限、失効。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): GitHub Organizationの
  current posture、membership、Actions policy、audit operation。
- [`PSB-SOURCE-005`](../../source-protection/repository-destruction-recovery/README.md): Repository destruction制限、
  independent backup、restore drill。
- [`PSB-CONTAINER-002`](../../container-cloud-iac-security/container-registry-security/README.md): Registry policyの
  secure required state。
- [`PSB-REL-005`](../../release-integrity/artifact-signing-generation/README.md): Signing authorizationとartifact署名。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Time-bound exception lifecycle。

## References

- [GitHub: About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub: Managing rulesets for a repository](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/managing-rulesets-for-a-repository)
- [GitHub: Reviewing the audit log for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
- [GitHub: Organization audit-log events](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [GitHub: Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub: About passkeys](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys)

## Framework mapping boundary

行単位mappingは[`control.yaml`](control.yaml)に記録する。GitHub guidance、OpenSSF OSPS Baseline、
MITRE ATT&CKへのmappingは、各checkとの限定された関係を示すものであり、GitHub設定完了、organization adoption、
formal compliance、攻撃の完全なmitigationを意味しない。
