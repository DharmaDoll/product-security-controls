# PSB-CICD-008: CI/CDの特権control-plane変更を本人・承認・監査証跡へ結合する

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHubやcloudの管理者権限があるだけで、直ちに製品へ被害が出るわけではない。実害につながるのは、概ね次の条件がつながったときである。

1. 管理者または盗まれた管理者sessionが、branch ruleset、protected Environment、runner group、OIDC trust、artifact registry、signing policyなど、softwareの作成・承認・公開を支える設定を変更できる。
2. 変更内容を別人が事前確認しない、またはprovider画面やAPIから承認経路を迂回できる。
3. 変更後の権限を使って、未review codeのmerge、権限あるrunnerの利用、広いcloud roleの取得、artifactの差し替え、または本来許可されない署名を実行できる。
4. Providerのaudit logと変更後設定を確認していないため、不正変更を悪用前に発見・復元できない。

例えばrequired reviewを外しただけではproduction侵害は確定しない。しかし、そのrepositoryのdefault branchからpackage公開権限を持つrelease workflowが動くなら、未review codeから不正packageを公開できる経路が開く。逆に、release jobにpublish権限がない、別のapprovalが止める、consumerがexact artifact digestを検証する、といった条件があれば想定した被害は成立しにくい。

### 誰から、または何から守るか

盗まれた管理者sessionを使う外部攻撃者、単独で設定を弱めるinsider、共有管理者account、対象や値を取り違えたoperator、承認後に別の設定を適用するautomation、緊急権限を戻し忘れるincident対応、audit確認の欠落から守る。

### 何が対象か

SCM／CIの管理画面とAPI、branch／tag ruleset、protected Environment、runner access、CI-to-cloud trust、artifact registry、signing service、およびそれらを変更するhuman identity、session、申請、承認、provider audit event、変更後のcurrent setting。

### 何をするか

通常変更では「誰が、どのtargetを、どの値からどの値へ、なぜ変更するか」を別人が実行前に承認する。記名管理者が適用し、変更者以外がprovider audit eventとcurrent settingを確認する。緊急変更にはincident reasonと期限を付け、1時間以内に別人が継続またはrevertを判断する。

### 成功状態

宣言したscope内の変更について、named administrator、強い認証、exactなbefore／after、独立事前承認、provider event、変更後stateが一つのrecordで確認できる。Harmless drillで通常経路と無申請変更の検知を試し、未確認は`NOT_CHECKED`、不一致は`FAIL`、取得失敗は`ERROR`として残る。

### 対象外・残余リスク

このrepositoryの文書をcopyしてもprovider設定は変わらず、organization adoptionの証明にはならない。Providerが管理設定の二者承認を強制しない場合、無承認の直接変更を必ず事前阻止するcontrolではなく、運用上の抑止とaudit review cadence内の検知になる。各settingの安全な値、provider／IdPの同時侵害、audit log自体の完全性は別のcontrolまたは実環境確認が必要である。

## Guidance-first implementation

このcontrolのセキュリティ効果はrepositoryのscriptやfixtureではなく、live provider／IdPの設定、権限分離、承認運用、audit確認から生まれる。

### 実際に変えるもの

| 実環境の変更 | 最小の推奨状態 | 担当 | 攻撃や失敗に対して変わること |
|---|---|---|---|
| 管理者accountとrole | Shared accountを使わず、serviceごとに少数のnamed humanだけが変更できる | Organization owner／service owner | 変更者を特定でき、不要なauthorityを個別に失効できる |
| 管理者認証 | Phishing-resistant authentication、session最大1時間、実行前15分以内のstep-up | Organization owner／IdP administrator | 盗まれたpasswordや古いsessionを使える時間を短くする |
| 通常変更経路 | Requester／executor以外がexact targetとafter valueを実行前に承認する | Product owner／Security | 一人の誤操作や悪用だけでtrust boundaryを変更しにくくする |
| Provider確認 | Executor以外がaudit eventとcurrent settingをapproved requestへ照合する | Platform／SRE／Security | Ticket上の説明ではなく、providerで実際に起きた変更を確認する |
| Audit保管 | 可能ならcontrol-plane administratorだけでは消せないlogging accountへexportする | Platform／SRE | 管理者侵害時にprovider側の記録まで失うriskを下げる |
| Emergency path | Incident ID、exact target、最大1時間のexpiry、独立した`accepted`／`reverted`判断 | Incident response | 緊急権限や一時的な弱い設定が無期限に残ることを防ぐ |

Template、policy JSON、synthetic evidenceへ`secure: true`と書くだけでは、上記の状態は一つも変わらない。そのため本controlはlocal verifierを提供せず、live確認を正式なverificationとする。

### 誰が何をするか

| 担当 | 実施すること |
|---|---|
| Product owner／Development team | 対象、変更理由、期待結果、変更後に確認するbuild／release behaviorを説明する |
| Repository administrator／Organization owner | Named roleと認証を整備し、承認済みの値だけをproviderへ適用する |
| CI platform／Platform／SRE | 対象inventory、audit access、独立保管、review cadence、取得失敗時のownerを運用する |
| Security／Independent approver | Exact target、before／after、被害条件、side effect、rollbackを実行前にreviewする |
| Independent reviewer | Provider eventとcurrent settingを実行後に確認し、checkごとのresultを記録する |
| Incident response | Emergency changeのscope、expiry、独立post-review、revertを完了する |

Developerへorganization-wide admin権限、audit collector credential、evidence保管の責任を持たせない。

### 導入前に必要なもの

- 対象providerとsecurity-impacting settingのowner。
- Requester／executorとは別に、変更内容を判断できるapprover 1名以上。
- Audit logで一人のcurrent humanを識別できるnamed account。
- ProviderまたはIdPで利用できるphishing-resistant authentication。
- 承認と実行結果を残せるticket／change-management system。
- Executor以外が閲覧できるprovider audit logとcurrent setting。
- Harmless drill用のnon-production account、repository、branchのいずれか。

Provider／IdPがsessionまたはstep-upを確認できない場合、自己申告で埋めず`CPC-002: NOT_CHECKED`とする。GitHub Enterprise Server、GitLab、AWS、Azure、GCP等へ広げる場合は、stable target、audit event、current-state確認方法、plan上の制約を採用者が確認する。

### Copyして有効にする

採用先へcopyするfileは二つだけである。

- [`secure/privileged-change-runbook.md`](secure/privileged-change-runbook.md): 通常／緊急変更、failure handling、rollback。
- [`secure/change-record-template.md`](secure/change-record-template.md): Ticketへ貼り付ける申請、承認、実行、確認記録。

既存fileを上書きしないrepository-localなcopy例:

```bash
mkdir -p docs/security/privileged-changes
test ! -e docs/security/privileged-changes/runbook.md
test ! -e docs/security/privileged-changes/change-record-template.md
cp controls/cicd-security/privileged-control-plane-change/secure/privileged-change-runbook.md \
  docs/security/privileged-changes/runbook.md
cp controls/cicd-security/privileged-control-plane-change/secure/change-record-template.md \
  docs/security/privileged-changes/change-record-template.md
```

Copy後に次を実施して初めて有効になる。

1. 対象serviceとsecurity-impacting change typeを小さく宣言し、ownerを割り当てる。
2. Templateをapproved ticket systemへ登録し、通常変更は独立事前承認なしで実行しない運用にする。
3. Named administrator、強い認証、audit reviewerのread accessをlive provider／IdPで有効にする。
4. Provider-native approval gateがある場合は有効にする。ない場合はdirect changeを拾えるaudit review cadenceを決める。
5. 次のGitHub sandbox drillを実行し、結果とfailure ownerをticketへ残す。

### GitHubで始める最小構成

Reference providerはGitHub.com／GitHub Enterprise Cloudである。最初の対象は専用private sandbox repositoryの`control-test` branch rulesetとする。

1. `Repository > Settings > Rules > Rulesets`で、`Active`、target `control-test`、pull request必須、required approving reviews `1`のrulesetを用意する。
2. Rulesetがない場合は、`before: absent`、`after: 上記の初期状態`として最初の通常変更を申請・承認し、作成eventとcurrent settingを確認する。
3. Repository／rulesetのURLまたはstable ID、setting name、before、afterをchange recordへ記載する。
4. Executorとは別のapproverがexact targetとafterを実行前に承認する。ApproverにGitHub管理権限を与える必要はない。
5. Executorが承認済みの値だけを変更する。
6. Executor以外が`Organization > Settings > Audit log`のactor、action、time、targetと、ruleset画面のcurrent settingを確認する。

GitHubで汎用の二者承認を強制できないadministrative settingは、step 2のticketだけでは直接変更をpreventできない。Provider-native gateまたは別途reviewしたchange gatewayがなければ、本controlが確認できるのはaudit review cadence内の検知である。

[`insecure/uncontrolled-change.md`](insecure/uncontrolled-change.md)は、共有Owner accountからrulesetを直接弱め、承認もaudit確認も残らない危険例である。Providerへ適用する設定ではない。

## 何が、どの条件で被害になるか

| 変更対象 | 被害が成立する主な条件 | 起こり得ること | 条件が揃わない例 |
|---|---|---|---|
| Branch／tag ruleset | Reviewやdeletion保護が弱まり、変更者がrefを書き換えられ、後続CIがそれを信頼する | 未review codeのmerge、release tagやsource identityの差し替え | 変更者にwrite権限がなく、releaseがexact commit／artifact digestを別途検証する |
| Protected Environment | Reviewerやdeployment branch制限を外し、対象jobがsecretやdeploy権限を持つ | 未承認deployment、Environment secretの利用 | JobがEnvironmentを参照せず、実効deploy権限もない |
| Runner group | 未信頼workflowがcredential、persistent state、internal networkを持つrunnerを選べる | Credential窃取、横展開、後続jobへの永続化 | Runnerがone-jobで破棄され、credentialやinternal routeを持たない |
| OIDC trust | 広げたissuer／audience／subjectをCIが発行でき、cloud roleが重要操作を許す | Cloud変更、artifactやdeployment authorityの取得 | Cloud側conditionが拒否する、またはroleが対象操作を許可しない |
| Registry protection | Immutabilityや削除制限を弱め、別artifactをpushでき、consumerが名前だけを信頼する | Release artifactの差し替え | Consumerがverified immutable digestだけを使用する |
| Signing policy | 新しいprincipalが署名でき、consumerがその署名を信頼する | 未承認artifactへの正規署名 | Principalにsign権限がなく、release authorizationも別途必要 |

Setting changeという事実だけで最大severityにしない。変更者が利用できるauthorityとdownstream consumerまでの経路を確認する。一方、経路を確認できない場合も安全扱いせず、`NOT_CHECKED`としてownerを割り当てる。

## Live verification

Repository内のfixtureやREADME文字列からorganization adoptionを判定しない。次のpositive／negative drillをprivate sandboxで行う。Production保護を弱めて試してはならない。

### Positive drill

1. `control-test` rulesetのrequired approving reviewsが`1`であることを記録する。
2. `1`から`2`へ強化する変更をtemplateで申請する。
3. Executorとは別の人物がexact targetと`after: 2`を承認する。
4. Executorがrulesetを変更する。
5. Reviewerがaudit logのactor、action（referenceでは`repository_ruleset.update`）、time、targetを確認する。
6. Reviewerがrulesetを再表示し、current valueが`2`であることを確認する。
7. `CPC-001..007`を評価し、current evidenceに基づく`PASS`または理由をreviewした`N/A`だけを完了扱いにする。
8. `2`から`1`へ戻す必要があれば、それも別の承認済み変更として行う。

### Negative drill

1. Approval欄を空にしたsandbox変更をexecutorが開始せず、`CPC-004: FAIL`として返すことを確認する。
2. Provider-native gateがない場合だけ、ticketなしでsandbox rulesetを`1`から`2`へ強化し、次回audit reviewが対応するapproved requestを見つけられず`CPC-003／004: FAIL`として扱うことを確認する。

二つ目は事前防止を証明しない。無申請のdirect changeをreview cadence内に発見できることだけを確認する。

### Resultと必要なevidence

| Result | 使用条件 |
|---|---|
| `PASS` | Currentなauthoritative evidenceが期待状態と一致する |
| `FAIL` | Self-approval、無申請変更、target／value不一致、期限超過など、評価できた違反がある |
| `NOT_CHECKED` | Provider機能、担当者、scope、live evidenceのいずれかが未確認 |
| `ERROR` | API／画面取得失敗、audit欠落、partial export、時刻不整合などで判定できない |
| `N/A` | Scopeに存在しない対象についてownerが理由をreviewした |

Completed recordはpublic repositoryへcommitせず、approved ticket／evidence systemへ保存する。Providerとstable target、取得元と時刻、requester／executor／approver／reviewer、before／after、approval／execution時刻、provider event ID、current setting、collection scope、result、failure ownerを含める。Token、cookie、authorization header、private key、secret valueは含めない。

### Canonical command

```bash
make verify-control CONTROL=PSB-CICD-008
```

期待結果は`NOT_CHECKED`とexit `2`である。非zero exitは、repository文書をlive verification済みとして先へ進ませないためのものである。

```text
NOT_CHECKED PSB-CICD-008: manual verification; follow controls/cicd-security/privileged-control-plane-change/README.md#live-verification
```

## Failure recovery、rollback、残余リスク

| 状況 | 対応 |
|---|---|
| Target、before、after、approvalが不足 | 変更を開始せず`NOT_CHECKED`または`FAIL`としてrequesterへ戻す |
| Audit eventまたはcurrent settingを取得できない | `ERROR`とし、last-known-goodやexecutorの自己申告でcloseしない |
| Approved afterとcurrent settingが違う | `FAIL`とし、追加変更を止め、downstream run／artifact／cloud operationを確認する |
| Unauthorized direct change | 変更者が正規管理者でもincidentまたはfollow-upを起票し、影響とrevertを判断する |
| Evidenceへcredentialが混入 | 共有を止めて隔離し、実credentialなら[`PSB-GOV-004`](../../governance-operations/credential-exposure-containment/README.md)で失効する |

Hosted settingを戻す操作もprivileged changeである。安全設定を無承認で弱めるautomatic rollbackは提供しない。通常変更またはemergency procedureを通し、revert後のprovider eventとcurrent stateを再確認する。

Providerがdirect changeを許す場合は検知まで弱い状態が残り得る。Human approverはunsafeな値を承認し得る。Provider／IdP／audit backendが同時に侵害されれば記録を偽装・欠落できる。一つのGitHub sandbox drillからOrganization全体、AWS、registry、signing serviceの導入を推論してはならない。

## 他controlとの分担

- [`PSB-CICD-004`](../actions-least-privilege/README.md): Workflow／job token permission。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): Untrusted PR codeとprivileged executionの分離。
- [`PSB-CICD-006`](../audience-bound-oidc-federation/README.md): Machine OIDC claimとcloud trustの安全な値。
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner routing、registration、network、lifecycle。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): GitHub Organizationのmembership、role、current posture。
- [`PSB-CONTAINER-002`](../../container-cloud-iac-security/container-registry-security/README.md): Registryの安全なrequired state。
- [`PSB-REL-005`](../../release-integrity/artifact-signing-generation/README.md): Signing authorizationとartifact署名。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Time-bound exception lifecycle。

本controlが所有するのは、これらの設定を変更するときのactor、approval、execution、provider observationである。各settingの安全な値は所有controlで確認する。

## Framework／guidance mappings

Machine-readableな正本は[`control.yaml`](control.yaml)、参照元の固定情報は[GitHub Security Guidance registry](../../../frameworks/github-security-guidance/README.md)、[OpenSSF OSPS Baseline registry](../../../frameworks/openssf-osps-baseline/README.md)、[MITRE ATT&CK registry](../../../frameworks/mitre-attack/README.md)にある。

| Framework／guidance | Relationship | Checks | このmappingが示す範囲 |
|---|---|---|---|
| [GitHub: Best practices for securing accounts (`GHSC-SECURE-ACCOUNTS`)](https://docs.github.com/en/code-security/tutorials/implement-supply-chain-best-practices/securing-accounts) | `supports`／high | CPC-001, CPC-002, CPC-004 | Named administrator、強い認証、独立reviewを支持する。Live設定済みとは主張しない |
| [GitHub Actions: Secure use reference (`GHAS-REF-SECURE-USE`)](https://docs.github.com/en/actions/reference/security/secure-use) | `supports`／medium | CPC-003–006 | Exact change review、provider確認、緊急経路をActions管理へ適用する |
| [GitHub: SAML SSO identity and access management (`GH-ADMIN-SAML-IAM`)](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on) | `related-to`／medium | CPC-001, CPC-002 | Membershipと認証のprovider境界。IdPの実設定はexternal evidence |
| [GitHub: About rulesets (`GH-ADMIN-RULESETS`)](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) | `related-to`／medium | CPC-003, CPC-005 | GitHub sandbox drillのtargetとcurrent state |
| [GitHub: Organization audit-log events (`GH-ADMIN-AUDIT-EVENTS`)](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) | `supports`／medium | CPC-005–007 | Actor、action、time、targetのprovider observation。完全なretentionは別途必要 |
| [OpenSSF OSPS Baseline 2026.02.19 — OSPS-AC-01.01](https://baseline.openssf.org/versions/2026-02-19#osps-ac-0101) | `supports`／high | CPC-001, CPC-002 | Sensitive actionにMFAを要求する。Phishing resistanceとsession boundは本controlの追加条件 |
| [OpenSSF OSPS Baseline 2026.02.19 — OSPS-AC-02.01](https://baseline.openssf.org/versions/2026-02-19#osps-ac-0201) | `supports`／medium | CPC-001, CPC-004 | Collaborator permissionの制限と独立reviewを支持する |
| [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) | `mitigates`／medium | CPC-001, CPC-002 | 盗まれた有効account／sessionの悪用機会を減らす。Authorized insiderは防げない |
| [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) | `detects`／medium | CPC-003, CPC-005 | Approved requestとprovider stateの不一致から、unauthorized trust／account manipulationを検知する |

これらは限定されたmappingであり、formal compliance、GitHub設定完了、organization adoption、攻撃の完全なmitigationを意味しない。
