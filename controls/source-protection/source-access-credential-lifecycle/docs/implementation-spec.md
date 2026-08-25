# PSB-SOURCE-004 実装仕様書

## 文書情報

| 項目 | 値 |
|---|---|
| Control ID | `PSB-SOURCE-004` |
| Domain | `source-protection` |
| 実装方式 | Guidance-first GitHub baseline |
| 補助方式 | Read-only audit optionの紹介 |
| 状態 | Reference implementation完了、live organization adoptionは`NOT_CHECKED` |
| 主な担当 | Organization owner、repository administrator、security |

この文書の「必須」はreference implementationの要件を表す。組織固有値は最小推奨構成の後に
調整するが、security outcome、fail-closed境界、live evidence要件を弱めてはならない。

## 1. 目的

Developerまたはautomationが使用するGitHub OAuth grant、PAT、SSH authentication key、
GitHub App／workload identityを、必要なactor、purpose、repository、permission、期間へ限定し、
保管、棚卸し、失効、監査までを通常ライフサイクルとして運用する。

Security向上はrepository内のJSONやverifierからではなく、次の実状態から生まれる。

- GitHub／IdPで強制された認証・programmatic access policy。
- User credentialとautomation identityの分離。
- Credentialのowner、purpose、resource、permission、expirationが分かるcurrent inventory。
- Offboarding、role change、device loss、exposure、長期未使用に応じた失効。
- Credential lifecycleと利用を調査できるaudit evidence。

## 2. 採用する実装方式

### 2.1 主実装

主実装は、GitHubの具体的な管理設定とcopy可能な運用runbookを中心とするguidance-first方式とする。
Adopterは管理画面または承認済み管理手順で実設定を変更し、read-only確認と専用test credentialを
用いた無害な拒否・失効試験で結果を確認する。

### 2.2 補助実装

既存の`secure/`、`insecure/`、`scripts/verify.py`、
`scripts/verify-github-mcp-auth.py`は、baseline metadataとMCP sampleの差を説明し、repository側の
regressionを検出する補助実装として残す。これらの`PASS`はlive GitHub adoptionを証明しない。

### 2.3 Read-only audit

GitHub API、管理export、audit logを使ったread-only監査は、現段階では必須実装にしない。
READMEと監査オプション文書で確認可能な範囲、必要権限、plan制約、取得できない証跡を紹介する。
Collectorは具体的なadopter要件が発生してから別変更として実装する。

## 3. Scope

### 3.1 In scope

- GitHub organizationへ到達するOAuth、classic／fine-grained PAT、SSH、GitHub App credential。
- Interactive developer accessとsource-platform automation identityの選択。
- Repository／permission／lifetimeの最小化。
- OS keychain、hardware-backed key、approved secret managerによる保管。
- Credential inventory、quarterly以内のreview、event-driven revocation、audit。
- GitHub MCPのOAuth-first認証と、不可避なPAT fallbackのcredential lifecycle。
- Narrow、owned、approved、expiringなexception。

### 3.2 Out of scope

| 対象外 | Owning controlまたは境界 |
|---|---|
| Endpoint全体の暗号化、patch、EDR、local isolation | `PSB-SOURCE-001` |
| Commit前secret blockingとGit hook | `PSB-SOURCE-002` |
| Public surface／Git historyのexposure検出 | `PSB-SOURCE-003` |
| CI-to-cloud OIDC claim／audience／replay | `PSB-CICD-006` |
| MCP artifact identity／integrity | `PSB-AI-002` |
| MCP tool、network、write approval、runtime authority | `PSB-AI-004` |
| Exception schemaと期限判定 | `PSB-GOV-002` |
| 漏洩後のsupply-chain横断rotationとold-authority denial | `PSB-GOV-004` |

## 4. 前提条件とtrust assumptions

- Adopterは対象organizationとcritical repositoryを特定できる。
- Organization owner、security reviewer、repository administratorを同一人物に固定しない。
- GitHub planとIdP構成を把握し、利用できない機能を`PASS`としない。
- 管理設定変更前に、影響するmember、outside collaborator、OAuth App、GitHub App、SSH key、
  automation consumerを棚卸しする。
- 2FA、OAuth restriction、PAT policy等が既存accessを停止し得る場合、通知、change window、
  break-glass、recovery ownerを先に決める。
- Testには専用test repositoryと専用test identity／credentialだけを使用し、production credentialを
  repository、command line、log、evidenceへ保存しない。

## 5. 役割と責務

| Role | 必須作業 | 承認・証跡 |
|---|---|---|
| Product owner | 対象repository、必要なaccess、停止時のbusiness impactを決める | 対象scopeとowner |
| Organization owner／IdP administrator | 2FA／SSO、PAT、OAuth／GitHub App、membership policyを変更する | Current provider setting |
| Repository administrator | App／PATのrepositoryとpermissionを限定し、user tokenをautomationから除く | Grant review |
| Platform／SRE | GitHub App等の短命identityとprotected secret deliveryを構築する | Consumer inventory |
| Developer | Approved OAuthまたはhardware-backed SSHを使い、PAT fallbackを安全に保管する | Local storage確認 |
| Security | Baseline、exception、inventory、audit coverage、drill結果を独立reviewする | Review decision |
| Incident response | Exposure等でtoken、grant、key、sessionを失効し、影響を調査する | Sanitized incident record |

## 6. Repository成果物

実装完了時の最小成果物は次とする。新しいframeworkやcollectorは必須ではない。

| File | 役割 |
|---|---|
| `README.md` | 一枚summaryの直後に最短導入、実効性、役割、完了条件を示す |
| `docs/github-adoption-runbook.md` | GitHub設定、実施順序、manual verification、recovery、rollback |
| `docs/read-only-audit-options.md` | 将来自動化できる監査、取得元、制約、結果状態を紹介する |
| `secure/*.json` | Copy／review可能なreference metadataとMCP sample |
| `insecure/*.json` | 隔離された危険例 |
| `scripts/verify*.py` | Reference metadataのpositive／negative／error regression test |
| `control.yaml` | Atomic check、external evidence、mappingのcanonical metadata |

`docs/manual-verification.md`や独自evidence schemaは作らず、manual verificationはadoption runbookへ
まとめる。架空のlive evidence fileは追加しない。

## 7. 必須security requirements

### SR-1: 対象とcredential inventory

- Product ownerは対象organization、repository、automation、MCP利用有無を確定する。
- Inventoryはcredential値を含めず、class、sanitized stable ID、owner、purpose、resource、
  permission、created／last-used／expiry、review／revocation stateを記録する。
- Owner不在、purpose不明、resource不明、expiration不明は未完了とする。

対応check: `SCL-009`、`SCL-011`。

### SR-2: Interactive authentication

- Organizationはmemberとoutside collaboratorへ2FAを要求する。
- 利用可能なplanではGitHubのsecure 2FA methodだけを許可してSMSを除外し、IdP／SAML SSOを接続する。
- GitHubのsecure 2FA分類だけをphishing-resistantの証明にしない。Sensitive accessにはpasskey／
  security key等をIdP／enterprise policyまたはreview可能なorganization policyで要求する。
- Password、SMS、phishable factorだけでsensitive credential作成・organization accessを許可しない。
- 変更前に非準拠userへの影響を確認し、予告なしの大量lockoutを避ける。

対応check: `SCL-007`。

### SR-3: Automation identity

- Automationはdeveloper OAuth tokenまたはPATを使用しない。
- GitHub App installation tokenまたは同等のtask-bound short-lived identityを使う。
- GitHub Appは`Only select repositories`相当のresource selectionと必要最小permissionにする。
- Installation tokenの短命性だけで安全とせず、App installation自体のrepository／permissionをreviewする。

対応check: `SCL-001`。

### SR-4: PAT policy

- Classic PATはorganization resourceへのaccessを原則restrictする。
- Fine-grained PATはorganization approval必須とし、ownerを1つ、repositoryを明示選択、
  permissionを必要最小限にする。
- Reusable user credentialのmaximum lifetimeは90日以下とし、taskが短い場合はさらに短くする。
- `repo`、`workflow`等のbroad authorityはdefault denyとし、不可避な場合だけ`PSB-GOV-002`の
  exact、approved、expiring exceptionを使う。

対応check: `SCL-002..005`、`SCL-012`。

### SR-5: OAuth／GitHub App governance

- OAuth App access restrictionsを使用し、organization dataへ到達するAppをowner approval対象にする。
- GitHub App installationはorganization ownerのreviewを通し、installed Appを定期棚卸しする。
- OAuth restrictionの初回有効化は既存OAuth Appや一部SSH accessへ影響し得るため、pre-change
  inventoryとreauthorization planなしに実施しない。

対応check: `SCL-009..011`。

### SR-6: Storage and delivery

- OAuth／PATを`.env`、shell profile、IDE JSON literal、Git remote URLへ保存しない。
- Interactive tokenはOS keychain等、automation secretはapproved secret managerへ置く。
- SSH authenticationは可能な範囲でhardware-backed、non-exportable、user-verifying keyを使う。
- Environment variableはsecret storeではなく、exact processへの配送手段として扱う。

対応check: `SCL-006`、`SCL-008`。

### SR-7: Review、revocation、audit

- Active credentialを90日以内のcadenceでreviewする。
- Offboarding、role change、device loss、exposure、長期未使用を失効triggerにする。
- Revocationはfile削除やreplacement発行で代替せず、old credentialと関連sessionの拒否を確認する。
- Creation、authorization、use、change、revocation eventを保持し、ownerと対象resourceへ相関できるようにする。

対応check: `SCL-009..011`。

### SR-8: GitHub MCP conditional profile

- GitHub MCPを使用する場合だけ適用する。
- Approved remote OAuthまたはmemory-only OAuthを第一選択とする。
- PAT fallbackはMCP専用fine-grained PAT、read-only、explicit repository、90日以内とする。
- PATはprotected input referenceからexact MCP childへだけ配送し、IDE parentやshell全体へexportしない。
- MCP binary integrityは`PSB-AI-002`、tool／write authorityは`PSB-AI-004`で別に確認する。

対応check: `SCL-013..017`。

## 8. GitHub最小推奨設定

Adoption runbookは、実装時点のofficial GitHub documentationで画面名とplan条件を再確認し、
少なくとも次をこの順で案内する。

1. **Impact inventory**: member、outside collaborator、App、PAT、SSH、automation consumerを確認する。
2. **Authentication security**: Organization SettingsのAuthentication securityで2FAを要求し、
   利用可能ならsecure 2FA methodのみを許可してSMSを除外する。Passkey／security key等の
   phishing-resistant要件は別のIdP／enterprise policyとevidenceで確認する。
3. **Personal access tokens**: Organization SettingsのPersonal access tokensでclassic PATをrestrictし、
   fine-grained PATをapproval必須、maximum lifetime 90日以下にする。
4. **OAuth app policy**: Third-party AccessのOAuth app policyでaccess restrictionsを使用する。
5. **GitHub Apps**: Member privilegesでApp installation権限をowner reviewへ寄せ、installed Appごとに
   repository selectionとpermissionを確認する。
6. **Automation migration**: Developer token consumerをGitHub App等へ移行し、旧credentialを失効する。
7. **Storage**: Developerとautomationのapproved storage／deliveryを確認する。
8. **Review and response**: Quarterly review、revocation trigger、audit review、exception expiryを運用開始する。

画面名や機能がplanで異なる場合、存在しないsettingを自己申告で`PASS`にせず、代替controlと
residual riskを記録する。

## 9. Verification仕様

### 9.1 Repository self-test

```bash
make verify-control CONTROL=PSB-SOURCE-004
```

このtestは次だけを証明する。

- Secure reference metadataをacceptする。
- Insecure reference metadataをfindingとしてrejectする。
- Malformed／credential-bearing inputを`ERROR`にする。
- GitHub MCPのOAuth-firstとbounded PAT fallback sampleを区別する。

Live organization、credential、IdP、IDE storageは証明しない。

### 9.2 Live manual verification

Adopterは専用test repositoryと専用test credentialで次を行う。本物のcredential値やprivate
repository名をrepository evidenceへ保存しない。

| Test | 操作 | 期待状態 |
|---|---|---|
| Positive | 許可されたtest repositoryのmetadataまたはcontentsをread | 成功し、audit eventへ相関できる |
| Negative: permission | 明示的に未付与のpermissionを必要とする無害な操作を試す | Providerが拒否し、変更が発生しない |
| Negative: scope | 選択外test repositoryをread | Providerが拒否する |
| Revocation | 専用test credentialを失効後、同じreadを再試行 | 旧authorityが拒否される |
| Error | Evidence取得権限またはAPIが失敗 | Cleanではなく`ERROR`／`NOT_CHECKED` |

Production credentialを失効試験に使わない。API write、repository mutation、organization-wide
policy changeを自動testから実行しない。

### 9.3 Result model

| State | 意味 |
|---|---|
| `PASS` | Current live settingまたは実拒否結果がrequired stateを証明した |
| `FAIL` | Current live stateまたは実試験がunsafe stateを示した |
| `NOT_CHECKED` | Plan、authority、endpoint、evidenceがなく確認していない |
| `ERROR` | Collection、authentication、pagination、parse、freshness等に失敗した |
| `N/A` | Reviewed reasonにより対象credential class／MCP等が存在しない |

## 10. Read-only audit option

READMEは概要だけを示し、詳細は`docs/read-only-audit-options.md`へ分離する。紹介する能力は次とする。

| Source | 確認できる可能性がある内容 | 主な制約 |
|---|---|---|
| Fine-grained PAT REST API | Request、active grant、repository、permission、expiry、last use | 一部endpointはGitHub App認証とorganization permissionが必要 |
| Organization／Enterprise audit log | Membership、permission、App、credential lifecycle、API利用event | Enterprise Cloud、retention、event種別、取得権限に依存 |
| Installed GitHub Apps API／UI | App、permission、selected repository、suspension | App所有者、user authorization、downstream secretは別確認 |
| OAuth App policy／UI | Restrictionとapproved App | Organization-wide grantの完全性はplan／interfaceに依存 |
| SAML／SCIM／IdP evidence | Membership、SSO authorization、offboarding | GitHubだけではIdP policyやauthenticator custodyを証明できない |
| Endpoint／IDE evidence | Keychain保管、child-only delivery、SSH hardware binding | GitHub APIから確認できない |

将来collectorを実装する場合は次を必須とする。

- Read-onlyの専用identityと最小permission。
- 固定API version、complete pagination、rate-limit／network failureのfail-closed。
- Target organizationと取得時刻、source、collector authority、freshnessの明示。
- Field allow-listによるsecret、authorization header、個人情報、private repository名の除外。
- Fixture verificationとlive assessmentの分離。
- Collectorとcredential revoke／policy mutationの分離。

## 11. Evidence contract

導入完了に使用できるevidenceは、少なくとも次を満たす。

- Current provider／IdP settingのread-only取得または管理画面review記録。
- 対象、取得時刻、収集元、reviewer、権限境界が分かる。
- Inventoryのscopeとpaginationが完全であるか、未確認範囲を明記する。
- Credential値、private key、authorization header、不要な個人情報を含まない。
- Revocation drillはtest credential ID、対象test scope、実施時刻、拒否結果だけを残す。
- Missing、stale、partial、malformedなevidenceを`PASS`へ変換しない。

Evidenceを用意できないcheckは`NOT_CHECKED`のままにし、架空のevidence fileを作らない。

## 12. 導入完了条件

次をすべて満たしたときだけ、対象scopeでのadoptionを完了とする。

1. 対象repository、credential class、automation consumer、ownerがcurrent inventoryに含まれる。
2. GitHub／IdPのrequired settingがcurrent stateとして確認される。
3. Developer tokenをautomationが使用せず、App／workload identityがresourceとpermissionへ限定される。
4. Active PAT、OAuth、SSH、App grantにowner、purpose、scope、review、expiry／revocation stateがある。
5. Expected allow、ungranted-permission denial、out-of-scope denial、revocation denialを専用test scopeで確認する。
6. Audit eventをcredential ownerとtargetへ相関できる。
7. Exceptionは`PSB-GOV-002`に登録され、期限切れがbaselineを通過しない。
8. `NOT_CHECKED`とresidual riskが明示され、fixture `PASS`をlive adoptionとして使用していない。

## 13. 残余risk

- Phishing-resistant authenticationでも、認証済みendpoint sessionの侵害は残る。
- Hardware-backed SSHでも、正規sessionからの不正操作を完全には止めない。
- Fine-grained PATもrepository、permission、durationが広ければ過剰権限になる。
- Provider UI／API、plan、retention、event coverageは変更され得る。
- Audit logは予防controlではなく、不完全なevent coverageや保存期間の制約がある。
- Revocation後もclone、fork、cache、取得済みsourceは回収できない。
- GitHub control plane、IdP、organization owner自体の侵害は別のtrust boundaryである。

## 14. 参照

- [GitHub: Setting a personal access token policy for your organization](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
- [GitHub: REST API endpoints for personal access tokens](https://docs.github.com/en/rest/orgs/personal-access-tokens)
- [GitHub: About OAuth app access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [GitHub: Limiting OAuth app and GitHub App access requests and installations](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [GitHub: Reviewing GitHub Apps installed in your organization](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-github-apps-installed-in-your-organization)
- [GitHub: Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub: Reviewing the audit log for your organization](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
