# PSB-SOURCE-004 read-only監査オプション

## 1. 目的

この文書は、案1のmanual GitHub baselineを将来read-only監査で補助する場合に、何を確認でき、
何を確認できないかを示します。Collectorの実装や導入を要求する文書ではありません。

確認日: 2026-08-25。

公式REST例で確認したAPI version: `2026-03-10`。

API version、permission、plan、response fieldは変わり得ます。Future collectorは実装時点でofficial
documentationを再確認し、versionとsource review dateを固定してください。

## 2. 先に知っておくべき境界

- GitHub APIはcredential値を列挙しません。Metadataとauthorization stateを確認します。
- Fine-grained PAT、classic PAT、OAuth、SSH、GitHub Appでは確認interfaceが異なります。
- Organization setting、active grant、audit eventの一つだけでは完全なlifecycleを証明できません。
- GitHub APIはIdP policy、FIDO2 authenticator custody、OS keychain、IDE environment inheritanceを
  証明しません。
- Audit logは過去eventであり、current settingや現在の実権限と同じものではありません。
- API／plan／permission failureは`ERROR`または`NOT_CHECKED`であり、clean resultではありません。

## 3. 利用可能な確認方法

### 3.1 Fine-grained PAT request

| 項目 | 内容 |
|---|---|
| Endpoint | `GET /orgs/{org}/personal-access-token-requests` |
| 主な確認 | Pending request、owner、repository selection、permission、created／expiry |
| Authentication | GitHub App user／installation access tokenのみ |
| Required permission | Organization `Personal access token requests: read` |
| Check候補 | `SCL-003`、`SCL-005` |

Repository selectionの完全確認には各requestのrepository endpointもcomplete paginationで取得します。
Pending requestの不存在は、active tokenが安全である証明ではありません。

### 3.2 Active fine-grained PAT

| 項目 | 内容 |
|---|---|
| Endpoint | `GET /orgs/{org}/personal-access-tokens` |
| 主な確認 | Approved active token、owner、repository selection、permission、expiry、last use |
| Authentication | GitHub App user／installation access tokenのみ |
| Required permission | Organization `Personal access tokens: read` |
| Check候補 | `SCL-003`、`SCL-005`、`SCL-009` |

各tokenのrepositoryは`GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories`で取得できます。
Token IDとownerはsensitive security metadataとして扱い、public artifactへ出しません。

このendpointはorganization member所有のapproved fine-grained PATを対象とします。Classic PAT、
organization外identity、取得不能なgrantまで完全に表すとは主張しません。

### 3.3 Installed GitHub Apps

| 項目 | 内容 |
|---|---|
| Endpoint | `GET /orgs/{org}/installations` |
| 主な確認 | Installation ID、App ID、permission、repository selection、suspension、更新時刻 |
| Authentication | Organization owner相当のread authority |
| Required permission例 | Organization `Administration: read` |
| Check候補 | `SCL-001`、`SCL-009`、`SCL-011` |

`repository_selection=selected`だけでは対象repositoryの完全性を証明しません。Installationごとの
repository listを取得し、expected inventoryと比較する必要があります。

APIはAppのdownstream consumer、private key custody、installation token delivery、実際のtask purposeを
証明しません。これらはPlatform／SREのconsumer inventoryとsecret-delivery evidenceが必要です。

### 3.4 SAML SSO credential authorizations

| 項目 | 内容 |
|---|---|
| Endpoint | `GET /orgs/{org}/credential-authorizations` |
| 主な確認 | SAML SSO organizationでauthorizedされたPAT、SSH、OAuth、GitHub App user token metadata |
| Availability | GitHub Enterprise CloudとSAML SSO構成に依存 |
| Required authority例 | Organization owner、`read:org`または`Administration: read` |
| Check候補 | `SCL-006..010` |

Responseをraw保存しません。Credential ID、fingerprint、login等はorganization private evidenceでも
必要fieldだけへallow-listします。SAML authorizationはIdP session、authenticator、credential storageの
安全性を証明しません。

同じAPI groupにはcredential authorizationのrevoke endpointがありますが、このread-only optionでは
呼び出しません。Collection identityへwrite permissionを与えません。

### 3.5 Organization audit log

| 項目 | 内容 |
|---|---|
| Endpoint | `GET /orgs/{org}/audit-log`またはGraphQL audit log |
| 主な確認 | Membership、permission、App、credential lifecycle、設定変更、API request event |
| Availability | Audit log APIはGitHub Enterprise Cloudが必要 |
| Required authority例 | `read:audit_log`を持つauthorized identity |
| Check候補 | `SCL-010`、`SCL-011` |

GitHub documentation上、GraphQLで取得できる期間は90～120日、RESTのGit event保持は7日、その他の
eventは最大7か月で、default queryは直近3か月です。実際のplan／configuration／streaming policyを
確認し、必要なreview cadenceより短いretentionを完全なevidenceとして扱いません。

Audit eventにはactor、user、repository、token ID／scope等のsecurity metadataや個人情報が含まれ得ます。
Public evidenceにはaction class、sanitized stable target、timestamp、result、source cursorだけを残します。

### 3.6 GitHub UI／approved export

API adapterを作らなくても、organization ownerとsecurity reviewerが次をread-only確認できます。

- `People`: Member、outside collaborator、2FA state。
- `Personal access tokens`: Policy、pending request、active fine-grained PAT。
- `Third-party Access`: OAuth App policy、approved OAuth App、installed GitHub App。
- `Audit log`: Credential／App／membership event検索とbounded export。
- `Authentication security`: 2FA／SSO関連current setting。

Screen captureを唯一のevidenceにせず、対象organization、取得時刻、reviewer、setting名、判定、
未確認scopeを記録します。Screenshotへuser list、email、token metadataを不要に含めません。

### 3.7 IdP／SCIM

GitHub外のread-only sourceで次を確認します。

- Phishing-resistant authentication requirement。
- SAML／OIDC application assignment。
- Joiner／mover／leaver eventとGitHub membership removal。
- Session invalidationとconditional access。
- SCIM provisioning failure、retry、遅延。

GitHub membershipが消えたことだけでは、PAT、SSH、OAuth、session、downstream credentialがすべて
無効化されたとは限りません。Provider側credential inventoryと相関します。

### 3.8 Endpoint／IDE

GitHub APIでは次を確認できません。

- OAuth／PATがOS keychainに保存されているか。
- `.env`、shell profile、IDE JSON、Git remote URLにcredentialが残っていないか。
- Parent IDE environmentからunrelated childへtokenが継承されないか。
- SSH private keyがhardware-backed、non-exportable、user-verifyingか。
- `${input:github_token}`が実際にprotected storeからexact MCP childへだけ解決されるか。

これらはendpointのread-only observation、managed configuration、secret-store auditを使います。
`PSB-SOURCE-001`のhost boundaryと`PSB-AI-004`のruntime boundaryを参照し、確認できなければ
`NOT_CHECKED`とします。

## 4. Check別の監査source

| Check | 第一source | 補助source | APIだけで完了できるか |
|---|---|---|---|
| `SCL-001` | App installation＋consumer inventory | Audit log | いいえ |
| `SCL-002` | PAT organization policy | Active PAT inventory | いいえ。classic PAT consumer reviewが必要 |
| `SCL-003` | Fine-grained PAT API | Approval record | 条件付き |
| `SCL-004` | Grant inventory | `PSB-GOV-002` register | いいえ |
| `SCL-005` | PAT expiry／policy | Credential authorization | 条件付き |
| `SCL-006` | Endpoint storage assessment | Credential-free remote review | いいえ |
| `SCL-007` | IdP／GitHub auth policy | 2FA member state | いいえ |
| `SCL-008` | SSH enrollment／hardware record | SAML credential authorization | いいえ |
| `SCL-009` | Complete multi-class inventory | PAT／App／SSO APIs | いいえ |
| `SCL-010` | Revocation drill | Audit event | いいえ |
| `SCL-011` | Audit coverage／retention | Representative event | 条件付き |
| `SCL-012` | `PSB-GOV-002` register | Grant inventory | いいえ |
| `SCL-013..017` | OAuth／IDE／MCP live evidence | Reference verifier | いいえ |

## 5. Future collector architecture

Collectorを実装する場合も、provider変更やcredential revokeを同じprocessへ入れません。

```text
approved read-only identity
          ↓
versioned GitHub API / approved export / IdP source
          ↓
complete pagination + source health + freshness
          ↓
field allow-list + sanitized stable identities
          ↓
PASS / FAIL / NOT_CHECKED / ERROR
          ↓
organization-private evidence system
```

### 5.1 Identity

- Collector専用GitHub App等、必要なread permissionだけを持つidentityを使用する。
- Developer PAT、broad classic PAT、interactive admin sessionを常設collector credentialにしない。
- Secretはapproved secret managerからexact collector processへ短時間だけ配送する。
- Identity owner、installation、repository／organization scope、expiry／rotationをinventory化する。

### 5.2 Request

- HTTPSの`api.github.com`またはapproved GHE.com endpointへ限定する。
- `Accept: application/vnd.github+json`とreview済み`X-GitHub-Api-Version`を明示する。
- Organization stable identityとrequested organizationが一致することを確認する。
- Page sizeを最大100にしても一pageで完了と仮定せず、official pagination link／cursorを追う。
- Repeated cursor、page limit超過、rate limit、timeout、5xx、403、unexpected redirectを`ERROR`にする。

### 5.3 Normalization

必要fieldの例:

- Schema／collector version。
- Source typeとAPI version。
- Collected at／evidence freshness deadline。
- Organization stable IDのsanitized reference。
- Credential classとsanitized provider ID。
- Owner role、repository selection、permission class。
- Created／last-used／expiry／review state。
- Pagination complete、source health、result reason。

禁止field:

- Token、private key、authorization header、cookie、recovery code。
- Raw audit payload、email、IP address、user agent、unnecessary login。
- Private repository name／URL、source code、issue／pull request content。
- MCP argument、prompt、tool output。

### 5.4 Result

| State | 条件 |
|---|---|
| `PASS` | Current、complete、authorized sourceがone atomic required stateを証明 |
| `FAIL` | Current sourceがbroad、expired、unowned等のunsafe stateを証明 |
| `NOT_CHECKED` | Required source／plan／authorityがなく評価していない |
| `ERROR` | Missing、stale、partial、malformed、permission、rate-limit、network、parser failure |
| `N/A` | Reviewed scopeに対象credential classが存在しない |

`PASS`は一つのatomic checkにだけ使用します。PAT APIの`PASS`をSSH、OAuth、endpoint storage、
organization全体のadoptionへ拡張しません。

## 6. Manual reviewからcollectorへ移す判断

次をすべて満たす場合だけcollector実装を検討します。

1. Manual reviewで見逃しまたはcadence負担が具体的に発生している。
2. 対象GitHub planとAPI fieldが確定している。
3. Read-only identityとsecret deliveryを安全に運用できる。
4. Complete pagination、freshness、sanitizationをtestできる。
5. Outputを受け取り、`FAIL`／`ERROR`へ対応するownerがいる。
6. Collectorがない状態でも案1のmanual baselineを継続できる。

単に`E3`や自動化率を上げる目的では実装しません。

## 7. Collectorを作る場合のminimum tests

- One-pageとmulti-pageのcomplete collection。
- Empty current inventoryとmissing permissionの区別。
- `403`、`404`、`429`、`5xx`、timeout、malformed JSONの`ERROR`。
- Repeated cursor／pageとtruncated inventoryの拒否。
- Stale evidenceの拒否。
- Safe fixtureの`PASS`とbroad／expired／unowned fixtureの`FAIL`。
- Raw token、authorization header、email、repository名がoutputへ出ないこと。
- Live smoke testとfixture testの分離。

API mutation、PAT revoke、App suspension、policy updateをself-testに含めません。

## 8. Official references

- [REST API endpoints for personal access tokens](https://docs.github.com/en/rest/orgs/personal-access-tokens)
- [REST API endpoints for organizations](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs)
- [Reviewing installed GitHub Apps](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-github-apps-installed-in-your-organization)
- [Reviewing the organization audit log](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
- [Audit log events for an organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
- [Setting organization PAT policy](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
