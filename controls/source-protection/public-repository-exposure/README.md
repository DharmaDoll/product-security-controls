# PSB-SOURCE-003: Public repository exposure monitoring

自社 domain を起点に、攻撃者と同じ public-only の視点で GitHub の公開情報を定期検索し、
初出または再出現した候補だけを review へ送る control です。この package は GitHub Actions で動く
scanner core PoC と再実装仕様を提供し、本番の Slack／case-management integration は別 repository に
委ねます。

## このcontrolを一枚で理解する

### セキュリティ上の問題

自社 domain、従業員 email suffix、内部 endpoint、設定断片が public code、Issue、PR、Gist 等へ現れると、
攻撃者は通常の検索から資産を列挙し、credential 探索や標的選定に利用できます。

### 誰から、または何から守るか

GitHub／Web 検索を使う外部攻撃者と収集 bot、公開範囲を誤る投稿者、rate limit・pagination・state 更新失敗を
「0件」と誤認する監視運用から守ります。

### 何が対象か

設定した自社 domain に一致する GitHub の public code、public repository の Issue／PR、新規・更新 public
Gist、および人が通常の browser GET 検索で確認する GitHub／Gist／Web index が対象です。

### 何をするか

Domain から固定 query を生成し、公式 REST API の結果を差分化します。既知 finding と期限付き review は専用
state branch に保存し、`NEW`／`REOPENED` の sanitized JSON を通知 adapter へ渡します。

### 成功状態

Trusted schedule が完走し、新規候補が review され、同一候補は重複通知されない状態です。Review 期限切れや
remediation 後の再出現は再通知され、scanner failure は exit `2` になります。

### 対象外・残余リスク

GitHub の index 外・過去 Git 履歴・削除済み Gist・外部 cache・画像・難読化情報は網羅しません。Browser
query は人が開かなければ検査にならず、0件も過去露出がなかった証明にはなりません。

## セキュリティ向上の効果はどこから生まれるか

効果は、private な monitor repository で定期 scan を実行し、`NEW`／`REOPENED` を担当者が確認して、
不要な公開を止めることから生まれます。実 credential が疑われる場合は、repository 上の削除より先に
revoke／rotate します。次の変更が実環境に必要です。

- 所有を確認した自社 domain を `secure/domain-monitor.json` に設定する。
- Private repository access を持たない検索専用 identity を用意する。
- Trusted `schedule`／`workflow_dispatch` で workflow を有効化する。
- 専用 branch `psb-source-003-state` の `state/findings.json` を GitHub Actions が更新できるようにする。
- Security が finding の disposition、owner、reason、expiry を review する。
- `new-findings.json` を Slack 等へ送る adapter を別 repository で接続する。

この README、workflow、sample state をコピーするだけでは監視は始まりません。GitHub Actions の実行、
state 書き込み、結果 review、通知と remediation の運用が揃って初めて security state が変わります。

## 誰が何をするcontrolなのか

| 担当 | 実作業 |
| --- | --- |
| Security／AppSec | Domain の所有と外部 provider への送信可否を確認し、query、finding、期限付き review、escalation を所有する。 |
| Repository administrator | Private monitor repository、Actions policy、`PUBLIC_SEARCH_TOKEN`、state branch、job の `contents: write` を設定する。 |
| Development team | 自分の product に関する候補を調査し、不要な公開を削除し、再発防止を行う。 |
| Platform／SRE | 公開された endpoint や infrastructure 情報の影響と access control を確認する。 |
| Incident response | Credential exposure の可能性があれば revoke／rotate、log 調査、containment を行う。 |
| Product owner | 意図的な公開の business justification と期限付き残余 risk を承認する。 |

Scanner は候補を vulnerability や incident と自動確定しません。

## 最短の導入手順

### 1. 前提条件

- Private な GitHub monitor repository
- GitHub-hosted Ubuntu runner と Python 3.10 以上
- 外部検索してよい、組織が所有する domain
- Private repository の read 権限を持たない専用 GitHub identity の token
- Repository の Actions workflow に対する `contents: write` 許可

この PoC は Docker、package manager、SQLite、browser automation を必要としません。検索 identity と
state 更新 identity は分離します。`PUBLIC_SEARCH_TOKEN` は public search だけ、`GITHUB_TOKEN` は monitor
repository の state file だけに使います。

### 2. Copy する file

次を private monitor repository の同じ相対 path へ copy します。

```text
secure/domain-monitor.json
secure/state/findings.json
secure/.github/workflows/public-exposure-monitor.yml
scripts/monitor-public-exposure.py
```

Workflow を実際に起動するには、copy 後に
`secure/.github/workflows/public-exposure-monitor.yml` を
`.github/workflows/public-exposure-monitor.yml` へ移します。この blueprint 内では sample が自動起動しない
よう `secure/` 配下に隔離しています。

### 3. Domain を設定する

`secure/domain-monitor.json` の synthetic domain を置換します。最初は代表 domain 一つで十分です。

```json
{
  "schema_version": "1.0",
  "domains": [
    {
      "id": "ORG-DOMAIN-PRIMARY",
      "value": "corp.example.invalid"
    }
  ]
}
```

`value` は scheme、path、wildcard、email address ではなく DNS domain だけにします。個人名、実 secret、
customer identifier、秘密の codename は登録しません。実 email address ではなく `@domain` を scanner が
導出します。

### 4. State branch を作る

GitHub UI で default branch から `psb-source-003-state` を作り、sample
`secure/state/findings.json` の内容を branch 上の `state/findings.json` として commit します。Scanner は
この exact branch／path だけを Contents API で読み書きし、branch 上の code を checkout または実行しません。

Branch ruleset は次を最小状態にします。

- 人の直接 push は拒否する。
- Monitor workflow の `GITHUB_TOKEN` に `state/findings.json` 更新を許可する。
- Force push と delete は拒否する。
- Repository administrator と Security が state history を閲覧できる。

Ruleset が GitHub Actions の file update を拒否する環境では、例外主体を monitor workflow に限定します。
広い bot bypass や default branch への write を追加しません。

### 5. Search token を登録する

Private repository の Actions secret `PUBLIC_SEARCH_TOKEN` を作ります。Dedicated audit identity は private
repository や organization administration の権限を持たせず、public GitHub REST Search と public Gist
取得だけに使います。Token 種別や有効期限は organization policy に合わせて調整してください。

Issue／PR の Search API item は repository metadata を再取得し、`private: false` でなければ scan 全体を
error にします。これは token の権限分離を置き換えるものではなく、誤設定を fail closed にする追加確認です。

### 6. 明示的に有効化する

Workflow を default branch へ reviewed change として追加し、GitHub Actions の
`Public exposure monitor` を default branch を選んで `workflow_dispatch` で一度実行します。Workflow は
default branch 以外を選んだ privileged job を skip します。成功時は次を確認します。

- Actions Summary に scan health と browser 用 GET link が出る。
- API で新規候補があれば job は exit `1` になり、`NEW` が表示される。
- 候補がなければ job は exit `0` になる。
- `psb-source-003-state` の `state/findings.json` に cursor と sanitized finding が更新される。
- Provider、pagination、state read／write の失敗は exit `2` になり、`SCAN_ERROR` と表示される。

初期 Gist scan は直近1時間の new／updated public Gist を対象にします。その後は state cursor 以降を
追跡します。過去 Gist の baseline は Summary に生成された browser link を人が確認します。

### 7. 通知を接続する

`reconcile` が作る `generated/assessment/new-findings.json` には `NEW`／`REOPENED` だけが含まれます。
別 repository の通知 adapter は、この JSON を受けて Slack／case-management へ送ります。PoC repository
には production webhook、channel ID、retry queue を追加しません。

Adapter は `reconcile` が state 更新まで完了して exit `1` を返した場合だけ JSON を消費します。Exit `2` で
残った local file を送信してはいけません。本番化では delivery ID、retry、dead-letter、acknowledgement と、
state の `last_notified` とは別の delivery ledger を adapter 側で定義します。

## Query と検査範囲

### 自動実行するもの

Domain ごとに公式 GitHub REST API で次を収集します。

| Surface | Query | 目的 |
| --- | --- | --- |
| Code Search | `"domain" in:file`、`"@domain" in:file` | Public code の domain、subdomain、URL、email suffix、設定参照。 |
| Issue Search | `"domain" is:issue`、`"@domain" is:issue` | Public repository の Issue title／body／comment に由来する候補。 |
| PR Search | `"domain" is:pr`、`"@domain" is:pr` | Public repository の Pull Request に由来する候補。 |
| Public Gist delta | `GET /gists/public?since=...` と `GET /gists/{id}` | Cursor 以降の new／updated Gist の description、filename、content。Non-match は memory から破棄する。 |

Result は provider、surface、stable object identity、indicator ID、repository／Gist ID、path、public URL だけへ
正規化します。Match snippet、domain value、email local part、credential、raw provider response は state と
notification JSON に保存しません。

Search API の `incomplete_results`、1,000 result cap、malformed pagination、Gist の page limit／truncation、
rate limit、HTTP error は clean にせず exit `2` にします。公式仕様は
[REST search](https://docs.github.com/en/rest/search/search)、
[Gists API](https://docs.github.com/en/rest/gists/gists)、
[repository contents](https://docs.github.com/en/rest/repos/contents) を基準にしています。

### 人が通常の browser GET で確認するもの

`queries` command は、GitHub Code Search の Boolean、`content:`、`path:`、regular expression と、Issue／PR、
Gist、generic Web search の query を生成します。例:

```text
content:"corp.example.invalid" AND (password OR token OR secret OR api_key OR client_secret OR credential)
content:"corp.example.invalid" AND (path:*.env OR path:*.yml OR path:*.tf)
site:github.com "corp.example.invalid" ("password" OR "token" OR "secret")
site:gist.github.com "corp.example.invalid"
```

GitHub／Gist link は GET query parameter を percent encode して生成します。ただし scanner は HTML を取得、
parse、crawl しません。GitHub の browser search は sign-in や product-specific behavior があり、robots policy
にも従う必要があるためです。Query の構文は
[GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
を基準にします。最終確認日: 2026-08-26。

Browser link の生成成功は、その検索を実行または review した証拠ではありません。Security は初回 baseline と
定期的な query review を別途行います。

## State と review

Fingerprint は provider、surface、provider object identity、indicator ID から SHA-256 で作ります。
Query ID、result order、取得時刻だけが変わっても別 finding にはしません。

| 状態 | 動作 |
| --- | --- |
| 未登録 fingerprint | `open` で保存し、`NEW` を一度出す。 |
| 同一 fingerprint | `last_seen` を更新し、重複通知しない。 |
| `accepted-public`／`false-positive` | Exact finding の owner、reason、reviewed time、expiry が有効な間だけ通知を抑制する。 |
| Review 期限切れ | `open` に戻し、`REOPENED` を出す。 |
| `remediated` finding の再出現 | `open` に戻し、`REOPENED` を出す。 |
| 同じ path の object identity 変更 | 新しい occurrence として `NEW` を出す。 |
| Search から消失 | Index fluctuation を考慮し、自動で `remediated` にしない。 |

State 更新は取得時の exact blob SHA を使う compare-and-swap です。同時更新、malformed state、権限拒否は
exit `2` になります。Review reason へ検索本文、email address、credential を貼り付けないでください。

## 安全な自己テスト

Network と token を使わない最小 test:

```bash
python3 scripts/monitor-public-exposure.py queries \
  --config secure/domain-monitor.json \
  --output /tmp/psb-source-003-queries.md
```

Expected output と exit:

```text
WROTE /tmp/psb-source-003-queries.md
exit 0
```

Harmless negative test:

```bash
python3 scripts/monitor-public-exposure.py queries \
  --config insecure/domain-monitor.json \
  --output /tmp/psb-source-003-invalid.md
```

Expected stderr と exit:

```text
ERROR queries: domain value is invalid
exit 2
```

Scanner test suite:

```bash
make verify-control CONTROL=PSB-SOURCE-003
```

Test は、query 生成、public result normalization、deduplication、Gist delta、redaction、`NEW`／known／
`REOPENED`、review expiry、state compare-and-swap、fail-closed error、workflow trust boundary を fixture で確認します。
Fixture の PASS は organization の live adoption を証明しません。

終了コード:

| Exit | 意味 |
| --- | --- |
| `0` | 対象の automated scan が完了し、`NEW`／`REOPENED` なし。 |
| `1` | State 更新後に `NEW`／`REOPENED` を生成した。Review が必要。 |
| `2` | Input、provider、pagination、truncation、state read／write のため完了不能。Clean ではない。 |

詳細な expected output は `expected-results/public-exposure-monitor.md` にあります。

## Common failure と recovery

| Failure | Recovery |
| --- | --- |
| `PUBLIC_SEARCH_TOKEN` unavailable／HTTP 401 | Secret 名と expiry を確認し、private access を付けずに token を再発行する。 |
| Search rate limit／`incomplete_results` | 0件として閉じず、provider 回復後に trusted manual run を再実行する。 |
| State branch／file not found | Exact branch `psb-source-003-state` と `state/findings.json` を sample から復元する。 |
| State update conflict | Concurrent run が終わった後に再実行する。最新 state を古い artifact で上書きしない。 |
| Branch ruleset rejects update | Workflow identity だけに exact state branch の update を許可する。Default branch write は広げない。 |
| Gist page／truncation limit | Run を error のまま保持し、window を短くするか別 repository の production collector で分割取得する。 |
| Browser link が sign-in を求める | Public-only audit account で人が開く。HTML scraping や CAPTCHA bypass へ切り替えない。 |

## Rollback

1. Default branch から monitor workflow を reviewed change で削除し、schedule を停止する。
2. `PUBLIC_SEARCH_TOKEN` を revoke する。
3. 通知 adapter を停止する。
4. State retention／incident record の要否を Security が確認する。
5. Retention が不要と承認された場合だけ `psb-source-003-state` を削除する。

Global Git、shell、IDE、OS setting は変更しません。State branch を削除すると review history と cursor は通常の
操作では復元しにくくなるため、先に export と retention を確認します。

## CI・server-side enforcement と導入完了条件

この control は pre-commit check ではなく centralized monitoring です。各 product repository への hook、clone、
workflow 配布は不要です。一方、repository visibility、Secret Scanning、Push Protection、credential lifecycle、
incident response は別 control／provider setting で引き続き必要です。

導入完了は次の live 状態で判断します。

- Private monitor repository で reviewed workflow が schedule 実行されている。
- Search identity が private repository を読めず、state identity と分離されている。
- State branch が更新され、failure が clean と区別される。
- 初回 browser baseline が人により確認されている。
- `NEW`／`REOPENED` の担当、SLA、通知先が決まっている。
- 実 finding で review／remediation／reopen の運用を dry-run している。

Sample JSON や unit test の PASS だけでは導入完了ではありません。Live evidence として残す場合は、実 workflow
run URL、取得時刻、対象 monitor repository、search identity の権限境界、state commit、通知 delivery、review
結果を access-controlled な場所へ記録します。架空の evidence file は作りません。

## 限界と運用コスト

- GitHub Search は exhaustive ではなく、index、default branch、result cap、rate limit の影響を受ける。
- Public Gist feed の delta は cursor 後の new／updated item を見るもので、過去全件検索ではない。
- Domain match は context を理解しないため、意図的公開や false positive を含む。
- 難読化、分割、画像、binary、削除済み content、external cache、過去 clone は見逃し得る。
- Public URL を state に保持するため、monitor repository と Actions Summary は private にする。
- Domain catalog を増やすと Search API call と review volume が線形に増える。
- Provider API／browser syntax／contract plan の変更時は query catalog と仕様を再 review する。

Clone と全 Git history の検査をこの PoC の完了条件にしないのは、未知の public repository を攻撃者視点で
効率よく見つけることが本 control の essence だからです。既知 repository の commit 前防止や全履歴 incident
調査は、それぞれ既存 control と incident runbook が所有します。

## 他controlとの分担

- `PSB-SOURCE-002`: Repository-local な commit 前 secret blocking。本 control は centralized public reconnaissance。
- `PSB-SOURCE-004`: Source credential の lifecycle。本 control は公開候補を検出して response へ handoff。
- `PSB-GOV-004`: Credential containment、consumer migration、old authority denial。
- `PSB-GOV-002`: Security exception contract。本 control の disposition は exact finding の review であり、一般例外ではない。
- `PSB-CICD-004／005`: Workflow permission と untrusted PR boundary。本 sample は trusted trigger と最小 permission を適用。

Normative な再実装仕様は `docs/PUBLIC_EXPOSURE_MONITOR_POC_SPEC.md` です。

## Framework mapping

Framework mapping は存在します。Canonical なmachine-readable mappingは
[`control.yaml`](control.yaml)に記録し、READMEでは次のように要約します。

| Framework | Version | ID | Relationship | Confidence | このcontrolとの関係 |
| --- | --- | --- | --- | --- | --- |
| MITRE ATT&CK | v19.1 | `T1593.003` Code Repositories | `detects` | high | 攻撃者がpublic code repositoryを検索する偵察行動を、owned-domain検索によって防御側から再現し、外部から発見できる情報を検出する。 |
| MITRE ATT&CK | v19.1 | `T1552.001` Credentials In Files | `detects` | medium | Domainに関連するpublic code／Gistからcredentialまたはcredential周辺設定の候補を検出する。Credentialの存在や有効性までは確認しない。 |
| NIST SSDF | 1.1（SP 800-218, 2022） | `RV.1.1` | `supports` | medium | Public surfaceの反復収集、差分、review、失敗の明示により、潜在的なsecurity issueを特定・確認する活動を支援する。 |
| OpenSSF OSPS Baseline | 2026.02.19 | `OSPS-BR-07.01` | `supports` | low | Public fileとcollaboration contentの監視によりsecret／credentialの安全な取扱いを補助するが、公開防止やrotateは実施しない。 |

MITRE ATT&CK mappingは関連する攻撃行動を示すもので、対策の完全性を意味しません。NIST SSDF／OpenSSF
mappingもformal compliance、完全なsecret検出、organization adoptionの証明ではありません。Check単位の
`applies_to`、rationale、reviewer、review dateは`control.yaml`を正とします。
