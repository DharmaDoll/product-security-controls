# PSB-SOURCE-003 implementation instructions

この file は `PSB-SOURCE-003` に固有の実装境界を定める。repository root と
`controls/AGENTS.md` を先に読み、ここに一般規約を複製しない。

## Control essence

- Domain は `source-protection`、基準 provider は GitHub.com である。
- この control は、Security／AppSec が攻撃者と同じ public-only の視点で行う reconnaissance を小さく
  自動化する。各 product repository へ hook、agent、workflow を配布する方式ではない。
- Adopter が最初に設定するのは、自社が所有する target domain と stable indicator ID だけでよい。
- Domain、subdomain、`@domain`、公開 URL、設定 file、認証 marker、infrastructure marker を組み合わせ、
  public code、Issue／PR、Gist、Web index から、攻撃に利用され得る資産情報や credential exposure の候補を
  効率よく探す。
- 一つの repository に限定した clone や全履歴 scan は主実装にしない。Current public search に出ない
  過去 content、private content、unknown cache は残余境界として明記する。
- Security 効果は、実際の定期 search、新規 finding の差分、review、notification、是正から生まれる。
  Query sample、fixture、Actions workflow を copy するだけでは監視は開始されない。

## Chosen implementation profile

PoC は GitHub Actions 上で `schedule` と明示的な `workflow_dispatch` により実行する。Durable state は
SQLite や外部 database ではなく、同じ monitor repository の専用 state branch にある sanitized JSON
と Git history を使う。

実装者が守る normative contract は
[`docs/PUBLIC_EXPOSURE_MONITOR_POC_SPEC.md`](docs/PUBLIC_EXPOSURE_MONITOR_POC_SPEC.md) に定義する。
別環境で再実装する場合も同仕様を正とし、interface、state、query、exit status を変更する場合は先に
仕様 version と移行方法を更新する。

この package が提供するのは次だけである。

1. Attacker-view reconnaissance の思想、query category、trust boundary、運用仕様。
2. Domain 設定から高度な GitHub／Web dork を生成する scanner PoC。
3. GitHub public Search API で取得可能な result の allow-list normalization と差分判定。
4. State branch の既知 finding／review state を読んで更新する reference workflow。
5. Actions Summary と machine-readable JSON による `NEW`／`REOPENED`／`SCAN_ERROR` output。
6. Scanner の主要 behavior だけを確認する小さな offline test。

本番の Slack App／webhook、case management、repository hosting、organization-specific schedule、retention、
escalation、dashboard は別 repository で実装する。PoC は notification-ready JSON を渡すところまでとし、
Slack secret や production channel をこの public package に追加しない。

## Supported assumptions

- PoC は GitHub-hosted Ubuntu runner と Python 3.10+ standard library で動作させる。Docker、browser
  automation、package manager、database service を追加しない。
- Reference workflow は `secure/.github/workflows/` に copyable sample として置き、この blueprint の
  default workflow として自動 activation しない。
- 実 domain と state branch は private な organization security repository で管理する。Public repository の
  branch は state branch も public になるため、実 organization data の保管先に使わない。
- Search 用 identity は private repository access を持たない dedicated audit identity を基準とする。
  Actions の current-repository token が monitor repository を読める場合でも、query は public-only にし、
  provider response の `private` state を検査する。
- GitHub Code Search API、Web UI、query syntax、index scope は変わり得る。Current official documentation、
  explicit API version、review date、残余境界を README に記録する。
- Owned domain を GitHub や外部 Web search provider へ送信できることを Security／data owner が承認する。
  内部 codename、customer identifier、secret value を query に追加しない。

## Minimal adoption path

README は mandatory one-page summary の直後で、次の最短経路を示す。

1. `secure/domain-monitor.json` を private security repository へ copy し、`example.invalid` を自社 domain に
   置き換える。
2. `secure/.github/workflows/public-exposure-monitor.yml` を review して copy する。
3. 専用 state branch を明示的に作り、sample `state/findings.json` を置く。Workflow に state branch の
   source code や workflow を実行させない。
4. Repository Actions policy で workflow write を trusted `schedule`／manual execution に限定する。
5. `workflow_dispatch` で一度実行し、Actions Summary の browser dork、new finding、scan health を確認する。
6. Review 済み exact fingerprint に owner、reason、disposition、expiry を記録し、state branch へ反映する。
7. `new-findings.json` を別 repository の Slack／case-management adapter へ接続する。

Rollback は schedule を停止し、copy した workflow、config、state branch を adopter-owned review で削除する。
Global Git、shell、IDE、OS setting を変更しない。State branch の削除は履歴を失うため、retention と export を
確認してから行う。

## Domain and query contract

最小 config は一つ以上の owned domain だけとする。

```json
{
  "schema_version": "1.0",
  "domains": [
    {"id": "ORG-DOMAIN-PRIMARY", "value": "corp.example.invalid"}
  ]
}
```

- ID は `ORG-*` の stable non-sensitive identifier とする。
- Domain は lowercase／IDNA を正規化し、DNS suffix boundary を検証する。Wildcard、URL、email address、
  public suffix だけの値を拒否する。
- 実 email address は登録せず、`@domain` を query generator が導出する。
- Query には必ず owned domain anchor を含める。`password OR token` のような generic global search、第三者
  domain、実 secret、個人 identifier の search を生成しない。

最低限の query category は次とする。

- Identity: `@domain`、employee email suffix、commit／config に現れる organization identity。
- Host and URL: exact domain、subdomain、URL、API endpoint、admin／VPN／SSO／staging／development host。
- Credential adjacency: owned domain と `password`、`token`、`secret`、`api_key`、`client_secret` 等の組合せ。
- Configuration and infrastructure: owned domain と `.env`、YAML、JSON、properties、Terraform、Kubernetes、
  DNS、CNAME、ingress 等の組合せ。
- Public distribution: GitHub code、Issue／PR、Gist、`raw.githubusercontent.com`、`site:github.com` を使う
  browser query。

PoC は GitHub Code／Issue／PR Search API と public Gist delta API の result を自動差分化する。また、
GitHub Code Search URL、Issue／PR Search URL、Gist Search URL、generic Web dork text を Actions Summary に
生成する。通常 Web page を HTML scrape したり、CAPTCHA や provider rate limit を回避したりしない。
Web-only query は Security reviewer が browser で確認する。

## State branch contract

State contract の対象は exact path `state/findings.json` の strict JSON data だけとする。Branch 作成時の ancestry
に他 file が存在しても scanner は checkout せず、exact path 以外を読まない。State content を import、source、
eval、shell expansion しない。

State file は少なくとも次を保持する。

- schema version と query／indicator version;
- exact sanitized fingerprint;
- source、query ID、indicator ID、public repository ID／name、path、public URL;
- first seen、last seen、last notified;
- `open`、`accepted-public`、`false-positive`、`remediated` disposition;
- review owner、reason、reviewed time、expiry。

Match snippet、domain value、email local part、credential、authorization header、raw provider response を
state branch に保存しない。Review reason に raw content を貼らない。

Fingerprint は provider、stable repository ID、path、provider object／blob identity、indicator ID を
canonical encoding して SHA-256 化する。Repository display name、result order、取得時刻だけを fingerprint に
使わない。

State transition は次のとおりにする。

- 未登録 fingerprint: `open` として追加し、`NEW` を一度出す。
- 同一 fingerprint: last seen を更新し、毎回 new notification を出さない。
- 有効期限内の exact `accepted-public`／`false-positive`: 通知を抑制する。
- Review expiry 後、または `remediated` finding の再出現: `open` に戻して `REOPENED` を一度出す。
- Object identity が変わった同一 path: 新しい occurrence として review する。
- Search result から消えた finding: index fluctuationを考慮し、自動で `remediated` にしない。

State update は exact base blob SHA を使った compare-and-swap とし、concurrent modification、branch missing、
malformed state、permission denial、push／API failure を `ERROR` にする。新しい state を書けなかった run を
clean または通知完了にしない。成功 run は Gist cursor を進めるため、finding event がなくても state を更新する。

## GitHub Actions rules

- Trigger は `schedule` と trusted `workflow_dispatch` だけとし、`pull_request`、`pull_request_target`、
  untrusted `push` content から write job を起動しない。
- Privileged monitor job は repository default branch の reviewed ref だけで動かし、manual dispatch で別branchを
  選んだ場合は実行しない。
- Workflow top level は `permissions: {}` とし、monitor job だけに必要な `contents: write` を宣言する。
  State branch 以外への変更を script 側で拒否する。
- `concurrency` は一つの monitor group、`cancel-in-progress: false` とし、同時 state update を避ける。
- Third-party Actions は full commit SHA で pin する。Checkout は `persist-credentials: false` とし、state
  read／write credential を worktree の Git config に残さない。
- Token は step environment から exact child process にだけ渡し、CLI、URL、debug output、artifact に出さない。
- Query、actual domain、state、finding artifact を public Actions log／artifact に出さない。Actual monitor
  repository は private を前提とし、Actions Summary の閲覧権限も review する。
- Search、state update、notification output を順序付け、途中失敗を0 findingsへ変換しない。

## Output and notification boundary

PoC は次を出す。

- Actions Summary: scan health、query ID、clickable browser dork、new／known count、sanitized finding link。
- `new-findings.json`: `NEW`／`REOPENED` の notifier-ready event。
- `updated-state.json`: compare-and-swap で state branch へ書く sanitized next state。
- `SCAN_ERROR`: API、pagination、query、state read／write の失敗。

Notification event は event type、fingerprint、indicator／query ID、public repository、path、public URL、
first／last seen を含めてよい。Domain value、matched snippet、secret、personal email、token を含めない。
Slack delivery、retry、ack、channel routing は別 repository が所有する。

Exit status は `0=complete with no NEW/REOPENED`、`1=NEW/REOPENED emitted`、
`2=input／provider／pagination／state error` とする。

## Coverage boundary

- GitHub public search は攻撃者視点の有用な reconnaissance だが exhaustive scan ではない。
- GitHub Search API の result cap、repository scope、default branch、file size、index、rate limit、
  `incomplete_results` と、public Gist delta の cursor／truncation／page limit を README に記録する。
- Browser query は reviewer が実行して初めて結果になる。URL生成成功を scan completion にしない。
- Clone と全 Git history scan をこの PoC の完了条件にしない。Current index から消えた content、external
  cache、old clone、screenshot は残余リスクである。
- Domain は通常 secret ではない。Finding は「攻撃者に有用となり得る自社関連 public information」であり、
  すべてを vulnerability や incident と自動判定しない。
- Credential exposure を確認した場合は repository cleanup より先に revoke／rotate し、`PSB-GOV-004` へ
  handoff する。

## Relationship to other controls

- `PSB-SOURCE-002` は repository-local hook と commit前のsecret blockingを所有する。本 control はそれを
  複製しない。
- `PSB-SOURCE-004` は source credential の通常 lifecycle を所有する。本 control は public exposure の
  reconnaissance と response handoff を所有する。
- `PSB-GOV-004` は credential containment、consumer migration、old-authority denial を所有する。
- `PSB-GOV-002` は security exception contract を所有する。Finding review は exact result disposition であり、
  他 control の exception ではない。
- `PSB-CICD-004／005` は workflow permission と untrusted PR boundary を所有する。Reference workflow は
  それらの secure pattern を再利用する。

## Verification strategy

Scanner の一連の test だけを追加し、production GitHub／Slack、large permutation、形式的 schema test に
注力しない。Sanitized response fixture と temporary state JSON を使い、少なくとも次を確認する。

- domain config から owned-domain-anchored query が生成される;
- code、Issue、PR が public-only result として正規化され、Issue／PR の repository visibility が再確認される;
- public Gist delta が cursor を使用し、matched content を保存せず、truncation で fail closed する;
- initial result は `NEW`、同一 result は known になる;
- exact review は期限内だけ通知を抑制し、expiry／remediated 再出現は `REOPENED` になる;
- object identity の変更は新しい occurrence になる;
- raw domain、snippet、email local part、credential、authorization header が出力されない;
- `incomplete_results`、pagination、rate limit、malformed response／state は `ERROR` になる;
- workflow sample は trusted trigger、explicit permission、pinned Action、fixed state branch を使う。

Live smoke test は opt-in とし、network egress と identity を明示する。Production repository へ canary
secretをpushしない。README文字列だけのtest、no-op、synthetic evidenceのadoption claimを追加しない。

## Metadata and required verification

- `control.yaml` は canonical source である。Attacker-view monitor の atomic state だけを残し、clone、全履歴、
  non-code surface、Secret Protection setting をPoCが自動検証するようなclaimを残さない。
- `secure/evidence-snapshot.json` と自己申告 verifier は主実装にしない。実 run の state commit、scan health、
  new finding、review、notification handoff が organization evidence である。
- Framework mapping は exact check への限定的 relationship であり、compliance や完全な漏洩検出を意味しない。

変更後は次を実行する。

```bash
bash tests/test.sh
make verify-control CONTROL=PSB-SOURCE-003
make validate-controls
```

Metadata を変更した場合は、必要に応じて `make generate-index`、`make generate-mappings`、
`make generate-checklists` を実行し、`PSB-SOURCE-003` 由来の差分だけを review する。
