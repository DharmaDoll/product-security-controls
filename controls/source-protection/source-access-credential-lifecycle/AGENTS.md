# PSB-SOURCE-004 implementation instructions

Source-platform credential の通常ライフサイクルに固有の指示である。repository root と
`controls/AGENTS.md` を先に読むこと。

## Control essence

- `PSB-SOURCE-004`（`source-protection`）が守る対象は、developer と automation が
  source platform へアクセスするための
  OAuth grant、classic／fine-grained PAT、SSH authentication key、GitHub App／workload
  identity である。
- 本質は、credential を actor・purpose・exact resource・permission・期限に bind し、
  保護された保管、定期 review、event-driven revocation、audit までを一つの lifecycle として
  扱うことである。
- GitHub MCP はこの lifecycle の具体的な開発者利用例である。OAuth を優先し、
  PAT は必要な場合だけ専用・read-only・短寿命にして exact child process へ配送する。

## Supported profile and assumptions

- GitHub.com／GitHub Enterprise Cloud を基準 profile とし、他 provider は具体的な adopter
  要件と証跡 contract がある場合だけ追加する。
- 基準環境は macOS、VS Code、Python 3.10+ とし、Windows は明示要件とテストができてから追加する。
- Verifier は Python 3.10+ standard library だけで動作させる。この control のために
  package manager、framework、Docker を追加しない。
- SSO、PAT／OAuth App policy、SSH inventory、audit、IdP lifecycle は組織側の authority であり、
  local fixture から導入済み状態を推測しない。

## 実装方式を選ぶ前の問い

すべての security control を script、fixture、synthetic evidence、policy JSON、自動判定器へ
変換しない。この package を変更する agent は、実装方式を決める前に次を明示的に判断する。

1. Security 向上は、どの実設定または運用から生まれるか。
2. Repository へ file や script を追加するだけで、その効果が本当に発生するか。
3. 誰が実施するか。少なくとも developer、repository administrator、organization owner、
   platform／SRE、product owner、security、incident response のどの役割かを特定する。
4. 自動テストで確認できる範囲と、実環境でしか確認できない範囲は何か。
5. Synthetic fixture の `PASS` が organization adoption と誤解されないか。
6. Evidence file を追加することで、実際の設定や運用を本当に証明できるか。

この control の security state は、GitHub 側の認証・token・App・SSH・監査設定と、組織の
棚卸し・失効・incident response 運用から生まれる。現在の policy JSON と verifier は安全な
baseline を説明して regression を防ぐ reference implementation であり、主たる enforcement
point ではない。Script を追加しても security state が変わらず、自己申告 JSON を検査するだけに
なる場合は、その script を主実装にしない。

## Guidance-first controlの必須内容

次の性質を持つ部分は、具体的な設定・運用手順を中心とする guidance-first implementation を
正式な実装方式として扱う。

- GitHub 等の SaaS／cloud service 管理画面で行う security setting。
- Organization owner、repository administrator、security、IdP administrator 等にまたがる権限分離。
- Backup、restore、incident response 等の運用。この control では credential containment、
  offboarding、device loss、exposure、access review、revocation が該当する。
- 組織固有の RPO、RTO、retention、承認経路。この control では無関係な RPO／RTO を作らず、
  maximum lifetime、review cadence、revocation objective、audit retention を定める。
- Live organization、IDE、secret store、IdP でなければ効果を確認できない要件。
- Token・SSH key・OAuth grant・App authorization の発行、変更、失効のように、自動化すると
  誤対象や lockout の危険がある管理操作。
- GitHub plan、enterprise policy、SSO 構成、IDE capability により実装方法が変わる要件。

Guidance-first は「曖昧な文書だけ」を意味しない。README または linked runbook は早い位置で
次の三項目を具体化する。

### このcontrolで採用する方式

- 主実装は案1の guidance-first GitHub baseline とする。GitHub／IdP の実設定、役割分担、credential
  inventory、定期 review、失効 runbook、sanitized revocation drill を導入単位として示す。
- 既存 policy JSON、secure／insecure fixture、verifier は baseline の説明と regression 用の補助であり、
  live enforcement や organization adoption の証明に昇格させない。
- 案2の read-only audit は現時点の必須実装にしない。ただし README に「監査を自動化する場合に何が
  できるか」を紹介し、将来の adopter が選択肢と限界を把握できるようにする。
- 紹介対象は、GitHub の read-only API／管理 export／audit log による organization policy、PAT／
  OAuth／App／SSH metadata、owner、repository／permission、expiry／last use、approval／revocation event
  の確認である。API／plan で得られない項目は IdP／SCIM、IDE、secret store 等の別 evidence が必要と示す。
- 将来 collector を作る場合は、read-only、明示 API version、complete pagination、field allow-list、
  freshness、stable target identity、secret-free normalization を必須とし、`PASS`、`FAIL`、
  `NOT_CHECKED`、`ERROR` を分離する。実 credential の変更・失効機能は同じ collector に持たせない。
- Audit 紹介は adoption prerequisite にせず、案1の手動 current-state review と revocation drill だけでも
  導入できる構成に保つ。具体的な collector は adopter 要件と利用可能な provider evidence が揃ってから追加する。

### セキュリティ向上の効果はどこから生まれるか

- 実際に変更する organization SSO／MFA、PAT、OAuth App、SSH key、GitHub App、audit log の
  provider setting を特定する。
- User credential と automation identity の分離、requester と approver、credential owner と
  security reviewer の分離を示す。
- Credential 発行、quarterly review、offboarding／role change／device loss／exposure 時の失効、
  audit review を運用として定める。
- 攻撃や障害に対して、credential の blast radius と有効期間が縮小し、orphaned authority が
  発見・失効され、利用履歴を調査できるようになることを説明する。
- Documentation、policy JSON、sample MCP configuration、verifier を copy するだけでは
  live GitHub access は変化せず、security 効果も発生しないことを明記する。

### 誰が何をするcontrolなのか

少なくとも次の役割分担を、採用対象に合わせて README へ記載する。

- Product owner: 保護対象 repository と業務上必要な access、許容停止時間を決める。
- Organization owner／identity administrator: SSO、phishing-resistant MFA、PAT／OAuth App policy、
  membership lifecycle、audit log を provider／IdP 側で設定する。
- Repository administrator: GitHub App／fine-grained PAT の exact repository と permission を選び、
  developer user token を automation から除去する。
- Platform／SRE: App installation token 等の短命 automation identity と approved secret delivery を
  構築し、credential 値を evidence へ残さない。
- Developer: approved OAuth または hardware-backed SSH を使い、PAT が不可避なら専用・短命・
  protected-store 保管とする。
- Security: active grant、exception、review cadence、audit coverage、revocation drill を独立 review する。
- Incident response: exposure、device loss、offboarding 等で関連 grant、key、token、session を失効し、
  sanitized audit evidence から影響範囲を確認する。

### 最短の導入手順

- Provider 名、管理画面または API の設定項目、推奨値、実施順序、担当者、成功状態を具体的に示す。
- 最初に GitHub 向けの最小推奨構成を示し、「組織に合わせて適切に設定する」だけで終わらせない。
- General baseline は `secure/credential-policy.json`、GitHub MCP 利用時だけ
  `secure/github-mcp-*.json` を copy／参照対象とし、複雑な設定生成器を追加しない。
- Plan や UI 差異がある場合も、安全側の既定値、確認すべき provider property、利用できない場合の
  bounded fallback を先に示し、組織固有の調整は後の adopter-tuning へ分離する。
- 最後に read-only current-state 確認、harmless positive／negative self-test、期待状態、失敗時の
  recovery、rollback、server-side に残る確認を示す。
- Local activation は credential を発行・変更・失効せず、global Git、shell、IDE、OS 設定を
  暗黙に上書きしない。既存設定は adopter が merge review し、rollback は copy／参照した local
  設定だけを外して organization policy を弱めない。

## Implementation rules

- Real secret、valid token／key、個人・実 repository・production data を fixture／log／evidence に
  入れない。Inventory は secret 値でなく、class、sanitized stable ID、owner、purpose、resource、
  permission、lifetime、review／revocation state だけを持つ。
- `.env`、shell profile、IDE JSON literal、Git remote URL に PAT を保存する例を secure
  implementation に追加しない。Environment variable は secret store ではなく配送手段と扱う。
- OAuth を単に「安全」、fine-grained PAT を単に「最小権限」と判定しない。
  Organization approval、SSO、resource owner、repository set、permission、lifetime を別々に確認する。
- Automation に developer OAuth／PAT を使わない。GitHub App installation token または
  task-bound short-lived workload identity を優先する。
- Classic PAT、broad `repo`／`workflow` scope、90 日を超える再利用可能 credential は
  secure default にしない。必要な場合は exact scope、owner、理由、compensating control、
  approval、expiry を持つ `PSB-GOV-002` の exception に接続する。
- Hardware-backed SSH は file theft 対策であり、compromised session 対策や commit signing と混同しない。

## GitHub MCP boundary

- Remote／memory-only OAuth が使える場合は PAT fallback を使わない。OAuth の
  approved application、granted scope、SSO は live external evidence のままとする。
- PAT fallback は MCP 専用 fine-grained PAT、owner は 1 つ、repository は明示選択、
  permission は read-only 最小限、有効期間は 90 日以下、組織 approval 必須とする。
- `${input:github_token}` は秘密値ではなく参照である。IDE が OS keychain 等で保護し、
  exact MCP child にだけ解決することが確認できない間は `NOT_CHECKED` とする。
- `secure/github-mcp-pat-fallback.json` の exact command は組織の配布 contract であり、
  binary integrity の証明ではない。実 artifact の canonical source、digest、semantic review は
  `PSB-AI-002` に接続する。
- Default read-only、exact toolset、unknown-tool deny、write approval は `PSB-AI-004` の runtime
  enforcement でも独立に確認する。credential scope の正しさだけで write 操作を許可しない。

## Relationship to other controls

- `PSB-SOURCE-001`: host／endpoint protection。本 control は source credential の保管と lifecycle だけを持つ。
- `PSB-SOURCE-002`: Git hooks と secret blocking。第二の scanner／hook framework を作らない。
- `PSB-SOURCE-003`: public surface／history exposure。本 control は通常時の発行から失効を持つ。
- `PSB-CICD-006`: CI-to-cloud OIDC claim／audience／replay。federation verifier を複製しない。
- `PSB-AI-002／004`: MCP dependency integrity と runtime authority。本 control は MCP credential の
  選択、保管、配送、期限、失効だけを持つ。
- `PSB-GOV-002／004`: exception contract と incident-wide credential containment／rotation。独自 format
  や横断 rotation engine を作らない。
- Composition は exact control／check ID と canonical command で参照し、他 control の fixture を複製しない。

## Atomic checks and metadata

- `control.yaml` が canonical source である。`check_context_version: "1.0"` と check 固有の
  threat actor、scenario、why required を保持する。
- `SCL-001..012` は provider-wide の credential selection、scope、lifetime、storage、MFA、
  SSH、inventory、revocation、audit、exception である。`SCL-013..017` は GitHub MCP 固有の
  OAuth-first、PAT fallback、child-only delivery、runtime handoff、live-adoption boundary である。
- ID は不要に renumber しない。追加は他 check／control にない atomic state だけとし、変更時は
  target、role、verification、evidence、mapping を同時 review する。Mapping は compliance claim ではない。
- `external-evidence` はこの control の欠陥ではない。実在する provider／IdP／endpoint の
  authority が必要な check を、synthetic policy や自己申告で `PASS` にしない。

## Verificationの扱い

- `scripts/verify.py` と `scripts/verify-github-mcp-auth.py` は single-purpose、決定的、
  standard-library only に保つ。Live GitHub API の変更や secret store へのアクセスを行わない。
- Exit status は `0=accepted`、`1=security finding`、`2=input／parser／evidence error` を保つ。
  Malformed、unreadable、credential-bearing evidence を clean に変換しない。
- Test は人が読んで境界が分かる最小構成にする。基本は secure positive、inert insecure
  negative、malformed error、sensitive-value rejection で十分である。低価値な組合せ網羅を追加しない。
- Policy key や判定を追加する場合は、secure／insecure fixture、expected result、negative test、
  README、`control.yaml` の対応する atomic check を一緒に更新する。
- 実 GitHub／IDE の評価が必要な場合は、fixture verification と read-only live assessment を
  分離する。サポート不能または組織所有の証跡は `NOT_CHECKED`、収集失敗は `ERROR` とする。

意味のある自動検証として認めるのは、次のように security outcome と直接つながるものだけである。

- Import／copy 可能な設定 file の security property を検証する。
- Temporary environment で安全な credential-free lifecycle behavior を検証する。
- Read-only provider API で current setting を完全に収集し、期待状態と照合する。
- Insecure configuration や無効な evidence が実際に拒否されることを確認する。

次は追加しない。

- README に特定文字列があることだけを確認する test。
- 手書き JSON の `secure: true` や自己申告 `PASS` を信頼する verifier。
- Synthetic evidence の `PASS` を organization の安全性として扱う assessment。
- 常に成功する形式的 test、security outcome と無関係な schema validation、必須 interface を
  満たすためだけの no-op script。

Control の本質を自動検証できない場合は、形式的な test を作らず、manual verification または
live environment での確認手順、必要な担当者、入力、成功状態、失敗時の扱いを正式な verification
として記述する。Repository 規約が一律に test script を要求して no-op しか作れない場合は、no-op を
追加せず、manual verification を表現できるよう repository 規約側の見直しを提案する。

## Evidenceの扱い

- Synthetic evidence、secure fixture、policy verifier の成功は、organization adoption または実際の
  security state を証明しない。
- Durable evidence file は、provider API の current setting、実 backup service の job result、実際の
  restore／revocation drill、実環境の grant／revocation／拒否結果、または収集元・取得時刻・対象・
  権限境界が明確な sanitized record のいずれかでなければならない。
- Provider response が credential value、authorization header、SSH public key 本文、個人情報、private
  repository 名を含む場合は、永続化前に allow-list で必要 field だけへ normalize する。
- Currentness、完全な scope／pagination、stable target identity、collector authority を確認できない
  evidence は `PASS` に使わない。Missing、stale、partial、malformed、permission／provider failure は
  `ERROR` または `NOT_CHECKED` とし、clean result にしない。
- 実 evidence を用意できない場合は架空の evidence file を作らず、「採用組織が実環境で確認すべき
  項目」として README または `control.yaml` の external-evidence contract に記述する。

## 最終判断

シンプルになることを恐れない。Control の本質が provider setting と運用である部分は、具体的で
正確な README、copy 可能な runbook、live verification 手順だけの方が、形骸化した script、fixture、
assessment schema より優れた実装である。一方、実際に安全な importable configuration、read-only
check、credential-free negative test を小さく提供できる場合は追加し、documentation-only を安易な
逃げ道にしない。

変更後は、この control を初めて読む adopter が次を一読で判断できなければならない。

- 何を設定するのか。
- 誰が設定・review・失効するのか。
- なぜ credential theft、overprivilege、persistence の risk が下がるのか。
- どの harmless self-test または live check を実際に行うのか。
- 何が自動検証できず `NOT_CHECKED` または external evidence のままか。
- どの current setting、棚卸し、失効・監査結果が揃えば導入完了とするのか。

## Required verification after changes

この package で次を実行する。

```bash
bash tests/test.sh
```

repository root から少なくとも次を実行する。

```bash
make verify-control CONTROL=PSB-SOURCE-004
make validate-controls
```

`control.yaml` の check／mapping／status を変更した場合は、影響する index、mapping、checklist を
canonical Make target で再生成し、`PSB-SOURCE-004` 由来の差分だけを review する。テストを通すために
security requirement を弱めない。
