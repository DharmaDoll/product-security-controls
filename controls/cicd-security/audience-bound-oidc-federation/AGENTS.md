# PSB-CICD-006 implementation instructions

この file は `PSB-CICD-006`（`cicd-security`）固有の実装境界を定める。変更前に
[repository root の AGENTS.md](../../../AGENTS.md)、
[controls の AGENTS.md](../../AGENTS.md)、
[PROJECT_CHARTER](../../../docs/PROJECT_CHARTER.md)、
[ARCHITECTURE](../../../docs/ARCHITECTURE.md)、
[CONTROL_MODEL](../../../docs/CONTROL_MODEL.md)、
[REPOSITORY_STRUCTURE](../../../docs/REPOSITORY_STRUCTURE.md)、
[THREAT_MODEL](../../../docs/THREAT_MODEL.md)、
[ROADMAP](../../../docs/ROADMAP.md)、関連 ADR、この package の
[README.md](README.md) と [control.yaml](control.yaml) を読むこと。

## Control essence

- 対象は、GitHub Actions の workload identity を cloud provider が一つの限定された
  deploy authority へ交換する境界である。
- Security 効果は、採用先の cloud trust policy が GitHub issuer、用途固有の audience、
  exact subject を照合し、交換後の role を短命かつ対象 action／resource 限定にすることから生まれる。
- GitHub repository に長期 cloud credential を残さない。OIDC を追加しただけで旧 access key を
  残す移行は完了ではない。
- JWT の署名、issuer key rotation、token validity は provider の federation service に検証させる。
  Repository-owned script で provider の代わりとなる token service を実装しない。
- 最小 profile では、protected Environment を参照する一つの trusted deploy job と、それ専用の
  cloud role だけを扱う。全 claim、全 workflow、全 provider を一度に抽象化しない。
- Security 効果は live GitHub setting、live cloud trust／authorization、実 workflow から生まれる。
  README、policy JSON、fixture、synthetic JWT、`PASS` 出力を copy しただけでは導入済みにならない。

本 control は OIDC 全般の解説ではない。核心は「正規に署名された別 workload の token でも受理しない
exact trust」と「受理後に必要最小限の一時 authority しか渡さないこと」である。

## Implementation hypotheses and decision

実装前に少なくとも次の仮説を比較し、反証を探す。

1. **Repository-local evaluator を主実装にできる**という仮説。
   Synthetic JWT、自己記述 policy、replay JSON、receipt JSON の整合性は regression test にはなるが、
   live provider が同じ trust condition を使うこと、旧 secret がないこと、role が狭いことを証明しない。
   この仮説は主実装としては棄却する。
2. **文書だけで十分**という仮説。
   Provider setting が主境界でも、review 可能な workflow と、provider が import／適用できる最小 trust
   configuration は copy 可能である。選択済み provider で具体設定を提供できる限り、この仮説も棄却する。
3. **Guidance-first を主とする小さな hybrid**という仮説。
   実 provider setting と運用手順を主実装にし、copy 可能な workflow／provider policy を一つずつ示し、
   自動検証は実際に適用される configuration の security property に限定する。この方式を採用する。

新しい事実がこの判断を反証する場合は、実装方式を惰性で維持しない。例えば read-only provider API で
完全な current trust policy を安全に取得できるなら、その live check は有用である。一方、入力 JSON の
`secure: true` や自己申告 status しか読めない check は追加しない。

## Supported assumptions

最小 reference profile は次へ限定する。

- GitHub.com または GitHub Enterprise Cloud の Actions
- GitHub-hosted Ubuntu runner と macOS／Linux の開発環境
- review 済み default branch と一つの protected deployment Environment
- credential-free な build／test と、分離された一つの deploy job
- AWS standard partition、`sts.amazonaws.com` audience、一つの AWS account と専用 IAM role
- AWS IAM／CloudTrail と GitHub Environment を変更・確認できる各管理者

Direct workflow を baseline とする。Reusable workflow は利用する採用先だけの追加 profile であり、
`job_workflow_ref`／`job_workflow_sha` を最小 profile の必須条件にしない。GitHub Enterprise Server、
self-hosted runner、Windows、AWS China／GovCloud、複数 cloud、cross-account role chain、package registry trusted publishing は
別 profile とし、同じ設定が安全に移植できると推測しない。

Reference provider は AWS とし、direct workflow から一つの IAM role を 900 秒で引き受ける profile だけを
copyable baseline にする。Azure、Google Cloud 等は audience、condition、role binding、最小 TTL、audit の
表現が異なるため、README の紹介を超える実装は別 task で公式仕様と live environment を確認する。

## 実装前に確認する control 固有入力

Provider 固有の file または手順を作る前に、次を確認する。

1. 対象 AWS partition、account ID、region、GitHub契約 plan は何か。
2. Exchange 後に引き受ける exact role と、必要な action／resource は何か。
3. GitHub organization、repository name、owner ID、repository ID は何か。
4. 許可する exact branch または tag と protected Environment は何か。
5. Repository は実際にどの `sub` format を発行するか。Immutable subject を使用しているか。
6. Provider が照合できる claim は何か。`iss`、`aud`、`sub` 以外を使えると推測していないか。
7. Direct workflow か reusable workflow か。後者なら caller と called workflow の exact identity は何か。
8. Provider が発行できる最短 credential TTL と、実 deploy に必要な時間は何か。
9. 現在の repository／Environment secret inventory に長期 cloud credential が残っていないか。
10. GitHub setting、cloud trust、role policy、audit、positive／negative test を誰が live で確認するか。

これらがない場合、架空の provider、role、repository ID、画面、CLI 出力、credential receipt を作らない。
Provider-neutral な設計境界だけを維持し、provider 固有実装と organization adoption は `NOT_CHECKED` とする。
情報不足を埋めるために `.invalid` host や存在しない login command を「copy 可能な secure 実装」として残さない。

## 誰が何をする control なのか

- Development team: deploy に必要な operation と時間を列挙し、build／test と token exchange を分離し、
  copy した workflow を実 repository に合わせる。
- Repository administrator: exact repository identity、trusted ref、protected Environment、workflow inventory、
  secret inventory、required review／check を設定・確認する。
- Cloud／platform administrator: OIDC provider、exact audience／subject trust、専用 role、resource policy、TTL、
  provider audit を設定する。
- Organization owner／CI platform: immutable subject policy、approved reusable workflow、organization-level
  Actions setting を所有する。
- Security: GitHub と cloud の両側を突合し、wildcard、legacy key、権限、negative test、例外、live evidence を
  独立 review する。

同じ workflow や変更者だけに、trust policy 変更、role 付与、test evidence 生成、最終承認を完結させない。
Provider setting の変更管理と緊急 bypass は `PSB-CICD-008` と組み合わせる。

## Guidance-first implementation contract

README の mandatory one-page summary の直後、またはそれに続く早い位置に次を置く。

### セキュリティ向上の効果はどこから生まれるか

次を具体的に説明する。

- GitHub job に `id-token: write` を付けるだけではなく、cloud 側の trust policy を変更すること。
- Exact audience と subject が、別 repository、別 environment、別用途の正規 token を拒否すること。
- 専用 role の action／resource／TTL が、approved deploy job を侵害された場合の影響を限定すること。
- 旧 cloud key を削除することで、OIDC trust を迂回する長期 authority をなくすこと。
- Documentation、fixture、local evaluator の copy だけでは、上記の効果が発生しないこと。

### 誰が何をする control なのか

上記 roles を provider profile の実担当名へ落とし込む。単に「管理者が適切に設定する」で終わらせない。

### 最短の導入手順

一つの provider profile について、provider 名、console／IaC resource、設定 field、exact 値の組み立て方、
実行順序、成功状態を示す。最小順序は次である。

1. 実 token の claim shape と repository の immutable subject 状態を read-only に確認する。
2. 専用 cloud role を作り、deploy に必要な exact action／resource だけを許可する。
3. GitHub issuer を登録し、provider 推奨 audience と実 repository／Environment の exact subject を設定する。
4. GitHub Environment の trusted branch／review protection を有効にする。
5. Workflow top-level を deny-all にし、deploy job だけへ `contents: read` と `id-token: write` を与える。
6. Trusted ref から harmless な caller-identity または dry-run operationを実行し、期待 role と TTL を確認する。
7. 許可していない branch／repository／audience 相当の harmless negative test が exchange を拒否されることを確認する。
8. OIDC path の成功後に旧 cloud key の consumer を確認して削除し、OIDC path をもう一度確認する。
9. Provider audit で exact repository／run／role／decision を確認する。

Migration の順序は cloud trust を先に追加し、GitHub subject customization を後に切り替える。Cloud 側が新しい
subject を受理する前に token format を変更して deploy を停止させない。Rollback は旧 long-lived key の恒久復活を
既定にせず、OIDC trust change の復元、workflow revision の復元、time-bound emergency path を明示する。

## Copyable implementation rules

- `secure/` の workflow は実在する provider CLI または full commit SHA へ pin した provider Action を使う。
  Placeholder login command を runnable implementation と呼ばない。
- Provider policy は provider が import／apply できる形式を優先する。Repository 独自の中間 JSON は、同じ JSON が
  live setting を生成または取得する明確な adapter を持たない限り主実装にしない。
- 最初の slice は一つの provider、一つの repository、一つの Environment、一つの role、一つの resource family に
  保つ。Organization wildcard や repository wildcard を便利な初期値にしない。
- Environment を subject に使う場合、branch は subject に同時に現れると仮定せず、GitHub Environment の deployment
  branch rule で強制する。
- Stable owner／repository identity を利用できる profile では immutable subject を優先する。利用できない provider／
  GitHub product では、名前再利用の残余リスクと代替の provider condition／governance を明記する。
- Reusable workflow を使う profile では、called workflow を full commit SHA へ pin し、provider が実際に条件化できる
  identity だけを trust policy に使う。
- `insecure/` は exact trust と wildcard trust の差が一読で分かる最小例にし、deployable default にしない。
- Provider-valid token、secret、account data、private payload を fixture、log、expected output に保存しない。

## Verification boundary

本 control の主 verification は live GitHub／cloud setting と harmless exchange test である。結果は `PASS`、
`FAIL`、`NOT_CHECKED`、`ERROR` を区別する。

Meaningful な自動検証は次に限定する。

- 実際に import／apply する provider trust policy から wildcard、wrong audience、wrong subject を検出する。
- Copy 対象 workflow で `id-token: write` が exact deploy job だけにあり、static cloud key を参照しないことを検出する。
- Temporary test environment で trusted case が expected role を取得し、unauthorized case が provider に拒否されることを
  安全に確認する。
- Read-only provider API が返した current setting を、対象、取得時刻、完全性と共に確認する。

次は verification にしない。

- README の文字列 test、no-op test、schema だけの test。
- Self-authored policy、JWT、secret inventory、replay state、credential receipt の相互整合だけによる adoption 判定。
- Static JSON の `status: complete`、`secure: true`、`issued` を authority とする判定。
- Provider が保証しない `jti` single-use ledger を fixture で再現し、live replay protection と主張すること。
- Synthetic `PASS` を organization の GitHub／cloud state と扱うこと。

削除した synthetic verifier、JWT、replay state、credential receipt を再導入しない。将来 regression fixtureが必要に
なっても、実 AWS configuration または安全な live check を直接検証できないかを先に検討する。Canonical runner を
満たすためだけの代替 no-op test は追加しない。

Control の本質を live でしか確認できない profile は `manual`、一部の importable configuration を自動検証し live setting も
必要なら `hybrid` とする。Manual control の `make verify-control` が `NOT_CHECKED` と exit `2` を返すのは正しい。
Scanner／API／permission／pagination／input failure を `PASS` に丸めない。

## Live verification and evidence

導入完了には少なくとも次を一つの review record で結び付ける。

- exact repository／revision／workflow／Environment
- current cloud OIDC provider と trust policy
- current role policy と credential TTL
- current sanitized repository／Environment secret-name inventory
- trusted positive exchange と unauthorized negative exchange の provider decision
- provider audit event、取得元、取得時刻、reviewer
- old cloud key の削除と既知 consumer の移行結果

Evidence は provider UI の current setting、approved read-only API output、actual harmless run、provider audit のいずれかとする。
架空 receipt や fixture は live evidence ではない。Token、temporary credential、secret value、private provider response は保存しない。
Evidence を取得できない項目は `NOT_CHECKED`、取得失敗や不完全 inventory は `ERROR` とし、導入完了にしない。

## Atomic checks

[`control.yaml`](control.yaml) が canonical metadata である。生成済み参照を守るため、既存 ID を不要に renumber しない。

- `OIDC-001`: JWT authenticity は live provider federation が issuer discovery／JWKS で検証する。Local fixture は provider
  adoption の証拠にしない。
- `OIDC-002`: Exact `iss`／`aud`／`sub` と利用可能な immutable repository identity を所有する本 control の中心 check。
- `OIDC-003`: Trusted deploy context を確認する。Reusable workflow identity は実際に利用する profile だけへ適用する。
- `OIDC-004`: Token freshness と短寿命を確認する。Provider が single-use を保証しない場合、replay ledger を捏造せず残余リスクにする。
- `OIDC-005`: Exchange job だけの token issuance を確認するが、一般的な workflow permission は `PSB-CICD-004` と合成する。
- `OIDC-006`: Static cloud credential 不在は live secret-name inventory と workflow で確認する。
- `OIDC-007`: Exchange 後の dedicated role、exact action／resource、最短実用 TTL を確認する。
- `OIDC-008`: Missing／stale／partial／failed verification と、予期せず拒否された trusted exchange を clean にしない。

Check の scope または証拠能力を変更するときは、required state、check 固有の threat actor／scenario／why required、
`applies_to`、verification、mapping、README claim を同時に reviewする。Provider が実装しない property を automated check と
して残さない。

## Relationship to other controls

- [`PSB-CICD-001`](../action-sha-pinning/README.md): third-party Action と reusable workflow の immutable SHA pinning。
- [`PSB-CICD-003`](../actions-static-analysis/README.md): workflow 全体の pinned static scanner と error semantics。
- [`PSB-CICD-004`](../actions-least-privilege/README.md): `GITHUB_TOKEN` permission と `id-token: write` の job-level isolation。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): fork／untrusted PR と privileged job の分離。
- [`PSB-CICD-007`](../runner-hardening/README.md): runner image、network、credential exposure、lifecycle、teardown。
- [`PSB-CICD-008`](../privileged-control-plane-change/README.md): cloud trust／role 等の privileged setting 変更の approval と audit。
- [`PSB-BUILD-001`](../../build-security/build-containment/README.md): approved job 内の sandbox、egress、runtime credential containment。
- [`PSB-SOURCE-004`](../../source-protection/source-access-credential-lifecycle/README.md): source-platform credential lifecycle。Cloud deploy key の
  OIDC migration は本 control が扱う。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): exception の owner、approval、scope、expiry。

本 control に general workflow permission scanner、fork policy、runner hardening、provider change approval system を複製しない。
これらは前提または合成 control として exact check を参照する。

## Required counterexample review

実装または security claim の変更ごとに、少なくとも三つの成立仮説と反証を記録する。最低限、次を検討する。

- 別 repository／branch／Environment の正規 GitHub token が trust policy に一致しないか。
- Approved deploy job 内の code が侵害された場合、role と TTL が被害を本当に限定するか。
- GitHub の expected subject と cloud の current subject condition が drift していないか。
- OIDC 成功後も legacy cloud key が別 secret store／consumer に残っていないか。
- Provider が利用できない claim を policy JSON だけで検査し、強制済みと誤認していないか。
- Negative test の拒否が trust policy ではなく、無関係な syntax／network／permission error によるものではないか。

最初に疑った原因だけを説明しない。各 attack path について、attacker-controlled input、実 authority、到達可能な action／resource、
成立しない条件を示す。確認できない項目は安心材料に置き換えず、明示的な limitation とする。

## Required verification after changes

Repository root から、変更内容に応じて少なくとも次を実行する。

```bash
make verify-control CONTROL=PSB-CICD-006
make validate-controls
python3 -m unittest tests.test_control_metadata tests.test_run_controls
```

最初の command は live evidence を自動取得しないため `NOT_CHECKED` と exit `2` を期待する。Generated index、mapping、
checklist は user が明示的に求めた場合だけ commit 対象にする。Test を通すために exact audience／subject、least privilege、
static key removal、fail-closed behavior を弱めない。

## Working scope

- This directory is the primary scope of the current task.
- Limit changes to this directory unless the task explicitly requires otherwise.
- Before modifying files outside this directory, explain why they are required.
- Follow the testing, architecture, and security requirements documented here.
