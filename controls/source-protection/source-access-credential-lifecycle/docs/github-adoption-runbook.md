# PSB-SOURCE-004 GitHub導入runbook

## このrunbookで行うこと

GitHub上のOAuth、PAT、SSH鍵、GitHub Appを、必要な利用者、リポジトリ、権限、期間だけに限定し、
不要になったら確実に失効できる状態にします。

セキュリティ効果はGitHub／IdPの実設定と運用から生まれます。この文書やJSONサンプルをコピーするだけでは、
実際のアクセス権は変わりません。

対象はGitHub.com／GitHub Enterprise Cloudです。GitHub Enterprise Server、GitLab、Bitbucketでは、
同じ目的を各サービスの機能に置き換えてください。

このrunbookを主に使うのは、GitHub組織管理者とセキュリティ担当です。開発者がすべての設定を
変更する必要はありません。組織設定を変更する権限がない場合は、次のチェックリストを組織管理者へ渡し、
自分が担当する認証情報の移行と試験だけを行ってください。

## 導入完了チェックリスト

この一覧を組織内の作業チケットへコピーして使えます。チェックを付ける根拠は、現在の設定、
棚卸し結果、または実際の試験結果です。このrunbookやテスト用JSONの存在を根拠にしてはいけません。

**開始前**

- [ ] GitHub組織管理者、セキュリティ確認者、問題発生時の復旧担当者を決めた。
- [ ] OAuth App、PAT、SSH鍵、GitHub Appと、それらを使う人・bot・CIを棚卸しした。
- [ ] 二要素認証やOAuth制限で停止する可能性がある利用者とAppを確認し、変更時間帯を決めた。
- [ ] 対象organization内に検証用の非公開リポジトリを2つ作り、専用の検証用認証情報を用意した。

**GitHub／IdPの設定**

- [ ] Organization `Settings` → `Authentication security`で二要素認証を必須にした。
- [ ] SMSだけに依存せず、機微なアクセスにはIdP／Enterprise側でパスキーまたはセキュリティキーを要求した。
- [ ] `Personal access tokens` → `Tokens (classic)`でclassic PATの組織アクセスを制限した。
- [ ] `Fine-grained tokens`で管理者承認、対象リポジトリ、最小権限、90日以下の期限を確認した。
- [ ] `Third-party Access` → `OAuth app policy`で、必要なOAuth Appだけを許可した。
- [ ] `Third-party Access` → `GitHub Apps`で、各Appを選択したリポジトリと最小権限に限定した。

**認証情報の移行と保管**

- [ ] CI、bot、release処理から開発者個人のOAuth／PATを除き、専用GitHub Appなどへ移行した。
- [ ] PATとOAuth tokenをOSのキーチェーンまたは承認済みシークレット管理サービスへ保管した。
- [ ] `.env`、shell profile、IDEのJSON、Gitのremote URLに認証情報の値が残っていない。
- [ ] GitHub MCPを使う場合、OAuthを優先し、PATは専用・読み取り専用・90日以下にした。

**実際に試す**

- [ ] 許可した`allowed-test`の読み取りが成功し、監査イベントと対応付けられた。
- [ ] 付与していない権限を必要とする操作が拒否された。
- [ ] 対象外の`unselected-test`へのアクセスが拒否された。
- [ ] 検証用認証情報を失効し、直前まで成功していた操作が拒否された。

**継続運用**

- [ ] 90日以内ごとに、所有者、用途、対象、権限、最終利用、有効期限を確認する担当と日程を決めた。
- [ ] 退職、異動、端末紛失、漏えい、所有者不在を契機に失効する手順を決めた。
- [ ] 現在の設定、棚卸し、監査イベント、失効試験を組織内の証跡管理先へ保存した。
- [ ] 確認できない項目を`PASS`にせず、`NOT_CHECKED`または`ERROR`として残した。

すべての必須項目に実環境の証跡があり、対象外の項目を確認者が`N/A`と判断できれば導入完了です。

## 「検証環境」とは

ここでいう検証環境は、別のGitHub Enterpriseや大掛かりなsandboxではありません。原則として、
**対象organization内の検証用非公開リポジトリ2つと、専用の検証用認証情報**を指します。

| 構成 | 用途 |
|---|---|
| `allowed-test` | 検証用認証情報に読み取りを許可する。READMEだけの初期commitを置く |
| `unselected-test` | 同じorganizationに置くが、検証用認証情報の対象から外す |
| 検証用認証情報 | 確認する認証方式専用のGitHub App、fine-grained PAT、OAuth grant、SSH鍵など |
| 別の管理者 | 想定外の書き込みが起きた場合の削除と、試験後の認証情報失効を行う |

2個のrepositoryには、本番ソース、Actions workflow、secret、deployment key、webhook、releaseを置きません。
検証用認証情報も本番処理には使用しません。別のsandbox organizationで事前に手順を練習しても構いませんが、
それは対象organizationの設定を証明するものではありません。

検証用repositoryで安全に確認できる範囲と、確認できない範囲は次のとおりです。

| 確認対象 | 検証用repositoryで確認できるか | 確認方法 |
|---|---|---|
| 対象リポジトリの限定 | できる | `allowed-test`は成功し、`unselected-test`は拒否されることを試す |
| GitHub権限の限定 | できる | 付与していない権限を必要とする無害な操作が拒否されることを試す |
| 認証情報の失効 | できる | 失効前に成功した操作が、失効後に拒否されることを試す |
| 二要素認証、OAuth App制限、PAT方針 | できない | 対象organizationの実設定と影響対象を管理画面で確認する |
| IdP、端末のキーチェーン、ハードウェア鍵 | できない | IdPと`PSB-SOURCE-001`の端末証跡で確認する |

つまり、検証用repositoryは組織設定変更の影響を隔離する仕組みではありません。二要素認証、OAuth App制限、
PAT方針は対象organization全体へ効くため、事前の影響確認、利用者への通知、変更時間帯、復旧担当者が必要です。

## 1. 変更前に準備する

### 担当者

| 担当 | 主な作業 |
|---|---|
| プロダクト責任者 | 対象リポジトリと必要なアクセスを決める |
| GitHub組織管理者 | 組織設定を変更する |
| IdP管理者 | SSO、強固な認証、メンバー削除を設定する |
| リポジトリ管理者／Platform／SRE | AppとPATの対象・権限を限定し、自動処理を移行する |
| セキュリティ担当 | 変更内容、棚卸し、例外、試験結果を確認する |
| インシデント対応担当 | 漏えい時の失効と影響調査を行う |

GitHub組織管理者だけで変更と承認を完結させず、セキュリティ担当など別の確認者を置きます。

### 現在の認証情報を棚卸しする

組織の承認済み管理台帳へ、次を記録します。このリポジトリには、実在する組織名、利用者名、
private repository名、認証情報の値をcommitしません。

| 記録する項目 | 内容 |
|---|---|
| 所有者 | 人、service account、GitHub Appなど |
| 用途 | CLI、bot、release、MCPなど |
| 認証方式 | OAuth、classic PAT、fine-grained PAT、SSH鍵、deploy key、GitHub App |
| 対象 | 組織、明示したリポジトリ |
| 権限 | read／write、organization permission、PAT permissionなど |
| 期限・利用状況 | 有効期限、最終利用、最終確認日 |
| 対応責任者 | 移行、更新、失効を行う人 |

トークン、Authorization header、秘密鍵、recovery codeは台帳へ保存しません。

### 影響を確認する

設定変更前に、次を確認します。

- 二要素認証の要件を満たさないメンバー、外部コラボレーター、bot。
- 現在利用中のOAuth App、GitHub App、classic／fine-grained PAT、SSH鍵、deploy key。
- 各認証情報を使うCI、bot、CLI、package／release処理。
- 承認済みの復旧手段を持つGitHub組織管理者が少なくとも2名いること。
- 利用者への通知、変更時間帯、問題発生時の責任者。

二要素認証やOAuth App制限を初めて有効にすると、利用者、App、一部のSSHアクセスが停止する場合があります。
停止後にすべてを無条件で再許可せず、棚卸し済みの必要な対象だけを戻します。

### 検証用repositoryと認証情報を用意する

- 本番ソースを含まないprivate test repositoryを2つ作る。
  - `allowed-test`: 読み取りを許可する。
  - `unselected-test`: 認証情報の対象から外す。
- 一つの認証方式だけに使う検証用ID／認証情報を用意する。
- 検証用認証情報とリポジトリを削除できる、試験実施者とは別の管理者を決める。

## 2. GitHub／IdPを設定する

GitHubの画面名は英語表示を基準にしています。契約プランやUIによって項目が表示されない場合は、
確認済みとして扱わず`NOT_CHECKED`にします。

| 対象 | GitHub上の場所 | 推奨設定 | 担当 | 成功状態 |
|---|---|---|---|---|
| 二要素認証 | Organization `Settings` → `Authentication security` | `Require two-factor authentication for everyone in your organization`を有効化 | 組織管理者／IdP管理者 | 全メンバーと外部コラボレーターに二要素認証が必要 |
| 安全な二要素認証 | 同上 | 利用できる場合は`Only allow secure two-factor methods`も有効化 | 組織管理者／IdP管理者 | SMSだけではアクセスできない |
| Classic PAT | `Settings` → `Personal access tokens` → `Settings` → `Tokens (classic)` | Organization resourceへのアクセスを`Restrict access` | 組織管理者 | Classic PATが組織のリソースへ到達しない |
| Fine-grained PAT | 同上 → `Fine-grained tokens` | 管理者承認を必須化。対象リポジトリと権限を限定。有効期限は90日以下 | 組織管理者 | 所有者、用途、対象、最小権限、期限が確認済み |
| OAuth App | `Settings` → `Third-party Access` → `OAuth app policy` | `Restrict third-party application access`を有効化し、必要なAppだけを承認 | 組織管理者 | 所有者・用途・必要scopeが不明なAppは未承認 |
| GitHub Appの申請 | `Settings` → `Member privileges` → `GitHub Apps` | インストールを組織管理者の確認経路へ集約 | 組織管理者 | メンバーが無審査でAppを追加できない |
| インストール済みGitHub App | `Settings` → `Third-party Access` → `GitHub Apps` | `Only select repositories`相当と必要最小限のpermission | 組織管理者／リポジトリ管理者 | `All repositories`や不要な組織権限がない |
| SSO／メンバー管理 | Enterprise／IdPの管理画面 | SAML SSO、強固な認証、SCIMなどの退職・異動連携 | IdP管理者 | 無効化した利用者のGitHubアクセスも停止する |

### 設定時の注意

- GitHubの`Only allow secure two-factor methods`はSMSを除外しますが、これだけでフィッシング耐性を
  証明できるわけではありません。機微なアクセスにはIdP／Enterprise側でパスキーやセキュリティキーを要求します。
- Fine-grained PATを使わない運用が可能なら、利用自体を制限します。必要な場合だけ、申請を一件ずつ確認します。
- GitHub組織管理者が自分で作成したfine-grained PATも、別の確認者が台帳上で確認します。
- 有効期限方針による利用停止は失効ではありません。不要な旧トークンは明示的にrevokeします。
- Owner不在または未使用のGitHub Appは、影響を確認してsuspend／uninstallします。

## 3. 自動処理から個人トークンを除く

自動処理には、開発者個人のOAuthやPATではなく、専用GitHub Appなどの短期IDを使います。

1. 個人トークンを使っている処理を一つ選ぶ。
2. 専用GitHub Appまたは同等の短期workload identityを用意する。
3. Appの対象を必要なリポジトリだけにし、権限を必要な操作だけに限定する。
4. Job開始時にinstallation tokenを取得し、終了後は再利用しない。
5. 承認済みのsecret deliveryから、対象プロセスだけへトークンを渡す。
6. `allowed-test`で必要な操作を確認してから処理を切り替える。
7. 旧個人トークンをGitHub側で失効し、再利用が拒否されることを確認する。

Installation tokenが短期でも、GitHub App自体が全リポジトリへ広い権限を持っていれば影響範囲は大きいままです。
トークンの寿命とAppの権限を別々に確認します。

## 4. 開発者の認証情報を保護する

端末側の詳細は`PSB-SOURCE-001`が担当します。このrunbookでは、GitHub上の認証情報と端末側の保護が
接続されていることだけを確認します。

- Git／CLIでは、組織が承認したOAuthまたはハードウェア保護されたSSH鍵を優先する。
- PATが不可避なら、fine-grained、用途専用、対象リポジトリ明示、最小権限、90日以下とする。
- OAuth／PATはOSのキーチェーンまたは承認済みシークレット管理サービスへ保存する。
- `.env`、shell profile、IDEのJSON、Gitのremote URL、shell historyへ認証情報の値を置かない。
- SSH認証鍵は可能ならexport不能で、利用者確認を伴うハードウェア保護鍵にする。
- SSH認証とcommit署名を台帳上で区別する。

端末上の保管やハードウェア保護はGitHub APIだけでは証明できません。`PSB-SOURCE-001`の端末確認と
組み合わせ、証跡がなければ`NOT_CHECKED`にします。

### GitHub MCPを使う場合

MCPを使わない場合は、確認者が`N/A`と判断します。

1. [`../secure/github-mcp-oauth.json`](../secure/github-mcp-oauth.json)のremote OAuthを優先する。
2. PATが不可避な場合だけ、[`../secure/github-mcp-auth-policy.json`](../secure/github-mcp-auth-policy.json)の
   限定的な代替構成を使う。
3. PATはMCP専用、fine-grained、対象リポジトリ明示、読み取り専用、90日以下にする。
4. IDE設定には`${input:github_token}`など、保護された値への参照だけを置く。
5. 認証情報は対象のMCP子プロセスだけへ渡し、IDEやshell全体へexportしない。
6. MCP binaryの正当性は`PSB-AI-002`、ツールの許可・書き込み承認は`PSB-AI-004`で確認する。

`password: true`は表示を隠すだけの可能性があります。OSのキーチェーンへの保管と、子プロセスだけへの
受け渡しを実端末で確認できない限り、`SCL-015`は`NOT_CHECKED`です。

## 5. 許可・拒否・失効を試す

認証情報の値を、コマンド履歴、ログ、試験記録へ残してはいけません。試験記録には、control／check ID、
認証方式、サニタイズした対象ID、実施日時、操作の種類、結果、確認者だけを記録します。

| 順序 | 試験 | 操作 | 期待結果 |
|---:|---|---|---|
| 1 | 許可確認 | `allowed-test`を読み取る | 成功し、監査イベントと対応付けられる |
| 2 | 権限の拒否確認 | 明示的に付与していない権限を必要とする無害な操作を行う | `403`などで拒否され、変更がない |
| 3 | 対象範囲の拒否確認 | `unselected-test`を読み取る | `403`または`404`で拒否される |
| 4 | 失効確認 | 検証用認証情報を失効し、`allowed-test`を再度読み取る | `401`、`403`、`404`のいずれかで拒否される |

読み取り専用の構成では、`allowed-test`へ一意なtest refを作成する操作を、権限の拒否確認に使えます。
`POST /repos/{owner}/{allowed-test}/git/refs`へ、その時だけ使う`refs/heads/psb-source-004-denial-<date>`を
指定します。期待結果は`403`または`404`です。`201`なら`FAIL`とし、別の管理者が変更を削除して権限を是正します。

Timeout、rate limit、認証エラー、解析失敗は拒否成功ではなく`ERROR`です。

### 結果の記録

- `PASS`: 現在の設定または試験結果で要求状態を確認できた。
- `FAIL`: 過剰権限、想定外の成功、失効漏れなどを確認した。
- `NOT_CHECKED`: プラン、権限、端末、証跡が不足し確認できない。
- `ERROR`: 収集、認証、API、解析、鮮度確認に失敗した。
- 確認済みの`N/A`: 対象の認証方式やMCPを使用していない。

## 6. 棚卸しと失効を継続する

### 90日以内ごとの棚卸し

すべての認証情報について、次を確認します。

- 所有者が在籍し、現在の役割と一致している。
- 用途と利用処理が現在も存在する。
- 対象リポジトリと権限が現在の作業に必要である。
- 最終利用を説明でき、未使用の認証情報を失効候補にしている。
- 有効期限が方針内である。
- OAuth、App、SSOの承認が現在も有効である。
- 例外に所有者、承認、期限、是正責任者がある。

一覧が一部しか取得できない、ページネーションが不完全、古い、読み取れない場合は、棚卸しを完了扱いにしません。

### 直ちに失効する条件

- 退職、異動、team／repository ownershipの変更。
- 端末紛失、端末侵害、認証情報の漏えいまたはその疑い。
- 所有者不在、用途消滅、長期未使用。
- 過剰権限、期限違反、無効な例外の発見。

### 失効の順序

1. 対象ID、所有者、利用処理、対象リポジトリを特定する。
2. GitHub側でOAuth grant、PAT、SSH鍵、App credential／installationをrevoke／suspendする。
3. 関連セッションと下流の認証情報を無効化する。
4. 必要な処理を新しい限定的なIDへ移す。
5. 旧認証情報で以前の許可操作が拒否されることを確認する。
6. 監査記録から利用状況と影響を受けたリポジトリを確認する。
7. 漏えい元を除去し、必要に応じて`PSB-SOURCE-003`と`PSB-GOV-004`へ引き継ぐ。

ファイル削除、Git履歴の書き換え、代替トークンの発行、自然な期限切れだけでは失効完了になりません。

## 7. 導入完了の証跡

組織のprivate evidence systemで、次を確認できれば導入完了です。

- 現在の二要素認証、SSO、フィッシング耐性のある認証方針。
- Classic／fine-grained PATの方針と、有効なPATの棚卸し結果。
- 承認済みOAuth Appとインストール済みGitHub Appの確認結果。
- 認証情報・利用処理一覧と、90日以内の確認日。
- 端末上の保管状態とSSH鍵登録の確認結果。
- 監査対象、保持期間、代表的なライフサイクルイベント。
- 失効試験と旧認証情報の拒否結果。
- 有効な例外と期限、または例外がないことの確認。

方針文書やテスト用サンプルの出力を、現在のGitHub設定の代わりにしてはいけません。

## 8. 失敗時の復旧とロールバック

| 問題 | 対応 |
|---|---|
| 二要素認証変更で外部コラボレーターが除外された | 要件を満たす二要素認証の設定後、所有者が確認して再招待する |
| PAT方針で処理が停止した | 限定的なfine-grained PATまたはGitHub Appへ移し、旧トークンを失効する |
| OAuth制限で承認済みAppが停止した | 棚卸しと所有者を確認し、必要なAppだけを再認証する |
| Appの権限が不足した | 不足している操作だけを確認して追加する |
| Audit APIを利用できない | 管理画面または承認済みexportで確認し、API確認は`NOT_CHECKED`にする |
| 証跡を収集できない | `ERROR`として再収集し、安全と判定しない |
| 想定外の書き込みが成功した | `FAIL`とし、別の管理者が変更を除去して権限を是正し、再試験する |

組織設定をscriptで一括して元へ戻してはいけません。変更前の状態、影響対象、戻す理由を別の確認者と確認し、
設定単位で戻します。Classic PAT、無制限OAuth、全リポジトリ対象Appを黙って再許可しません。

継続運用のため一時的な経路が必要なら、利用者、リポジトリ、権限、期限を限定し、
`PSB-GOV-002`の例外として記録します。

## 参考資料

- [GitHubのpersonal access token方針](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
- [Fine-grained PAT申請の管理](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/managing-requests-for-personal-access-tokens-in-your-organization)
- [OAuth Appのアクセス制限](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [GitHub Appの申請・インストール制限](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [インストール済みGitHub Appの確認](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-github-apps-installed-in-your-organization)
- [GitHub組織での二要素認証要件](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub REST API: Git references](https://docs.github.com/en/rest/git/refs)
