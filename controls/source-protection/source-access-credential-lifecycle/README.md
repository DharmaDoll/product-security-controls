# PSB-SOURCE-004: ソースアクセス認証情報のライフサイクル管理

## このcontrolを一枚で理解する

### セキュリティ上の問題

GitHubのOAuthトークン、PAT、SSH鍵、GitHub Appの認証情報が長期間有効なまま、過剰な権限を持ち、適切に保管・棚卸しされていないと、一つの認証情報の窃取がソースコードの改ざんや組織全体の侵害へ発展する。

### 誰から、または何から守るか

フィッシング、情報窃取型マルウェア、悪意のあるツール、端末への不正アクセス、漏えいした認証情報の再利用、管理者不在、更新・失効漏れから守る。

### 何が対象か

開発者と自動処理がソース管理基盤へアクセスするためのOAuth、PAT、SSH鍵、GitHub Appを対象とする。GitHub MCPへ認証情報を渡す経路、アクセス範囲、対象リポジトリ、保管方法、有効期限、利用記録、インシデント時の失効も含む。

### 何をするか

GitHubとIdPの認証、PAT、OAuth App、GitHub Appの設定を安全側へ変更し、自動処理には開発者個人の認証情報ではなく短期の専用IDを使う。各認証情報を所有者、目的、対象リポジトリ、権限、保管場所、有効期限にひも付け、定期的な棚卸し、失効、監査を行う。

### 成功状態

現在のGitHub／IdP設定と認証情報一覧が基準を満たし、検証専用環境で、許可された操作の成功、未付与権限による操作の拒否、対象外リポジトリへのアクセス拒否、失効後の再利用拒否を確認できる。確認できていない項目は`NOT_CHECKED`のまま残す。

### 対象外・残余リスク

テスト用サンプルの検証だけでは、実際の設定や組織への導入を証明できない。IdP、開発者端末、GitHubの管理基盤自体が侵害された場合や、すでに取得されたclone・ソースコードの回収は対象外である。

## このコントロールの本質

本質は、**ソース管理基盤に現在どの認証情報が存在し、誰が、何のために、どのリポジトリへ、
どの権限で、いつまでアクセスできるかを把握し、不要になった権限を確実に失効できる状態を維持すること**です。
端末を安全にすること自体ではなく、GitHub上の認可を発行から棚卸し・失効・監査まで管理することが、
このコントロール固有の役割です。

## 導入

### セキュリティ向上は何によって実現するか

このコントロールの効果は、リポジトリ内のJSONをコピーすることではなく、次の実設定と運用から生まれます。

- GitHubとIdPで二要素認証、フィッシング耐性のある認証、PAT、OAuth App、GitHub Appの方針を強制する。
- 自動処理から開発者個人の認証情報を除き、GitHub Appなどの短期IDへ移行する。
- 有効な認証情報を、所有者、目的、対象リポジトリ、権限、有効期限とひも付けて見直す。
- 退職・異動、端末紛失、漏えい、長期未使用を契機に、認証情報と関連セッションを失効する。
- 認証情報の発行・利用・変更・失効を記録し、影響を受けたリポジトリを追跡できるようにする。

`secure/*.json`と検証スクリプトは、参照用の基準を説明し、意図しない変更を検出するためのものです。
これらをコピーしても実際のGitHubアクセス権は変わらず、組織への導入を証明することもできません。

### 誰が何をするコントロールか

| 担当 | 作業 |
|---|---|
| プロダクト責任者 | 対象リポジトリ、必要なアクセス、自動処理の利用者を確定する |
| 組織管理者／IdP管理者 | 二要素認証、SSO、PAT、OAuth App、GitHub App、メンバー管理の方針を変更する |
| リポジトリ管理者 | AppやPATの対象リポジトリと権限を限定し、自動処理から個人トークンを除く |
| Platform／SRE | 短期の自動処理用IDと、承認済みの認証情報配送経路を構築する |
| 開発者 | 承認済みOAuthまたはハードウェア保護されたSSH鍵を使い、やむを得ず使うPATは保護された保管領域へ置く |
| セキュリティ担当 | 認証情報一覧、例外、監査範囲、失効訓練を独立して確認する |
| インシデント対応担当 | 漏えいなどの際に権限付与、トークン、鍵、セッションを失効し、影響範囲を確認する |

### 前提条件と信頼上の仮定

- GitHub組織、対象リポジトリ、認証方式、自動処理の利用者を列挙できること。
- 組織管理者とセキュリティ確認者を分離できること。
- 利用中のGitHubプラン、SAML／SCIM、IdP、MCPの有無を把握していること。
- 管理設定を変更する前に、メンバー、外部コラボレーター、OAuth App、GitHub App、PAT、SSHへの影響を確認すること。
- 成功・拒否試験用に、本番環境から分離した検証用リポジトリと専用の認証情報を用意できること。

### コピーまたは参照するファイル

| 用途 | ファイル |
|---|---|
| 実設定と運用 | [`docs/github-adoption-runbook.md`](docs/github-adoption-runbook.md) |
| 一般的な参照基準 | [`secure/credential-policy.json`](secure/credential-policy.json) |
| GitHub MCP OAuth | [`secure/github-mcp-oauth.json`](secure/github-mcp-oauth.json) |
| GitHub MCPでPATを代替利用する場合 | [`secure/github-mcp-auth-policy.json`](secure/github-mcp-auth-policy.json)と[`secure/github-mcp-pat-fallback.json`](secure/github-mcp-pat-fallback.json) |
| 将来の読み取り専用監査 | [`docs/read-only-audit-options.md`](docs/read-only-audit-options.md) |

### 最短の導入手順

詳細な手順と復旧方法は[GitHub導入runbook](docs/github-adoption-runbook.md)を参照してください。

1. **棚卸し**: 対象リポジトリ、メンバー、App、OAuth、PAT、SSH、自動処理の利用者と所有者を記録する。
2. **認証**: Organization Settingsの`Authentication security`で二要素認証を必須にする。利用できる場合は
   `Only allow secure two-factor methods`を有効にしてSMSを除外する。パスキーやセキュリティキーの要件は、
   IdPまたはEnterpriseの方針で別に強制・確認する。
3. **PAT**: `Personal access tokens`でclassic PATの利用を制限する。Fine-grained PATが必要な場合は、
   管理者承認を必須とし、対象リポジトリと最小権限を明示し、有効期限を90日以下にする。
4. **OAuth／App**: `OAuth app policy`で組織へのアクセスを制限する。GitHub Appのインストールは組織管理者が
   確認し、対象を選択したリポジトリだけに限定して、必要最小限の権限を与える。
5. **自動処理**: 開発者個人のOAuthやPATを使う処理をGitHub App installation tokenなどへ移行し、旧認証情報を失効する。
6. **保管**: トークンをOSのキーチェーンまたは承認済みシークレット管理サービスへ移す。SSH鍵は可能ならハードウェアで保護する。
7. **運用**: 90日以内ごとの棚卸し、イベントに応じた失効、監査記録の確認、期限付き例外の管理を開始する。
8. **確認**: 専用の検証範囲で、許可操作の成功、未付与権限による拒否、対象外リポジトリへの拒否、失効後の拒否を確認する。

### 安全な自己テスト

認証方式ごとに、専用の検証用リポジトリだけで実行します。認証情報の実値をコマンド履歴、ログ、
リポジトリ上の証跡へ残してはいけません。

| 試験 | 操作 | 期待状態 |
|---|---|---|
| 許可確認 | 許可された検証用リポジトリで、定義済みの許可操作を行う | 操作が成功し、監査イベントと対応付けられる |
| 権限の拒否確認 | 明示的に付与していない権限を必要とする、無害な操作を試す | `403`などで拒否され、変更が発生しない |
| 対象範囲の拒否確認 | 選択していない検証用リポジトリを読み取る | `403`または`404`で拒否される |
| 失効確認 | 専用認証情報を失効し、同じ読み取りを再試行する | `401`、`403`、`404`のいずれかで旧認証情報が拒否される |

読み取り専用の構成では、専用の検証用リポジトリへ一意なテスト用refを作成する操作を、権限の拒否確認に使えます。
書き込みを許可した自動処理では、正当な書き込みを許可確認に使い、拒否確認には別の未付与権限を選びます。
操作が予期せず成功した場合は`FAIL`とし、別の管理者がテストによる変更を除去して権限を是正します。

### 期待する結果と状態

実環境への導入状況は、次の状態で判定します。

- `PASS`: 現在の設定または実際の拒否結果によって、要求状態を確認できた。
- `FAIL`: 現在の設定または実試験によって、安全でない状態が判明した。
- `NOT_CHECKED`: プラン、権限、端末、証跡などが不足し、確認できていない。
- `ERROR`: 収集、認証、ページネーション、解析、鮮度確認などに失敗した。
- 確認済みの`N/A`: 対象の認証方式またはMCPを使用していない。

参照実装は次のコマンドで確認できます。

```bash
make verify-control CONTROL=PSB-SOURCE-004
```

終了コードは`0=参照実装を受理`、`1=セキュリティ上の問題を検出`、`2=入力または証跡のエラー`です。

### よくある失敗と復旧

- 二要素認証の有効化で外部コラボレーターが除外された: 要件を満たす二要素認証の設定後に確認し、再招待する。
- PATの有効期限方針で既存トークンが拒否された: 利用処理を新しい限定的な認証情報へ移し、旧トークンを明示的に失効する。
- OAuth制限でAppまたはSSHアクセスが止まった: 変更前の棚卸しで承認した対象だけを再認証する。
- GitHub Appへの移行で自動処理が停止した: Appの対象リポジトリ、権限、利用側の設定を修正する。広い権限を持つ個人PATを無期限に復活させない。
- APIまたは監査証跡を取得できない: `PASS`にせず、`NOT_CHECKED`または`ERROR`にする。

### サーバー側の強制とロールバック

開発者端末の設定だけでは完了しません。GitHub／IdP側の方針、Appへの権限付与、PAT承認、監査、
メンバーのライフサイクル管理を必ず維持します。サービス側の設定を一括で自動復元せず、変更前の状態と
影響対象を確認して、設定単位で戻します。ロールバックによってclassic PAT、無制限のOAuth App、
広い権限を持つGitHub Appを黙って再許可してはいけません。緊急時は`PSB-GOV-002`の、対象が狭く、
所有者と期限が明確な例外手続きを使います。

### 導入完了条件

- 対象となる認証情報と利用処理について、所有者、目的、対象、権限、確認日、有効期限または失効状態が分かる。
- GitHub／IdPの現在の設定が基準を満たす。
- 自動処理が開発者個人のトークンを使用していない。
- 許可操作の成功、未付与権限による拒否、対象範囲外への拒否、失効後の拒否を専用の検証環境で確認している。
- 監査イベントを認証情報の所有者と対象へ対応付けられる。
- 未確認項目と残余リスクを`NOT_CHECKED`として残し、テスト用サンプルの`PASS`を実環境への導入証跡に使っていない。

### 読み取り専用監査を追加する場合

今すぐ収集ツールを導入する必要はありません。Fine-grained PAT、インストール済みGitHub App、SAML認証情報の
承認状態、監査ログの一部は、GitHub APIまたはexportを使って読み取り専用で確認できます。一方、IdPの方針、
キーチェーンへの保管、IDEから対象の子プロセスだけへの受け渡し、SSH鍵のハードウェア保護には別の証跡が必要です。
確認できる項目、プランや権限による制約、将来収集ツールを実装する場合のfail-closed要件は、
[`docs/read-only-audit-options.md`](docs/read-only-audit-options.md)にまとめています。

## PSB-SOURCE-001との分担と必要性

PSB-SOURCE-001とは、認証情報の保管、強固な認証、ハードウェア保護鍵の部分で重なります。
ただし、主たる判断対象は異なります。端末を暗号化し、トークンをキーチェーンへ保管しても、
GitHub側に過剰なOAuthの権限付与、長寿命PAT、退職者のSSH鍵、所有者不明のGitHub Appが残っていれば、
それらの権限は引き続き利用できます。反対に、GitHub側で権限を絞っても、端末上で認証情報を平文保存すれば
窃取されます。そのため、重なる項目を二重に実装するのではなく、端末側とサービス側の二つの境界を
接続して確認します。

| コントロール | 主に守る境界 | このコントロールに含めないもの |
|---|---|---|
| `PSB-SOURCE-001` | 開発者端末。OS、暗号化、マルウェア対策、キーチェーン、ローカルの鍵、IDE、実行環境を保護する | GitHub上の全権限の棚卸し、対象リポジトリ・権限・有効期限の承認、退職時のサービス側失効 |
| `PSB-SOURCE-004` | ソース管理基盤の認可。OAuth、PAT、SSH鍵、GitHub Appを発行から失効・監査まで管理する | 端末全体のハードニング、MDM／EDR、ディスク暗号化、マルウェア封じ込め |

`SCL-005`の有効期限、`SCL-006`の保管、`SCL-007`の強固な認証、`SCL-008`のハードウェア保護鍵は、
PSB-SOURCE-004で別の端末対策を再実装するための項目ではありません。PSB-SOURCE-001が提供する端末側の
保護を、GitHub上の有効期限方針、認証情報一覧、承認、失効と接続できていることを確認する境界項目です。

同様に、`SCL-016`と`SCL-017`はMCPの実行権限を再実装する項目ではありません。GitHub認証情報の範囲を
`PSB-AI-004`のツール認可へ引き渡せていることを確認する接続項目です。MCPツールの許可・拒否そのものは
`PSB-AI-004`が担当します。

したがって、このコントロールは必要です。ただし、価値があるのはGitHub／IdPの実設定、認証情報の棚卸し、
失効訓練、監査までを行う場合に限ります。JSONサンプルの検証だけを行うのであれば、独立したコントロールとしての
セキュリティ効果はありません。

## 脅威、操作、対象

- フィッシング、情報窃取型マルウェア、悪意のある拡張機能・依存関係、端末利用者が、保存済みの認証情報を盗む。
- 権限が広すぎるトークンによって、目の前の作業には不要なリポジトリ、ワークフロー、組織情報、リリースへアクセスされる。
- 異動、退職、端末紛失、インシデントの後も、放置されたトークンやSSH鍵が利用可能なまま残る。
- 悪意のあるIDE拡張、子プロセス、プロンプトインジェクションを受けたMCPツールが、IDEやshellに広く渡されたPATを取得して再利用する。
- 対象は、利用者へのOAuth権限付与、PAT、SSH鍵、GitHub App、組織による承認・失効・監査という、ソース管理基盤の認可境界である。

一つの開発者用認証情報が、長期間にわたる無制限の組織アクセスへ変わることを防ぎます。
端末そのものの防御は`PSB-SOURCE-001`、CI/CDからクラウドへのworkload federationは別のコントロールが担当します。

## 安全な例と危険な例

- `secure/credential-policy.json`は、短期またはAppのインストール単位の認証方式を優先し、PATを限定し、
  棚卸しと失効を求める参照用の方針です。
- `insecure/credential-policy.json`は、classic PAT、無制限の対象、平文保管、無期限の利用、
  棚卸し・監査の欠落を意図的に許可した危険な例です。
- `secure/github-mcp-*.json`は、GitHub MCPでOAuthを優先し、PATが不可避な場合も、読み取り専用の
  特定MCPプロセスだけへ限定して渡す構成例です。
- `insecure/github-mcp-*.json`は、トークン値の直書き、変更可能なコンテナimage、全toolsetの有効化、
  ライフサイクル所有者の欠落を含む危険な例です。

テスト用サンプルには、トークン、秘密鍵、利用者名、実在するリポジトリ名、本番の証跡を含めていません。
GitHubや端末へ自動適用されることもなく、テストの成功は組織への導入証跡にはなりません。

## 認証方式の選び方

利用者または処理主体に適した、最も権限の狭い方式を選びます。

1. 自動処理では、対象リポジトリと権限を明示したGitHub App installation tokenなど、短期のworkload identityを優先する。
2. 開発者が対話的にGitを使う場合は、GitHub CLIのOAuthやハードウェア保護されたSSHなど、組織が承認した方式を使う。
   フィッシング耐性のあるMFA、SSO承認、限定的なgrant、保護された保管を組み合わせる。
3. PATが不可避な場合は、所有者、対象リポジトリ、権限、有効期限を限定したfine-grained PATを優先する。
4. Classic PATや`repo`、`workflow`などの広いscopeは例外経路とし、必要性、所有者、承認、有効期限を記録する。

Fine-grained PATであることだけでは最小権限を証明できません。リソース所有者、対象リポジトリ、権限、
有効期間、組織承認をそれぞれ確認する必要があります。

## GitHub MCPを開発者IDEで使う場合

環境変数は安全な保管場所ではなく、認証情報を必要なプロセスへ渡すための経路です。PATを
`.bashrc`、`.zshrc`、`.env`、IDEのJSON、Gitのremote URLへ保存したり、PATを持つ親shellから
IDE全体を起動したりすると、別の拡張機能や子プロセスまでGitHubへの権限を取得できます。

次の優先順位で認証方式を選びます。

1. GitHub.comと対応IDEの組み合わせでは、公式remote MCPのOAuthを第一選択にする。
2. Local MCPでOAuthを利用できる場合も、利用者が管理するPATより、メモリ上だけに保持するOAuthを優先する。
3. PATが不可避な組み合わせに限り、GitHub MCP専用のfine-grained PATを発行する。
4. PATの所有者を一つに限定し、対象リポジトリを明示的に選び、権限を読み取り専用の最小限にする。
   有効期限は90日以下とし、組織承認とSSO方針へ接続する。
5. PATはOSのキーチェーンまたは承認済みシークレット管理サービスへ置き、IDE設定には
   `${input:github_token}`という参照だけを記録する。
6. `GITHUB_PERSONAL_ACCESS_TOKEN`は対象のMCP子プロセスだけへ渡し、IDEの親プロセスや
   shell環境全体へexportしない。
7. MCPは既定で読み取り専用とし、`context,repos,pull_requests`だけを公開する。書き込み用途は
   別のprofileとし、`PSB-AI-004`による対象ツールの認可と人間の承認を通す。

OAuthの最小構成は[`secure/github-mcp-oauth.json`](secure/github-mcp-oauth.json)です。
PATによる代替構成の[`secure/github-mcp-pat-fallback.json`](secure/github-mcp-pat-fallback.json)は、
認証情報の値を含まず、組織が管理・配布する特定のcommandへ認証情報の参照だけを渡します。
`password: true`は表示を隠すだけの可能性があるため、IDEが入力をOSのキーチェーンなどへ保存し、
対象のMCP子プロセスだけへ渡すことを実端末の証跡で確認するまでは、
`NOT_CHECKED`です。

各コントロールの責務は次のとおりです。

| コントロール | GitHub MCPに対する責務 |
|---|---|
| `PSB-SOURCE-004` | OAuth／PATの選択、PATの権限・期限・保管・更新・失効・監査 |
| `PSB-AI-002` | 公式MCP serverの正規の入手元、変更不能なartifact、内容確認、依存関係の失効 |
| `PSB-AI-004` | MCPのcommand／URL、読み取り専用toolset、書き込み承認、実行中のinventoryと監査 |

## 検証

リポジトリのルートで次を実行します。

```bash
make verify-control CONTROL=PSB-SOURCE-004
```

参照実装の検証では、次を確認します。

- 安全なmetadataのテスト用サンプルを受理する。
- 安全でないサンプルを、原子的な要件ごとの問題として拒否する。
- 形式が不正または読み取れない入力を、終了コード`2`の`ERROR`として扱う。
- 実際の認証情報を読み取らず、出力もしない。
- OAuth優先と、範囲を限定したPAT代替構成のGitHub MCPサンプルを受理する。
- 認証情報の直書き、広い環境への受け渡し、過剰な権限、変更可能な構成を拒否する。
- 不正形式または認証情報を含むMCP証跡を終了コード`2`の`ERROR`とし、安全な構成として扱わない。

実環境への導入にはrunbookを使い、組織の現在のトークン方針、OAuth／Appへの権限付与、SSH鍵一覧、
監査記録、保管状態、アクセス棚卸し、サニタイズ済みの失効訓練を確認します。実環境の証跡がなければ
`NOT_CHECKED`のままです。

## インシデント対応

認証情報の漏えいが疑われる場合は、次の順序で対応します。

1. OAuth grant、PAT、SSH鍵、Appの認証情報を最初に失効する。
2. 関連セッションを無効化し、下流の認証情報を更新する。
3. 必要事項だけを残した監査証跡を保全し、その認証情報で到達できたリポジトリと操作を特定する。
4. ソース、ログ、artifact、cache、履歴から漏えい値を除去する。
5. forkと、すでにcloneされた複製を確認する。
6. 過剰権限または長期利用を許したライフサイクル上の欠陥を修正する。

ファイルからトークンを削除したりGit履歴を書き換えたりしても、トークン自体は失効しません。

## 制約と運用コスト

リポジトリ内の検証スクリプトは参照用metadataを確認するだけで、実際のGitHub認証情報を列挙・失効できません。
GitHub Organization／Enterpriseの設定、SSO、監査ログの保持期間、トークン承認機能は、契約プランと構成に
よって異なります。端末で安全に保管していても、OAuth grantが必要以上に広い、または長期間有効な場合があります。
SSHによるcommit署名とSSH認証は別の用途であり、それぞれ管理が必要です。

PATサンプルに記載した管理対象commandは、組織が配布時に固定する契約であり、インストール済みのGitHub MCP
binaryが正規品であることの証明ではありません。binaryは`PSB-AI-002`で、確認済みの変更不能なartifactへ
ひも付けます。また、IDEごとに認証情報の保存方法や環境変数の継承方法が異なるため、`${input:...}`という
参照だけでは、OSのキーチェーンへの保管や子プロセスだけへの受け渡しを証明できません。実端末の証跡で
両方を確認するまで、導入状態は`NOT_CHECKED`です。

短い有効期限、ハードウェア鍵、承認手続き、定期的なアクセス棚卸しは、開発者と管理者の作業を増やします。
緊急用アクセスは対象を狭くし、監視し、期限を設ける必要があります。

## フレームワークとの対応

フレームワークとの対応は欠けているわけではありません。機械可読な正本を`control.yaml`へ置くという
リポジトリ規約に従っていましたが、READMEには一覧を掲載していませんでした。これはREADMEの説明不足です。
現在の対応は次のとおりです。

| フレームワーク | バージョン／ID | 関係 | 主な対象 |
|---|---|---|---|
| GitHub Security Guidance | `github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24)`／`GHSC-SECURE-ACCOUNTS` | `supports` | 認証情報の選択、保管、棚卸し、失効を含む全体 |
| GitHub Security Guidance | 同上／`GH-ADMIN-CREDENTIAL-TYPES` | `supports` | PAT、OAuth、App、SSHの種別、期限、承認、失効 |
| GitHub Security Guidance | 同上／`GH-ADMIN-SAML-IAM` | `supports` | SAML認証、認証情報の承認、棚卸し、失効 |
| GitHub Security Guidance | 同上／`GH-ADMIN-SCIM-ORGANIZATIONS` | `supports` | メンバー削除に伴う棚卸しと失効 |
| MITRE ATT&CK | `v19.1`／`T1078 Valid Accounts` | `mitigates` | 漏えいした有効な認証情報の長期利用と影響範囲の縮小 |
| MITRE ATT&CK | `v19.1`／`T1552.001 Credentials In Files` | `mitigates` | ファイルや広い環境へのトークン・秘密鍵の露出抑制 |
| NIST SSDF | `1.1`／`PS.3.1` | `supports` | ソースコードへの不正アクセス・変更を防ぐための開発用認証情報管理 |
| OpenSSF OSPS Baseline | `2026.02.19`／`OSPS-AC-01.01` | `supports` | 機微な操作に対するMFAと集中管理された認証 |
| OWASP Agentic Top 10 | `2026`／`ASI03` | `mitigates` | MCPでの権限継承、PATの過剰権限、agent identityの悪用 |

各対応関係には、`control.yaml`で対象チェック、関係、信頼度、根拠、確認日を記録しています。
これらは関連するセキュリティ要件や攻撃手法を示すものであり、正式な準拠や完全な対策を主張するものではありません。

## 参考資料

- [実装仕様書](docs/implementation-spec.md)
- [実装計画書](docs/implementation-plan.md)
- [GitHub導入runbook](docs/github-adoption-runbook.md)
- [読み取り専用監査の選択肢](docs/read-only-audit-options.md)
- [GitHubのpersonal access token方針](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization)
- [GitHub OAuth Appのアクセス制限](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- [GitHub Appの申請・インストール制限](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations)
- [GitHub組織での二要素認証要件](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
- [GitHub MCP Serverの設定](https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server)
- [`3778a41476e31a072430cfee7c5d31c5f72def60`に固定したGitHub MCP Server README](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/README.md)
- [`3778a41476e31a072430cfee7c5d31c5f72def60`に固定したGitHub MCPの方針とガバナンス](https://github.com/github/github-mcp-server/blob/3778a41476e31a072430cfee7c5d31c5f72def60/docs/policies-and-governance.md)
- [REF-AI-004 GitHub MCP公式認証ガイダンス](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-004)
