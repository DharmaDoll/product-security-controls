# PSB-SOURCE-002: 開発者向けGit hooksセキュリティベースライン

## セキュリティ上の問題

commitやpushによって、secret、秘密鍵、環境設定ファイル、内部情報、
個人のメールアドレスなどが漏洩する可能性があります。一度commitした後に
削除した情報もGit履歴には残るため、最新のworktreeが安全に見えるだけでは
不十分です。

開発者端末上のGit hooksは、情報が端末から共有リポジトリへ出る前に問題を
検出できます。ただし、hooks自体がリポジトリから提供される実行コードであり、
回避も可能です。

このコントロールは、リポジトリが所有する次のhooksと、決定的に動作する
scannerを提供します。

- `pre-commit`
- `commit-msg`
- `pre-push`

hooksを自動インストールすることはありません。導入時は、内容をレビューした
うえで、対象リポジトリに対して明示的に設定します。

```bash
git config --local core.hooksPath .githooks
```

## 脅威と信頼境界

信頼境界は、開発者のworktreeおよびローカルGit object databaseから、
共有リポジトリの履歴へ情報が移動する箇所です。

このコントロールは、主に次の失敗を対象とします。

- stagedされたsecretや機密ファイルがcommitされる
- commit messageへsecretが含まれる
- secretを後から削除したものの、push対象の過去commitに残っている
- author emailやcredential入りremote URLから情報が漏洩する
- global、絶対パス、共有ディレクトリにある未レビューのhookが実行される
- 広すぎるpush設定によって意図しないrefが公開される

## 安全でない例と安全な例

- `insecure/recommended.gitconfig`
  - `/tmp`配下の共有hooksを使用
  - credentialを平文保存
  - `safe.directory=*`
  - commitとtagの署名を無効化
  - Gitによるidentityの推測を許可
  - `push.default=matching`
- `secure/recommended.gitconfig`
  - リポジトリ相対のhooks pathを使用
  - identityの明示設定を要求
  - commitとtagの署名を要求
  - push対象を限定
- `secure/.githooks/`
  - 3種類のhookと`scan-sensitive.py`を格納

安全でない設定は隔離されたテストfixtureであり、実際のGit設定には適用されません。

## 検証方法

リポジトリのルートで次を実行します。

```bash
make verify-control CONTROL=PSB-SOURCE-002
```

テストは一時Gitリポジトリを作成し、設定検証だけでなくhooksを実際に実行します。

- 通常のソースコードをcommitできる
- 禁止ファイル名とsynthetic tokenがcommit前に拒否される
- commit message内のsecretが拒否される
- 検出したsecret値がログへ出力されない
- 一度commitして削除したsynthetic tokenを`pre-push`が履歴から検出する
- scannerの実行失敗とcleanな結果が別の終了コードになる

scannerの終了コードは次のとおりです。

| 終了コード | 意味 |
| --- | --- |
| `0` | 検出なし |
| `1` | ポリシー違反を検出 |
| `2` | 検査を正常に完了できなかった |

検出時はルール名と場所だけを表示し、secret値そのものは表示しません。

## 推奨する開発者設定

次の設定は、内容を確認したうえで対象リポジトリへローカル設定します。

```bash
git config --local core.hooksPath .githooks
git config --local push.default simple
git config --local user.useConfigOnly true
git config --local commit.gpgSign true
git config --local tag.gpgSign true
```

追加の推奨事項は次のとおりです。

1. hooksの変更を実行コードとしてレビューし、`.githooks/`をCODEOWNERSや
   同等のレビュー規則で保護する
2. OS keychain、Git Credential Manager、SSH agent、または承認済みの
   credential helperを利用し、`credential.helper=store`は使用しない
3. remote URLへtokenを埋め込まない
4. 公開リポジトリではGitHubの`noreply`アドレスまたは承認済みの公開用identityを
   使用し、`git show --format=fuller`でcommit metadataを確認する
5. `safe.directory=*`は設定せず、必要な場合も所有権を確認した正確なworktree
   パスだけを許可する
6. ローカルhooksだけに依存せず、server-side push protection、secret scanning、
   protected branch、CI検査を有効にする
7. 本物のcredentialを検出した場合は直ちにrotateまたはrevokeし、影響する
   すべてのcommitから削除する

remote URLは次のコマンドで確認できますが、credentialが含まれる可能性があるため
出力をログやチケットへ貼り付けないでください。

```bash
git remote get-url --all origin
```

## `pre-commit`の検査内容

### 拒否するファイル

- 実行・native artifact
  - `.exe`、`.dll`、`.so`、`.dylib`、`.bin`、`.msi`
- archiveとpackage
  - `.zip`、`.tar`、`.gz`、`.7z`、`.rar`、`.jar`、`.war`
- database
  - `.sqlite`、`.sqlite3`、`.db`、`.mdb`
- 生成物
  - `.pyc`、`.pyo`、`.class`
- ローカルmetadata
  - `.DS_Store`、`Thumbs.db`
- key storeと秘密鍵
  - `.p12`、`.pfx`、`.jks`、`.keystore`、`.key`、`.pem`
- 環境設定とcredential
  - `.env`、`.env.*`、`.netrc`、`credentials.json`
  - `id_rsa`、`id_dsa`、`id_ecdsa`、`id_ed25519`

`.env.example`、`.env.sample`、`.env.template`はファイル名では拒否しませんが、
内容のsecret検査は実施します。

### 検出するsecret

- PEM private key header
- AWS Access Key ID
- AWS Secret Access Key
- Google API Key
- JWT
- Bearer Token
- GitHub Token
- Slack Webhook
- `api_key`、`client_secret`、`password`、`token`へのcredential代入

### ファイルサイズ

5 MiBを超えるファイルは拒否します。

5 MiBは、このコントロールに与えられたローカルレビューおよびscannerの運用方針値
です。Git、GitHub、MITRE ATT&CK、NIST SSDFが定める安全性の境界ではありません。

上限を増やすと端末上の処理コストが増え、上限を減らすと正当なファイルを拒否する
可能性が高くなります。大容量またはbinary assetを意図的に管理する場合は、
検査を黙って省略せず、レビュー済み例外か専用artifact storeを利用してください。

## `commit-msg`の検査内容

commit messageを同じsecret patternで検査します。検出時も、message内の値は
ログへ出力しません。

ただし、一般的な個人情報、顧客名、内部チケット番号、非公開URLなどを自動的に
分類するものではありません。組織固有の情報分類ルールが別途必要です。

## `pre-push`の検査内容

pushによってremoteへ新しく導入される全commitを列挙し、次を再検査します。

- 各commitのmessage
- 各commitで追加、コピー、変更、renameされたファイル
- 最新treeでは既に削除されている過去のファイル内容

これにより、`--no-verify`でcommitされたsecretや、後続commitで削除したsecretも
push前に検出できます。

## 制限事項と運用コスト

`pre-commit`、`commit-msg`、`pre-push`は`--no-verify`で回避できます。
また、Web UI、API経由の変更や、hooksを有効化していないcloneでは実行されません。
悪意ある開発者や侵害済み端末は、hooks、scanner、Git binary、ローカル設定を
変更できます。

pattern matchingでは、未知、encode、分割、暗号化されたsecretや独自形式を
完全には検出できず、false positiveも発生します。5 MiBを超えるファイルと
binaryファイルは、未検査のまま許可せず拒否します。

このサンプルは、顧客データ、社外秘ソース、内部設計書、すべての個人情報を
分類するものではありません。

commit署名はidentity keyを認証しますが、commit内容の安全性を保証しません。
`user.useConfigOnly`はGitによるidentityの推測を防ぎますが、公開用と非公開用の
正しいidentityが選ばれたことまでは保証しません。

ローカルhooksとは独立して、repository-side push protectionとCI scannerを
必須とします。scannerの失敗をcleanな結果として扱ってはいけません。

## 参照資料

- [Git hooks documentation](https://git-scm.com/docs/githooks)
- [Git configuration documentation](https://git-scm.com/docs/git-config)
- [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)
- [GitHub email addresses reference](https://docs.github.com/en/account-and-profile/reference/email-addresses-reference)
