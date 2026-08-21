# PSB-SOURCE-002: 開発者向けGit hooksセキュリティベースライン

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Developerがsecret、機密file、credential-bearing metadataをcommit・pushすると、現在treeから削除してもGit historyやremote copyへ残り続ける。 |
| 誰から、または何から守るか | Developerの不注意、侵害されたlocal tool、生成file、synthetic token patternの見逃し、hook bypass、scanner・Git実行障害から守る。 |
| 何が対象か | Repository-owned `pre-commit`・`commit-msg`・`pre-push` hook、staged file、commit message、導入される全履歴、forbidden file、secret pattern、file size。 |
| 何をするか | Reviewed `core.hooksPath`から共通scannerを実行し、commit前の内容・messageとpushで新規導入される全reachable historyを検査してblockする。 |
| 成功状態 | Secret・機密file・危険metadata・oversized fileがremote到達前に拒否され、matched valueは表示されず、scanner failureはcleanと区別される。 |
| 対象外・残余リスク | Local hookは変更・回避・省略でき、既に公開済みcopyを消せないため、server-side・CI scan、credential revoke、公開面reviewを別途必要とする。 |

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
- `secure/pre-commit-framework/.pre-commit-config.yaml`
  - pre-commit frameworkを使用する組織向けの代替activation sample
  - `pre-commit`、`commit-msg`、`pre-push`を同じrepository-owned scannerへ接続
- `insecure/pre-commit-framework/.pre-commit-config.yaml`
  - floating external revisionとmanual stageだけを使用する拒否fixture

安全でない設定は隔離されたテストfixtureであり、実際のGit設定には適用されません。

## 導入手順（最初にここを読む）

実際のrepositoryへ導入する手順は
[`docs/adoption-guide.md`](docs/adoption-guide.md)にまとめています。次の内容を、
前提確認から切り戻しまで順番に実行できます。

1. native hooks方式とpre-commit framework方式の選択
2. Linux、macOS、WindowsでのPython 3.10以上とvirtual environmentの準備
3. pre-commit 4.2.0の固定導入
4. `.githooks/`と`.pre-commit-config.yaml`の安全なcopyとreview
5. Gitleaks v8.30.0のfull commit SHA pin、release checksum検証、synthetic canary
6. commit署名identityとrepository-local Git設定
7. 導入状態checker、通常commit、negative test、pre-pushの確認
8. CI、GitHub Push Protection、既存repositoryの移行、troubleshooting、切り戻し

導入後はblueprintから次を実行すると、対象cloneの基本状態を検査できます。

```bash
python3 controls/source-protection/git-hooks-baseline/scripts/check-adoption.py \
  --repository /absolute/path/to/target --mode framework
```

`READY`はhook配置とactivationの確認結果です。Gitleaks canary、CI、server-side
enforcement、credential incident対応の確認を省略できるという意味ではありません。

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

## pre-commit framework用サンプル

pre-commit frameworkを標準化している組織では、次のサンプルをrepository rootの
`.pre-commit-config.yaml`として使用できます。

```text
secure/pre-commit-framework/.pre-commit-config.yaml
```

このファイルはYAML 1.2として有効なJSON-compatible形式です。
Repository-owned scannerはreview済みの`.githooks/`だけを`repo: local`で
呼び出し、独立したGitleaks検査は後述のfull commit SHAへ固定します。
`pre-commit`、`commit-msg`、`pre-push`の3 stageを既定のinstall対象にします。
pre-push adapterはpre-commitが提供する`PRE_COMMIT_*` contextをnative scanner入力へ
変換し、pushで導入される履歴全体を検査します。

native `core.hooksPath=.githooks`方式とframework方式はactivation mechanismが
異なります。framework方式を選ぶ場合は、tracked `.githooks/pre-commit`を
`pre-commit install`で上書きしないよう、local `core.hooksPath`を使わず
`.git/hooks`側へ明示的にinstallしてください。ツールを自動installしません。

```bash
pre-commit validate-config .pre-commit-config.yaml
pre-commit install --install-hooks
```

サンプルが要求する検証済みminimum versionは`4.2.0`です。組織のpackage managerと
lockfileでpre-commit本体もversion固定してください。外部hookを追加する場合は
tagではなくfull commit SHAへ固定し、semantic reviewと更新手順を追加します。

pre-commitの`SKIP`またはGitの`--no-verify`でlocal検査は回避できるため、
CIとrepository-side enforcementは引き続き必要です。

### Gitleaksによる多層検査

サンプルは既存のrepository-owned scannerに加え、Gitleaksを独立したsecret
detection engineとして推奨します。既存scannerは機密ファイル種別、commit
message、導入履歴を決定的かつofflineに検査し、Gitleaksはより広いsecret ruleと
entropy-based detectionを追加します。一方を他方の代替にはしません。

Gitleaks hookは公式release `v8.30.0`に対応する次のfull commit SHAへ固定しています。

```text
6eaad039603a4de39fddd1cf5f727391efe9974e
```

`v8.30.1`は採用していません。上流の公式issueでsecret detection回帰とWindows x64
artifact checksum不一致が報告されたためです。将来の更新でもversion番号だけでなく、
release artifact digest、synthetic canaryの拒否、clean fixtureの通過を独立して確認します。

設定は公式`gitleaks` hookを`pre-commit` stageで実行し、`--redact`、
`pass_filenames: false`、`always_run: true`を明示します。tag、branch、短縮SHAへ
変更するとcontrol verifierが拒否します。初回`pre-commit install --install-hooks`
ではsource取得とGo buildのnetwork accessが発生するため、明示的に実行し、
失敗したinstallやscanをcleanとして扱いません。

Gitleaksのexit `1`はsecret検出と実行エラーの両方で使用され得るため、commitは
どちらの場合もblockし、ログを確認して検出とtool failureを区別します。出力は
redactし、実際のsecretをCI logやticketへコピーしません。

prebuilt binaryを別経路で導入する場合は、versionだけでなく公式release checksumを
検証します。local hookとは別に、CIでfull historyを検査し、repository-side push
protectionも有効にしてください。

### Gitleaks以外の候補と使い分け

Gitleaks以外にも有力な選択肢があります。ただし、検出エンジンをすべてのcommitで
重ねると、待ち時間、重複finding、除外設定の不整合が増えます。名前や人気ではなく、
不足している検査層に合わせて選択します。

| 候補 | 得意な役割 | 採用に向く場面 | 主な注意点 | このサンプルでの位置付け |
| --- | --- | --- | --- | --- |
| detect-secrets | baselineと対話的auditを使った既存findingの段階的管理 | secret候補が既に多いlarge/legacy repositoryで、新規混入を止めながら既存分を分類・移行する | baseline登録は安全性の証明や恒久的なallowlistではない。owner、review、rotation期限が必要で、広い除外は禁止する | 移行時の代替候補。Gitleaksと同時に必須化しない |
| GitHub Secret Scanning / Push Protection | GitHub側でCLI push、Web UI、file upload、対応API経由のsecretをblockし、bypassを記録する | GitHubを共有repositoryとして利用する組織のserver-side enforcement | 検出対象pattern、契約、repository設定に依存する。許可されたbypassも監査・期限付き是正が必要 | local scannerとは独立して有効化する最終防波堤 |

TruffleHogはdeveloper-local hookとして推奨しません。導入時棚卸し、定期的な
full-history scan、incident調査、credential verificationのためにSecurity／AppSecが
管理する候補として、`PSB-SOURCE-003`でのみ紹介します。

推奨する最小構成は、次の3層です。

1. 開発者端末ではrepository-owned scannerと、full commit SHAへ固定したGitleaksを
   staged contentに対して実行する
2. 通常CIではGitleaksでpush対象またはfull historyを検査する
3. GitHub側ではSecret ScanningとPush Protectionを有効にし、bypassをsecurity review、
   audit log、期限付きremediationへ接続する

既存findingが多く、この構成を一度にfail-closedにできない場合だけ、
detect-secretsのbaselineと`audit`を移行管理に使用します。baselineへ追加した
credential候補は「対応不要」ではなく、rotate、revoke、false positive、または
review済み例外のいずれかへ分類します。

どのツールでも、検出されたcredentialはGit履歴から消すだけでは不十分です。
最初にrotateまたはrevokeし、その後に履歴、fork、cache、artifact、logへの拡散を
調査します。scannerが起動できない、network verificationが完了しない、対象履歴を
取得できない場合はcleanではなく実行エラーです。

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
- [pre-commit configuration and supported Git hook stages](https://pre-commit.com/)
- [Gitleaks official repository and pre-commit integration](https://github.com/gitleaks/gitleaks)
- [Gitleaks v8.30.0 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0)
- [Gitleaks v8.30.1 detection regression report](https://github.com/gitleaks/gitleaks/issues/2170)
- [Gitleaks v8.30.1 Windows checksum report](https://github.com/gitleaks/gitleaks/issues/2164)
- [detect-secrets baseline, audit, and pre-commit integration](https://github.com/Yelp/detect-secrets)
- [GitHub Secret Scanning Push Protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)
- [GitHub delegated bypass requests](https://docs.github.com/en/code-security/concepts/secret-security/bypass-requests)
