# PSB-SOURCE-002: 開発者向けGit hooksセキュリティベースライン

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Developerがsecret、機密file、credential-bearing metadataをcommit・pushすると、最新treeから削除してもGit historyやremote copyへ残り続ける。 |
| 誰から、または何から守るか | Developerの不注意、侵害されたlocal tool、生成file、hook bypass、scanner・Git・Docker実行障害から守る。 |
| 何が対象か | Repository-owned `pre-commit`・`commit-msg`・`pre-push` hook、staged file、commit message、導入される全履歴、forbidden file、secret pattern、file size。 |
| 何をするか | `.githooks`をrepositoryへcopyし、小さなPython scannerとdigest固定Gitleaks containerでcommit前とpush前に検査する。 |
| 成功状態 | Secret・機密file・oversized fileがremote到達前に拒否され、matched valueは表示されず、scanner failureはcleanと区別される。 |
| 対象外・残余リスク | Local hookは変更・回避・省略でき、既に公開済みcopyを消せないため、server-side・CI scan、credential revoke、公開面reviewを別途必要とする。 |

## セキュリティ上の問題

secretや秘密鍵は、一度commitすると後続commitで削除してもGit履歴に残ります。
commit message、remote URL、author metadataも情報公開面です。最新worktreeだけを見て
安全と判断できません。

このcontrolは、情報がdeveloper endpointから共有repositoryへ移る直前に検査します。
導入を単純にするため、hook frameworkやPython packageを追加しません。

## 最短導入

詳細は[`docs/adoption-guide.md`](docs/adoption-guide.md)にあります。基本操作は次の
4操作です。

```bash
cp -R /path/to/product-security-controls/controls/source-protection/git-hooks-baseline/secure/.githooks .githooks
git config --local core.hooksPath .githooks
docker pull ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9
.githooks/test-detection.sh
```

必要なのはGit、Python 3.10以上、組織で承認されたDockerです。Python scannerは
標準libraryだけで動きます。hookの有効化はrepository-localであり、global設定や
他repositoryを変更しません。

## 実装ファイル

- `secure/.githooks/pre-commit`
  - staged contentをPython scannerで検査後、Gitleaksを呼ぶ
- `secure/.githooks/commit-msg`
  - commit messageをPython scannerで検査する
- `secure/.githooks/pre-push`
  - pushで導入される全commitを再検査する
- `secure/.githooks/scan-sensitive.py`
  - Python 3.10+標準libraryだけの小さなdeterministic scanner
- `secure/.githooks/run-gitleaks.sh`
  - digest固定Gitleaksをread-only、networkなし、redacted outputで実行する
- `secure/.githooks/test-detection.sh`
  - safe contentとruntime生成canaryの導入先self-test
- `secure/recommended.gitconfig`
  - repository-local Git設定のreference
- `insecure/recommended.gitconfig`
  - shared hook、plaintext credential、wildcard trustなどの拒否fixture

安全でない設定は隔離されたtest fixtureであり、developer設定へ適用しません。

## 検査内容

### pre-commit

Python scannerはGit indexのstaged fileだけを読み、次を拒否します。

- executable／native artifact: `.exe`、`.dll`、`.so`、`.dylib`、`.bin`、`.msi`
- archive／package: `.zip`、`.tar`、`.gz`、`.7z`、`.rar`、`.jar`、`.war`
- database／生成物: `.sqlite`、`.db`、`.mdb`、`.pyc`、`.class`
- key store／credential file: `.pem`、`.key`、`.p12`、`.pfx`、`.jks`、`.env`、`.netrc`
- local metadata: `.DS_Store`、`Thumbs.db`
- 5 MiBを超えるfileとbinary file
- representative AWS、Google、GitHub、JWT、Bearer、Slack、private key、generic credential pattern

`.env.example`、`.env.sample`、`.env.template`はfile名では拒否しませんが、内容は
検査します。

Python scannerがcleanの場合、Gitleaks v8.30.0 containerでもstaged stateを独立検査
します。container imageは次のdigestへ固定します。

```text
ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9
```

sourceはread-only mount、runtime networkは`none`、outputは`--redact`です。
`--pull never`によりcommit中にnetwork取得しません。導入時に明示的にimageをpull
します。

### commit-msg

commit messageを同じPython secret patternで検査します。一般的な個人情報、顧客名、
内部ticket番号、非公開URLの分類は組織固有ruleとして追加します。

### pre-push

pushでremoteへ新しく導入される全commitについて、messageと追加・変更・renameされた
fileを検査します。`--no-verify`でcommitした後にsecretを削除しても、過去commitに
残る値を検出できます。

## matched valueを表示しない

findingにはrule名とfileまたはcommit位置だけを表示します。matched valueは表示
しません。実際のcredentialをCI log、issue、ticketへcopyしないでください。

```text
BLOCK credential-assignment "config/example.txt"
REJECTED 1 finding(s); matched values suppressed
```

## 終了コード

| 終了コード | 意味 |
|---|---|
| `0` | 検出なし |
| `1` | policy finding |
| `2` | Python／Git／Docker未導入／入力の問題で検査不能 |
| その他のnon-zero | DockerまたはGitleaksの起動・実行失敗 |

GitleaksとDocker固有のnon-zeroもhookをblockします。findingかtool errorかはsanitized logで
区別しますが、どちらもcommitを続行しません。

## self-test

導入先で次を実行します。

```bash
.githooks/test-detection.sh
```

self-testはsafe contentの通過、無効なruntime canaryの拒否、redaction、Gitleaks
container実行を確認します。本物のsecretやprovider-valid tokenは使用しません。

期待する最終行は次です。

```text
READY PSB-SOURCE-002 detection self-test passed
```

reference control全体のpositive／negative testは次で実行します。

```bash
make verify-control CONTROL=PSB-SOURCE-002
```

## 推奨Git設定

導入先repositoryだけに設定します。

```bash
git config --local core.hooksPath .githooks
git config --local push.default simple
git config --local user.useConfigOnly true
git config --local commit.gpgSign true
git config --local tag.gpgSign true
```

commit／tag署名は事前に組織のsigning keyを設定します。private keyをrepositoryへ
copyしてはいけません。`credential.helper=store`、credential入りremote URL、
`safe.directory=*`は使用しません。

## 運用と調整

この実装は理解しやすいbaselineです。組織固有のfile名、secret形式、size上限は
`.githooks/scan-sensitive.py`の定数へreview済みpull requestで追加できます。

広いexclude、scanner skip、matched value出力、Docker imageのfloating tag化は
行いません。Gitleaks更新時はdigest、safe input、finding canary、redactionを確認します。

Docker daemon accessは強いlocal権限を持つため、このcontrolのためだけに未管理Dockerを
導入しません。既に組織管理されているdeveloper environmentを使用します。

## 制限事項

- `--no-verify`、Web UI、API、未導入cloneではlocal hookを回避できる
- compromised endpointはhook、Python、Git、Docker自体を変更できる
- pattern matchingは未知、encode、分割、暗号化されたsecretを完全には検出できない
- false positiveが発生し得る
- 5 MiB上限はrepository policyであり標準が定めるsecurity boundaryではない
- commit署名はidentity keyを認証するが内容の安全性を証明しない
- 既に公開されたhistory、fork、clone、cache、artifactはlocal hookで回収できない

このためCIのdigest固定Gitleaks、GitHub Secret Scanning／Push Protection、protected
branch、credential revoke／rotateを独立して必要とします。

## 参照資料

- [Git hooks documentation](https://git-scm.com/docs/githooks)
- [Git configuration documentation](https://git-scm.com/docs/git-config)
- [Gitleaks official repository](https://github.com/gitleaks/gitleaks)
- [Gitleaks v8.30.0 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0)
- [GitHub Push Protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)
