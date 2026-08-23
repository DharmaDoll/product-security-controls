# PSB-SOURCE-002 最短導入ガイド

このcontrolは、review済みの`.githooks`を対象repositoryへそのままcopyして使います。
hook frameworkやPython packageのinstallは不要です。

必要なものは次の3つだけです。

- Git
- Python 3.10以上（標準libraryだけを使用）
- 組織で利用を承認されたDocker

Docker daemonへのaccessは強いlocal権限を持ちます。未導入の端末へこのcontrolのため
だけにDockerを追加するのではなく、既に管理されている開発環境で使用してください。

開始前にversionとDocker daemonへの接続を確認します。

```bash
git --version
python3 --version
docker version
```

`python3 --version`は3.10以上が必要です。Python package、virtual environment、`pip`
設定は不要です。Python自体がない場合だけ、組織が管理するOS packageまたは開発環境
imageでPython 3.10以上を用意してください。

## 一括install

実行前に、このcontrolの`secure/.githooks`と`scripts/install.sh`を通常のcode reviewで
確認してください。review済みのblueprintから、次の1 commandで導入できます。

```bash
/absolute/path/to/product-security-controls/controls/source-protection/git-hooks-baseline/scripts/install.sh \
  --target /absolute/path/to/target-repository
```

installerは前提条件を確認し、digest固定Gitleaks imageを明示的にpullした後、次を一連の
処理として実行します。

1. review済み`.githooks`を導入先へcopyする
2. `core.hooksPath`、`push.default`、`user.useConfigOnly`をrepository-localに設定する
3. safe inputと無効なcanaryによるself-testを実行する

既存`.githooks`または異なるlocal設定がある場合は、Docker pullやrepository変更より前に
終了します。self-testまでの処理が失敗した場合は、copyした`.githooks`とinstallerが今回
追加したlocal設定だけを自動で切り戻します。既存設定、global設定、他repositoryは変更
しません。

期待する最終行は次です。

```text
READY PSB-SOURCE-002 installed in /absolute/path/to/target-repository
```

commit／tag署名は、組織の署名方式とkeyを準備済みの場合だけ明示的に追加します。

```bash
/absolute/path/to/product-security-controls/controls/source-protection/git-hooks-baseline/scripts/install.sh \
  --target /absolute/path/to/target-repository \
  --enable-signing
```

key未設定の状態で`--enable-signing`を指定すると、その後のcommitが失敗します。installerは
private keyの作成、copy、またはglobal Git設定の変更を行いません。

以下は、一括installerが実行する内容を個別に確認・実行したい場合の手動手順です。

## 1. `.githooks`をcopyする

blueprintと導入先の絶対pathを設定します。

```bash
PSB_ROOT="/absolute/path/to/product-security-controls"
TARGET_ROOT="/absolute/path/to/target-repository"
test -f "$PSB_ROOT/controls/source-protection/git-hooks-baseline/control.yaml"
git -C "$TARGET_ROOT" rev-parse --show-toplevel
```

導入先に`.githooks`がないことを確認してcopyします。既に存在する場合は上書きせず、
既存hookと手動でmergeしてください。

```bash
test ! -e "$TARGET_ROOT/.githooks"
cp -R "$PSB_ROOT/controls/source-protection/git-hooks-baseline/secure/.githooks" \
  "$TARGET_ROOT/.githooks"
chmod +x "$TARGET_ROOT/.githooks/pre-commit" \
  "$TARGET_ROOT/.githooks/commit-msg" \
  "$TARGET_ROOT/.githooks/pre-push" \
  "$TARGET_ROOT/.githooks/run-gitleaks.sh" \
  "$TARGET_ROOT/.githooks/scan-sensitive.py" \
  "$TARGET_ROOT/.githooks/test-detection.sh"
```

次のfileを通常のpull requestでreviewしてcommitします。

```text
.githooks/pre-commit
.githooks/commit-msg
.githooks/pre-push
.githooks/run-gitleaks.sh
.githooks/scan-sensitive.py
.githooks/test-detection.sh
```

## 2. Gitleaks imageを一度だけ取得する

hookはGitleaks v8.30.0 containerをimmutable digestへ固定しています。

```text
ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9
```

commit中にnetwork取得しないよう、導入時に明示的にpullします。

```bash
docker pull \
  ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9
```

pull失敗、digest不一致、Docker daemon停止は導入エラーです。scan成功として扱いません。

## 3. 対象repositoryだけでhookを有効化する

```bash
git -C "$TARGET_ROOT" config --local core.hooksPath .githooks
git -C "$TARGET_ROOT" config --local push.default simple
git -C "$TARGET_ROOT" config --local user.useConfigOnly true
git -C "$TARGET_ROOT" config --local --get core.hooksPath
```

最後の出力が`.githooks`ならactivation完了です。`--global`は使用しません。

commitとtagの署名も推奨baselineに含まれます。既に組織の署名keyが設定されている場合、
次を追加します。key未設定のまま有効化するとcommitできないため、署名方式の準備は
開発者または組織の手順に従ってください。

```bash
git -C "$TARGET_ROOT" config --local commit.gpgSign true
git -C "$TARGET_ROOT" config --local tag.gpgSign true
```

## 4. 検出self-testを実行する

導入先repositoryのrootで実行します。

```bash
cd "$TARGET_ROOT"
.githooks/test-detection.sh
```

self-testはruntimeで作る無効なcanaryだけを使用し、次を確認します。

- 安全なfileをPython scannerとGitleaksが許可する
- credential形式のcanaryを両方が拒否する
- matched valueをoutputへ表示しない
- Dockerまたはscannerが実行できなければ成功扱いにしない

期待するoutputは次です。

```text
PASS Python scanner accepts safe content
PASS Python scanner blocks and redacts the inert canary
PASS Gitleaks accepts safe staged content
PASS Gitleaks blocks and redacts the staged inert canary
READY PSB-SOURCE-002 detection self-test passed
```

`READY`が出ない場合はhookを導入済みにしません。本物のcredentialをtestに使わないで
ください。

## 5. 通常どおり使う

以後は通常の`git commit`と`git push`で自動実行されます。

| hook | 実行内容 |
|---|---|
| `pre-commit` | staged fileを読みやすいPython scannerとGitleaksの2系統で検査 |
| `commit-msg` | commit messageをPython scannerで検査 |
| `pre-push` | pushで新しく導入する全commitと削除済み過去fileをPython scannerで再検査 |

終了状態は次のように扱います。

| 状態 | 意味 | 操作 |
|---|---|---|
| exit `0` | 検出なし | 続行 |
| exit `1` | finding | commitまたはpushを停止 |
| exit `2`またはDockerの実行失敗 | 正常に検査できない | 停止。cleanとして扱わない |

## よくある失敗

- `python3: command not found`
  - Python 3.10以上を組織の標準手順で導入し、`python3 --version`を確認します。
- `docker: command not found`またはdaemon接続エラー
  - 管理済みDocker環境を起動します。このcontrolのために未管理Dockerを追加しません。
- `--pull never`でimage not found
  - 手順2のdigest固定`docker pull`を実行します。
- commit署名エラー
  - 組織のsigning key設定を確認します。署名を黙って無効化して通しません。
- `already exists; review and merge it manually`
  - 既存`.githooks`を上書きできないため、導入先のownerが差分をreviewして手動mergeします。
- `local ... already has a different value`
  - 既存のrepository-local Git設定を上書きできません。設定のownerが意図を確認し、採用する
    値をreviewしてください。
- `ROLLBACK removed installer-created hooks and local settings`
  - install途中で失敗し、今回作成したhookと設定を自動で切り戻した状態です。直前の
    `ERROR`を解消してから再実行します。
- 正常なfileが拒否される
  - `.githooks/scan-sensitive.py`のfile名、pattern、5 MiB上限をreview済みpull requestで
    調整します。広い除外やscanner skipは追加しません。

## CIとGitHubでも検査する

local hookは`--no-verify`、Web UI、API、未導入cloneで回避できます。最低限、次も
別に有効化します。

1. CIでdigest固定Gitleaksを実行する
2. GitHub Secret ScanningとPush Protectionを有効化する
3. 初回はfull historyを検査する
4. credential findingは最初にrevokeまたはrotateする

local hookの成功だけをrepository全体の安全性や既存履歴のclean証拠にしません。

## 切り戻し

対象cloneだけでhookを停止する場合は次を実行します。

```bash
git -C "$TARGET_ROOT" config --local --unset core.hooksPath
```

installerが追加した`push.default`、`user.useConfigOnly`、または明示指定した署名設定も
不要になる場合に限り、現在値とrepository方針をreviewして個別に解除します。installer
実行前から存在した設定は解除しません。

```bash
git -C "$TARGET_ROOT" config --local --unset push.default
git -C "$TARGET_ROOT" config --local --unset user.useConfigOnly
git -C "$TARGET_ROOT" config --local --unset commit.gpgSign
git -C "$TARGET_ROOT" config --local --unset tag.gpgSign
```

tracked `.githooks`を削除する場合は通常のpull requestでreviewします。global Git設定、
他repository、他developerのcloneは変更しません。

## control実装の検証

blueprint側のpositive／negative fixtureは次で確認できます。

```bash
make verify-control CONTROL=PSB-SOURCE-002
```

これはreference実装のtestです。実際の導入先では必ず
`.githooks/test-detection.sh`も実行してください。
