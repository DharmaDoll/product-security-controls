# PSB-SOURCE-002 導入ガイド

このガイドは、別のGitリポジトリへPSB-SOURCE-002を導入する担当者向けです。
コマンドは対象リポジトリのrootで実行します。本物のcredentialを動作確認に
使用しないでください。

## 最初に選ぶ導入方式

| 方式 | 向いている環境 | 必要なもの | Gitleaks |
|---|---|---|---|
| pre-commit framework方式（推奨） | Pythonとpre-commitを標準化できるteam | Git、Python 3.10以上、pre-commit 4.2.0以上、初回取得時のnetworkとGo実行環境 | full commit SHAからpre-commitが専用環境へbuildする |
| native hooks方式 | offline環境、または段階導入の第1段階 | Git、Python 3.10以上 | 含まれないため、CIまたは別工程で独立Gitleaks検査が必要 |

完全な推奨構成はpre-commit framework方式です。native方式だけでは`GHK-014`の
独立Gitleaks検査を満たしません。両方式を同時に有効化するとhookの配置先が競合する
ため、1つのcloneではどちらか一方を選びます。

## 導入前提

最低限必要なversionは次のとおりです。

- Git: 組織がsupportする更新済みversion
- Python: 3.10以上
- pre-commit framework方式: pre-commit 4.2.0以上
- Gitleaks: v8.30.0、commit
  `6eaad039603a4de39fddd1cf5f727391efe9974e`

Python 3.10以上が必要なのは、repository-owned scannerがPython 3.10で導入された
型構文を使用するためです。Python packageをsystem Pythonへ直接混在させず、
virtual environmentまたは組織管理のtool environmentを使用します。

### Linux / macOSでPython環境を作る

```bash
git --version
python3 --version
python3 -m venv .venv-psb-source-002
. .venv-psb-source-002/bin/activate
python --version
```

`python3 -m venv`が失敗するLinux環境では、組織が承認したOS packageからvenv
supportを導入します。distribution名やfloating packageをこのcontrolから
無条件にinstallせず、社内baselineでversionを管理してください。

### Windows PowerShellでPython環境を作る

```powershell
git --version
py -3 --version
py -3 -m venv .venv-psb-source-002
.\.venv-psb-source-002\Scripts\Activate.ps1
python --version
```

PowerShell execution policyでactivate scriptが拒否される場合、global policyを
弱めず、組織のWindows管理手順に従います。activateせずに
`.\.venv-psb-source-002\Scripts\python.exe -m ...`と明示しても構いません。

`.venv-psb-source-002/`は対象リポジトリの`.gitignore`へ追加し、commitしません。

## 推奨: pre-commit framework方式

### 1. pre-commitを固定して用意する

組織管理のpackage mirrorとlockfileがある場合は、それを優先します。直接導入する
場合もversionを省略しません。

```bash
python -m pip install "pre-commit==4.2.0"
pre-commit --version
```

この簡易コマンドはtransitive dependencyのartifact hashまでは固定しません。
継続運用では、承認済みmirrorへwheelを保存し、platformごとのlockfileとSHA-256を
管理してください。取得やinstallが失敗した状態でhookを有効化してはいけません。

### 2. controlファイルを対象リポジトリへコピーする

このblueprintリポジトリを`$PSB_ROOT`、導入先を`$TARGET_ROOT`として説明します。
最初に実在する絶対パスを設定し、取り違えがないことを確認します。

```bash
PSB_ROOT="/absolute/path/to/product-security-controls"
TARGET_ROOT="/absolute/path/to/target-repository"
test -f "$PSB_ROOT/controls/source-protection/git-hooks-baseline/control.yaml"
git -C "$TARGET_ROOT" rev-parse --show-toplevel
```

```bash
cp -R "$PSB_ROOT/controls/source-protection/git-hooks-baseline/secure/.githooks" \
  "$TARGET_ROOT/.githooks"
cp "$PSB_ROOT/controls/source-protection/git-hooks-baseline/secure/pre-commit-framework/.pre-commit-config.yaml" \
  "$TARGET_ROOT/.pre-commit-config.yaml"
chmod +x "$TARGET_ROOT/.githooks/pre-commit" \
  "$TARGET_ROOT/.githooks/commit-msg" \
  "$TARGET_ROOT/.githooks/pre-push" \
  "$TARGET_ROOT/.githooks/pre-push-pre-commit"
```

Windows PowerShellでは次のようにcopyします。hookは`sh`を使用するため、Windows版
Gitに含まれるGit Bashを利用できることも確認します。

```powershell
$PsbRoot = "C:\absolute\path\to\product-security-controls"
$TargetRoot = "C:\absolute\path\to\target-repository"
Test-Path "$PsbRoot\controls\source-protection\git-hooks-baseline\control.yaml"
git -C $TargetRoot rev-parse --show-toplevel
Copy-Item -Recurse `
  "$PsbRoot\controls\source-protection\git-hooks-baseline\secure\.githooks" `
  "$TargetRoot\.githooks"
Copy-Item `
  "$PsbRoot\controls\source-protection\git-hooks-baseline\secure\pre-commit-framework\.pre-commit-config.yaml" `
  "$TargetRoot\.pre-commit-config.yaml"
```

既に`.githooks/`または`.pre-commit-config.yaml`がある場合は上書きせず、既存hook、
language、stage、excludeをreviewして手動mergeします。特に広い`exclude`、`SKIP`、
`always_run: false`へ弱めないでください。

コピー後、次をreview対象としてcommitします。

- `.githooks/pre-commit`
- `.githooks/commit-msg`
- `.githooks/pre-push`
- `.githooks/pre-push-pre-commit`
- `.githooks/scan-sensitive.py`
- `.pre-commit-config.yaml`

### 3. framework hooksを明示的に有効化する

native方式の設定が残っていると`.git/hooks`へinstallしたframework hookが実行されない
ため、まずlocal設定だけを確認します。

```bash
git config --local --get core.hooksPath
```

出力が`.githooks`なら、方式を切り替えることを確認してからlocal設定だけを解除します。

```bash
git config --local --unset core.hooksPath
pre-commit validate-config .pre-commit-config.yaml
pre-commit install --install-hooks
```

`pre-commit install --install-hooks`はconfigの
`default_install_hook_types`により`pre-commit`、`commit-msg`、`pre-push`を導入します。
初回はGitleaks source取得とbuildでnetwork accessが発生します。完了しなければ
導入失敗です。

### 4. 導入状態を確認する

blueprint側のcheckerを使用します。

```bash
python3 "$PSB_ROOT/controls/source-protection/git-hooks-baseline/scripts/check-adoption.py" \
  --repository "$TARGET_ROOT" --mode framework
```

最後に次が表示されることを確認します。

```text
READY PSB-SOURCE-002 framework activation verified
```

### 5. Gitleaksの検出canaryを実行する

本物のsecretやprovider固有token形式ではなく、Gitleaksのgeneric ruleを確認するための
無効なcanaryを一時fileとして使用します。

```bash
printf '%s\n' \
  'api_key = "hF9kLm2Np4Qr6St8Uv0Wx3Yz5Ab7Cd9E"' \
  > .psb-source-002-canary.txt
git add .psb-source-002-canary.txt
pre-commit run gitleaks --files .psb-source-002-canary.txt
git restore --staged .psb-source-002-canary.txt
rm .psb-source-002-canary.txt
```

Gitleaksがnon-zeroで終了し、matched valueを表示せずfindingを報告することが成功です。
canaryがpassした場合、またはtool errorになった場合は導入を完了扱いにしません。
cleanupは検出結果にかかわらず行います。

### 6. 通常の動作を確認する

```bash
pre-commit run --all-files
git config --local --get core.hooksPath
git status --short
```

2番目のコマンドはframework方式では空であることが通常です。既存repositoryでfindingが
出た場合、広い除外で通さず、credentialのrevokeまたはrotate、false positive review、
期限付き例外の順で扱います。

## native hooks方式

### 1. repository-owned hooksをコピーする

```bash
cp -R "$PSB_ROOT/controls/source-protection/git-hooks-baseline/secure/.githooks" \
  "$TARGET_ROOT/.githooks"
chmod +x "$TARGET_ROOT/.githooks/pre-commit" \
  "$TARGET_ROOT/.githooks/commit-msg" \
  "$TARGET_ROOT/.githooks/pre-push" \
  "$TARGET_ROOT/.githooks/pre-push-pre-commit"
```

既存`.githooks/`がある場合は上書きせずreviewしてmergeします。

### 2. 対象cloneだけで有効化する

```bash
git config --local core.hooksPath .githooks
git config --local push.default simple
git config --local user.useConfigOnly true
git config --local commit.gpgSign true
git config --local tag.gpgSign true
```

`--global`は使用しません。このcontrolは他のrepositoryやdeveloper設定を黙って変更しません。

### 3. commit署名identityを準備する

既に組織管理のsigning設定がある場合は変更しません。SSH署名を使用する例は次の
とおりです。公開鍵fileとidentityは組織の値へ置き換えます。

```bash
git config --local gpg.format ssh
git config --local user.signingKey "$HOME/.ssh/id_ed25519.pub"
git config --local user.name "YOUR REVIEWED NAME"
git config --local user.email "YOUR APPROVED EMAIL"
```

private keyをrepositoryへコピーしてはいけません。GPG、SSH、hardware-backed signing、
GitHub managed signingのどれを使うかは組織policyに従います。署名keyを準備せず
`commit.gpgSign=true`だけ設定するとcommitが失敗します。

### 4. 導入状態を確認する

```bash
python3 "$PSB_ROOT/controls/source-protection/git-hooks-baseline/scripts/check-adoption.py" \
  --repository "$TARGET_ROOT" --mode native
```

期待する最終行は次です。

```text
READY PSB-SOURCE-002 native activation verified
```

native方式でもCIまたは別の管理工程へGitleaksを追加し、検出canaryを実行します。

## standalone Gitleaks binaryを導入する場合

pre-commit framework方式では専用環境へGitleaksをbuildするため、通常はstandalone
binaryを別途installしません。CIやnative方式でbinaryを使う場合は、OS packageの
floating versionではなく公式v8.30.0 release artifactとSHA-256を使用します。

主要architectureの公式release digestは次のとおりです。

| OS / architecture | artifact | SHA-256 |
|---|---|---|
| Linux x64 | `gitleaks_8.30.0_linux_x64.tar.gz` | `79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e` |
| Linux arm64 | `gitleaks_8.30.0_linux_arm64.tar.gz` | `b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f` |
| macOS Intel | `gitleaks_8.30.0_darwin_x64.tar.gz` | `ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5` |
| macOS Apple Silicon | `gitleaks_8.30.0_darwin_arm64.tar.gz` | `b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7` |
| Windows x64 | `gitleaks_8.30.0_windows_x64.zip` | `54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573` |

download、checksum検証、展開の例です。`curl | sh`は使用しません。

```bash
curl --fail --location --remote-name \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz
echo '79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e  gitleaks_8.30.0_linux_x64.tar.gz' \
  | sha256sum --check -
tar -xzf gitleaks_8.30.0_linux_x64.tar.gz gitleaks
./gitleaks version
```

macOSでは`sha256sum`の代わりに`shasum -a 256`を使用できます。Windows PowerShell
x64の例は次のとおりです。

```powershell
$Artifact = "gitleaks_8.30.0_windows_x64.zip"
$ExpectedSha256 = "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573"
Invoke-WebRequest "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/$Artifact" -OutFile $Artifact
$ActualSha256 = (Get-FileHash -Algorithm SHA256 $Artifact).Hash.ToLowerInvariant()
if ($ActualSha256 -ne $ExpectedSha256) { throw "Gitleaks checksum mismatch" }
Expand-Archive $Artifact -DestinationPath .\gitleaks-v8.30.0
.\gitleaks-v8.30.0\gitleaks.exe version
```

checksum不一致、architecture不一致、download失敗、version不一致はすべて導入失敗
です。binaryを承認済みtool directoryへ移す権限と所有者は組織policyに従います。

## control自体を検証する

blueprintリポジトリで次を実行します。

```bash
make verify-control CONTROL=PSB-SOURCE-002
```

これはblueprint fixtureの検証です。導入先repositoryが安全という証拠にはならないため、
導入先では`check-adoption.py`、Gitleaks canary、通常fileのcommit、synthetic findingの
block、pre-pushの動作を別途確認します。

## GitHub側とCIで必ず補完する

local hookは`--no-verify`、`SKIP`、Web UI、API、未導入cloneで回避できます。
production導入では最低限、次を別々に有効化します。

1. pull requestまたはpush CIでGitleaksを実行し、tool failureもblockingにする
2. GitHub Secret ScanningとPush Protectionを有効化する
3. bypassを監査し、owner、理由、期限、remediationを記録する
4. full historyの初回scanを実行し、最新treeだけをclean判定に使わない

CIのthird-party Actionはfull commit SHAへ固定し、workflow permissionを明示的かつ
最小にします。untrusted pull requestへprivileged credentialを渡しません。

## よくある失敗

| 症状 | 確認すること | 対処 |
|---|---|---|
| `python3: command not found` | `python3 --version`またはWindowsの`py -3 --version` | Python 3.10以上を組織管理手順で導入し、PATHを再確認する |
| `No module named venv` | OSのPython packaging | 承認済みOS packageでvenv supportを追加する。system pipへ直接混在させない |
| `pre-commit: command not found` | virtual environmentがactiveか | environmentをactivateするか、environment内の実行fileを絶対パスで呼ぶ |
| Gitleaks setupがnetworkで失敗 | proxy、CA、GitHub access、Go実行環境 | 原因を直して再実行する。hookをskipして成功扱いにしない |
| commit時に署名で失敗 | `user.signingKey`、agent、公開鍵、signing format | 組織のsigning方式を設定し、署名を無効化して回避しない |
| framework hookが動かない | `git config --local --get core.hooksPath` | native設定との競合を解消し、`pre-commit install --install-hooks`を再実行する |
| `--no-verify`ならpushできる | local hookの設計上の限界 | CI required checkとserver-side push protectionでblockする |
| canaryをGitleaksが検出しない | Gitleaks revision、config、hook environment | 導入を停止し、pinとbuild logをreviewする。cleanとして扱わない |

## 無効化・切り戻し

障害対応で切り戻す場合も、security ownerの承認とserver-side補完を先に用意します。

framework方式:

```bash
pre-commit uninstall --hook-type pre-commit
pre-commit uninstall --hook-type commit-msg
pre-commit uninstall --hook-type pre-push
```

native方式:

```bash
git config --local --unset core.hooksPath
```

tracked `.githooks/`や`.pre-commit-config.yaml`を削除する場合は通常のpull requestで
reviewします。global Git設定、他clone、developer端末全体を一括変更しません。

## 導入完了条件

- `check-adoption.py`が選択した方式で`READY`を返す
- 通常fileのcommitが成功する
- repository-owned scannerとGitleaks canaryが値を表示せずblockする
- commit messageとpre-pushのnegative testがblockする
- hookまたはscanner failureが操作をblockする
- CI secret scanとGitHub Push Protectionが独立して有効である
- bypass、false positive、例外、credential incidentのownerと手順が決まっている

## 公式資料

- [PythonのWindows利用ガイド](https://docs.python.org/3/using/windows.html)
- [Python virtual environments](https://docs.python.org/3/library/venv.html)
- [pre-commit installation](https://pre-commit.com/#install)
- [Gitleaks official repository](https://github.com/gitleaks/gitleaks)
- [Gitleaks v8.30.0 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0)
- [Git hooks](https://git-scm.com/docs/githooks)
- [GitHub Push Protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)
