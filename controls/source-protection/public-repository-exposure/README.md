# PSB-SOURCE-003: 公開リポジトリ露出とGitHub dorking検証

## セキュリティ上の問題

公開リポジトリでは、source codeだけでなく、Git履歴、Issue、Pull Request、
Discussion、Wiki、Actions logやartifact、Release、Pagesも第三者から探索されます。
攻撃者はGitHub検索や外部検索エンジンを使い、secret、内部hostname、顧客情報、
非公開設計、debug情報などを組み合わせて侵入や標的選定に利用できます。

最新treeからファイルを削除したこと、repositoryをprivateへ変更したこと、検索結果が
0件だったことのいずれも、過去の公開が消えた証明にはなりません。

## このcontrolを一枚で理解する

### 誰から、または何から守るか

- GitHub検索、commit URL、fork、artifactを使って公開情報を集める外部攻撃者
- credential公開直後に自動取得するsecret harvesting botとcrawler
- Push Protectionを誤ってbypassするcontributorや侵害されたwrite account
- visibilityを誤設定するrepository管理者
- API rate limit、不完全clone、search index制限、scanner停止などの検査失敗

### 何が対象か

- public repositoryのdefault branchと現在のfile
- 全branch、tag、到達可能な過去commit
- Issue、Pull Request、Discussion、Wiki
- Actions logとartifact、Release asset、Pages
- public fork、mirror、clone、cached view、PR reference
- 自社domain、従業員email domain、内部hostname、codename、機密区分marker

### 何をするか

| 検査層 | 実施内容 | 主に見つけるもの |
| --- | --- | --- |
| Repository-scoped Web検索 | 一つの`owner/repository`へqueryを固定 | 把握済みrepositoryの現在の公開code |
| Global attacker-view Web検索 | 自社indicatorを必須にしてGitHub.com全体を検索 | inventory外のfork、mirror、個人repository |
| Complete-clone scan | 全branchとtagのfile versionをoffline scan | default branchから削除された過去情報 |
| GitHub surface review | Issue、PR、Wiki、Actions、Release等を確認 | Git tree外へ貼付・生成・配布された情報 |
| Response verification | revoke/rotate、copy調査、再scanを確認 | 取得済みcredentialと残存copyによる継続risk |

### なぜ複数の方法を使うか

攻撃者は一つの入口だけを使いません。GitHub Code Searchは攻撃者と同じ現在の公開検索面を
確認できますが、default branchとindex対象に限られます。Complete cloneは履歴を
検査できますが、IssueやActions artifact、未知のforkは含みません。Secret Scanningも
組織固有のcodenameや全情報分類を知りません。

そのため、各チェックは重複ではなく異なるblind spotを埋めます。生成チェックリストの
各行には、想定する脅威主体、具体的な攻撃／失敗、なぜその行が必要かを記録しています。

このコントロールは、次の5つを一つの評価にします。

1. 一つの対象repositoryへ限定したGitHub dork query
2. 全branchとtagから到達可能なGit履歴のoffline secret scan
3. code以外の公開面、Secret Scanning、Push Protection、bypass reviewの
   sanitized evidence snapshot
4. 自社domain、email domain、機密区分markerを使った組織固有情報の全履歴scan
5. 同じ組織固有indicatorを使ったGitHub.com全体の通常Web Code Search

「dorking」は攻撃者と同じ公開検索面をread-onlyで確認する防御目的に限定します。
GitHub.com全体を検索する場合も、自社が管理するdomain、email domain、codename、
機密markerの完全一致を必須とし、`password`だけのような無差別queryは生成しません。

## 脅威と信頼境界

信頼境界は、組織内で扱うsource、metadata、CI出力がGitHubの公開repository networkへ
移る箇所です。主な失敗は次のとおりです。

- public化の承認と期限がなく、非公開情報を含むrepositoryが公開される
- current codeだけを検査し、削除済みcommitや別branch、tagを見逃す
- Issue、PR、Discussion、Wiki、Actions、Release、Pagesを検査対象から外す
- GitHub検索queryが対象repositoryへ限定されず、不要な第三者情報を収集する
- Secret Scanning、Push Protection、bypass reviewが無効
- scannerの失敗や未完了検索を0 findingsとして扱う
- secretを履歴から削除するだけで、credentialをrevokeまたはrotateしない
- fork、clone、cached view、PR referenceへ残った公開物を確認しない

## 実装

安全な例:

- `secure/exposure-policy.json`
  - public visibilityのowner、review日、expiryを要求
  - 全queryに`repo:{repository}`を要求
  - code、履歴、Issue、PR、Discussion、Wiki、Actions、Release、Pagesを列挙
  - revoke/rotateを履歴cleanupより先に実施
- `secure/evidence-snapshot.json`
  - secret値や検索結果本文を含まないsanitized evidence
  - query、公開面、repository controlごとに完了状態を記録
- `scripts/scan-git-history.py`
  - `PSB-SOURCE-002`のrepository-owned scannerを再利用
  - `git rev-list --all`で到達可能な全commitを検査
  - matched valueを表示せず、clean、finding、実行errorを終了コードで分離
- `secure/organization-indicators.json`
  - `example.invalid`だけを使用したsyntheticな自社domain／email domainサンプル
  - `INTERNAL-ONLY-SYNTHETIC`等の機密区分markerサンプル
- `scripts/scan-organization-exposure.py`
  - 全branchとtagから到達可能なfile versionを走査
  - indicator ID、commit短縮ID、pathだけを出力
  - matched domain、email address、marker本文を出力しない
- `scripts/generate-github-web-dorks.py`
  - GitHub.comの通常Code Searchで開けるclickable URLを生成
  - exact string、Boolean、括弧、`content:`、`path:`、`language:`、正規表現を使用
  - 既定は攻撃者視点のGitHub全体、`--owner`指定時は一つのorganizationへ限定

安全でない例:

- repository scopeのない検索
- current codeだけの検査
- 無効なSecret ScanningとPush Protection
- history scanner errorを0 findingsとして記録
- revoke/rotateを含まない削除だけの対応

安全でない例は隔離されたfixtureであり、実環境へ適用しません。

## 検証

```bash
make verify-control CONTROL=PSB-SOURCE-003
```

テストは一時Git repositoryを作成し、次を確認します。

- 安全なpolicyとsnapshotが受け入れられる
- repository scopeのないqueryと欠落した公開面が拒否される
- 最新treeから削除済みのsynthetic tokenを過去commitから検出する
- 削除済みfile内のsyntheticな自社domain、email、機密markerを検出する
- 自社indicatorを必ず含むGitHub.com全体向けWeb dork URLを生成する
- matched token値を出力しない
- scannerや入力のerrorをcleanから区別する

終了コード:

| 終了コード | 意味 |
| --- | --- |
| `0` | 必須検査が完了し、未解決findingなし |
| `1` | policy違反または公開候補を検出 |
| `2` | 入力、Git、scanner等のため検査を完了できない |

## 導入方法

`secure/exposure-policy.json`を組織用に複製し、`{repository}`はpolicyでは
placeholderのまま維持します。実行時に対象の`owner/repository`へ置換して各queryを
GitHub UI、承認済みCLI、またはAPIで実行します。

queryはあくまでreview seedです。組織固有のhostname、メールdomain、製品codename、
ticket prefix、cloud account識別子を追加します。ただし、実際のsecret値、customer
identifier、個人情報をquery catalogへ記録してはいけません。

履歴検査:

```bash
python3 controls/source-protection/public-repository-exposure/scripts/scan-git-history.py .
```

### 組織運用向け補完ツール: TruffleHog

TruffleHogは開発者のpre-commitや端末baselineとしては推奨せず、Security／AppSecが
管理する次の用途の紹介ツールとして位置付けます。

- repository導入時の全Git履歴棚卸し
- scheduled full-history scan
- secret漏洩incidentの追加調査
- 検出したcredentialが現在も有効かを確認し、対応優先度を判断する補助
- GitHub organization配下など複数repositoryの横断調査

Git履歴を対象にするときは、current worktreeだけを見るfilesystem scanと区別し、
complete cloneのGit historyを検査します。ただし、本controlの採用実装とテストは
repository-owned `scan-git-history.py`を使用しており、TruffleHogをdownloadまたは
実行しません。

将来、組織運用adapterとして採用する場合は、repository-owned scannerでは再現できない
full-historyまたはcredential verificationのgapをfixtureで示し、versionとartifact
integrity、AGPL-3.0の利用・配布条件、provider別egress、rate limit、redaction、
`clean`／`finding`／`ERROR`の分離をレビューします。credential verificationは
外部providerへ通信し得るため、developer hookやuntrusted pull requestから暗黙に
実行しません。

固定した参照sourceと採用境界は
[`REF-SOURCE-001`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-source-001)
に記録しています。

### 自社domain・email・機密markerの検査

`secure/organization-indicators.json`をrepository外のaccess-controlledな場所へ複製し、
次を組織固有の値へ変更します。

- `domains`: 内部hostnameや自社専用domainのsuffix
- `email_domains`: public sourceへ掲載しない従業員email domain
- `confidentiality_markers`: `INTERNAL ONLY`、社外秘header、proprietary code header等

各indicatorには値を含まない安定した`ORG-*` IDを付けます。`*`などのwildcard、
4文字未満のmarker、重複ID、空の設定は拒否されます。実際のemail addressやsecret
そのものは登録せず、domain suffixまたは文書分類markerを使用します。

対象public repositoryの全branchとtagを取得した完全cloneに対して実行します。

```bash
python3 \
  controls/source-protection/public-repository-exposure/scripts/scan-organization-exposure.py \
  /path/to/complete-public-clone \
  --indicators /controlled/path/organization-indicators.json
```

出力例:

```text
BLOCK ORG-EMAIL-INTERNAL "0123456789ab:path/to/file.txt"
REJECTED 1 organization exposure finding(s); matched values suppressed
```

この出力はmatched emailやdomainを含みません。実際の値をCI log、spreadsheet、
ticketへコピーせず、調査担当者がaccess-controlledな環境で該当commitとpathを
確認します。5 MiBを超えるfile versionなど、設定上scanできなかった対象が一つでも
あれば終了コード`2`とし、cleanにはしません。

既知のrepositoryだけでなく、organization配下の全public repositoryをinventory化し、
各完全cloneへ同じscanを実行します。個人fork、移管済みrepository、組織外のmirrorは
別途GitHub検索とincident responseの対象です。組織固有indicatorをGitHub検索へ
送信できるかは、情報分類と利用規約を確認してから判断してください。

### 攻撃者視点のGitHub.com Web検索

GitHub Code Searchへ直接アクセスするURLをMarkdownとして生成します。既定では
`repo:`や`org:`を付けず、サインイン中のaccountから見えるGitHub全体を検索します。
攻撃者に近い公開範囲だけを確認する場合は、private repositoryへのaccessを持たない
承認済みaudit accountを使用します。GitHub Code Searchはpublic codeでもsign-inが
必要です。

```bash
python3 \
  controls/source-protection/public-repository-exposure/scripts/generate-github-web-dorks.py \
  --indicators /controlled/path/organization-indicators.json \
  --output generated/assessments/github-public-exposure-dorks.md
```

生成される代表的なquery:

```text
content:"corp.example.invalid"
content:"corp.example.invalid" AND (password OR token OR secret OR api_key OR client_secret OR credential)
content:"corp.example.invalid" AND (path:*.env OR path:*.yml OR path:*.yaml OR path:*.json OR path:*.properties OR path:*.tf)
/https?:\/\/[A-Za-z0-9._-]*corp\.example\.invalid/
content:"@corp.example.invalid"
content:"INTERNAL-ONLY-SYNTHETIC" AND NOT is:generated AND NOT is:vendored
```

`--owner example-org`を付けると全queryへ`org:example-org`を追加できます。最初は
owner scopeで運用確認し、その後に承認を得てglobal searchを行う使い方もできます。

生成Markdownには実際の組織indicatorが平文とURL encodingの両方で含まれます。
public repositoryへcommitせず、access-controlledな`generated/assessments/`や
case management領域へ保存してください。検索結果本文を証跡へコピーせず、
repository、path、query ID、判定、incident referenceだけを記録します。

GitHub Web検索はdefault branchだけが対象で、結果は100件に制限され、exhaustive
searchではありません。またbinary、350 KiB超のfile、非UTF-8 file等はindex対象外
です。このため「Web検索0件」だけでcleanとせず、把握済みrepositoryの完全clone scan、
Secret Scanning、fork／cache調査を組み合わせます。

GitHub側の結果は`secure/evidence-snapshot.json`と同じ構造で保存します。
検索結果本文、secret値、credential、個人情報をsnapshotへコピーせず、
`evidence_code`、件数、完了状態だけを残します。実際の証跡はaccess-controlledな
case management systemで管理します。

公開repositoryの推奨頻度:

- public化前
- visibility、Pages、Wiki、Discussion、Actions設定の変更時
- release前
- Secret Scanning alertまたは外部報告の受領時
- 定期的なscheduled scan

## 検出後の対応

secretまたはcredentialを検出した場合、最初にrevokeまたはrotateします。その後、
current contentの削除、必要性を評価したhistory rewrite、fork／clone所有者との調整、
cached viewとPR referenceのGitHub Support依頼、全公開面の再scanを行います。

一般的な内部情報や個人情報ではcredential rotationだけで影響を止められないため、
data owner、privacy、legal、incident responseと影響範囲を判断します。

false positiveや正当な公開情報は、owner、理由、対象、期限を持つreview済み例外として
扱います。queryやscannerへ広いignoreを追加しません。

## 制限事項と残存リスク

- GitHub Code Searchは全Git履歴のscanではありません
- GitHub Code Searchはdefault branch、index対象、query長、表示件数に制限があり、
  exhaustive searchではありません
- 組織固有indicator scanは、登録されていないcodename、画像内文字列、encode、
  暗号化、分割文字列、意味的に機密なcodeを自動分類できません
- Secret Scanningも全種類のsecretや組織固有情報を完全には検出しません
- 外部検索index、archive、第三者clone、screenshot、download済みartifactは
  repository ownerが削除できない場合があります
- public repositoryをprivateへ変更しても既存のpublic forkは公開状態で残り得ます
- history rewriteはcommit IDを変更し、古いcloneからの再混入を招く可能性があります
- `git rev-list --all`はlocal cloneが取得していないremote refやGitHub固有surfaceを
  検査できません
- 0 findingsは「秘密が存在しない」という完全性の証明ではありません

## Framework mappingの読み方

mappingは、このcontrolが該当する攻撃行動、secret保護、情報収集・確認を支援する
関係を示します。CISA、MITRE ATT&CK、SSDF、OpenSSFへの準拠や完全なcoverageを
主張するものではありません。

## 参照資料

- [GitHub Secret Scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
- [GitHub Push Protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)
- [GitHub repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)
- [GitHub fork visibility](https://docs.github.com/en/pull-requests/reference/forks)
- [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Filtering and searching issues and pull requests](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/filtering-and-searching-issues-and-pull-requests)
- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitHub Code Search limitations](https://docs.github.com/en/search-github/github-code-search/about-github-code-search)
- [TruffleHog Git and filesystem scan distinction](https://trufflesecurity.com/blog/trufflehog-commands-git-vs-filesystem)
- [TruffleHog GitHub source capabilities](https://trufflesecurity.com/docs/github)
- [TruffleHog reviewed source snapshot](https://github.com/trufflesecurity/trufflehog/tree/ac39a5653be27b1a6613d75e18535764cc7a11cf)
