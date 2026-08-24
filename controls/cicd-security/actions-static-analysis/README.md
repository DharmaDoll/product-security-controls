# PSB-CICD-003: GitHub Actionsの静的解析

## このcontrolを一枚で理解する

### セキュリティ上の問題

Workflow変更にcommand injection、mutable dependency、危険なtrigger、過剰権限が入っても、通常reviewだけでは見落とされやすい。

### 誰から、または何から守るか

悪意あるcontributor、設定ミス、zizmor配布物の差替え、untrusted PRとprivileged SARIF uploadの混同、scanner失敗から守る。

### 何が対象か

GitHub Actions workflow、zizmor binary、scanner workflow、SARIF evidence、untrusted PR gate、trusted reporting job。

### 何をするか

Versionとchecksumを固定したzizmorでworkflowを静的解析し、untrusted gatingとprivileged SARIF uploadを別trust boundaryに分離する。

### 成功状態

Scanner identityが固定され、findingはblockされ、clean・finding・scanner errorが別状態となり、repository workflowもreview済みpolicyへ一致する。

### 対象外・残余リスク

Static analysisはjobが実際に必要とする権限、external Actionの内部挙動、runtime network・credential accessを完全には証明しない。

## 目的

GitHub Actions workflowの変更時に、command injection、危険なtrigger、
過大な`permissions`、mutableなAction参照などを、レビューだけに依存せず
`zizmor`で検出します。

このcontrolは「スキャンを実行した」ことだけを成功条件にしません。

- findingあり: policy violation（exit 1）
- findingなし: clean（exit 0）
- scanner失敗、入力不正、SARIF破損: verification error（exit 2）

の3状態を区別します。

## Threat / failure scenario

攻撃者または誤操作により、安全でないworkflow変更がpull requestへ追加されます。
静的解析がない場合、`${{ }}`の危険な展開、`pull_request_target`の誤用、
過大なtoken権限、floating tagなどがdefault branchへ到達します。

また、SARIF生成やscanner自体が失敗したのに「resultが0件」と解釈すると、
検証不能な状態がcleanへ化けます。

## Insecure example

[`insecure/workflow.yml`](insecure/workflow.yml)は、次の問題を意図的に含むfixtureです。

- `permissions: write-all`
- `actions/checkout@v6`と`zizmor-action@v0.6.1`のmutable参照
- scanner versionが`latest`
- pull request上でSARIF write相当のmodeを分離していない
- online audit用tokenとcheckout credentialの境界が不明確
- input不在をcleanに見せ得る`fail-on-no-inputs: false`

このfixtureは`.github/workflows`外に隔離され、実行されません。

## Secure implementation

採用workflowは
[`secure/workflow.yml`](secure/workflow.yml)と同一です。

```text
pull_request / push
        |
        +--> gate
        |    contents: readのみ
        |    tokenをscannerへ渡さない
        |    findingで失敗してmerge gateに利用
        |
        +--> report（mainへのpushだけ）
             security-events: write
             SARIFをSecurity tabへupload
```

blocking jobとreporting jobを分離する理由は、SARIF modeではfindingがあっても
scanner step自体は成功する一方、SARIF uploadには`security-events: write`が必要
だからです。untrusted pull requestではwrite権限を持たないblocking modeだけを
実行し、privilegedなreport jobはtrustedな`main` pushへ限定します。

両jobはrepositoryのworkflowをデータとして解析するだけで、pull request内の
scriptやbuildを実行しません。

## Version and integrity pinning

- `zizmorcore/zizmor-action`:
  `6fc4b006235f201fdab3722e17240ab420d580e5`（v0.6.1）
- `zizmor`: `1.28.0`
- OCI image digest:
  `sha256:8e6b3e4fb74d1aa5d23e83ea369f386c66eced0d1fb944d32cd8b2aac100b00d`

固定したActionは内蔵version tableからこのdigestを解決し、
`ghcr.io/zizmorcore/zizmor:1.28.0@sha256:...`として取得します。
未知versionは失敗するため、tagだけを信用する構成ではありません。

`online-audits: false`かつ`token: ""`とし、scanner containerへ
`GITHUB_TOKEN`を渡しません。代わりに、GitHub APIが必要なonline-only auditは
対象外になります。`persona: auditor`でinformational/low severityを暗黙に
抑制せず、triage対象として可視化します。

## 導入

採用済みworkflowは
[`/.github/workflows/actions-security.yml`](../../../.github/workflows/actions-security.yml)
です。別repositoryへ導入する場合はsecure exampleをコピーし、次を設定します。

1. `gate`をrequired status checkにする
2. public repository、またはGitHub Code Securityを利用できるprivate repositoryで
   SARIF uploadを有効にする
3. code-scanning alertをmerge条件に使う場合はrulesetも設定する
4. version更新時はAction commit、内蔵digest、release noteを再レビューする

## 検証

```bash
make verify-control CONTROL=PSB-CICD-003
```

検証は次を実行します。

- secure/insecure workflowのpositive/negative test
- Action SHA、scanner version、権限境界、token非注入のpolicy検証
- clean SARIF、finding SARIF、scanner failure SARIFの状態判定
- malformed SARIFのfail-closed
- repository採用workflowとsecure exampleの一致確認

期待される最終出力:

```text
PASS secure scanner workflow policy accepted
PASS mutable and over-privileged scanner workflow rejected
PASS clean and finding SARIF states distinguished
PASS scanner execution failure distinguished from a clean result
PASS malformed SARIF fails closed
PASS adopted workflow matches the reviewed secure example
```

## Triageと例外

findingは、該当workflowが実際に到達可能か、attacker-controlled inputか、
付与権限とsecretの有無を確認してtriageします。件数を減らすための広範なignoreは
認めません。false positiveを抑制する場合も、rule、対象path、owner、理由、
期限を限定したsecurity exceptionとして別途管理します。

## 補完ツールの採用境界

このcontrolの採用済みscannerは`zizmor`です。複数scannerを無条件に重ねず、
同じsecure/insecure fixtureを候補ツールでも評価し、現在の検証経路が見逃す
必須の問題を再現できた場合だけ補完します。

| ツール | 想定する補完範囲 | 現在の扱い |
| --- | --- | --- |
| `zizmor` | GitHub Actionsのsecurity-focused static analysis | 採用済み。Action commit、scanner version、OCI digestを固定して実行 |
| `actionlint` | syntax、expression type、Action input/output、reusable workflow interface、埋め込みshell/Pythonの検証 | 評価候補。security findingと一般lintを区別し、固有の失敗fixtureが確認できるまで追加しない |
| `poutine` | pipeline定義にまたがるsupply-chain vulnerabilityやrepository／organization inventory | 評価候補。`PSB-CICD-001..005`と重複しないcontrol gapが確認できるまで追加しない |

候補を採用するときは、少なくとも次を満たします。

1. 既存経路では検出できず、候補だけが検出するnegative fixtureを追加する
2. executable versionと配布artifactのchecksumまたは署名を固定する
3. `clean`、`finding`、tool/input failureの終了状態を分離する
4. untrusted pull requestへtokenやwrite権限を渡さない
5. 重複findingのowner、抑制単位、更新手順、CI時間を文書化する

この比較判断は
[`SECURITY_GUIDANCE_SOURCES.md`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-002)
に固定sourceとともに記録します。

## 限界と運用コスト

静的ruleで検出しやすいのは、template injection、危険なtrigger、mutable参照、
明示的な過大権限などです。一方、次は別controlまたは人手レビューが必要です。

- jobが実行する処理に対して「実効権限が本当に最小か」
- Environment protection、ruleset、repository設定の設計
- third-party Action固有inputの安全性
- invoked scriptやbuild tool内部のtaint、network egress、credential利用
- findingのreachabilityとbusiness context

各pull requestでcontainer imageを取得して全workflowを解析するため、CI時間と
registry availabilityへの依存も増えます。scanner取得失敗はcleanではなく
job failureとして扱います。

## References

- [zizmor GitHub Actions integration](https://docs.zizmor.sh/integrations/)
- [zizmor audit rules](https://docs.zizmor.sh/audits/)
- [zizmor exit status and SARIF behavior](https://docs.zizmor.sh/usage/)
- [zizmor-action v0.6.1 source](https://github.com/zizmorcore/zizmor-action/tree/6fc4b006235f201fdab3722e17240ab420d580e5)
- [zizmor reviewed source snapshot](https://github.com/zizmorcore/zizmor/tree/6ea55f583ef6681a59b1c180950e47861a3c0293)
- [actionlint reviewed source snapshot](https://github.com/rhysd/actionlint/tree/011a6d15e749bb3f2d771eed9c7aa0e7e3e10ee7)
- [poutine reviewed source snapshot](https://github.com/boostsecurityio/poutine/tree/bd4c1f86fe8cfe61b456f1ea2b2106ce0cac51d6)
- [GitHub: secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Flatt Security: GitHub Actionsのセキュリティ対策 第4回](https://blog.flatt.tech/entry/2026-github-actions-security-part4)
- [Flatt Security tool-comparison source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-008)
