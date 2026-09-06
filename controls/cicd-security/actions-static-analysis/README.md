# PSB-CICD-003: GitHub Actionsの静的解析

## このcontrolを一枚で理解する

### セキュリティ上の問題

Workflow変更にcommand injection、mutable dependency、危険なtrigger、過剰権限が入っても、通常reviewだけでは
見落とされやすい。Scannerが失敗した状態をfindingなしと扱うと、検証できていない変更がdefault branchへ到達する。

### 誰から、または何から守るか

悪意あるcontributor、workflow設定ミス、zizmor配布物の差替え、untrusted PRとprivileged SARIF uploadの混同、
scanner／registry障害から守る。

### 何が対象か

GitHub Actions workflow、zizmor Actionとcontainer、pull-request gate、SARIF reporting、scanner resultである。

### 何をするか

Versionと配布identityを固定したzizmorでworkflowを静的解析し、tokenなしのblocking gateと権限を持つSARIF reportingを
別jobにする。Clean、finding、scanner errorを別状態にする。

### 成功状態

Safe PRではunprivileged gateが成功し、security findingまたはscanner errorでは失敗する。Gateはrequired checkであり、
SARIF write権限はtrusted default-branch pushだけに存在する。

### 対象外・残余リスク

Static analysisはjobの実効権限が処理に対して最小か、external Action内部の挙動、呼び出すscript、runtime network／
credential access、provider rulesetがliveで有効かを完全には証明しない。

## セキュリティ効果が生まれる場所

このcontrolの主実装は、copy可能な
[secure workflow](secure/workflow.yml)とGitHub側のrequired status checkである。

```text
pull_request / push
        |
        +--> gate
        |    contents: readのみ
        |    tokenをscannerへ渡さない
        |    finding／scanner errorで失敗
        |    required status checkとしてmergeを止める
        |
        +--> report（trusted default-branch pushだけ）
             actions: read／contents: read／security-events: write
             SARIFをCode Scanningへupload
```

`gate`と`report`を分ける理由は、SARIF modeではfindingがあってもreportingを継続する場合があり、SARIF uploadには
`security-events: write`が必要だからである。Untrusted pull requestにはblocking modeだけを実行し、write authorityを
渡さない。

Workflowをcopyしただけではmerge protectionは発生しない。Repository administratorがlive rulesetで`gate`をrequiredにし、
safe／finding／missing checkを実際に試して初めて導入完了となる。

## 誰が何をするか

| 担当 | 作業 |
| --- | --- |
| Development team | Workflowをpull requestでcopyし、scanner findingを対象workflowで修正する |
| Repository administrator | Default branch、required status check、ruleset、Code Scanningを設定する |
| CI platform／organization owner | External Action、`ghcr.io`、approved runnerを利用可能にする |
| Security | Scanner identity、audit範囲、期限付きexception、live negative testをreviewする |

開発者へ追加scanner、独自runtime、provider mutation script、organization-wide設定変更を要求しない。最小導入は
workflow一つとrequired check一つである。

## 最短の導入手順

### 前提

- GitHub.com、またはこのprofileを確認済みのGitHub Enterprise Cloud。
- GitHub-hosted Ubuntu runnerを利用できる。
- GitHub Marketplace Actionと`ghcr.io`からreview済みzizmor imageを取得できる。
- Repository administratorが[GitHub ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)を変更できる。
- Referenceのdefault branchは`main`。異なる場合は次の手順で明示する。
- SARIF reportingを使う場合は対象repositoryで[Code ScanningへのSARIF upload](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)を利用できる。

### 1. Workflowをcopyする

Repository rootで実行する。既存fileがあれば上書きせず停止する。

```bash
workflow_target=.github/workflows/actions-security.yml
test ! -e "$workflow_target" || {
  echo "ERROR $workflow_target already exists; review and merge it manually" >&2
  exit 1
}
mkdir -p .github/workflows
cp controls/cicd-security/actions-static-analysis/secure/workflow.yml \
  "$workflow_target"
```

別repositoryへ導入する場合、copyする必須fileは
[secure/workflow.yml](secure/workflow.yml)だけである。既存workflowへ手作業で組み込む場合も、`gate`と`report`の
permission／event境界を維持する。

### 2. Default branchを合わせる

Default branchが`main`でなければ、次の2か所だけを実branchへ変更する。

- `on.push.branches`
- `report.if`の`refs/heads/main`

Control packageのlocal verifierも利用する場合は同じbranchを明示する。

```bash
python3 controls/cicd-security/actions-static-analysis/scripts/verify.py \
  workflow .github/workflows/actions-security.yml \
  --default-branch <default-branch>
```

### 3. Safe PRで起動する

通常のpull requestを作り、`Block workflow security findings`が実行されることを確認する。PR jobは
`contents: read`だけを持ち、zizmorへtokenを渡さない。

### 4. Gateをrequiredにする

GitHubのrepository settingsでrulesetを開き、default branchを対象に`Block workflow security findings`を
required status checkへ追加する。設定方法は
[GitHubのrequired status check説明](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging)を参照する。

Failed、cancelled、missingのいずれでもmergeできないことを確認する。SARIF alertだけをmerge gateにしない。

### 5. SARIF reportingを確認する

SARIFを利用できる場合、default branchへのtrusted pushで`Upload trusted-branch SARIF`が実行され、Code Scanningに
resultが表示されることを確認する。Pull requestではこのjobがskipされることを確認する。

SARIFを利用できない場合も`gate`によるblockingは使用できる。ただし[`SAS-003`](control.yaml)の適用可否を記録し、
reportingを導入済みと扱わない。

## Safe self-test

### Local positive test

```bash
python3 controls/cicd-security/actions-static-analysis/scripts/verify.py \
  workflow .github/workflows/actions-security.yml \
  --default-branch main
```

Expected resultはexit `0`である。Default branchが異なるadopterは`main`を実branchへ置き換える。Reference repositoryの
maintainerは、続けてcanonical testを実行する。

```bash
make verify-control CONTROL=PSB-CICD-003
```

### Live positive test

CommentまたはREADMEだけを変更したsafe PRを作り、次を確認する。

- `Block workflow security findings`がgreenになる。
- `Upload trusted-branch SARIF`はPR上でskipされる。
- Green gateのままruleset条件を満たせばmerge可能になる。

### Live negative test

Mergeしないtest branchで、次のinert workflowを一時的に`.github/workflows/actions-security-negative-test.yml`へ置く。
これは意図的にinsecureである。Default branchへmergeしない。

```yaml
name: Actions security negative self-test

on:
  workflow_dispatch:

permissions: {}

jobs:
  inert:
    if: ${{ false }}
    runs-on: ubuntu-latest
    steps:
      - name: Inert mutable reference
        uses: actions/checkout@v4
```

Jobは常にskipされるためActionは実行されないが、offline `unpinned-uses` auditはmutable tagを検出する。Expected resultは
`Block workflow security findings`の失敗である。確認後にtest fileを削除する。さらに、failed check、
cancelled check、required checkが起動しない状態でmergeできないことを確認する。

## Result semantics

| 状態 | Exit status | 扱い |
| --- | ---: | --- |
| Scanner正常完了、findingなし | `0` | Clean |
| Security policy findingあり | `1` | Mergeをblock |
| Scanner／input／SARIF error | `2` | 判定不能としてmergeをblock |

`continue-on-error`、`|| true`、`fail-on-no-inputs: false`、無条件fallbackでexit `1`または`2`をcleanへ変換しない。
Scanner取得失敗やregistry outageもcleanではない。

## Live verification

Local fixtureの成功とlive adoptionを分離する。

| 確認対象 | Source | Success state |
| --- | --- | --- |
| Workflow revision | Git repositoryのexact revision | [secure workflow](secure/workflow.yml)とreview済み差分だけ |
| Safe PR | GitHub Actions run | Tokenなしの`gate`がsuccess |
| Inert finding | Mergeしないnegative test PR | `gate`がfailure |
| Merge enforcement | GitHub ruleset current setting | Failed／cancelled／missing checkではmerge不可 |
| SARIF authority | PR runとdefault-branch push run | PRではskip、trusted pushだけで実行 |
| Failure handling | Actual failed runまたはapproved staging test | Scanner failureがsuccessにならない |

Evidenceにはrepository、exact revision、run IDまたはURL、event、ref、取得時刻、reviewer、rulesetのcurrent sourceを含める。
Token、secret、private source、raw event payloadはcommitしない。設定未確認、権限不足、partial result、provider failureは
`NOT_CHECKED`または`ERROR`であり、`PASS`ではない。

## Secure implementation details

[secure/workflow.yml](secure/workflow.yml)は次のidentityを固定する。

- [`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`](https://github.com/actions/checkout/tree/de0fac2e4500dabe0009e67214ff5f5447ce83dd)（v6.0.2）
- [`zizmorcore/zizmor-action@6fc4b006235f201fdab3722e17240ab420d580e5`](https://github.com/zizmorcore/zizmor-action/tree/6fc4b006235f201fdab3722e17240ab420d580e5)（v0.6.1）
- `zizmor` `1.28.0`
- OCI digest `sha256:8e6b3e4fb74d1aa5d23e83ea369f386c66eced0d1fb944d32cd8b2aac100b00d`

固定したActionは内蔵version tableからdigestを解決する。Update時はcanonical release、Action commit、source内version
table、OCI digest、release note、audit／exit behaviorを同じ変更でreviewする。Pinningはmalicious pinned bytesや
scanner ruleの完全性までは証明しない。

`online-audits: false`かつ`token: ""`にするため、GitHub APIが必要なonline-only auditは対象外になる。Baselineへtokenを
追加してcoverageを広げない。Online auditが必要なら別のtrusted profileとしてauthorityとfailure stateを設計する。

## Insecure example

[insecure/workflow.yml](insecure/workflow.yml)は、次を意図的に組み合わせた実行されないfixtureである。

- Pull requestだけでprivileged reportingを実行する。
- `permissions: write-all`とself-hosted runnerを使う。
- Top-level `env`でtokenをscannerへ再注入し、blocking gateを`if: false`でskipする。
- Scanner jobの中でpull-request repository commandを実行する。
- Checkoutとscannerにfloating tagを使う。
- Online auditへ`GITHUB_TOKEN`を渡す。
- `continue-on-error: true`でscanner failureを隠す。
- `latest`、不完全な入力、`fail-on-no-inputs: false`を使う。

このfixtureは`.github/workflows`外に隔離し、defaultで実行しない。

## Automated verification

[scripts/verify.py](scripts/verify.py)と[tests/test.sh](tests/test.sh)はPython standard libraryとshellだけを使い、
次を検査する。

- Event、default branch、`gate`／`report` job構造。
- Jobごとのrunner、permission、checkout credential境界。
- Gateをskipするcondition、job／step追加、environment経由のcredential再注入。
- Action full SHA、zizmor Action commit、scanner version、input、mode。
- Failureを隠す`continue-on-error`。
- Diagnosticへuntrusted scanner input値を出さないこと。
- Clean、finding、scanner failure、malformed SARIFの状態。
- Repositoryで採用したworkflowとreferenceのdrift。

Verifierはzizmor audit engineを再実装しない。Handcrafted SARIFはresult parserのregression evidenceであり、実scannerの
検出力やorganization adoptionを証明しない。

Repository rootから実行する。

```bash
bash controls/cicd-security/actions-static-analysis/tests/test.sh
make verify-control CONTROL=PSB-CICD-003
```

Expected output:

```text
PASS secure scanner workflow policy accepted
PASS alternate default branch accepted when declared explicitly
PASS mutable privileged token-bearing and failure-ignoring workflow rejected
PASS untrusted scanner input values omitted from diagnostics
PASS clean and finding SARIF states distinguished
PASS scanner execution failure distinguished from a clean result
PASS malformed SARIF fails closed
PASS missing and unsupported workflow inputs fail closed
PASS adopted workflow matches the reviewed secure example
```

README文字列test、手書きJSONの`secure: true`、no-op test、provider-valid credential、real secret、synthetic fixtureの
organization `PASS`化は追加しない。

## Recovery and rollback

| 状況 | Recovery |
| --- | --- |
| Workflow finding | 対象lineを修正し、broad ignoreを追加せず再実行する |
| Scanner identity drift | [secure workflow](secure/workflow.yml)のreview済みidentityへ戻す |
| Registry／Actions outage | Service回復後にrerunする。Failureをwarningへ変えない |
| SARIFだけ利用不可 | Blocking gateを維持し、reportingを`NOT_CHECKED`として扱う |
| 誤ったdefault branch | Branch filterとreport conditionを同時に修正し、verifierへ同じbranchを渡す |

完全rollbackが必要な場合は、repository administratorとSecurityが既知のgood scanner versionへ戻す。Workflowを削除する
場合は、required checkが永続的にmissingとなってmergeを停止しないよう、ruleset変更とfile削除を一つのreview済み
rollbackとして扱う。Rollback後もmanual workflow reviewは必要であり、同等のserver-side scannerがない限り検出力は下がる。

## Existing controlsとの分担

- [PSB-CICD-001: Action SHA pinning](../action-sha-pinning/README.md)は全third-party Action、reusable workflow、Docker Actionのimmutable referenceを所有する。
- [PSB-CICD-002: Actions command injection](../actions-command-injection/README.md)はActions expressionからrunner shellへの直接injectionを所有する。
- [PSB-CICD-004: Actions least privilege](../actions-least-privilege/README.md)はjob operationに対するsemantic token／OIDC least privilegeを所有する。
- [PSB-CICD-005: Untrusted PR boundary](../untrusted-pr-boundary/README.md)はuntrusted code、credential、runner、cross-run dataの一般境界を所有する。
- [PSB-CICD-007: Runner hardening](../runner-hardening/README.md)はrunner image、network、lifecycle、teardownを所有する。
- [PSB-BUILD-001: Build containment](../../build-security/build-containment/README.md)はjob内sandbox、egress、credential、telemetryを所有する。
- [PSB-SOURCE-006: GitHub Organization governance](../../source-protection/github-organization-governance/README.md)はorganization-wide Actions policyを所有する。
- [PSB-GOV-002: Time-bound security exceptions](../../governance-operations/time-bound-security-exceptions/README.md)はexceptionのscope、approval、expiryを所有する。

Zizmorがこれらの問題をfindingとして検出しても、本controlは各owner controlの完全な実装やlive adoptionを証明しない。

## Complementary tool boundary

| Tool | Potential contribution | Current decision |
| --- | --- | --- |
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions向けsecurity static analysis | Adopted |
| [actionlint](https://github.com/rhysd/actionlint) | Syntax、expression type、Action interface、embedded shell lint | Unique negative fixtureが確認できるまで追加しない |
| [poutine](https://github.com/boostsecurityio/poutine) | Pipeline supply-chain issueとrepository／organization inventory | Existing controlと重複しないgapが確認できるまで追加しない |

候補scannerは、既存経路が見逃す必須のinert finding、pinned executable、integrity verification、clean／finding／error
semantics、owner、CI costを示せる場合だけ追加する。Tool数をcoverageとして扱わない。

## Limitations and operational cost

- Static ruleはjobが実際に必要とするsemantic permissionを証明しない。
- External Action内部、repository script、build tool、runtime network／credential useは観測しない。
- Offline profileはGitHub APIを必要とするauditを実行しない。
- SARIF upload単体はmerge gateではない。
- Pinned scannerにもreview済みupdateとregistry availabilityが必要である。
- 全PRでcontainerを取得して`.github`を解析するため、CI時間とexternal registry dependencyが増える。
- Findingのreachabilityとbusiness contextにはhuman triageが必要である。

## Framework mappings

Machine-readable sourceは[control.yaml](control.yaml)である。Mappingはsupporting relationshipであり、formal complianceや
organization adoptionを示さない。

- [GitHub Actions Secure Use Reference — GHAS-REF-SECURE-USE](https://docs.github.com/en/actions/reference/security/secure-use)
  - Version: `github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24)`
  - Relationship: `supports`
  - Confidence: `high`
  - Rationale: Action固定、最小権限、untrusted PRとprivileged reportingの分離を自動reviewで支援する。
- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-VM-06.02](https://baseline.openssf.org/versions/2026-02-19#osps-vm-0602)
  - Relationship: `supports`
  - Confidence: `medium`
  - Rationale: Workflow変更をsecurity testing policyの対象にし、findingとscanner failureを区別する。

NIST SSDF、SLSA、MITRE ATT&CK等は、exact requirementへの直接的なevidenceをreviewできるまで新規mappingを追加しない。

## Guides and references

- [zizmor GitHub Actions integration](https://docs.zizmor.sh/integrations/)
- [zizmor usage and result behavior](https://docs.zizmor.sh/usage/)
- [zizmor audit rules](https://docs.zizmor.sh/audits/)
- [zizmor-action pinned source](https://github.com/zizmorcore/zizmor-action/tree/6fc4b006235f201fdab3722e17240ab420d580e5)
- [zizmor reviewed source snapshot](https://github.com/zizmorcore/zizmor/tree/6ea55f583ef6681a59b1c180950e47861a3c0293)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub workflow permission syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [GitHub ruleset rules and required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub SARIF upload guidance](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- [Repository-reviewed zizmor source record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-002)
- [Repository-reviewed scanner comparison record](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-cicd-008)
