# PSB-DETECT-001: Integrity-verified security scanner execution

## このcontrolを一枚で理解する

### セキュリティ上の問題

Security scanner自身、database、policyが改ざん・陳腐化・停止していると、危険なsourceやartifactを検査するjobが侵害経路または偽のclean evidenceになる。

### 誰から、または何から守るか

Scanner配布経路の攻撃者、malicious dependency・contributor、scanner・DB障害、secret-bearing log、broad ignore、AI remediationの誤判定から守る。

### 何が対象か

Scanner binaryとrelease evidence、vulnerability DB、source、container、IaC、secret、SBOM、exception、normalized scan evidence、CI gate。

### 何をするか

Scanner version・checksum・publisher identityとDB identityを固定し、offline scanを実行し、finding・clean・errorを分離し、evidence redactionとexact期限付き例外を強制する。

### 成功状態

承認済みscanner bytesとcurrent dataで全categoryを評価し、blocking findingは終了1、tool・DB・parser・evidence障害は終了2となり、どちらもreleaseをblockする。

### 対象外・残余リスク

Synthetic DB fixtureはcurrent production vulnerability evidenceではなく、scanner false positive・false negative、未対応ecosystem、許可済み例外の誤判断は残る。

## 何を守るコントロールか

このコントロールは、脆弱性・コンテナ設定・IaC・シークレット・SBOMを
スキャンするだけでなく、**スキャナー自身を信用してよいか**と、
**スキャン失敗を clean と誤認していないか**を検証します。

想定する攻撃者と失敗は次のとおりです。

| 誰／何から | 対象 | 攻撃・失敗 | このcontrolが行うこと |
|---|---|---|---|
| scanner配布経路を侵害した攻撃者 | CI runner、source、artifact | 改ざんscannerをsecurity jobとして実行させる | release、asset SHA-256、publisher checksum、Sigstore identityを固定・検証する |
| dependency導入者、悪意あるcontributor、設定ミス | source tree、image metadata、IaC、SBOM | 既知脆弱性、危険な設定、secretをreleaseへ混入させる | categoryごとにblocking findingを生成する |
| scanner／DB障害、timeout、integration不備 | CI quality gate | 実行できなかった結果を「0件」と扱う | clean=`0`、finding=`1`、error=`2`を分離する |
| CI log／artifactの閲覧者 | scanner evidence | 検出したcredential値を二次流出させる | match、content、line、snippetを正規化時に除去する |
| gateを迂回するoperator | scanner exception | wildcard／恒久ignoreで将来のfindingまで隠す | rule、target、owner、承認者、理由、期限を必須化する |
| untrusted contributor、LLM provider、scanner障害 | Dockerfile／Composeの修正支援とCI gate | AI scoreを合否根拠にする、API keyを渡す、DockSec status 2／3をcleanにする | offline scan-onlyのstructured findingだけを判定に使い、AIは任意・非blockingに分離する |

## うれしいこと

`trivy fs` が動いたという事実だけでは、結果の信頼性は分かりません。この
controlを使うと、レビュー担当者は次を別々に判断できます。

1. どのscanner bytesとpublisher identityを承認したか。
2. どのvulnerability DBとpolicy bundleで判定したか。
3. scanが完了したのか、findingがあったのか、実行に失敗したのか。
4. 保存したevidenceに検出対象のsecret値が残っていないか。
5. ignoreが限定的で、期限後に自動的に拒否されるか。
6. DockSecの開発者向け説明を使っても、AIやorchestrator障害がrelease判定を弱めないか。

## 最初に実行するコマンド

```bash
make verify-control CONTROL=PSB-DETECT-001
```

通常のcontrol verificationはネットワークに接続せず、production registry、
cloud credential、実scanner binaryを必要としません。isolated fixtureで次を
検証します。

- Trivy `v0.72.0` release receiptの受理
- known affected release、改ざんartifactの拒否
- dependency、container、IaC、synthetic secret、CycloneDX SBOM finding
- unavailable scanner、DB mismatch、malformed JSONのerror扱い
- secret-safe normalization
- exactかつtime-boundなexception
- Trivy／Checkovの重複比較
- DockSecの固定optional profile、AI-free gate、clean／finding／error変換

期待する終了コードは以下です。

| 終了コード | 意味 | release gateでの扱い |
|---:|---|---|
| `0` | scan完了、blocking findingなし | 次へ進める |
| `1` | scan完了、blocking findingあり、またはsecurity policy違反 | blockする |
| `2` | scanner、input、DB、policy、integrity、evidenceのerror | **cleanにせずblockする** |

## Secure implementation

### 1. Scanner releaseを取得する

ネットワーク利用は通常検証から分離されています。明示的に取得する場合だけ、
新規output directoryを指定して次を実行します。

```bash
controls/detection-verification/integrity-verified-scanner/scripts/fetch-trivy.sh \
  --output-directory .local/trivy-0.72.0
```

このscriptは以下をすべて通過するまで展開しません。

- GitHub release tag `v0.72.0`
- Linux 64-bit archive SHA-256
  `bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea`
- verified archiveから展開した`trivy` binary SHA-256
  `0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e`
- official checksum fileそのもののSHA-256
- archive用Sigstore bundleそのもののSHA-256
- GitHub Actions OIDC issuer
- Trivy release workflowのcertificate identity

`cosign` は既に組織で承認・完全性検証されたtrust toolをPATHへ用意します。
scriptは`curl | sh`を行わず、既存directoryを上書きしません。

### 2. Current DBを別jobで準備する

repositoryの
[`secure/database-metadata.json`](secure/database-metadata.json) は
deterministic test用のsynthetic identityです。運用時は、network-enabledな
更新jobでTrivy DBを取得し、最低でも次を記録します。

- OCI repository
- schema version
- resolved OCI digest
- downloaded time
- expiry／next refresh time

scan jobはそのcacheをread-onlyに受け取り、network updateを無効化します。
DB取得失敗や期限切れを、空のDBやclean resultへ変換してはいけません。

### 3. Offline scanと正規化を行う

```bash
controls/detection-verification/integrity-verified-scanner/scripts/run-trivy-offline.sh \
  --trivy .local/trivy-0.72.0/trivy \
  --cache-directory .local/trivy-cache \
  --target PATH_TO_REVIEWED_TARGET \
  --output raw-trivy.json

python3 \
  controls/detection-verification/integrity-verified-scanner/scripts/normalize-trivy.py \
  raw-trivy.json \
  current-database-metadata.json \
  filesystem \
  scanner-evidence.json \
  --target PATH_TO_REVIEWED_TARGET \
  --categories vulnerability,iac-misconfiguration,secret

python3 \
  controls/detection-verification/integrity-verified-scanner/scripts/verify.py \
  result \
  controls/detection-verification/integrity-verified-scanner/secure/policy.json \
  current-database-metadata.json \
  scanner-evidence.json
```

raw Trivy JSONにはmatched secretやsource snippetが含まれる可能性があります。
アクセスを限定し、normalized evidenceを保存した後は組織のretention policyに
従ってraw dataを破棄します。

## Insecure implementation

[`insecure/release-receipt.json`](insecure/release-receipt.json) は、mutable
release、未検証checksum、未検証signatureを「scanner実行可能」として扱う例です。
Trivyの2026年の配布経路侵害で影響が報告された版をnegative fixtureに含めています。

[`insecure/results/scanner-error.json`](insecure/results/scanner-error.json) を
finding 0件として処理することも危険です。`execution.status=error` は、findings
arrayが空でも必ず終了コード`2`になります。

[`insecure/results/secret-leak.json`](insecure/results/secret-leak.json) は
synthetic値を使い、`match` fieldがevidenceへ残る設計を拒否します。実credentialは
fixtureに使用していません。

## Checkovをなぜ既定で追加しないか

[`secure/checkov-comparison.json`](secure/checkov-comparison.json) はCheckov
`3.3.8`のPyPI sdist SHA-256を固定し、同じIaC fixtureでTrivyと比較したdecision
recordです。最初のsliceではblocking coverageの固有差がなかったため、Checkovを
実行dependencyへ追加していません。

今後、組織固有policyの独立検証など、Trivyにない価値をpositive／negative fixtureで
示せた場合にだけ再評価します。ただし、resolved Terraform planのdeny contract、
provider-side enforcement、drift detectionは`PSB-IAC-001`の責任です。

## DockSecをどのように組み込むか

DockSec `2026.7.5`はTrivy、Hadolint等の結果をまとめ、Dockerfileの文脈に沿った
修正説明やCompose横断のfeedbackを提供します。本controlでは新しい検出責任者に
せず、Trivyをprimary scannerに残した
**optional developer-remediation orchestrator**として採用します。

ブロッキング判定は
[`secure/docksec-profile.json`](secure/docksec-profile.json)で固定した次の
contractだけを使います。

```text
docksec TARGET --scan-only --offline --fail-on high --json --no-cache
      0 -> CLEAN
      1 -> FINDING / BLOCK
  2 or 3 -> ERROR / BLOCK
```

ロック済み環境にDockSec CLIを用意した後、adapterを次のように実行します。

```bash
python3 \
  controls/detection-verification/integrity-verified-scanner/scripts/run-docksec-scan-only.py \
  --docksec .local/docksec/bin/docksec \
  --profile controls/detection-verification/integrity-verified-scanner/secure/docksec-profile.json \
  --target Dockerfile \
  --output generated/assessments/docksec-gate.json
```

adapterはLLM provider用environment variableを子processから除去し、AIなし、
offline、cache bypassで実行します。保存する証跡はtool version、policyが期待する
wheel SHA-256、target basename、severity count、decisionだけです。adapter自身は
installed environmentの由来を再構築しないため、実際のwheel／lock検証receiptは
別途必要です。raw JSONの
vulnerability detailや絶対pathは通常証跡へコピーしません。

AIによる修正説明を使う場合は、gate後の別jobまたは開発者の明示操作として扱い、
その出力だけで合否を変えません。外部providerへDockerfile／Composeを送るには
data classification、egress、credential、retentionの承認が必要です。
`--no-redact`と`docksec install-skill`はこのprofileでは禁止します。

### 公式GitHub Actionを採用しない理由

DockSec source commit
`4ddcb5285f437c0e84a42c748b0f61f56543e344`をレビューした結果、公式Actionの
DockerfileはHadolintを`releases/latest`から取得し、Trivy installerを
`curl | sh`で実行していました。Action自体をfull commit SHAへ固定しても、
build時の内部dependencyがmutableなため、本PJのsecurity invariantを満たしません。

そのため、公式の`uses: OWASP/DockSec@...`例は使用せず、次を満たす
組織管理environmentだけを許可します。

- PyPI wheel `docksec-2026.7.5-py3-none-any.whl`をSHA-256
  `7f8781db7651216556c86c71ab45527bc484801b974ff264fe0ebe7f70a6f5fb`へ固定する。
- transitive Python dependencyをlockし、hash付きで構築する。
- TrivyとHadolintを個別にversion固定・integrity検証する。
- upstreamのautomatic external-tool installerを使用しない。
- scanner／DB／policy更新を通常のoffline gateと分離する。

## SLSAとの関係

SLSAは「どのsourceを、どのbuild platformが、どのprocessでartifactにし、その
provenanceを真正に検証できるか」を扱います。このcontrolは「そのartifactやSBOMに
既知の脆弱性や設定不備が検出されたか」を扱います。

```text
SLSA provenance verification
        |  exact artifact digestを識別
        v
PSB-DETECT-001
        |  同じartifact／SBOMをscan
        v
vulnerability and configuration decision
```

相互補完関係はありますが、脆弱性scanはSLSA Build requirementではありません。
したがって、このcontrolにSLSA mappingを付けず、SLSA Level 2達成も主張しません。
container admissionでprovenance authenticityを利用する責任は
`PSB-REL-001`と`PSB-CONTAINER-001`のcompositionに残します。

## 運用上の注意

- DB／policy更新jobとoffline scan jobを分離し、network authorityを最小化する。
- DB digestとscan timeをevidenceに残し、結果の鮮度をdashboardで監視する。
- scanner errorをfinding countへ集約せず、別metric／alertにする。
- exceptionは対象ruleとpath／resourceをexactにし、ownerと承認者を分離する。
- scanner upgrade時はrelease integrity、fixture結果、normalizer schemaを同時にreviewする。
- SARIFへ変換する場合も、matched secret、snippet、environment valueを保存しない。
- DockSecのAI説明は脆弱性の有無やframework適合を証明しない。修正案は人と元scanner findingで再確認する。

## 残余リスク

- repository fixture DBはproductionの最新脆弱性を示しません。
- signature verification用`cosign`自体は、組織のbootstrap trust processで別途
  完全性を保証する必要があります。
- known vulnerabilityがないことは未知脆弱性、安全なapplication behavior、
  exploit不可能性を証明しません。
- Trivyはapplication SAST、DAST、manual review、runtime behavioral monitoringを
  置き換えません。
- NIST SP 800-190 `4.1.3`のembedded malware detectionは未実装であり、このcontrolの
  mappingには含めません。
- DockSec wheelはreview時点でPyPI Trusted Publishingを使用しておらず、固定hashは
  publisher identityやtransitive dependency完全性の代替になりません。
- `--offline`はDockSecへ渡すapplication-level指定であり、悪意あるbinaryに対する
  OS-level network sandboxを証明しません。

## 参照

- [Trivy v0.72.0 release](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0)
- [Trivy release signature verification](https://trivy.dev/latest/docs/advanced/signatures/)
- [Trivy offline mode](https://trivy.dev/latest/docs/advanced/air-gap/)
- [GitHub advisory GHSA-69fq-xp46-6x23](https://github.com/advisories/GHSA-69fq-xp46-6x23)
- [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final)
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OWASP DockSec](https://owasp.org/DockSec/)
- [DockSec v2026.7.5 source](https://github.com/OWASP/DockSec/tree/4ddcb5285f437c0e84a42c748b0f61f56543e344)
- [DockSec 2026.7.5 on PyPI](https://pypi.org/project/docksec/2026.7.5/)
