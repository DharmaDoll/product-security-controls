# PSB-CICD-003 implementation instructions

このfileは`PSB-CICD-003`（`cicd-security`）固有の実装境界を定める。作業前に
[repository rootのAGENTS.md](../../../AGENTS.md)、[controlsのAGENTS.md](../../AGENTS.md)、必須設計資料、関連ADR、
[README.md](README.md)、[control.yaml](control.yaml)を読むこと。

## Control essence

- Review済みversionへ固定した`zizmor`で、repository内のGitHub Actions workflowをmerge前に静的解析する。
- Pull requestのblocking scanはcredentialなし・read-onlyで実行し、findingをrequired checkで止める。
- `clean`、`finding`、scanner／input／result errorを別状態にし、判定不能をfindingなしへ変換しない。
- SARIF uploadは可視化でありmerge gateではない。Write権限が必要なreportingはtrusted default-branch pushへ分離する。
- Security効果は実repositoryのscanner workflowとactive rulesetから生まれる。Fixtureやlocal verifierの`PASS`だけでは
  organization adoptionを証明しない。
- 本controlが所有するのはscanner orchestration、trust-separated reporting、結果状態である。検出する個別問題の
  設計責任まで取り込まない。

## 実装方式を決めるときの仮説と反証

最初の印象を結論にせず、少なくとも次を確認する。

1. **Guidance-onlyでよいか**: rulesetはprovider settingだが、scanner gateはcopy可能で意味のある自動判定を行える。
   したがってguidance-onlyではなく、実行可能なworkflowを主実装にする。
2. **個別auditを独自parserで再実装すべきか**: GitHub syntaxとzizmor ruleから乖離するため行わない。Local verifierは
   wrapper policyとdecision semanticsだけを検査する。
3. **zizmorが検出する問題をすべて本controlが所有するか**: immutable Action、expression injection、semantic least
   privilege、untrusted PR boundaryにはowner controlがある。Findingはそれらを支援するsignalである。
4. **SARIF uploadが主目的か**: upload成功はmergeを止めない。Primary outcomeはunprivileged blocking gateである。
5. **workflow copyで導入完了か**: required check、default branch、Code Scanning availabilityはcopyでは変わらない。

結論は**executable-configuration-first with live provider activation**である。

## Supported assumptions and implementation inputs

Reference profileはGitHub.comまたは動作確認済みGitHub Enterprise Cloud、GitHub-hosted Ubuntu、
`.github/workflows/*.yml`／`.yaml`、default branch `main`を前提とする。Local verificationはmacOSまたはLinuxと
Python 3.10+で動かす。Pull requestはtokenなしのoffline audits、reportingはCode Scanningを利用できるrepositoryで行う。

Provider固有実装またはadoption claimの前に次を確認する。

1. 対象provider／plan、実default branch、scanner対象path。
2. External Actionと`ghcr.io` imageを許可するnetwork／organization policy。
3. `gate`をrequired status checkにするrepository administrator。
4. Code Scanning／SARIF uploadの利用可否。利用不可ならfindingの確認経路。
5. Online-only auditの必要性。必要ならtokenを渡せる別のtrusted context。
6. Scanner update、triage、期限付きexception、障害対応のowner。

このfileの作成にorganization固有値は不要である。値が未確認なら架空の設定やevidenceを作らず、live stateを
`NOT_CHECKED`とする。GitHub Enterprise Serverまたは別CIは、event、token、SARIF、required-check semanticsを確認した
別profileとして扱う。

## Roles

- Development team: workflowをpull requestで導入し、対象workflowのfindingを修正する。
- Repository administrator: default branch、required status check、ruleset、Code Scanningをliveに設定する。
- CI platform／organization owner: external Action／container policy、approved runner、registry reachabilityを提供する。
- Security: scanner identity、audit coverage、exception、live negative testをreviewする。

開発者へorganization-wide automation、追加scanner、独自runtimeの構築を要求しない。最小導入は一つのworkflow copyと
一つのrequired check設定に保つ。

## Small implementation contract

1. [`secure/workflow.yml`](secure/workflow.yml)はcopy可能なreferenceである。
2. [`insecure/workflow.yml`](insecure/workflow.yml)は実行されない場所に隔離したnegative exampleである。
3. [`scripts/verify.py`](scripts/verify.py)はPython standard libraryだけでworkflow policyと正規化SARIF状態を検査する。
   Zizmor audit engineは再実装しない。
4. [`tests/test.sh`](tests/test.sh)はsecure、finding、scanner error、malformed result、adopted workflow driftを区別する。
5. [`expected-results/`](expected-results/)にはdeterministicなlocal outputだけを置き、live adoption evidenceを置かない。

このcontrolのためだけにYAML framework、package manager、wrapper framework、sidecar policy JSON、Docker Compose、
provider mutation scriptを追加しない。既存経路で再現できない具体的なsecurity gapがある場合だけ、inert negative case、
dependency trust、owner、失敗状態を先に定義して追加を検討する。

`SAS-005`は`.github/workflows/actions-security.yml`とのdriftを対象にする。Control directory外の採用workflowを変更する
必要がある場合は、scope拡張を先に説明し、[`secure/workflow.yml`](secure/workflow.yml)と同時にreviewする。

## Required workflow profile

- Workflow-levelは`permissions: {}`、triggerは`pull_request`とtrusted default-branch `push`。
- Top-level／job／step `env`からscannerへcredentialを再注入しない。
- `gate` jobはGitHub-hosted runnerと`contents: read`だけを使い、`if`等でskip可能にしない。
- 各jobはreview済みcheckoutとzizmorの2 stepだけを持ち、repositoryの`run:`、build、test、dependencyを実行しない。
- Checkoutとzizmor Actionはreview済みfull commit SHAへ固定し、checkout credentialをpersistしない。
- Zizmorはreview済みversionを明示し、Action内のversion-to-OCI-digest bindingをupdate時に再確認する。
- Blocking scanは`inputs: .github`、`collect: all`、`persona: auditor`、`online-audits: false`、`token: ""`、
  `advanced-security: false`、`fail-on-no-inputs: true`を明示する。
- Reportingは別jobでtrusted default-branch pushだけに限定する。Job-level permissionは`actions: read`、
  `contents: read`、`security-events: write`だけとし、同じpinned scannerを`advanced-security: true`で使う。
- Report jobやCode Scanning alertだけをmerge gateにせず、`gate`自体をrequired checkにする。

SARIFを利用できないadopterはgate-onlyでfindingをblockできる。ただしcanonical referenceからreportを削る場合は
`SAS-003`の適用可否、`control.yaml`、README、verification claimを同時にreviewし、未実施checkを実施済みにしない。

## Scanner update and decision semantics

- Third-party Actionはfull commit SHA、scannerはexact versionを使い、`latest`、range、floating tagへ変更しない。
- Update時はcanonical release、Action commit、source内version table、OCI digest、release notes、audit／exit behaviorを
  reviewする。
- [`scripts/verify.py`](scripts/verify.py)のAction SHA／scanner version、secure workflow、README、SARIF tool versionを
  一つの変更として揃える。
- Upgradeを通すためseverity、`collect`範囲、fail-closed behaviorを弱めたり、広いignoreを追加したりしない。

Exit statusは`0=clean`、`1=finding`、`2=input／scanner／result error`とする。`1`と`2`はどちらもrequired checkを
成功させない。`continue-on-error`、`|| true`、無条件fallback、`fail-on-no-inputs: false`でcleanへ変換しない。
SARIF modeはfinding後もreportingを続ける場合があるため、別のblocking modeを必ず維持する。Upload failureもclean scanの
証拠にしない。

Outputはrule ID、repository-relative path、line、normalized state等の最小情報に限定する。Token、secret、environment
value、private event payload、source本文をexpected resultやartifactへ複製しない。

False positiveはrule、exact path、owner、理由、作成日、expiryを限定し、
[`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md)へ委譲する。Scanner全体や広いpathを
無期限にignoreしない。

## Minimal adoption and self-test

READMEの早い位置で次を具体的に示す。

1. Prerequisiteを確認し、実default branchとCode Scanning availabilityを記録する。
2. [`secure/workflow.yml`](secure/workflow.yml)を`.github/workflows/actions-security.yml`へcopyする。既存fileがあれば
   停止し、adopter-owned reviewでmergeする。
3. Referenceの`main`だけを実default branchへ置き換え、scanner identity、permissions、tokenless gateを変えない。
4. Safe PRで`Block workflow security findings`がcredentialなしで成功することを確認する。
5. Rulesetでそのcheckをrequiredにし、failed／cancelled／missingのままmergeできないことを確認する。
6. SARIFを使う場合、trusted default-branch pushだけでreportが動き、Code Scanningへresultが現れることを確認する。
7. Mergeしないtest PRへ、自動triggerと実処理を持たないworkflowの`permissions: write-all`等、inert findingを一つだけ
   追加する。Gateの失敗を確認後、そのtest fileを削除する。

Local self-test:

```bash
python3 controls/cicd-security/actions-static-analysis/scripts/verify.py \
  workflow .github/workflows/actions-security.yml
make verify-control CONTROL=PSB-CICD-003
```

Expected stateはlocal exit `0`、safe PRのgreen required gate、inert negative PRのfailed gate、trusted pushだけのreportで
ある。Registry／Action取得不能、scanner crash、malformed resultはgreenにしない。

Recoveryは対象workflowのfinding修正、review済みscanner identityへの復元、外部障害解消後のrerunである。Gateをskip
しない。RollbackはadministratorとSecurityが既知のgood versionへ戻す。Workflowを外す場合はrequired checkとの不整合を
避けるreview済み変更とし、残るmanual review riskを明記する。Global Git、shell、IDE、OS settingは変更しない。

## Verification and evidence boundary

Local testsは次だけを証明する。

- Secure policyをacceptし、mutable scanner、過大権限、token／online audit、入力なし許容、trust境界混同をrejectする。
- Clean SARIFをexit `0`、findingを`1`、scanner failureとmalformed SARIFを`2`にする。
- Missing／unreadable input、wrong scanner identity／version、empty resultをcleanにしない。
- Gate skip、credential再注入、unreviewed job／step／scanner inputをrejectし、diagnosticへinput値を出さない。
- 採用workflowがreview済みreferenceからdriftしたら失敗する。

Local verifierとhandcrafted SARIFはwrapper policyとdecision parserのregression evidenceであり、zizmor各auditの検出力を
証明しない。特定auditのcoverageをclaimする場合は、review済みpinned zizmorを実際にinert fixtureへ実行して
clean／finding／tool failureを再現する。Network downloadはversionとintegrityを固定して明示し、通常のnetwork-free testへ
無理に混ぜない。

README文字列test、手書きJSONの`secure: true`、no-op、provider-valid credential、real secret、synthetic fixtureの
organization `PASS`化は追加しない。Static analysisが証明しないsemantic permission、Action内部、invoked script、runtime
egress、credential use、provider setting、finding reachabilityは限界として残す。

Reference evidenceはfixture、verifier output、scanner identity reviewである。Live evidenceはexact repository／revision、
workflow run、event／ref、gate conclusion、required-check current setting、inert negative result、取得元／時刻／reviewerとする。
SARIFを使う場合はtrusted report runも含める。Missing、stale、partial、permission denied、provider／scanner failureは
`NOT_CHECKED`または`ERROR`であり、`PASS`ではない。Secret、private code、raw event payloadはcommitしない。

## Atomic checks and other controls

[`control.yaml`](control.yaml)がcanonical metadataである。既存IDの意味を維持する。

- `SAS-001`: Scanner Action、version、runtime artifact identityをreview済みidentityへ固定する。
- `SAS-002`: Pull requestをcredentialなしのunprivileged blocking jobで評価する。
- `SAS-003`: SARIF write authorityをtrusted default-branch pushへ分離する。
- `SAS-004`: Clean、finding、scanner／input／result errorを区別する。
- `SAS-005`: 実際に採用したworkflowのunreviewed driftを検出する。

Check変更時はcontext、role、target、verification、evidence、mapping、README claimを同時にreviewし、
`check_context_version: "1.0"`を維持する。Scannerが検出し得るだけでcheckやmappingを増やさない。

- [`PSB-CICD-001`](../action-sha-pinning/README.md): General Action／reusable workflow／Docker Action pinning。
- [`PSB-CICD-002`](../actions-command-injection/README.md): Expressionからshellへのinjection。
- [`PSB-CICD-004`](../actions-least-privilege/README.md): Job operationに対するsemantic token／OIDC least privilege。
- [`PSB-CICD-005`](../untrusted-pr-boundary/README.md): Untrusted code、credential、runner、cross-run dataの一般境界。
- [`PSB-CICD-007`](../runner-hardening/README.md): Runner image、network、lifecycle、teardown。
- [`PSB-BUILD-001`](../../build-security/build-containment/README.md): Job内sandbox、egress、credential、telemetry。
- [`PSB-SOURCE-006`](../../source-protection/github-organization-governance/README.md): Organization-wide Actions policy。
- [`PSB-GOV-002`](../../governance-operations/time-bound-security-exceptions/README.md): Exception lifecycle。

Zizmor findingはこれらowner controlの完全な実装やlive adoptionを証明しない。別controlのparser、workflow、policy、evidenceを
このpackageへ複製しない。

## Required verification after changes

Repository rootから実行する。

```bash
bash controls/cicd-security/actions-static-analysis/tests/test.sh
make verify-control CONTROL=PSB-CICD-003
make validate-controls
```

`control.yaml`変更時はcanonical generatorでindex、mapping、checklistを再生成し、このcontrol由来の差分だけをreviewする。
Testを通すためにscanner identity、tokenless PR gate、trusted report boundary、finding／error separationを弱めない。
