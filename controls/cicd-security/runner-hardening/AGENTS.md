# PSB-CICD-007 implementation instructions

このfileは`PSB-CICD-007`（`cicd-security`）固有の実装境界を定める。変更前にrepository rootと
`controls/`の`AGENTS.md`、必須設計資料、このpackageの`README.md`、`control.yaml`を読むこと。

## Control essence

- 本質はCI jobを長寿命または共有hostへ残さず、jobごとにcleanなrunnerへ割り当て、job終了後に
  underlying computeとephemeral storageを再利用せず破棄すること。
- 最短baselineはGitHub-hosted runner。process／network／file traceをmanaged serviceで得たい場合の
  optional profileとしてTakumi Runnerを扱う。
- Organization-owned self-hosted runnerは、trusted jobに必要な場合だけ、限定runner group、JIT one-job
  registration、fresh compute、host境界遮断、external log、compute／storage destructionを一つのlifecycleで実装する。
- security効果はlive runner service、GitHub setting、provisioner、network、log backend、teardownから生まれる。
  documentationやworkflowをcopyしただけではorganization adoptionを証明しない。
- このcontrolをworkflow trust classifier、job sandbox、cloud IAM verifier、runtime detection product、
  container platform、fleet orchestration frameworkへ拡張しない。

## Supported profiles

1. `GitHub-hosted`: 通常のLinux build／testの推奨default。single-CPU container型labelではなく、jobごとに
   new VMを提供するversioned standard labelを例にする。
2. `Takumi Runner`: GitHub.com／GitHub Enterprise Cloud、Linux x86_64向けmanaged one-job VM profile。
   GitHub App、runner group scope、契約、vendor data boundary、trace limitationを明示する。
3. `Organization JIT`: private network、特殊hardware、独自image等が必要なtrusted workflow向け。
   cloud／ARC／on-premisesを推測で一つに固定しない。

Containerだけを削除して同じprivileged host、workspace、runtime socket、cache、credentialを再利用する構成は、
fresh one-job computeとして扱わない。DeveloperのMacBookや常用workstationをorganization runnerへ登録しない。

## 実装前に確認するcontrol固有入力

Provider固有実装またはadoptionを変更する前に、次を確認する。

1. 対象jobはGitHub-hostedで満たせるか。Takumiまたはorganization-owned self-hostedを必要とする理由は何か。
2. 対象organization、repository、workflow path／ref、runner group、labelのownerは誰か。
3. Self-hostedの場合、毎jobにfresh computeを作成・破棄するauthorityとproviderは何か。
4. Runner imageのcanonical source、immutable identity、review owner、runner version更新方法は何か。
5. Metadata endpoint、management CIDR、internal service、host runtime socketをどこでdenyするか。
6. Runner／worker logまたはmanaged traceをどこへ保持し、access、retention、alertを誰が所有するか。
7. Current setting、job dispatch、compute destruction、log arrivalをどのread-only sourceから確認するか。
8. Organization owner、Repository administrator、Platform／SRE、Security、Incident responseが割り当て済みか。

Provider-neutral guidanceの改善ではprovider未決定を架空値で埋めない。Provider固有のcopy可能な実装を追加する
場合は、activation、rollback、harmless positive／negative test、actual deletion evidenceまでend-to-endで示す。

## Guidance-first implementation rules

- READMEの早い位置に、security効果を生むlive setting／運用と担当者を示す。
- 最小推奨構成、copyするfile、明示的activation、expected output／exit、recovery、rollbackを先に示し、
  organization固有tuningは後に分離する。
- UI pathとsetting valueは具体的に書く。`適切に設定する`だけで終えない。
- Third-party Actionが不要なら追加しない。必要な場合はfull commit SHAへ固定する。
- Existing adopter workflowを自動上書きせず、global Git／shell／IDE／OS settingを変更しない。
- Credential-bearing provisioner、toy autoscaler、複数cloudの未検証templateを導入しない。

## Control ownership boundary

- `PSB-CICD-005`: fork／untrusted PR分類、credential-free routing、unsafe trigger。RNR-001はそのdecisionを消費する。
- `PSB-BUILD-001`: job内credential、privilege、egress、sandbox、runtime telemetry／threat detection。
- `PSB-CICD-004`: `GITHUB_TOKEN` permission。
- `PSB-CICD-006`: cloud OIDC trust policy。
- `PSB-CICD-008`: runner group等の管理面変更に対するhuman identity、approval、audit。
- `PSB-SOURCE-004`: provisioner用GitHub App／tokenの選択、保管、期限、失効。
- `PSB-GOV-002`: persistent runnerまたはbroad scopeのtime-bound exception。

Takumi trace／threat notification、StepSecurity Harden-Runner、cicd-sensor等のruntime detectionは補完としてlinkしてよい。
このcontrolが所有するのはteardown後も調査可能なexternal log／traceがあることまで。Detection rule、egress
baseline、alert triageを重複実装しない。

## Atomic checks

`control.yaml`がcanonical metadataである。既存IDを不要にrenumberしない。

- `RNR-001`: exact runner profileとself-hosted group／repository／workflow scope。
- `RNR-002`: JIT runnerとunderlying fresh computeが一jobだけで再利用されないこと。
- `RNR-003`: managed providerのcurrent image contract、またはimmutable self-hosted imageとsupported runner version。
- `RNR-004`: assignment時にprior stateとhost credentialがないこと。
- `RNR-005`: metadata、management／internal network、host runtime socketへ到達しないこと。
- `RNR-006`: one-use registration authorityとordinary management ingress deny。
- `RNR-007`: job後のderegistration、compute／workspace／storage／process destruction。
- `RNR-008`: destruction後もexternal log／traceをexact job／runner generationで取得できること。
- `RNR-009`: required live sourceが取得不能なら`PASS`でなく`ERROR`または`NOT_CHECKED`になること。

Check変更時は`applies_to`、role、check固有のthreat actor／scenario／why required、verification、evidence、mappingを
同時reviewし、`check_context_version: "1.0"`を維持する。

## Verification and test boundary

Primary verificationは`docs/ADOPTION.md#live-verification`にあるlive settingとharmless lifecycle testである。

意味のある確認:

- copy可能なworkflowを二回実行し、別generationでprior markerがないことを確認する。
- inert markerを同じjobで作るnegative inputがfailすることを確認する。
- Read-only GitHub settingでgroup、selected repositories／workflows、public accessを確認する。
- Actual provider eventでprovision、deregistration、compute／storage destructionを確認する。
- Actual runner namespaceからadopter-defined metadata／management／host socket probeがdenyされることを確認する。
- Teardown後にactual external log／traceをjob IDとrunner generationでqueryする。

追加しないもの:

- READMEの文字列だけを確認するcontrol-local test。
- 手書きJSONの`secure: true`、`destroyed: true`、`logs_exported: true`を検査するverifier。
- Synthetic evidenceの`PASS`をorganization adoptionへ変換するassessment。
- 常に成功するtest、no-op script、形式的schema validation、real credentialを使うtest。

本controlはtop-level `verification.type: external-evidence`を使う。`tests/test.sh`を置かず、
`make verify-control CONTROL=PSB-CICD-007`はlive evidenceがないためexit `2`と`NOT_CHECKED`を返す。
全control suiteはexternal-evidence controlを`verified`へ数えず、明示的に`NOT_CHECKED`としてreportする。

## Evidence rules

- Adoption evidenceはcurrent runner-group setting、actual job dispatch、actual provider provision／destruction event、
  actual external log arrival、live deny resultに限る。
- Evidenceにはsource、取得時刻、target、job／runner generation、collector authority、completenessを含める。
- Token、encoded JIT config、authorization header、private log本文、secret-bearing argumentをcommitしない。
- Missing、stale、partial、malformed、permission denied、provider／collector failureは`ERROR`または
  `NOT_CHECKED`であり、current `PASS`ではない。
- Live evidenceを用意できない場合は架空fileを作らず、採用組織が確認すべきsourceとsuccess stateをrunbookへ書く。

## Completion criteria

変更後、adopterが次を一読で判断できる状態にする。

- どのprofileで何をliveに設定するか。
- 誰がGitHub、managed provider、self-hosted infrastructureを設定するか。
- one-job fresh compute、host isolation、destructionがなぜ安全性を上げるか。
- どのpositive／negative job、deny probe、log、destruction eventを実際に確認するか。
- provider内部やcontrol plane等、何を自動検証できないか。
- 何をもって導入完了とし、障害時にどうrollbackするか。

## Required repository verification after changes

Repository rootから次を実行する。

```bash
python3 -m unittest tests.test_control_metadata
make validate-controls
make verify-control CONTROL=PSB-CICD-007
```

最初の二つはexit `0`、最後は意図どおり`NOT_CHECKED`を表示してexit `2`でなければならない。Generated index、
mapping、checklistはrepository policyに従って別途再生成するが、generated output自体をこのcontrol変更へ含めるかは
task scopeに従う。検証を通すためにone-job、fresh compute、host isolation、destruction、fail-closed requirementを弱めない。
