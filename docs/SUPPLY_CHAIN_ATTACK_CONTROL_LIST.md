# Software supply-chain attack control list

## 目的

この文書は、software supply-chain attackを攻撃段階ごとに追い、関連する既存controlへ
移動するためのcurated indexです。新しいcontrol、framework mapping、compliance評価では
ありません。各controlの要求、検証、証跡、制限の正本は、それぞれの`README.md`と
`control.yaml`です。

リポジトリ内のsecure fixtureが成功しても、組織のdeveloper endpoint、SCM、CI/CD、
registry、cloud、productionでcontrolが導入済みであることを意味しません。live adoption、
証跡freshness、例外、provider固有の残作業は、各controlの境界に従って別に確認します。

## 攻撃段階、主な脅威、対応control

| 攻撃段階 | 主な脅威 | 対応control |
|---|---|---|
| 1. 開発端末とlocal trust | phishing、infostealer、malicious extension／hook、local credential・sourceの窃取、侵害端末からの不正操作 | [`PSB-SOURCE-001`](../controls/source-protection/developer-endpoint-hardening/README.md) Developer endpoint hardening<br>[`PSB-SOURCE-002`](../controls/source-protection/git-hooks-baseline/README.md) Repository-owned Git hooks baseline<br>[`PSB-SOURCE-004`](../controls/source-protection/source-access-credential-lifecycle/README.md) Source access credential lifecycle |
| 2. Source、repository、VCS control plane | stolen accountによるsource／workflow／IaC改ざん、Unicode stealth、tag・ruleset操作、repository公開・大量削除、監査drift | [`PSB-CODE-005`](../controls/secure-coding/unicode-source-deception/README.md) Unicode source deception<br>[`PSB-SOURCE-003`](../controls/source-protection/public-repository-exposure/README.md) Public repository exposure monitoring<br>[`PSB-SOURCE-005`](../controls/source-protection/repository-destruction-recovery/README.md) Repository destruction recovery<br>[`PSB-SOURCE-006`](../controls/source-protection/github-organization-governance/README.md) GitHub Organization governance<br>[`PSB-CICD-008`](../controls/cicd-security/privileged-control-plane-change/README.md) Privileged control-plane change assurance |
| 3. AI-assisted development supply chain | poisoned AGENTS／Skill／MCP／plugin／prompt、prompt injection、過剰なagent権限、unsafe action、model・dataset・RAG corpusの改ざん | [`PSB-AI-001`](../controls/ai-development-security/repository-owned-ai-security-guidance/README.md) Repository-owned AI guidance<br>[`PSB-AI-002`](../controls/ai-development-security/agent-extension-dependency-governance/README.md) Agent extension dependency governance<br>[`PSB-AI-003`](../controls/ai-development-security/prompt-document-injection-containment/README.md) Prompt and document injection containment<br>[`PSB-AI-004`](../controls/ai-development-security/ai-coding-agent-runtime-hardening/README.md) AI coding agent runtime hardening<br>[`PSB-AI-006`](../controls/ai-development-security/agent-action-integrity-output-validation/README.md) Agent action integrity<br>[`PSB-DEPS-005`](../controls/dependency-security/ai-model-supply-chain/README.md) AI model and dataset integrity<br>[`PSB-AI-011`](../controls/ai-development-security/rag-corpus-integrity-retrieval/README.md) RAG corpus integrity |
| 4. Dependency選定、解決、取得 | typosquatting、dependency confusion、compromised maintainer、malicious release、install script実行、lockfile・artifact差し替え、未reviewのtransitive変更 | [`PSB-DEPS-001`](../controls/dependency-security/release-cooldown/README.md) Registry proxy and release cooldown<br>[`PSB-DEPS-002`](../controls/dependency-security/install-script-execution/README.md) Install execution default deny<br>[`PSB-DEPS-003`](../controls/dependency-security/lockfile-integrity/README.md) Lockfile and artifact integrity<br>[`PSB-DEPS-004`](../controls/dependency-security/dependency-change-review/README.md) Dependency graph change review<br>[`PSB-DETECT-001`](../controls/detection-verification/integrity-verified-scanner/README.md) Integrity-verified scanning |
| 5. CI workflow、PR、Action、cache | mutable／compromised Action、command injection、unsafe `pull_request_target`、forkからのprivilege昇格、過剰なtoken権限、cache poisoning、scanner失敗の見逃し | [`PSB-CICD-001`](../controls/cicd-security/action-sha-pinning/README.md) Action SHA pinning<br>[`PSB-CICD-002`](../controls/cicd-security/actions-command-injection/README.md) Command injection prevention<br>[`PSB-CICD-003`](../controls/cicd-security/actions-static-analysis/README.md) Workflow static analysis<br>[`PSB-CICD-004`](../controls/cicd-security/actions-least-privilege/README.md) Least-privilege workflow permissions<br>[`PSB-CICD-005`](../controls/cicd-security/untrusted-pr-boundary/README.md) Untrusted PR boundary<br>[`PSB-CICD-009`](../controls/cicd-security/cache-provenance-isolation/README.md) Cache provenance isolation |
| 6. CI/CD identityと管理面 | stored cloud key、OIDC audience／subject誤設定、token replay、管理者session侵害、runner group・environment・registry・signing policyの無承認変更 | [`PSB-CICD-006`](../controls/cicd-security/audience-bound-oidc-federation/README.md) Audience-bound OIDC federation<br>[`PSB-CICD-008`](../controls/cicd-security/privileged-control-plane-change/README.md) Privileged control-plane change assurance<br>[`PSB-SOURCE-004`](../controls/source-protection/source-access-credential-lifecycle/README.md) Source access credential lifecycle |
| 7. Runnerとbuild execution | persistent self-hosted runner、prior-job state、host／metadata／runtime socket侵入、credential exfiltration、broad egress、malicious build script、telemetry停止 | [`PSB-CICD-007`](../controls/cicd-security/runner-hardening/README.md) One-job runner isolation and destruction<br>[`PSB-BUILD-001`](../controls/build-security/build-containment/README.md) Build containment |
| 8. Build platformとprovenance生成 | unapproved builder、mutable build definition、invocation drift、tenantが偽造したprovenance、platform identity・署名境界の混同 | [`PSB-BUILD-002`](../controls/build-security/hosted-consistent-build/README.md) Hosted consistent build<br>[`PSB-BUILD-003`](../controls/build-security/platform-provenance-generation/README.md) Platform provenance generation |
| 9. Artifact、release、署名、SBOM | artifact substitution、署名対象の取り違え、provenance欠落・downgrade、署名権限悪用、SBOMとartifactの不一致、supplier SBOM偽装 | [`PSB-REL-001`](../controls/release-integrity/signature-provenance-verification/README.md) Signature and provenance verification<br>[`PSB-REL-002`](../controls/release-integrity/provenance-publication-distribution/README.md) Provenance publication and distribution<br>[`PSB-REL-003`](../controls/release-integrity/sbom-binding-publication/README.md) Artifact-bound SBOM lifecycle<br>[`PSB-REL-004`](../controls/release-integrity/supplier-sbom-trust/README.md) Supplier SBOM trust<br>[`PSB-REL-005`](../controls/release-integrity/artifact-signing-generation/README.md) Exact artifact signing |
| 10. Registry、IaC、deployment admission | anonymous／broad registry authority、mutable image、malicious image publication、IaC manipulation、policy bypass、artifactとdeployment identityの切断、危険なworkload設定 | [`PSB-CONTAINER-002`](../controls/container-cloud-iac-security/container-registry-security/README.md) Container registry security<br>[`PSB-IAC-001`](../controls/container-cloud-iac-security/secure-iac-golden-path/README.md) Secure IaC golden path<br>[`PSB-CONTAINER-001`](../controls/container-cloud-iac-security/container-admission-baseline/README.md) Container admission baseline<br>[`PSB-CICD-006`](../controls/cicd-security/audience-bound-oidc-federation/README.md) Deployment workload identity |
| 11. Production runtimeと外部露出 | container escape、shell・protected file・runtime socket操作、C2／lateral movement、resource abuse、sensor drop・rule欠落、未登録の外部公開asset | [`PSB-CONTAINER-003`](../controls/container-cloud-iac-security/container-host-daemon-hardening/README.md) Host and daemon hardening<br>[`PSB-CONTAINER-004`](../controls/container-cloud-iac-security/runtime-threat-detection/README.md) Falco／Sysdig runtime threat detection<br>[`PSB-DETECT-003`](../controls/detection-verification/external-attack-surface-reconciliation/README.md) External attack-surface reconciliation |
| 12. Detection、incident response、recovery | scanner／collector失敗のclean扱い、影響artifact・deploymentの特定不能、credential漏洩後の不完全rotation、期限なし例外、脆弱artifactの継続稼働 | [`PSB-DETECT-001`](../controls/detection-verification/integrity-verified-scanner/README.md) Integrity-verified scanning<br>[`PSB-GOV-001`](../controls/governance-operations/supply-chain-incident-readiness/README.md) Supply-chain incident readiness<br>[`PSB-GOV-002`](../controls/governance-operations/time-bound-security-exceptions/README.md) Time-bound exceptions<br>[`PSB-GOV-003`](../controls/governance-operations/exploited-vulnerability-prioritization/README.md) Exploited vulnerability prioritization<br>[`PSB-GOV-004`](../controls/governance-operations/credential-exposure-containment/README.md) Credential exposure containment<br>[`PSB-GOV-005`](../controls/governance-operations/deployed-artifact-refresh/README.md) Deployed artifact refresh closure |

同じcontrolが複数段階に現れるのは意図的です。例えば`PSB-CICD-006`はCI identityの
発行条件だけでなくdeployment authorityとの接続にも必要であり、`PSB-CICD-008`は
source、CI、registry、signingの各control plane変更を横断します。

## 代表的なattack pathの読み方

### Malicious dependencyからproductionまで

```text
malicious release / dependency confusion
  -> dependency resolution and install execution
  -> CI runner and build containment
  -> artifact, provenance, signature, and SBOM
  -> registry and deployment admission
  -> runtime detection and incident impact search
```

確認順は[`PSB-DEPS-001..004`](../controls/dependency-security/)、
[`PSB-CICD-007`](../controls/cicd-security/runner-hardening/README.md)と
[`PSB-BUILD-001`](../controls/build-security/build-containment/README.md)、
[`PSB-BUILD-002..003`](../controls/build-security/)、
[`PSB-REL-001..005`](../controls/release-integrity/)、
[`PSB-CONTAINER-001..004`](../controls/container-cloud-iac-security/)、
[`PSB-GOV-001`](../controls/governance-operations/supply-chain-incident-readiness/README.md)です。

### Compromised workflowからcloud／releaseまで

```text
mutable Action / poisoned PR / command injection
  -> workflow token or OIDC authority
  -> runner or cache persistence
  -> artifact publication or production deployment
```

[`PSB-CICD-001..005`](../controls/cicd-security/)、
[`PSB-CICD-009`](../controls/cicd-security/cache-provenance-isolation/README.md)、
[`PSB-CICD-006`](../controls/cicd-security/audience-bound-oidc-federation/README.md)、
[`PSB-CICD-007`](../controls/cicd-security/runner-hardening/README.md)を組み合わせます。
workflow内の設定だけで、runner host、cloud trust policy、registry policyまで安全だとは
判断しません。

### Developer／AI toolingからsource改ざんまで

```text
endpoint compromise / poisoned Skill or MCP / prompt injection
  -> source credential or agent authority abuse
  -> malicious source, workflow, or dependency change
  -> reviewed-looking build and signed release
```

[`PSB-SOURCE-001`](../controls/source-protection/developer-endpoint-hardening/README.md)、
[`PSB-SOURCE-004`](../controls/source-protection/source-access-credential-lifecycle/README.md)、
[`PSB-AI-001..004`](../controls/ai-development-security/)、
[`PSB-AI-006`](../controls/ai-development-security/agent-action-integrity-output-validation/README.md)、
[`PSB-CICD-008`](../controls/cicd-security/privileged-control-plane-change/README.md)を起点に確認します。
正しい署名やprovenanceは「内容が善良であること」までは証明しないため、source changeと
review identityを切らずに追跡する必要があります。

## 横断ビューと既知の境界

- [`Software supply-chain integration reconciliation`](../generated/checklists/profiles/supply-chain-integration/reconciliation.md)
  は、developer、SCM、dependency、build、release、registry、deployment間でidentityと
  decisionが切れていないかをexact check参照で確認します。
- [`SITF technique coverage`](../generated/checklists/profiles/sitf/technique-coverage.md)は、
  endpoint、VCS、CI/CD、registry、productionの全techniqueについて、直接実装とgapを
  区別します。
- [`Synthetic SITF attack flows`](../generated/checklists/profiles/sitf/attack-flows.md)は、
  単一controlでは見えにくいcross-component attack pathを確認するreview scenarioです。
- [`Software supply-chain security: 7つの実装原則`](SUPPLY_CHAIN_PRINCIPLES.md)は、
  dependency取得、build containment、release verification、SBOM、incident responseの
  基本的な連鎖を短く説明します。

現時点でも、maliciousだが形式上validなsource／dependency、CI runner内の完全なruntime
behavior monitoring、provider control plane自身の侵害、live sensor／collectorの導入、
non-container productionのdata exfiltrationや破壊的操作などは、controlごとの残余リスク
またはSITFのgapとして残ります。署名、SBOM、provenance、scanner、runtime sensorの
いずれか一つを、software supply-chain全体の安全性の証明として扱ってはいけません。

## 利用と保守

1. 上の表から攻撃段階を選び、リンク先controlの一枚概要とlimitationsを読む。
2. control-localの標準コマンド`make verify-control CONTROL=<ID>`を実行する。
3. 組織導入ではlive evidenceを収集し、fixture成功とadoptionを区別する。
4. 複数段階を横断する場合はintegration reconciliationとSITF attack flowを確認する。
5. 新規または改修controlの攻撃段階ownershipが変わったとき、このindexのリンクと説明を
   更新する。status、evidence level、atomic check、mappingはここへ複製せず、
   `control.yaml`と生成catalogを正本にする。

全controlをdomainから探す場合は[`Control catalog`](../controls/README.md)、担当、検証方法、
必要証跡、framework relationshipから絞り込む場合は
[`Adoption checklist`](../generated/checklists/product-security-checklist.md)を使用してください。
