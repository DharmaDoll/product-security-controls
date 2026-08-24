# PSB-CONTAINER-001: Fail-closed container workload admission

## このcontrolを一枚で理解する

### セキュリティ上の問題

Mutableまたは出所不明のimageや、root・host access・無制限resourceを持つworkloadをadmitすると、application侵害がnodeやclusterへ拡大する。

### 誰から、または何から守るか

Registry・publisher侵害、forged provenance、application内code execution、malicious workload、resource exhaustion、admission controller障害から守る。

### 何が対象か

Kubernetes AdmissionReview、OCI manifest digest、SLSA provenance、Pod security context、capability、host境界、resource、NetworkPolicy、admission policy。

### 何をするか

Exact OCI digestと`PSB-REL-001`のauthenticated provenanceを結び、non-root、drop ALL、read-only、host isolation、resource bound、default-deny networkをadmission前に検証する。

### 成功状態

全9 checksとplatform evidenceが一致したworkloadだけがallow候補となり、policy違反・malformed input・verifier停止はdenyまたはerrorとしてfail closedになる。

### 対象外・残余リスク

Fixtureはlive API server、admission controller、CNI、runtime enforcementを証明せず、許可済みimageやapplication logic自体の脆弱性も排除しない。

## 何を守るcontrolか

このcontrolは、Kubernetes workloadが実行される直前に、次の二つを同時に
検証します。

1. 実行するOCI imageは、review済みのexact digestとauthenticated provenanceに
   結び付いているか。
2. workloadは、applicationが侵害されてもhost、neighbor workload、network、
   shared resourceへ影響を広げにくい設定か。

単に`image: example:v1`をdigestへ変えるだけでは、imageの出所は分かりません。
逆に、署名済みprovenanceがあっても、実際にadmitするdigestとsubjectが違えば
別artifactの証跡です。そのため、`PSB-REL-001`をadmission decision内で実際に
再実行します。

| 誰／何から | 対象 | 攻撃・失敗 | このcontrolが行うこと |
|---|---|---|---|
| registryまたはpublisherを侵害した攻撃者 | OCI image | mutable tagや別registryへimageを差し替える | trusted registryとexact manifest SHA-256を照合する |
| forged build／誤ったrelease evidence | provenance | 正しいように見えるが別image用のprovenanceを添付する | `PSB-REL-001`で署名、builder、source、subjectを再検証する |
| application内でcode executionを得た攻撃者 | pod、node、runtime | root、capability、hostPath、runtime socketからhostへ到達する | non-root、no escalation、drop ALL、host境界denyを強制する |
| faulty／malicious workload | shared node | CPU、memory、PIDを枯渇させる | request、limit、platform PID limitを検証する |
| compromised workload | cluster network | lateral movement、C2、data exfiltrationを行う | workloadを選択するdefault-deny ingress／egressを要求する |
| admission controller障害・設定漏れ | API server | policyを評価できないrequestをallowする | CREATE／UPDATE、`failurePolicy: Fail`、deny-on-outageを検証する |

## まず実行するコマンド

```bash
make verify-control CONTROL=PSB-CONTAINER-001
```

通常検証はnetwork、cluster、registry、cloud credentialを使いません。安全・危険な
Kubernetes API JSON、OCI manifest、synthetic SLSA provenance、platform evidenceを
offlineで評価します。

終了状態は次のとおりです。

| 終了コード | 意味 | admissionでの扱い |
|---:|---|---|
| `0` | 全checkを評価し、違反なし | allow候補 |
| `1` | workload、policy、provenanceに違反あり | deny |
| `2` | malformed input、platform evidence error、verifier timeout／不在 | **errorとしてdeny** |

## 9つのatomic check

| Check | 確認内容 |
|---|---|
| `CNT-001` | trusted registryのexact OCI manifest digest |
| `CNT-002` | `PSB-REL-001`によるprovenance authenticityとsubject binding |
| `CNT-003` | non-root、no privileged、no escalation、token automount無効 |
| `CNT-004` | Linux capabilityを`ALL` dropし、追加なし |
| `CNT-005` | host namespace、hostPath、hostPort、runtime socketを使用しない |
| `CNT-006` | read-only root filesystemと`RuntimeDefault` seccomp |
| `CNT-007` | CPU／memory request・limitとruntime PID limit |
| `CNT-008` | workloadを選択するdefault-deny ingress／egress |
| `CNT-009` | immutable policy、CREATE／UPDATE、fail-closed admission |

担当、確認方法、期待証跡、行単位framework mappingは`control.yaml`から生成される
spreadsheetへ自動展開されます。

## Secure example

[`secure/admission-review.json`](secure/admission-review.json) は、Kubernetes
admission webhookが受け取るAPI-nativeな`AdmissionReview` fixtureです。
Deployment内のinit containerとapplication containerの両方を検査します。

[`secure/network-policy.json`](secure/network-policy.json) は、同じnamespaceと
pod labelを選択し、ingress／egressをdefault denyにします。実運用ではこのbaselineに
加えて、DNS、service、egress destinationなど、必要最小限のallow policyを別途
追加します。

[`secure/platform-evidence.json`](secure/platform-evidence.json) は、workload
manifestだけでは観測できない次のplatform stateを表します。

- admission controllerがCREATEとUPDATEをenforceする
- evaluator不在時にdenyする
- timeoutがpolicy範囲内である
- NetworkPolicy enforcementが利用できる
- runtime PID limitが有効である

これはdeterministic fixtureであり、live clusterの証跡ではありません。

## OCI digestとSLSA provenanceの結合

検証chainは次のとおりです。

```text
AdmissionReview image reference
        |
        | sha256 digest
        v
exact OCI manifest bytes
        |
        | subject.digest
        v
signed SLSA provenance
        |
        | consumer-owned key/builder/source expectations
        v
PSB-REL-001 verification
        |
        v
PSB-CONTAINER-001 allow / deny / error
```

container verifierは、annotationや`verified: true`のような自己申告fieldを信用せず、
repository内の`PSB-REL-001` verifierをsubprocessとして再実行します。

- image reference digestとOCI manifest bytesのSHA-256を照合
- provenance policyのsubject nameとimage repositoryを照合
- `PSB-REL-001`がmanifest bytesとprovenance subjectを照合
- provenance signature、builder、build type、source、revisionを検証
- verifier不在、timeout、parse errorを終了コード`2`にする

この実装により`CNT-002`だけがSLSA
`build-l2#consumer-validates-authenticity`と`build-provenance`へ
行単位mappingされます。non-root、NetworkPolicy、resource limitはSLSA Build
requirementではありません。

## Insecure example

[`insecure/admission-review.json`](insecure/admission-review.json) は
**テスト専用であり、deployしてはいけません**。次の危険な状態をまとめて示します。

- `docker.io/example/payments:latest`
- root、privileged、`allowPrivilegeEscalation: true`
- `SYS_ADMIN`
- host network、PID、IPC namespace
- `/var/run/docker.sock`のhostPath mount
- writable root filesystem、unconfined seccomp
- CPU／memory boundsなし
- service account token自動mount

[`insecure/policy.json`](insecure/policy.json) は、`failurePolicy: Ignore`、
wildcard registry、CREATEだけのcoverage、provenance任意など、policyそのものが
fail-openな例です。

[`insecure/platform-error.json`](insecure/platform-error.json) のようにplatform
状態を確認できない場合は、findings 0件ではなく`ERROR`になります。

## 実環境への統合

このreference verifierをlive admission adapterへ接続する場合は、次の順序を守ります。

1. API serverから受け取ったoriginal AdmissionReviewを改変せず取得する。
2. tagをregistryで解決し直すのではなく、request内のexact digestを使う。
3. そのdigestのOCI manifest bytesをauthenticated registryから取得する。
4. `PSB-REL-002`のpublication evidenceから対応provenanceを取得する。
5. consumer-owned trust policyで`PSB-REL-001`を実行する。
6. workload、network、platform evidenceをこのcontrolのschemaへ正規化する。
7. 終了コード`0`だけをallowへ変換し、`1`はdeny、`2`はadmission errorとしてdenyする。
8. UID、workload namespace/name、policy version、image digest、check IDだけを
   sanitized audit evidenceとして保存する。

registry access、signature／provenance retrieval、live CNI／runtime evidenceは
adapterの責任です。credential、environment value、image contentsをadmission logへ
保存してはいけません。

## Operational notes

- policy versionとeffective admission configurationを同じevidenceで結び付ける。
- CREATEだけでなくUPDATEも対象にし、後からのprivilege追加を防ぐ。
- init containerとephemeral containerもapplication containerと同じ基準で検査する。
- 複数imageを使用するworkloadでは、imageごとにmanifestとprovenance evidenceを
  用意する。
- default-deny policyとは別に、applicationごとのexact allow policyをreviewする。
- resource上限はnamespace quota、LimitRange、node capacityとも整合させる。
- PID limitはcontainer runtime／kubeletの実効設定をplatform evidenceから確認する。
- break-glass exceptionは別のgovernance controlでexact、owned、approved、
  expiringにする。admission policy内へ恒久ignoreを埋め込まない。

## Responsibility boundaries

- image／SBOM vulnerability scanning: `PSB-DETECT-001`
- provenance生成: `PSB-BUILD-003`
- provenance publication: `PSB-REL-002`
- consumer authenticity verification: `PSB-REL-001`
- registry security: `PSB-CONTAINER-002`
- container host／daemon hardening: `PSB-CONTAINER-003`
- post-admission runtime detection: `PSB-CONTAINER-004`
- application secret handling: `PSB-CODE-001`

## Limitations

- fixture成功はlive Kubernetes clusterへのadoptionを証明しません。
- 最初のsliceは一つのunique image identityだけを扱います。
- NetworkPolicyを実際にenforceするかはCNI依存です。
- resource quantity parserは一般的なCPU表記と`Ki`／`Mi`／`Gi`に限定しています。
- workload-levelにportableなPID fieldがないため、PIDはplatform evidenceです。
- service account RBAC、projected token audience、secret deliveryは未評価です。
- synthetic public keyとsignatureはproduction trust rootではありません。
- CIS Docker Benchmarkはversioned official source review前のためmappingしません。
- このcontrol単独ではSLSA Build Level 2達成やNIST SP 800-190全体coverageを
  主張しません。

## References

- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes Admission Webhook Good Practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
- [SLSA v1.2 Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final)
- [`REF-CONTAINER-001` OWASP Docker Security Cheat Sheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-container-001)
- [`REF-CONTAINER-002` Kubernetes workload and admission guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-container-002)
