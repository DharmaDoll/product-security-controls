# PSB-REL-005: exact release artifactへ保護されたidentityで署名する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Releaseへ署名が付いていても、mutable tag、別artifact、広い長期credential、exportable key、署名失敗を無視するpipelineでは、攻撃者や誤設定が正規releaseらしい不正artifactを生成できる。

### 誰から、または何から守るか

Compromised release job・maintainer、署名鍵窃取、artifact差替え、TOCTOU、broad authorization、stale signer inventory、署名・transparency service障害から守る。

### 何が対象か

Release artifact bytes／digest、immutable releaseとsource revision、signing request、workload authorization、signerとkey version、署名statement、publication／transparency receipt、release gate。

### 何をするか

Exact digestだけを短寿命・audience／scope-bound workload identityで、非exportableかつsign-onlyのKMS／HSM／keyless signerへ渡し、署名とreceiptが揃うまでreleaseをblockする。

### 成功状態

Artifact・request・authorization・signer・statement・signature・receiptが一つのrelease identityへ一致し、改ざんや不完全な署名はFAIL、検証不能はERRORとなりreleaseできない。

### 対象外・残余リスク

Offline fixtureはlive KMS／HSM、Fulcio、Rekor、OIDC issuer、key custody、publication ACLを証明しない。Consumer検証は`PSB-REL-001`、配布は`PSB-REL-002`が別に必要。

## Goalとcontrol boundary

Producer側で、build後に確定したexact artifact digestへ、保護されたsigner identityを
使って署名を生成し、その署名生成が成功したreleaseだけを公開可能にします。

責務は次のように分離します。

- `PSB-CICD-006`: CI workloadがcloud／signerへ渡す短寿命OIDC federation;
- `PSB-REL-005`: signing request、signer authority、署名生成、signing receipt、release block;
- `PSB-REL-001`: consumer側の署名・subject・builder／source expectation検証;
- `PSB-REL-002`: artifactとprovenanceのdiscoverability、immutability、retention;
- `PSB-REL-003`: artifact-bound SBOM生成・公開;
- `PSB-GOV-004`: signer exposure時のdistrust、rotation、old-authority denial。

Artifact signingはSLSA Build levelの独立要件ではないため、このcontrolをSLSAへ
mappingしません。署名があってもprovenance生成・配布・consumer検証要件の代わりには
なりません。

## Threat／failure scenario

Compromised release jobまたはoperatorが、`latest` tagやfile pathを署名対象として渡す、
artifact digest計算後にbytesを差し替える、全releaseへ使える長寿命credentialを流用する、
export可能なshared keyをworkspaceへ置く、あるいは署名serviceの失敗後もreleaseを完了
させる状況を想定します。攻撃者が正しい暗号署名を生成できる場合もあるため、署名の
数学的validityだけでなく、request、authorization、signer lifecycle、publication receiptを
同じidentityへbindingします。

## 安全な実装

`secure/`はsynthetic artifactについて次を固定します。

- artifact name、SHA-256、versioned release ID、tag ref、full source revision;
- exact workload、audience、artifact／release scope、5分TTL、nonceを持つauthorization;
- `kms`／`hsm`／`keyless`だけを許可し、active key version、non-exportable、`sign` onlyを要求;
- requestとauthorizationのdigest、artifact、release、source、signerを含むsigned statement;
- policy-pinned public keyで実際に検証できるEd25519 signature;
- immutable HTTPS location、transparency inclusion、release `BLOCK` policyを持つreceipt;
- identity token、private key、signature bodyを複製しないmetadata-only evidence。

`scripts/generate_fixture_bundle.py`は0600の一時Ed25519 keyを使い、このcontractに沿う
statement、signature、receiptを実際に生成します。これはlocal test harnessです。
Productionではprivate-key fileを渡さず、同じrequestをreview済みKMS／HSMまたは
keyless signing adapterへ渡し、authentic provider receiptを取り込みます。

## 安全でない実装

`insecure/`は明示的に隔離された非deploy fixtureです。暗号署名そのものはvalidですが、
次を意図的に含みます。

- `latest`とbranch ref、short source revision;
- wildcard scope、48時間authorization、token retention;
- workspace file型のexportable shared keyと`admin`／`decrypt`／`export`権限;
- HTTP mutable location、transparency receiptなし;
- 署名失敗時も`CONTINUE`するrelease gate;
- identity token、private-key material、signature bodyを保存するevidence policy。

このfixtureにより「署名がvalid」という一点だけでは、安全なrelease生成を意味しない
ことをnegative testで示します。

## 統合方法

1. Build完了後にartifact bytesを凍結し、SHA-256とimmutable release／source identityを
   signing requestへ記録します。
2. `PSB-CICD-006`相当のOIDC federationまたはsigner-native workload identityで、exact
   signer、audience、artifact family、releaseだけを許可する数分のauthorityを発行します。
3. KMS／HSM keyはexport不可・sign-onlyにし、keylessではexact issuer／subjectと短寿命
   certificateをconsumer policyへ渡せる形で保持します。
4. Artifact pathやtagでなくdigest-bound statementを署名します。Containerはtagでなく
   OCI manifest digestを対象にします。
5. Signature、certificate／public-key identity、timestamp／transparency proofをimmutable
   bundleまたはrelease manifestへ公開します。
6. Signing、receipt、publicationのどれかが失敗・timeout・parse不能ならrelease jobを
   `ERROR`で停止します。
7. 公開後は`PSB-REL-001`でconsumer検証し、`PSB-REL-002`で配布とretentionを検証します。

## 検証

```bash
make verify-control CONTROL=PSB-REL-005
```

Exit codeは`0=PASS`、`1=policy／binding finding`、`2=入力・OpenSSL・評価基盤ERROR`です。
`ERROR`を署名済みまたはclean resultとして扱ってはいけません。

Secure expected outputは8個のatomic checkと最終decisionだけを出し、artifact digest、
signature、token、key materialは出力しません。Testsはvalid-but-insecure signature、
artifact tamper、invalid signature、malformed input、missing OpenSSL、unsafe private-key mode、
一時鍵による実生成とprivate-key非残存を検証します。

## 運用上の注意

- Signer policy、key version、OIDC trust、release workflowは別ownerによる変更reviewを要求します。
- Signature creationとrelease publicationを同じbroad credentialに統合しません。
- Signer status、OIDC issuer、transparency log、publication probeにはfreshnessとavailability
  alertを設定します。
- Retryは同じrequest digestとidempotency identityへbindingし、別artifactを同じapprovalで
  署名しません。
- Rotation時は新keyへの移行だけでなく、`PSB-GOV-004`でold signerのdistrustと既発行
  artifactへの影響を確認します。
- Cosign等を使う場合もversion／bytesをpin・integrity verifyし、OIDC tokenやprivate keyを
  command line、log、artifactへ残しません。

## 制限と残余リスク

- Committed public key、signature、receiptはsynthetic deterministic fixtureです。Live KMS、
  HSM、Fulcio、Rekor、TUF root、OIDC issuer、clock、networkを評価しません。
- Nonceはsigned authorizationへbindingしますが、issuer側のatomic uniquenessとdurable
  replay ledgerはlive adapterで別途証明する必要があります。
- Fixture generatorのlocal private keyはtest-onlyです。Production key protectionの証跡に
  置き換えてはいけません。
- Authorized signerまたはrelease workflow自体が悪意を持つ場合、internally consistentな
  不正artifactへ署名できるため、build provenance、two-person policy、monitoringも必要です。
- Transparency inclusionは悪意あるartifactを安全にせず、発行を監査可能にするsignalです。
- Signature generationだけではavailability、vulnerability absence、SBOM completeness、
  SLSA level、formal complianceを証明しません。

## References

- [`REF-REL-003`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-rel-003) — Sigstore／Cosign official signing, bundle, identity, KMS guidance
- [NIST SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19)
- [MITRE ATT&CK T1553.002: Subvert Trust Controls — Code Signing](https://attack.mitre.org/techniques/T1553/002/)
