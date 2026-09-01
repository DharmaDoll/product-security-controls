# 中央Model Intake Control Plane導入ガイド

このガイドは、model／datasetを各development teamが直接取得する運用から、中央intake
serviceだけが取得・検証・昇格する運用へ移すための最小実装です。Repository内のself-test
は状態遷移とsecurity propertyを検証しますが、組織のregistry、IAM、KMS、egressが実際に
変更されたことの証拠ではありません。

## セキュリティ向上の効果はどこから生まれるか

実際の効果は次の実設定と運用から生まれます。

1. Training、evaluation、serving identityから外部model registryへのread権限と直接egressを外す。
2. 中央intake identityだけが、承認済みoriginからfull revisionで取得できるようにする。
3. `model-intake/quarantine`と`model-intake/trusted`を別namespaceとして作り、別permissionを与える。
4. Requestと全bundle materialをservice-owned quarantineへsnapshotし、model codeをloadせずに検証して、
   `ACCEPTED_FOR_STAGING`のexact digestだけを昇格する。
5. Runtimeはtrusted namespaceをread-onlyかつdigest指定で取得し、取得後にもSHA-256を照合する。
6. `QUARANTINE`と`ERROR`はtrusted namespaceを変更せず、それぞれsecurity reviewと運用alertへ送る。

これにより、developer credentialからの直接download、mutable tagの差替え、pickle／remote
codeのload、別modelのclean receipt再利用、verifier障害のfail-openが難しくなります。
Documentation、fixture、scriptをcopyしただけでは、この効果は発生しません。

## 誰が何をするcontrolなのか

| 担当 | 必須作業 | 完了条件 |
|---|---|---|
| Product owner | 対象model、目的、staging acceptance、productionへ進む別gateを承認する | requestにownerと用途があり、production直行を許可しない |
| Data owner | dataset source、license、purpose、consent、personal-data classificationを承認する | organization-owned authorization referenceを検証できる |
| Organization owner | IAM、KMS key policy、例外承認者を設定する | developer／runtimeがtrustedへwriteできない |
| Platform／SRE | intake API、isolated worker、registry namespace、network、retention、monitoringを構築する | 外部取得からtrusted昇格まで中央経路以外がない |
| Development team | requestを送信し、trusted digestだけをstagingで読む | model名やtagではなくreturned digestをdeploymentへ固定する |
| Security | service policy、verifier pin、signer lifecycle、negative test、例外をreviewする | live rejection、ERROR、readbackの記録を確認する |

`requested_by_role`はlocal contract上の値であり、本人確認ではありません。ProductionではAPI
gatewayまたはjob orchestratorがOIDC／workload identityを認証し、そのidentityからroleと
requester IDを注入してください。Client自己申告値をauthorizationに使いません。

## 最短のlocal導入手順

### Prerequisiteとtrust assumption

- macOSまたはLinux、Python 3.10以上、Bash、OpenSSLを使用する。
- Self-testはnetwork、Docker daemon、model runtimeを使わない。
- [service policy](../secure/service-policy.json)、[model intake policy](../secure/policy.json)、
  [verifier](../scripts/verify.py)、[signer status](../secure/signer-status.json)をconsumer-ownedな
  read-only入力として扱う。
- Checked-in public keyとsignatureはtest fixture専用であり、production trust rootには使わない。

### Copyまたは参照するfile

- [中央intake worker](../scripts/intake_worker.py)
- [service policy](../secure/service-policy.json)
- [model intake policy](../secure/policy.json)
- [secure request例](../secure/intake-request.json)
- [unsafe request例](../insecure/intake-request.json)
- [中央intake self-test](../tests/test-central-intake.sh)

`secure/`全体を最小bundle fixtureとしてcopyできます。Productionではservice policy、trusted
signer status、public trust rootをuntrusted intake bundleと同じwrite boundaryへ置かないで
ください。Worker deployment自体もreviewed commitまたはimage digestへpinします。

### 明示的なlocal activation

Control directoryで次を実行します。Global Git、shell、IDE、OS設定は変更しません。

```bash
intake_tmp="$(mktemp -d "${TMPDIR:-/tmp}/psb-model-intake.XXXXXX")"
mkdir "$intake_tmp/state" "$intake_tmp/quarantine" "$intake_tmp/trusted"
python3 -B scripts/intake_worker.py \
  --service-policy secure/service-policy.json \
  --request secure/intake-request.json \
  --bundle-dir secure \
  --state-dir "$intake_tmp/state" \
  --quarantine-dir "$intake_tmp/quarantine" \
  --trusted-dir "$intake_tmp/trusted" \
  --as-of 2026-08-06T12:00:00Z
```

成功時はexit `0`です。最後の二行は次の形になります。

```text
STATE PROMOTED immutable digest readback verified
RESULT PROMOTED sha256:df0c00870b43005f873ec026757af59db1956218773b4ee401df32a9536c1aed
```

昇格artifactは`$intake_tmp/trusted/sha256/<digest>/model.safetensors`、metadata-only
receiptは`.../promotions/intake-tiny-classifier-001.json`です。同じrequestを再実行すると
trusted bytesをreadbackしたうえで同じ結果を返します。

### Harmless positive／negative self-test

```bash
bash tests/test-central-intake.sh
```

Self-testはsynthetic 124-byte Safetensorsだけを使用し、次を確認します。

- Positive: requestとexact bundleをquarantineへsnapshotし、9 check後にexact digestをtrustedへ昇格する。
- Negative: mutable requestはexit `1`／`QUARANTINE`となり、trustedへ何も書かない。
- Failure: OpenSSL不在はexit `2`／`ERROR`となり、trustedへ何も書かない。
- Replay: 同一requestはidempotentで、同じrequest IDの別bytesはexit `2`となる。
- Evidence: state／receiptにmodel bytes、dataset rows、signature、key、credentialを含めない。

全controlのcanonical interfaceは次です。

```bash
make verify-control CONTROL=PSB-DEPS-005
```

## 実環境の最小architecture

```text
approved external origin
          |
          v
authenticated intake API --> isolated fetcher --> quarantine@sha256
                                                |
                                                v
                                   non-executing verifier + signer check
                                      |                         |
                             ACCEPTED_FOR_STAGING        QUARANTINE / ERROR
                                      |                         |
                                      v                         +--> no trusted write
                             trusted@sha256 --read-only--> staging consumer
```

State recordやmessage queueの`ACCEPTED`文字列だけをauthorityにしません。Promoterは
quarantine bytes、signed materials、trusted policyを再照合し、trustedへcopyしたbytesを
readbackして同じdigestである場合だけreceiptを確定します。

### IAM matrix

| Identity | External origin | Quarantine | Trusted | KMS sign | Production runtime |
|---|---:|---:|---:|---:|---:|
| Intake fetcher／verifier | approved origin read | read/write | deny | deny | deny |
| Promoter | deny | read exact digest | write exact digest | optional service sign | deny |
| Staging runtime | deny | deny | read exact digest | deny | staging only |
| Developer／model owner | request only | deny by default | read metadata or deny | deny | deny |
| Security reviewer | deny | metadata read | metadata read | verify only | deny |

最小構成ではone-shot service identityにfetch、verify、promoteを集約できます。本controlの
local workerはこの構成です。高価値modelではfetcherとpromoterを別workload identityへ分け、
promoterに外部egressを与えない構成を推奨します。

## Amazon ECRでの具体的な最小設定例

OCI-compatible registryの一例としてAmazon ECRを使います。別providerでも、二つの
namespace、immutable tag、digest-only consumer、書込主体の分離というsecurity propertyは
変えません。

1. AWS Consoleの`Amazon ECR > Private registry > Repositories > Create repository`で
   `model-intake/quarantine`と`model-intake/trusted`を作る。
2. 両方の`Image tag mutability`を`Immutable`、exceptionを空にする。Encryptionは組織標準の
   KMS keyまたは既定のat-rest encryptionを選ぶ。Tagがimmutableでもconsumerはdigestで読む。
3. Quarantine repository policyはintake identityだけにupload actionsを許可する。Trustedは
   promoter identityだけにupload actionsを許可し、staging runtimeには
   `ecr:BatchGetImage`と`ecr:GetDownloadUrlForLayer`等のpull actionsだけを許可する。
4. `ecr:PutImage`、layer upload、deleteをdeveloperとruntimeへ付与しない。ECR loginに必要な
   `ecr:GetAuthorizationToken`も承認identityのidentity policyだけへ限定する。
5. Organization-owned asymmetric KMS keyを`Key usage: Sign and verify`で作り、inspectorだけへ
   `kms:Sign`、verifier／securityへ`kms:Verify`を許可する。Key ID、algorithm、signed digest、
   signer validityをreceiptへ記録し、signature本文は一般evidenceへ複製しない。
6. Consumerのnetwork policyから外部model hostをdenyし、ECR trusted endpointだけをallowする。
7. ORAS等のclientでartifactをOCI manifestとしてpushする場合もversionをpinし、trusted
   consumerへは`repository@sha256:<manifest-digest>`だけを渡す。

ECRのartifact対応と設定名、権限actionは
[ECRのOCI-compatible artifact対応](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html)、
[repository作成API](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreateRepository.html)、
[tag immutability手順](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html)、
[private repository policy例](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html)を参照してください。
KMSの設定は[asymmetric signing key作成](https://docs.aws.amazon.com/kms/latest/developerguide/asymm-create-key.html)、
[Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)、
[Verify API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html)を参照してください。
Provider audit eventは[ECR actionsのCloudTrail logging](https://docs.aws.amazon.com/AmazonECR/latest/userguide/logging-using-cloudtrail.html)で確認します。

ECR built-in image scanはcontainer package vulnerability用であり、本controlのSafetensors header、
ML-BOM graph、dataset authorization、signed model intake検証を代替しません。

## Live verificationと導入完了条件

Local self-testとは別に、Platform／SREとSecurityが実環境で次を試します。

1. 承認済みsynthetic artifactをintakeし、quarantine object、signed decision、trusted digest、
   readback digest、staging pullが同一であることを確認する。
2. `latest`、branch、HTTP、pickle extension、`trust_remote_code=true`を一つずつ送り、すべて
   `QUARANTINE`でtrusted digestが増えないことを確認する。
3. Verifier、signer-status source、KMS verify、registry writeを一つずつ停止し、すべて
   `ERROR`でtrusted digestが増えないことを確認する。
4. Developer identityとstaging runtime identityからtrusted push／deleteを試し、providerが
   AccessDenied相当で拒否することを確認する。
5. Staging runtimeから外部model hostへの直接取得を試し、network policyが拒否することを確認する。
6. Trusted artifactをtagだけで指定したdeploymentをpolicyが拒否し、digest指定だけを許可する。

導入完了は、上記の実環境結果、対象account／repository、取得時刻、実行identity、request ID、
artifact／manifest digest、provider audit eventをSecurityがreviewした状態です。手書きの
`secure: true`、fixtureのPASS、READMEの存在は導入証拠にしません。

## Common failure recovery

- `RESULT QUARANTINE`: requestとbundleを変更せず保持し、check IDの原因を修正した新request IDで再申請する。
- `RESULT ERROR`: trustedへ昇格せず、signer status、pinned verifier digest、OpenSSL、KMS、registry、
  clockを復旧して同じrequestを再実行する。
- Request ID reuse: bytesを差し替えず、変更した内容には新request IDを発行する。
- Trusted readback mismatch: consumerを停止し、対象digestをincident handlingへ隔離する。別tagへの
  付替えで回避しない。
- Existing adopter configuration: workerはglobal設定を変更しない。既存registry policyやIAMは
  自動上書きせず、ownerが差分reviewしてmergeする。

## Rollback

1. 新規intake requestを止める。
2. 最後に検証済みのtrusted digestをstagingでpinしたまま、promoterのwriteを止める。
3. Intake service deploymentだけを直前versionへ戻し、policy、receipt、quarantineを保持する。
4. Positive／negative live testを再実行してから受付を再開する。

Rollbackでdevelopment teamの外部直接downloadを復活させません。Trusted digestを用意できない
場合はdeploymentを停止するのがfail-closedなrollbackです。Retention、legal hold、incident
preservationに反してquarantineやreceiptを削除しません。

## 自動検証できること／できないこと

自動検証できるのは、request／bundle identity、SHA-256、Safetensors structure、ML-BOM graph、
signature、signer status snapshot、dataset declaration、handoff、state transition、readback、
metadata-only evidenceです。

実環境でしか確認できないのは、publisherの正当性、dataset consent／licenseの実在、IAMと
egressの有効性、KMS custody、provider audit log、scanner isolation、semantic backdoor不存在、
accuracy／bias／privacy／robustness、production release判断です。Synthetic fixtureのPASSを
organization adoptionとして扱いません。

## 関連するframework

Mappingは関連性を示すもので、formal complianceや完全coverageを主張しません。正確な
relationship、confidence、rationaleは[control metadata](../control.yaml)がauthorityです。

- [NIST SSDF 1.1 / SP 800-218, PW.4.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [MITRE ATLAS 2026.05 / AML.T0010.003](https://atlas.mitre.org/techniques/AML.T0010.003/)
- [MITRE ATLAS 2026.05 / AML.T0010.002](https://atlas.mitre.org/techniques/AML.T0010.002/)
- [MITRE ATLAS 2026.05 / AML.T0011.000](https://atlas.mitre.org/techniques/AML.T0011.000/)
- [MITRE ATLAS 2026.05 / AML.M0014](https://atlas.mitre.org/mitigations/AML.M0014/)
- [MITRE ATLAS 2026.05 / AML.M0025](https://atlas.mitre.org/mitigations/AML.M0025/)
- [MITRE ATLAS 2026.05 reviewed YAML / format 6.0.0](https://github.com/mitre-atlas/atlas-data/blob/da9ebf9b66e6902ad97c267e2a20af0bd996a60f/dist/v6/ATLAS-2026.05.yaml)
- [OWASP AISVS 1.0 / v1.0-C3.1.2](https://github.com/OWASP/AISVS/blob/78775233666a2022dcfb82037e5e029116955c00/1.0/en/0x10-C03-Model-Lifecycle-Management.md)
- [OWASP AISVS 1.0 / v1.0-C4.1.2](https://github.com/OWASP/AISVS/blob/78775233666a2022dcfb82037e5e029116955c00/1.0/en/0x10-C04-Infrastructure.md)
- [OWASP AISVS 1.0 / v1.0-C6.1.2, C6.1.3, C6.2.1–C6.2.3](https://github.com/OWASP/AISVS/blob/78775233666a2022dcfb82037e5e029116955c00/1.0/en/0x10-C06-Supply-Chain.md)

## 実装guideと仕様

- [CycloneDX ML-BOM capability](https://www.cyclonedx.org/capabilities/mlbom/)
- [CycloneDX 1.7 specification at reviewed commit](https://github.com/CycloneDX/specification/tree/4b3f59453366e27c8073fd24e98bf21ef8892c8e)
- [CycloneDX AI models and model cards](https://cyclonedx.org/use-cases/ai-models-and-model-cards/)
- [OWASP CycloneDX Authoritative Guide to AI/ML-BOM](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-AI-ML-BOM-en.pdf)
- [Safetensors 0.8.0 reviewed source](https://github.com/huggingface/safetensors/tree/a406ca3e7a90598be0cd05a50069cb9bf5ef6ba6)
- [Safetensors security policy](https://github.com/huggingface/safetensors/security)
- [PyTorch `torch.load` security warning](https://docs.pytorch.org/docs/stable/generated/torch.load.html)
- [OCI Distribution Specification 1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [ORAS 1.3.2 release](https://github.com/oras-project/oras/releases/tag/v1.3.2)
- [ORAS attach command](https://oras.land/docs/commands/oras_attach/)
- [Cosign blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [Cosign KMS key management](https://docs.sigstore.dev/cosign/key_management/overview/)
- [Cosign 3.1.2 release](https://github.com/sigstore/cosign/releases/tag/v3.1.2)
- [in-toto Attestation Framework 1.2.0](https://github.com/in-toto/attestation/releases/tag/v1.2.0)

## 関連control

- [PSB-DEPS-003: loader package／lockfile integrity](../../lockfile-integrity/README.md)
- [PSB-BUILD-001: build worker containment](../../../build-security/build-containment/README.md)
- [PSB-CICD-006: audience-bound OIDC federation](../../../cicd-security/audience-bound-oidc-federation/README.md)
- [PSB-CONTAINER-002: container registry security](../../../container-cloud-iac-security/container-registry-security/README.md)
- [PSB-DETECT-001: integrity-verified scanner](../../../detection-verification/integrity-verified-scanner/README.md)
- [PSB-REL-003: SBOM binding and publication](../../../release-integrity/sbom-binding-publication/README.md)
- [PSB-REL-004: supplier SBOM trust](../../../release-integrity/supplier-sbom-trust/README.md)
- [PSB-AI-011: RAG corpus integrity and retrieval](../../../ai-development-security/rag-corpus-integrity-retrieval/README.md)
- [PSB-DETECT-002: AI TEVV release gate](../../../detection-verification/ai-tevv-release-gate/README.md)
- [PSB-GOV-002: time-bound security exceptions](../../../governance-operations/time-bound-security-exceptions/README.md)
