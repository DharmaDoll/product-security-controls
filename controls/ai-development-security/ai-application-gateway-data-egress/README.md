# PSB-AI-010: AI application gatewayでdata egressを制御する

## このcontrolを一枚で理解する

### セキュリティ上の問題

ApplicationがLLM providerへ直接接続すると、未承認model・tenant・region・retentionへsecret、source、個人情報、規制対象dataを送信できる。Gateway障害や観測欠損をallowに変換すると、policyは容易に迂回される。

### 誰から、または何から守るか

Prompt injectionや不正入力を送る利用者、侵害・誤設定されたapplication、盗まれたworkload identity、direct provider SDK、未承認model/provider、classification・redaction・gateway・telemetry障害から守る。

### 何が対象か

Application workload identity、LLM request route、provider・model・provider tenant・region、training/retention条件、input/output classification、送信byte・field数、redaction結果、gateway decisionとtelemetry。

### 何をするか

署名付き短寿命workload sessionをexact gateway audienceへbindし、全requestをmandatory HTTPS gatewayへ強制する。Targetを完全allowlistし、dataをlocal分類・最小化・redactionまたはdenyしてからdispatchを決定する。

### 成功状態

Publicと完全redaction済みpersonal-data fixtureだけが承認される。Secret、未承認target、wrong tenant/region、direct bypass、unknown workload、size超過はupstream dispatch前にdenyされ、gateway health不明は`ERROR`になる。

### 対象外・残余リスク

Synthetic fixtureはlive application route、IdP、gateway、provider contract、region、training/retention、telemetry receiverを証明しない。Semantic data classification、provider内部処理、response filtering、model safety、法的適合性も別途確認が必要である。

## セキュリティ上の問題

AI applicationは通常のexternal API clientより強いdata egress riskを持ちます。自然言語requestへ
customer information、source、debug log、credentialが混ざりやすく、provider/modelを変更しても
applicationが動作し続けるためです。

次の個別対策だけでは十分ではありません。

- SDK設定へprovider URLを書く: applicationやdependencyからdirect endpointへ変更できる;
- 「secretを送らない」とpromptへ書く: modelへ送る前のdata boundaryにならない;
- domain allowlistだけを使う: provider tenant、model、region、retention条件を区別できない;
- logを確認する: dispatch後の検知であり、機密dataはすでに境界を越えている;
- gateway outage時にdirect fallbackする: control failureがbypass経路になる。

このcontrolはapplicationからproviderまでを次のdecision chainとして扱います。

```text
authenticated workload
  -> mandatory gateway route
  -> exact provider/model/tenant/region policy
  -> local classification/minimization/redaction
  -> fail-closed decision
  -> metadata-only audit
  -> provider dispatch
```

## 誰から何を守るか

主な攻撃者・失敗源は次のとおりです。

- Secretや個人情報をLLM requestへ混入させる外部利用者・prompt injection;
- Provider SDKやenvironment variableを変更してgatewayを迂回する侵害application;
- 別serviceのidentityを再利用するworkloadやstale session;
- 未review model、consumer tenant、別region、training有効endpointへのrouting drift;
- Data class、byte数、redaction countを誤って申告するapplication;
- Gatewayのdecision engine、identity verifier、egress enforcer、telemetry sink障害;
- Raw prompt、response、customer recordをcentral logへ保存するcollector。

保護対象はcustomer/developer data、sourceとsecret、provider契約上のtenant・region・retention境界、
AI request authority、および後から検証できるsanitized decision evidenceです。

## Control境界

| Control | 所有する境界 |
|---|---|
| `PSB-AI-004` | Claude Code／Codex processのnetwork、MCP、credential、tool authority。Developer endpointのcoding-agent boundaryであり、application inference routeではない。 |
| `PSB-AI-005` | Agent memoryへ保存・取得されるcontextのclassification、scope、retention、deletion。 |
| `PSB-AI-006` | Model proposalからexternal side effectまでのrequest/result integrityとunknown outcome。 |
| `PSB-AI-010` | Application workloadからLLM providerへ出るrequestのgateway route、target、identity、classification、minimization、redaction、retention、dispatch decision。 |
| `PSB-SOURCE-004` | Developerが保持するGitHub token、PAT、SSH、App credentialのlifecycle。 |

LiteLLM、API gateway、service mesh、Model Armor、DLP、mTLS、DPoP、VPNは実装adapter候補です。
製品名はcontrol境界ではなく、ここで定義する結果を満たすかを検証します。

## 安全な実装

### Mandatory gatewayとworkload identity

[`secure/policy.json`](secure/policy.json)はapplicationが到達できるrouteを次へ固定します。

- scheme: `https`;
- host: `ai-gateway.example.invalid`;
- port: `443`;
- path: `/v1/inference`;
- mode: `mandatory-gateway`;
- direct provider access: deny;
- gateway unavailable: fail closed。

`.invalid` hostを使用するため実network通信は発生しません。

[`secure/workload-session.json`](secure/workload-session.json)はworkload、service account、tenant、
gateway audience、policy digest、5分TTL、nonce、sequenceをEd25519署名へbindします。Repositoryには
public keyだけを置き、fixture署名用private keyは保持しません。

### Exact inference target

Targetはprovider名だけでなく、次の組全体をallowlistします。

```text
provider + model + provider tenant + region + training policy + retention
```

Fixtureは`PROVIDER-APPROVED-001 / MODEL-REVIEWED-2026-001 / PROVIDER-TENANT-A /
jp / training=false / retention=0`だけを許可します。これは実provider推奨ではなく、policy
contractを検査するsynthetic identityです。

### Data classification、minimization、redaction

Payload本文はfixtureやevidenceへ保存せず、classification、byte数、field数、検知・redaction数、
content SHA-256だけを扱います。

| Input | 出力条件 | Decision |
|---|---|---|
| `public` | 最大4096 bytes、必要fieldだけ | allow |
| `personal-data` | localで全件redactionし`internal-redacted`へ変換、最大2048 bytes | allow |
| `credential` / `secret` / `source-code` / `regulated` | 変換・送信しない | deny |

Redactionはproviderへ送った後ではなくapplication trust boundary内で完了させます。検知数とredaction
数が一致しなければdenyです。Minimizationはoutbound bytesがinput以下、forwarded fieldsがreceived
以下であることを最低条件とし、productionではbusiness schemaのexact allowlistを追加します。

### Scenario corpus

[`secure/scenario-corpus.json`](secure/scenario-corpus.json)は8件を分離して検査します。

| Scenario | 期待decision | 理由 |
|---|---|---|
| `REQ-ALLOW-PUBLIC` | allow | Approved route/target、public、minimized |
| `REQ-ALLOW-PERSONAL-REDACTED` | allow | 2件検知・2件local redaction、zero retention |
| `REQ-DENY-SECRET` | deny | Prohibited data class |
| `REQ-DENY-UNAPPROVED-MODEL` | deny | Model mismatch |
| `REQ-DENY-WRONG-TENANT-REGION` | deny | Tenant/region/training/retention mismatch |
| `REQ-DENY-DIRECT-BYPASS` | deny | Mandatory gateway bypass |
| `REQ-DENY-UNKNOWN-WORKLOAD` | deny | Session identity mismatch |
| `REQ-DENY-OVERSIZED` | deny | Public outputが4096 bytes超過 |

Verifierはfixtureの`expected_decision`を信用せず、policyから理由を再計算してgateway evidenceと比較します。

## 危険な実装

`insecure/`は外部通信を行わないisolated negative fixtureです。

- Audienceを`DIRECT-PROVIDER-API`へ改変したworkload sessionを同じ署名で使う;
- Unknown workload、direct provider route、unapproved modelをallowする;
- Wrong provider tenant、region、training、30日retentionをallowする;
- Secret classとoversized payloadをdispatchする;
- Personal dataのredactionとfield minimizationを確認しない;
- Auditより先にdispatchし、各enforcement flagをfalseにする;
- Synthetic claimをlive `ADOPTED` evidenceとして提示する。

これらは既知のunsafe behaviorとして`FAIL`です。Malformed evidence、gateway/collector/evaluator障害、
trust/public key tamper、crypto verifier unavailable、raw prompt等のsensitive evidenceは`ERROR`です。

## 検証

Repository rootから実行します。

```bash
make verify-control CONTROL=PSB-AI-010
```

Verifierを直接実行する場合:

```bash
python3 controls/ai-development-security/ai-application-gateway-data-egress/scripts/verify.py \
  --repository-root . \
  --policy controls/ai-development-security/ai-application-gateway-data-egress/secure/policy.json \
  --workload-session controls/ai-development-security/ai-application-gateway-data-egress/secure/workload-session.json \
  --corpus controls/ai-development-security/ai-application-gateway-data-egress/secure/scenario-corpus.json \
  --evidence controls/ai-development-security/ai-application-gateway-data-egress/secure/gateway-evidence.json
```

終了コードは`0=accepted`、`1=known unsafe behavior`、`2=evidence／trust／evaluator error`です。
Invalid workload signatureは`FAIL`、public keyやcrypto verifierを使えない状態は`ERROR`です。

## 期待する出力

```text
PASS PSB-AI-010/AIG-001 gateway route workload trust and policy identity are immutable
PASS PSB-AI-010/AIG-002 workload session is authenticated audience-bound fresh and exact
...
PASS PSB-AI-010/AIG-011 synthetic evidence leaves every live enforcement point NOT_CHECKED
ACCEPTED AI application gateway evidence; live enforcement NOT_CHECKED
```

## Production統合

1. 全applicationとbatch jobのLLM SDK、endpoint、proxy、DNS、service mesh routeをinventoryする。
2. Application egressからprovider endpointをdenyし、組織gatewayだけをnetworkで許可する。
3. Workload identityを短寿命かつgateway audience限定にし、developer tokenや共有API keyを渡さない。
4. Provider、model、provider tenant、region、training、retentionを一つのversioned policyとしてreviewする。
5. Payload生成前にbusiness schemaで必要fieldだけを選択し、local classifierとredactorを適用する。
6. Credential、secret、source、regulated classはredaction fallbackではなくdenyを標準にする。
7. Classifier／redactor／identity／decision／enforcer／auditのいずれかが失敗したらdispatchしない。
8. Metadata-only telemetryへworkload、decision、reason、target identity、count、digest、timestampだけを送る。
9. Gateway bypass、unapproved model、wrong tenant/region、secret、partial redaction、oversizeを定期negative testする。
10. Provider contract、model revision、region、retention、gateway policy変更時に全corpusを再実行する。

## 運用上の注意と制限

- Gatewayを導入してもapplicationがdirect internetへ出られればbypass可能なため、network enforcementを分離する。
- Provider API keyをapplicationへ配らず、gatewayだけが短寿命またはprotected provider authorityを持つ。
- Classification modelを使用する場合、そのtimeoutやlow confidenceをallowへ変換しない。
- Tokenize後byte数、attachment、image、audio、embedding、tool result等、非text surfaceにも別上限が必要である。
- `training=false`や`retention=0`はprovider contract／configuration evidenceが必要で、request fieldだけでは証明できない。
- Redaction count一致はsemantic漏えいがない証明ではない。Known-safe/unsafe corpusとhuman reviewを継続する。
- Responseからのsensitive output、unsafe content、model hallucinationはこのrequest-egress sliceの対象外である。
- Central telemetryへraw contentを送るとgateway自体が情報漏えい源になる。
- Live gateway adoptionが確認できるまでassessmentは`NOT_CHECKED`である。

## Framework mappingと参考資料

行単位mappingは`control.yaml`が正本です。

- MITRE ATLAS `AML.T0040 AI Model Inference API Access`へ、署名workload identityとmandatory
  gateway route、exact inference targetの制限をmappingする;
- `AML.M0019 Control Access to AI Models and Data in Production`へ、workload、model、tenant、
  region、data classification、retentionのpolicy enforcementをmappingする;
- `AML.M0024 AI Telemetry Logging`へcontent-free decision and health evidenceをmappingする;
- `AML.M0032 Segmentation of AI Agent Components`へapplicationとproviderの間にmandatory
  fail-closed gatewayを置く境界をmappingする;
- OWASP Agentic Top 10 `ASI03 Identity and Privilege Abuse`へ、workload identityとprovider
  tenant authorityを限定的にmappingする。

Mappingはattack behaviorとrisk/mitigationの関連を示すだけで、complete coverage、provider contract、
data protection complianceを証明しません。

- [REF-AI-002 OWASP AI Agent Security Cheat Sheet](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)
- [REF-AI-003 AwesomeProductSecurity portfolio view](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-003)
- [OWASP Agentic Top 10 registry](../../../frameworks/owasp-agentic-top10/README.md)
- [MITRE ATLAS registry](../../../frameworks/mitre-atlas/README.md)
