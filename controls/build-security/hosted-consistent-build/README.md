# PSB-BUILD-002: 一貫したrelease buildを承認済みhosted platformで実行する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | 開発者端末や未評価builderで作られたreleaseは、誰がどのprocessとinputでbuildしたかをconsumerが信頼できない。 |
| 誰から、または何から守るか | Local buildの混入、未承認builder、version drift、手動parameter差替え、build record欠落や取得障害から守る。 |
| 何が対象か | Release build policy、hosted build platform、versioned build definition、source revision、top-level parameter、build record、release trigger。 |
| 何をするか | 承認済みhosted platformと固定capability evidenceを選び、同一sourceとversioned processを承認済みparameterで一貫してbuildしたrecordを検証する。 |
| 成功状態 | Builder identity、platform capability、source、definition、parameter、triggerがconsumer-owned expectationに一致し、不十分または取得不能なevidenceはfail closedとなる。 |
| 対象外・残余リスク | Reference verifierはhosted build service自体を構築せず、承認済みplatformやbuild definitionが安全であること、artifact再現性を単独では証明しない。 |

## Security problem

Release artifactを開発者端末や未評価のbuilderで作成できると、consumerはartifactが
どのbuild platform、source revision、build definition、parameterから生成されたかを
信頼できません。また、同じrelease手順を名乗っていてもmanual commandやfloating
workflowへ逸脱できれば、verifierは「正しいbuild」の期待値を形成できません。

このcontrolはproducer側のpolicyとbuild recordを照合し、次を要求します。

- targetはSLSA Build L2に固定する
- capability evidenceをdigest固定した承認済みbuilderだけを選定する
- release buildはbuild-platform-controlled hosted environmentで実行する
- sourceとbuild definitionをfull commit SHAで記録し、同じrevisionへ結び付ける
- repository、definition path、entry point、parameter、triggerをpolicyへ完全一致させる

## Threat and failure scenarios

- 開発者がlocal workstationでrelease artifactを作成し、正規artifactとして公開する
- 未評価またはL1までしか評価されていないbuilderをL2 releaseへ使用する
- release workflowをfloating referenceまたは別scriptへ差し替える
- debug parameterやmanual triggerで通常と異なるartifactを生成する
- verifierが読めないpolicy／recordをcleanな結果として扱う

## Assumptions

- producerはrelease対象artifactとsource repositoryを明確に定義している
- productionではplatform-issued recordを取得するadapterを用意する
- capability assessmentの内容とissuerはsecurity reviewerが別途確認する
- provenance生成・署名は`PSB-BUILD-003`、consumer検証は`PSB-REL-001`が扱う

## Secure and insecure examples

`secure/build-policy.json`はtarget L2、hosted builder、固定されたassessment evidence、
source revisionへbindingされたrelease workflowを定義します。
`secure/build-record.json`はそのpolicyへ一致するsynthetic recordです。

`insecure/`は以下を意図的に含む隔離fixtureであり、deployment用途ではありません。

- non-hosted、L1相当、未固定assessment evidence
- floating build definition
- developer workstation上のproducer-controlled execution
- local script、debug parameter、manual trigger

## Verification

```bash
make verify-control CONTROL=PSB-BUILD-002
```

直接verifierを利用する場合:

```bash
python3 controls/build-security/hosted-consistent-build/scripts/verify.py \
  --policy path/to/build-policy.json \
  --record path/to/build-record.json
```

終了コードは`0=accepted`、`1=policy violation`、
`2=missing/malformed/incomplete evidence`です。`2`をcleanとして扱ってはいけません。

Expected secure output:

```text
PASS consistent hosted build process verified for SLSA Build L2 producer requirements
```

## Integration

1. Release対象repositoryごとにproducer-owned policyをreviewします。
2. Build platformのcapability assessmentをimmutable artifactとして保存し、
   HTTPS URIとSHA-256をpolicyへ記録します。
3. Hosted platformからbuilder identity、source、definition、invocationを含む
   signed build recordを取得します。
4. Release gateでこのverifierを実行し、exit `1`と`2`をblockします。
5. `PSB-BUILD-003`でplatform-generated authentic provenanceを検証し、
   `PSB-REL-002`でconsumerへ配布します。

## Acceptance criteria

- secure policy／recordは受理される
- local、producer-controlled、process-drift fixtureは拒否される
- malformed／incomplete evidenceはdistinct errorになる
- SLSA mappingはproducer要件だけを対象とし、platform要件やLevel達成を主張しない
- generated SLSA L2 coverageで該当3要件が`mapped-evidence`になる

## Limitations and operational cost

- JSONはprovider-neutral contractであり、各hosted platform用adapterが必要です。
- Platform capabilityの再評価、evidence更新、失効管理には運用コストがあります。
- Recordの自己申告だけではproduction evidenceにならず、platform署名検証が必要です。
- HostedはL2の条件ですが、L3のbuild isolationやunforgeabilityを意味しません。

## References

- [SLSA v1.2 Build Track Basics](https://slsa.dev/spec/v1.2/build-track-basics)
- [SLSA v1.2 Build Requirements](https://slsa.dev/spec/v1.2/build-requirements)
