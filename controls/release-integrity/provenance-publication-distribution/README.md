# PSB-REL-002: Release artifactとprovenanceを一対一で公開・配布する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Build platformが正しいprovenanceを生成しても、artifactと一緒にimmutable・discoverableな形で配布・保持されなければconsumerは検証できない。 |
| 誰から、または何から守るか | Release automation・operatorのミス、証跡を削除する攻撃者、mutable storage管理者、遅延upload、release API・inventory・parser障害から守る。 |
| 何が対象か | Release artifact、provenance object、release manifest、artifact subject digest、publication location・timestamp、access、retention、no-downgrade policy。 |
| 何をするか | Artifactごとに一意なdigest-bound provenanceを同じversioned releaseへ同時公開し、exact HTTPS location、immutability、保持期間、discoverabilityを検証する。 |
| 成功状態 | 各artifactにexact subjectのprovenanceが一対一で存在し、5分以内に公開され最低365日保持され、欠落・再利用・mutable・取得不能は拒否される。 |
| 対象外・残余リスク | このcontrolはprovenance内容や署名を再検証せず、build時生成は`PSB-BUILD-003`、consumer authenticityは`PSB-REL-001`が所有する。 |

## セキュリティ上の問題

Build platformが正しいprovenanceを生成しても、artifactだけをreleaseし、provenanceを
別のprivate storage、mutableな`latest` URL、短期間で削除される場所へ置けばconsumerは
検証できません。また、一つのprovenanceを複数artifactへ流用したり、artifact公開後に
長時間遅れてuploadしたりすると、未検証artifactが先に利用されます。

このcontrolは「生成済みprovenanceを、対応するartifactと一緒にconsumerへ届け続ける」
producer側の公開境界を扱います。

## 誰から何を守るか

- release operatorまたはpublication automationの設定ミス;
- provenance検証失敗を隠すため証跡を削除する攻撃者;
- mutable URLやstorage objectを差し替えるstorage管理者;
- release API、inventory、parserの障害。

保護対象はrelease artifactと、それを検証するconsumerが取得するrelease manifest、
provenance object、publication timestamp、retention stateです。

## Control boundary

- `PSB-BUILD-003`: build platformによるprovenance生成とsigner authenticity;
- `PSB-REL-002`: publication、discoverability、access、retention、no-downgrade;
- `PSB-REL-001`: consumerによる署名、artifact subject、builder/source expectation検証;
- `PSB-REL-003`: SBOM生成、binding、publication、completeness。

したがって、このcontrolはprovenance内容やsignatureを再検証せず、release manifest上の
publication evidenceを検査します。

## 安全な実装

`secure/release-manifest.json`は二つのsynthetic artifactについて次を満たします。

- artifact SHA-256とprovenance `subject_sha256`が一対一で一致;
- provenance object digestがartifact間で重複しない;
- `application/vnd.in-toto+json`としてrelease manifestからdiscover可能;
- artifact、manifest、provenanceが同じversioned release pathにある;
- exact HTTPS host、TLS server authentication、immutable、public access;
- artifact公開後5分以内にprovenanceを公開;
- release公開から最低365日保持;
- protected artifact familyでprovenanceを必須化。

URLとdigestはすべてsyntheticです。検証器はnetworkへ接続しません。

## 安全でない実装

`insecure/`は意図的に次を含む隔離fixtureです。

- broad `.*` release IDとmutable `latest` path;
- HTTP、private、query-bearing、unavailable provenance location;
- artifact subject mismatchとprovenance digestの再利用;
- manual ticketに依存しrelease manifestから発見不能;
- 2時間遅延と7日だけの保持;
- protected familyのprovenance requirement無効化。

実環境へ配置しないでください。

## 統合方法

1. artifact familyごとにprovenance必須policyとversioned release IDを定義します。
2. build完了後、artifact digestと`PSB-BUILD-003`のprovenance digestをrelease manifestへ
   一対一で記録します。
3. artifact、provenance、manifestを同じimmutable release namespaceへpublishします。
4. provenance uploadとconsumer access probeが成功するまでreleaseをcompleteにしません。
5. release APIからartifact/provenance pair、timestamp、storage access、retentionを
   read-onlyで取得し、このmanifest schemaへ変換します。
6. supported artifact familyでは欠落をlegacy扱いせずreleaseをblockします。
7. consumerは取得後に`PSB-REL-001`でsignatureとartifact subjectを再検証します。

Private productでは`public`をそのまま使わず、intended consumerがcredentialをURLへ
埋め込まず取得できるauthenticated profileへ置き換えます。

## 検証

```bash
make verify-control CONTROL=PSB-REL-002
```

exit codeは次の意味です。

| Exit | 意味 |
| --- | --- |
| `0` | 全publication requirementを満たす |
| `1` | binding、location、timing、retention、downgrade finding |
| `2` | publication/storage probe不在、入力欠落、parse不能 |

`ERROR`をclean resultとして扱ってはいけません。

期待出力:

```text
PASS PSB-REL-002/RPD-001 every artifact has one digest-bound discoverable provenance object
PASS PSB-REL-002/RPD-002 release evidence is immutable authenticated and consumer-accessible
PASS PSB-REL-002/RPD-003 provenance publication delay and retention meet policy
PASS PSB-REL-002/RPD-004 protected artifact family retains required provenance
RESULT PASS profile=secure checks=4 failures=0
```

出力にはcredential、private release URL、object名、digest値を含めません。完全な
deterministic outputは`expected-results/`にあります。

## 運用上の注意

- artifact uploadだけ成功しprovenance uploadが失敗した状態をrelease成功にしません。
- CDNやmirrorを使う場合もcanonical manifestからexact provenance digestを辿れるように
  し、cache evictionをretentionと混同しません。
- object lockやversioned storageは削除権限、retention bypass、replication failureも
  別途監視します。
- publication delayとavailabilityをSLO化し、probe failure自体をalert対象にします。
- provenance削除のbreak-glassはowner、理由、期限、影響artifact、consumer通知を記録し、
  evidence requirementを恒久的に無効化しません。

## 制限と残余リスク

fixtureはproduction release API、object storage、CDN、TLSへ接続しないため、manifestの
主張だけで実稼働を証明しません。公開済みprovenanceが正しく署名されていること、
builderが信頼できること、artifact bytesとsubjectが一致することは`PSB-REL-001`で
consumerが検証する必要があります。

一つのcontrol mappingはSLSA level達成を意味しません。`PSB-BUILD-002`、
`PSB-BUILD-003`、`PSB-REL-001`、本controlのevidenceを揃えた後も、producer、
build platform、consumerを通した別のcumulative assessmentが必要です。

## References

- [SLSA v1.2 Build Track](https://slsa.dev/spec/v1.2/build-requirements)
- [SLSA v1.2 Distributing provenance](https://slsa.dev/spec/v1.2/distributing-provenance)
