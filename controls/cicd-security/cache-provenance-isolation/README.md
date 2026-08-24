# PSB-CICD-009: CI cache restoreを署名済みprovenanceとexact trust境界へ結合する

## このcontrolを一枚で理解する

### セキュリティ上の問題

CI cacheはrunをまたいでbytesを再利用するため、低信頼jobが書いたtoolやdependencyを後続のsecret-bearing jobがrestoreすると、workflow上の権限分離を迂回してcode executionを持ち込める。broad keyやprefix fallbackは別contextのcacheを暗黙に選ぶ。

### 誰から、または何から守るか

untrusted PR作成者、侵害されたproducer job、cache storageを改ざんする攻撃者、古い署名済みcacheのreplay、誤ったkey設計、評価器や暗号toolの障害から守る。

### 何が対象か

cache producer record、restore request、cache内容と展開path、repository／workflow／trust class／platform／revision／dependency identity、署名鍵、policy、restore quality gate。

### 何をするか

producer recordをEd25519署名し、cache keyと要求をstable repository ID、full-SHA workflow、trust class、platform、revision、lock digest、content digest、path、24時間以下の期限へ結合する。prefix restoreと異なるtrust class間の移送を拒否する。

### 成功状態

正規のtrusted producerから同一contextのtrusted consumerへのexact restoreだけが7チェックを通過し、改ざん・cross-boundary・期限切れはfinding、評価不能は独立したERRORになる。

### 対象外・残余リスク

trusted producer自体の侵害、live provider設定、秘密鍵運用、archive全entryの安全な展開、同一untrusted class内での悪意あるcache利用は別controlと導入先運用が必要。exact revisionはcache hit率を下げる。

## Security problem and threat scenario

cacheはbuild時間を短縮しますが、同時に前runの状態を後runへ渡す共有channelです。
`pull_request` jobとrelease jobが同じkeyを使う、またはrelease jobが`restore-keys`で
広いprefixへfallbackすると、攻撃者は直接secretを受け取らなくても、後続jobが実行する
binary、compiler plugin、package hook等をcacheへ置けます。

このcontrolは`PSB-CICD-005`のuntrusted PR境界と`PSB-CICD-007`のrunner isolationを
cache storageまで延長します。対象はcache serviceの可用性ではなく、「どのproducerの
どのbytesを、このconsumerがrestoreしてよいか」というauthorization decisionです。

## Secure and insecure examples

`secure/`には、review済みpolicy、synthetic cache content、canonical producer record、
Ed25519 detached signature、公開鍵、exact restore requestがあります。秘密鍵は収録しません。
keyは次の全要素から独立に導出されます。

```text
version / repository ID / workflow full-SHA digest / trust class / platform /
producer revision / dependency-lock SHA-256
```

`insecure/restore-request.json`は隔離された非実行fixtureです。別repositoryとworkflow、
untrusted consumer、別platformとdependency、別path、broad prefix、偽のexpected digestを
要求し、secure producer recordに対して拒否されます。

## Verification

```bash
make verify-control CONTROL=PSB-CICD-009
```

直接実行する場合:

```bash
python3 controls/cicd-security/cache-provenance-isolation/scripts/verify.py \
  --policy controls/cicd-security/cache-provenance-isolation/secure/policy.json \
  --record controls/cicd-security/cache-provenance-isolation/secure/cache-record.json \
  --signature controls/cicd-security/cache-provenance-isolation/secure/cache-record.sig \
  --content controls/cicd-security/cache-provenance-isolation/secure/cache-content.json \
  --request controls/cicd-security/cache-provenance-isolation/secure/restore-request.json \
  --as-of 2026-08-17T12:00:00Z
```

終了コードは`0=exact restoreを受理`、`1=security findingのため拒否`、
`2=入力、policy、file、暗号検証を評価不能`です。終了`2`をcache missやcleanとして
継続してはいけません。期待出力は`expected-results/`に固定しています。

testは正常・cross-boundaryに加え、record署名改ざん、content改ざん、期限切れ、invalid
policy、missing OpenSSL、malformed JSON、symlink入力を検証し、cache payloadのartifact名が
stdout／stderrへ出ないことも確認します。

## Integration guidance

1. producerとconsumerを`trusted`／`untrusted`等のreview済みtrust classへ分類し、class間でcache namespaceを共有しません。
2. repository名だけでなくproviderのstable repository ID、workflow fileとfull commit SHA、OS／architecture、source revision、lockfile digestからkeyを導出します。
3. cache作成後にarchive全entryをcanonical manifestへ列挙し、type、mode、link target、path、digestを署名serviceで署名します。private keyを一般build stepへ渡しません。
4. restore前にrecord署名、policy pin、content、path、期限、exact requestを検証し、その後に初めてarchiveを展開します。prefix fallbackは使いません。
5. dependency download cacheのようなdata-only pathへ限定します。`PATH`、compiler plugin、startup script、package executable、workspace rootへの展開を許可しません。
6. verifier終了`1`と`2`の両方でrestoreと後続privileged jobを停止し、metadata-only decisionを監査へ残します。
7. provider adapterではcache save権限、key上限、eviction、concurrency、APIのlookup semanticsを確認し、fixture contractとの差分を記録します。

## Expected output

secure fixtureは`CAC-001`から`CAC-007`をPASSし、exact trusted restoreをACCEPTします。
insecure fixtureは署名自体は真正なまま、consumer identity、trust transition、path、revision、
prefix、expected digestの12 findingでREJECTします。これにより、単に壊れた署名だけでなく、
正規producer recordを別contextへ流用する攻撃も負のtestに含めます。

## Limitations and operational cost

- provider-neutral offline evaluatorであり、GitHub Actions等のlive cache ACLやworkflow採用を証明しません。
- committed keyと署名はsynthetic fixtureです。production signingにはHSM／KMS等の隔離、rotation、revocation、auditが必要です。
- trusted producerが署名前に侵害された場合、悪意あるbytesも真正に署名できます。hermetic build、dependency verification、runner isolationを併用します。
- このsliceは単一blobをhashします。production archiveではentryごとのpath traversal、symlink、hardlink、device、mode、case collisionも検証します。
- exact revision keyは再利用率を下げ、storageとbuild時間を増やします。性能上の理由だけでtrust／revision bindingを外しません。
- metadata-only出力はcache内容を漏らしませんが、cache IDやworkflow identity自体の公開範囲は導入先で分類します。

## Framework relationship

SITF `T-C007 Action Cache Poisoning`へ`mitigates`として対応します。これは攻撃behaviorとの
関係であり、live CI providerへの採用、完全なSITF coverage、または準拠を意味しません。

## References

- [SITF pinned source and profile](../../../docs/SITF_COVERAGE.md)
- [SITF T-C007 coverage record](../../../policies/integration/sitf-coverage.json)
