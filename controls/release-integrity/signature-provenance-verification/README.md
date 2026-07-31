# PSB-REL-001: release署名とProvenanceを期待値に照合する

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | 署名が存在しても、別artifact、未承認builder・source、弱いtrust levelのprovenanceなら、consumerが偽または想定外releaseを正規品として受け入れる。 |
| 誰から、または何から守るか | Artifact・provenance差替え、unauthorized signer、compromised release channel、wrong builder・source、trust signal削除、crypto・parser障害から守る。 |
| 何が対象か | Release artifact、SLSA provenance、subject digest、Ed25519 signature、trusted public key、builder・build type・source・commit・ref expectation。 |
| 何をするか | Consumer側でartifact digestとsubject、署名、signer-builder pair、build process、source revision、no-downgrade policyを使用直前に照合する。 |
| 成功状態 | Exact artifactの署名付きprovenanceが全consumer expectationへ一致し、改ざん・不正署名・wrong source・downgradeは拒否、実行不能はERRORになる。 |
| 対象外・残余リスク | Local fixtureはkeyless PKI、transparency log、revocation、timestamp、trusted builder侵害を評価せず、SLSA levelやformal complianceを証明しない。 |

## Goal

release artifactの署名をtrusted public keyで検証し、provenanceのartifact digest、
signer-builder pair、build type、source repository、source commitをconsumer側の
期待値に照合します。署名またはprovenanceの欠落・低下はdowngradeとして拒否します。

## 実装

安全なfixtureは次を含みます。

- synthetic release artifact
- SLSA Provenance v1 predicateを使うin-toto statement
- Ed25519公開鍵とattestation署名
- consumer-owned `verification-policy.json`

検証順は次のとおりです。

1. artifact SHA-256と`subject.digest`の一致
2. provenance envelopeのEd25519署名
3. `_type`と`predicateType`
4. trusted signerに対応する`builder.id`
5. expected `buildType`
6. source repository、full commit SHA、release ref
7. 過去の信頼levelからのdowngrade拒否

これはSLSA Build levelの正式認証ではありません。fixtureは検証手順のreferenceであり、
builder platformが特定levelを満たすことを証明しません。

## 検証

```bash
make verify-control CONTROL=PSB-REL-001
```

終了コードは`0=検証成功`、`1=署名・digest・期待値違反`、`2=OpenSSL実行失敗、
入力欠落、parse不能`です。

negative testは改ざんartifact、不正署名、wrong builder、wrong source commit、
trust downgrade、malformed provenanceを含みます。

## 実環境への適用

- 公開鍵、certificate identity、OIDC issuer、builder IDをconsumer-owned policyに置く
- signerだけでなくsigner-builder pairをallowlistにする
- `subject`を使用直前のartifact digestへ照合する
- unknown external parameterをfail closedにする
- transparency log、certificate expiry／revocation、key rotationを検証する
- npmではregistry signatureについて`npm audit signatures`も実行する
- GitHub Actions dependencyのimmutable SHAは`PSB-CICD-001`で別途強制する

## 制限事項

- checked-in公開鍵はkeyless certificateやtransparency logを再現しない
- key revocation、certificate chain、timestampはこのlocal fixtureの対象外
- trusted builderまたはsigning key自体の侵害は検出できない
- provenanceの存在はbuild processの安全性やSLSA levelを証明しない
- OpenSSL実行失敗を署名検証成功として扱ってはいけない

## 公式リファレンス

- [SLSA v1.2: Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [SLSA v1.2: Build provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [npm registry signature verification](https://docs.npmjs.com/cli/v9/commands/npm-audit/#audit-signatures)
