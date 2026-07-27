# PSB-BUILD-003: Build platformがauthentic provenanceを自動生成する

## Security problem

Build script自身がprovenanceを任意生成できる構成では、provenanceを省略したり、
builder identity、source、parameterを偽装したりできます。署名があってもtenantが
platform identityで署名できるなら、consumerはbuild platform由来の情報として
信頼できません。

このcontrolはSLSA Build L1のprovenance existence／automatic generationと、
Build L2のauthenticity／control-plane generationを分けて検証します。

## Required behavior

- build成功時にplatformがprovenanceを自動生成する
- tenant build stepは生成を無効化または生成済みprovenanceを変更できない
- artifactをSHA-256 subjectで一意に識別する
- builder、build type、external parameter、top-level source、invocation IDを記録する
- L2必須fieldはcontrol-plane dataから取得する
- platform-owned identityで署名し、tenantへplatform signing capabilityを渡さない

## Secure and insecure examples

`secure/platform-policy.json`はcontrol-plane generator、automatic generation、
field source、platform signerを定義します。`secure/provenance.json`はSLSA
Provenance v1のsynthetic statementで、Ed25519署名とartifact digestを検証できます。

`insecure/`はtenant build stepがprovenanceを生成・変更・署名できる隔離fixtureです。
Artifact digest、predicate type、builder、source、signatureも期待値と一致しません。
実環境へdeploymentしてはいけません。

## Verification

```bash
make verify-control CONTROL=PSB-BUILD-003
```

直接実行:

```bash
python3 controls/build-security/platform-provenance-generation/scripts/verify.py \
  --policy path/to/platform-policy.json \
  --artifact path/to/release.bin \
  --provenance path/to/provenance.json \
  --signature path/to/signature.b64
```

終了コードは`0=accepted`、`1=security policy violation`、
`2=missing/malformed evidence or verifier unavailable`です。OpenSSLを実行できない
状態は`2`であり、署名検証済みとして扱いません。

Expected secure output:

```text
PASS automatic control-plane-generated authentic provenance verified
```

## Integration

1. Hosted platformのprovenance generation policyとtrust boundaryをreviewします。
2. Platform-issued statementとsignatureをbuild outputから取得します。
3. Builder identityに対応するtrusted public keyまたはcertificate policyを固定します。
4. Build gateでこのcontrolを実行し、exit `1`と`2`をblockします。
5. `PSB-REL-002`でprovenanceをartifactと共に配布し、consumerは
   `PSB-REL-001`で自身のtrust policyへ照合します。

## Acceptance criteria

- valid artifact、SLSA provenance、platform signatureは受理される
- tenant-generated field、unsafe generation policy、invalid signatureは拒否される
- malformed evidenceとOpenSSL execution failureはdistinct errorになる
- SLSA L1 automatic generationとL2 authentic provenanceへ行単位でマッピングされる
- L3 isolationまたはSLSA level達成を主張しない

## Limitations and operational cost

- Productionではprovider API／attestation bundle用adapterが必要です。
- Certificate、transparency log、timestamp、revocation検証はfixtureに含みません。
- Platform policyの自己申告では不十分で、trust-boundary assessmentが必要です。
- L3のstrong unforgeabilityとcross-build isolationは評価対象外です。

## References

- [SLSA v1.2 Build Requirements](https://slsa.dev/spec/v1.2/build-requirements)
- [SLSA v1.2 Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)
