# PSB-DEPS-004: Dependency change review

## このcontrolを一枚で理解する

### セキュリティ上の問題

Lockfile差分に新しいdirect／transitive dependency、version、source、license、脆弱性、provenance gapが混入しても、通常のcode reviewだけでは変更範囲とriskを見落としやすい。

### 誰から、または何から守るか

侵害されたmaintainer・registry、malicious dependency、dependency confusion、既知脆弱性、license不適合、review bot障害、自己承認、期限なし例外から守る。

### 何が対象か

Base／proposed lock graph、direct・transitive packageとedge、exact version、registry・source commit、license、advisory snapshot、provenance、review approval、例外。

### 何をするか

Baseとheadのdependency graph差分だけを抽出し、追加・version・source・edgeを、freshで完全なadvisory、license policy、subject-bound provenance、非author承認、期限付き例外へ照合する。

### 成功状態

全dependency deltaがdirect／transitive context付きで表示され、approved source、脆弱性閾値、license、provenance、非author承認を満たす。不完全・stale・malformed evidenceは`ERROR`となる。

### 対象外・残余リスク

正常判定はdependencyが無害であることを保証しない。未知脆弱性、悪意あるがadvisory未登録のcode、実lockfile parser、artifact hash、install script、runtime behaviorは別controlまたはadapterが必要である。

## このcontrolの役割

このcontrolは、通常installではなくdependency update PRの変更判断を担当します。
既存controlとの境界は次のとおりです。

| Control | 責任 |
|---|---|
| `PSB-DEPS-001` | managed registry proxyとrelease cooldown |
| `PSB-DEPS-002` | install時のdependency code execution |
| `PSB-DEPS-003` | frozen lockfile、origin、artifact integrity |
| `PSB-DEPS-004` | baseからheadへ新しく入るdependency riskのreview |
| `PSB-DETECT-001` | repository／artifact全体のvulnerability scan |

正しいhashを持つpackageでも、version更新によって既知脆弱性や不適合licenseが
入る可能性があります。逆にadvisoryが0件でも、advisory取得失敗なら安全とは
判断できません。このため、graph差分と外部risk evidenceを同じdecisionへ結びます。

## まず実行するコマンド

```bash
make verify-control CONTROL=PSB-DEPS-004
```

通常検証はnetworkやregistry credentialを使わず、provider-neutralなnormalized
lock graphとpinned synthetic advisory snapshotをofflineで評価します。

| 終了コード | 意味 |
|---:|---|
| `0` | exact dependency deltaと全risk evidenceを評価して許可 |
| `1` | vulnerability、license、source、provenance、review、例外違反をblock |
| `2` | advisory不完全・stale、schema不正、入力欠落などで評価不能 |

## 9つのatomic check

| Check | 確認内容 |
|---|---|
| `DCR-001` | exact base／head revision、graph、policyへのdecision binding |
| `DCR-002` | direct／transitive packageとadded／removed edge context |
| `DCR-003` | exact version、approved registry、immutable source commit |
| `DCR-004` | freshでcompleteなadvisoryとvulnerability threshold |
| `DCR-005` | changed dependencyのlicense policy |
| `DCR-006` | changed dependencyのverified subject-bound provenance |
| `DCR-007` | exact deltaへの非author dependency reviewer承認 |
| `DCR-008` | exact、owned、別承認者、短期限の例外 |
| `DCR-009` | policy・advisory・parser failureをcleanにしない |

これらは`control.yaml`から生成チェックリストとSpreadsheetへ展開されます。

## Secure example

`secure/base-lock.json`から`secure/proposed-lock.json`への変更は次の4件です。

- `core-lib`の`1.0.0`から`1.1.0`へのversion変更
- `core-lib`のexact source commit変更
- transitive `parser-lib@2.0.0`追加
- `core-lib`から`parser-lib`へのedge追加

全変更IDがreview evidenceに列挙され、changed packageはapproved registry、
immutable source commit、許可license、verified provenanceを持ちます。advisory
snapshotはfresh・completeで、対象purlにthreshold以上のrecordがありません。

## Insecure example

`insecure/`は**テスト専用であり、採用してはいけません**。危険例には次を含みます。

- allowlist外のHTTP registryとmutable source reference
- deniedまたはunknown license
- high／critical advisory
- missing provenance
- author自身のapproval
- wildcard、自己承認、長期限のexception

verifierの出力はpurl、check ID、advisory ID、理由だけです。advisory description、
source content、credential、exception justificationを保存しません。

## 実環境への統合

1. Package manager固有lockfileをread-only adapterでnormalized graphへ変換する。
2. Baseとheadのfull commit SHA、graph digest、policy bundle digest、advisory
   snapshot digestをreviewへ結ぶ。
3. GitHub Advisory Database、OSV、SCA providerなどからcomplete snapshotを取得し、
   source、取得時刻、pagination完了、snapshot digestを記録する。
4. PURL、scope、direct／transitive、edgeを失わず差分を作る。
5. Source registry、repository、exact commit、license、provenanceをchanged packageへ
   結び付ける。
6. Non-author dependency reviewerがcomputed change ID集合を承認する。
7. `0`だけをmerge候補とし、`1`はblock、`2`はsecurity check errorとしてblockする。

GitHub Dependency Reviewはbaseとheadのdependency差分、vulnerability severity、
license policyを扱う実環境adapter候補です。ただし、repository workflowへ導入する
場合は`PSB-CICD-001`のfull SHA pin、`PSB-CICD-004`の`contents: read`、
`PSB-CICD-005`のuntrusted PR境界を独立して適用してください。このoffline sliceは
Actionを追加せず、provider-neutral decision contractを実装します。

## Operational notes

- Advisory snapshotはpartial paginationやprovider outageを`complete: false`にする。
- Change ID集合はverifierが計算し、重複を含むPR本文の自己申告を信用しない。
- Registryだけでなくrepository URL prefixとfull source commitもpolicyで制限する。
- Direct dependencyだけでなく、追加されたtransitive packageとedgeをreviewする。
- License判定はSPDX identifier／expressionへ正規化する実環境adapterを用意する。
- Provenanceが提供されないecosystemは、暗黙passではなく限定例外またはpolicy変更を
  正式にreviewする。
- Vulnerability非該当を主張する場合は、単なるignoreではなく別controlでreviewされた
  VEX／exploitability evidenceへ結び付ける。
- Renovate／Dependabotなどのauthor automationもhuman reviewerと同一主体にしない。

## Limitations

- Fixtureの`graph_sha256`はsynthetic identityで、実ファイルhash計算adapterではない。
- Version range評価は行わず、advisory snapshotがexact PURLへ正規化済みと仮定する。
- Source provenance statement自体の署名検証はprovider adapterまたはrelease controlが
  担当する。
- License compatibilityは製品license、link方式、配布形態、法務判断に依存する。
- GitHub Dependency Review Actionやvendor APIをrepository testでは実行しない。
- Mappingは関連要求への支援であり、OSPS、SSDF、MITREの完全coverageを意味しない。

## References

- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [Configuring the dependency review action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)
- [OpenSSF OSPS Baseline 2026.02.19](https://baseline.openssf.org/versions/2026-02-19)
- [`REF-DEPS-002` GitHub dependency review guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-deps-002)
