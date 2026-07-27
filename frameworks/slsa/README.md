# SLSA Registry

SLSAはsource、build、provenance、verificationに関するsoftware supply-chain
security要件の根拠として使用します。

## 固定ベースライン

- Version: `1.2`
- Source tag: `v1.2`
- Source commit: `19e4e2f005f871270c4f555fc47afecfb37f3efe`
- Machine-readable registry: [`registry.json`](registry.json)

SLSA 1.2は全要件に短い公式IDを割り当てていないため、このレジストリでは
versioned specification pathを正規化したIDとして使用します。source要件とbuild要件は
混同せず、controlが実際に検証する要件だけを登録します。

## マッピング境界

マッピングはSLSA levelの達成や適合を自動的に意味しません。build platform全体の
評価を行っていないcontrolは、個別の要件を`supports`または`verifies`するものとして
扱います。
