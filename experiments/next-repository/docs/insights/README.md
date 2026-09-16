# Cross-cutting Security Insights

Insightは、複数のControl、Pattern、設計レビュー、教育へ持ち運べるRepository独自のMental Modelです。
Normative requirement、製品設定、適合証拠の代替ではありません。

## Pilot insights

| Insight | 持ち帰る見方 |
|---|---|
| [Security効果はEnforcement Pointに宿る](security-effects-live-at-enforcement-points.md) | Artifactの存在ではなく、実operationを変える境界を見る |
| [Credentialは文字列ではなく委任されたauthority](credential-is-delegated-authority.md) | Secret storageだけでなく、resource、operation、lifetime、consumerを追う |
| [Cooldownはtrustではなく観測時間を買う](cooldown-buys-time-not-trust.md) | 時間経過をpackage safetyと取り違えない |

## Insightの条件

- 一つのControlを言い換えただけではない。
- 中心となる見方、具体例、設計reviewへの応用、誤用、限界を持つ。
- 関連Control、Learning、Pattern、Sourceへlinkする。
- Sourceの事実とRepository interpretationを区別する。
