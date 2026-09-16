# Learning Guides

Learning Noteは、Controlの要約を長くするためではなく、一つのSecurity問題を具体Scenarioから理解し、
別のsystemへ応用できるようにする教材です。

## Pilot notes

| Domain | Learning Note | 中心となる問い |
|---|---|---|
| Source Protection | [Source access credential lifecycle](../../controls/records/source-protection/psb-source-004-source-access-credential-lifecycle/learning.md) | なぜcredentialを秘密文字列ではなくauthorityとして扱うのか |
| Dependency Security | [Dependency release cooldown](../../controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/learning.md) | なぜcooldownはpackage safetyではなく観測時間を提供するのか |

## Learning Noteに残すもの

- Actor、Data、Actionが分かる一つのScenario。
- Attacker capability、trust boundary、abuse path。
- 初めて出る用語。
- Security InvariantとEnforcement Point。
- Pass／Fail、隣接Property、保証しない範囲のcalibration。
- よくある誤解と、設計reviewで使える問い。

空のNoteやControl本文の複製は作りません。
