# Engineering

Engineering Patternは、繰り返すSecurity設計問題について「どう安全に作るか」を示します。
Framework controlの順番ではなく、developerやarchitectが探す設計問題で整理します。

## Pilot patterns

| Domain | Pattern | Use case | Implementations |
|---|---|---|---|
| Source Protection | [Source access credential lifecycle](source-protection/source-access-credential-lifecycle/README.md) | Human、automation、toolがsource platformへ接続する | [GitHub](source-protection/source-access-credential-lifecycle/implementations/github/README.md) |
| Dependency Security | [Dependency release cooldown](dependency-security/dependency-release-cooldown/README.md) | 新dependency versionを採用する前に観測期間を設ける | [npm](dependency-security/dependency-release-cooldown/implementations/npm/README.md) |

PatternとControlの関係は[Mappings](../mappings/README.md)で評価します。
