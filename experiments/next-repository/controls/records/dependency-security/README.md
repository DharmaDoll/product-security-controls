# Dependency Security

Dependencyの選択、取得、展開、実行を別々の境界として扱い、外部publisherのauthorityが
developer、CI、buildへ無条件に伝播しないようにします。

| Control | 問うこと | できてはいけないこと |
|---|---|---|
| [PSB-DEPS-001 Dependency release cooldown](psb-deps-001-dependency-release-cooldown/README.md) | 新versionへ観測期間を設け、その期間中と判定不能時に採用を止められるか | 公開直後またはpublish時刻不明のversionを、dependency code実行後に初めて検査する |

## Learning path

1. Control recordでcooldownが保証する範囲を確認する。
2. [Learning note](psb-deps-001-dependency-release-cooldown/learning.md)で、lockfile、scanner、proxyとの違いを理解する。
3. [Engineering Pattern](../../../engineering/dependency-security/dependency-release-cooldown/README.md)でenforcement方式を選ぶ。
4. npmを使う場合だけ[npm Implementation](../../../engineering/dependency-security/dependency-release-cooldown/implementations/npm/README.md)を読む。
