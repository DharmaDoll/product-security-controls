# Control Catalog

Controlは、製品やtoolに依存しない形で「何を満たすべきか」を定義します。
具体的な実装方法から探す場合は[Engineering](../engineering/README.md)を使用してください。

## Pilot controls

| Domain | Control | 問うこと | できてはいけないこと |
|---|---|---|---|
| [Source Protection](records/source-protection/README.md) | [PSB-SOURCE-004](records/source-protection/psb-source-004-source-access-credential-lifecycle/README.md) | Source platformへのauthorityを、必要な主体・目的・対象・期間に限定し、不要時に失効できるか | 一つの盗まれた、または放置されたcredentialが、不要なrepositoryへ長期間アクセスできる |
| [Dependency Security](records/dependency-security/README.md) | [PSB-DEPS-001](records/dependency-security/psb-deps-001-dependency-release-cooldown/README.md) | 公開直後のdependency versionを、観測期間が終わるまで実行・merge前に止められるか | 新しいversionを自動採用し、異常が発見される前にdeveloperやCIのauthorityで実行する |

これは完全なControl inventoryではありません。移行状況は
[Migration Ledger](../docs/MIGRATION.md)を参照してください。
