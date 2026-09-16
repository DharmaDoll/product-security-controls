# Mappings

Mappingは、独立して作られたControl、Engineering Pattern、Implementation、Framework、Threat間の関係評価です。
MappingからControlやPatternの意味を逆算しません。

Pilot内のArtifact relationshipは[`pilot.yaml`](pilot.yaml)、既存仕様とのrelationshipは
[`frameworks.yaml`](frameworks.yaml)にあります。参照仕様のidentity、採否、限界は
[`Sources and Specifications`](../sources/README.md)が正本です。

Pilotでは旧mappingのexact version、identifier、relationship、rationaleを省略せず保持しました。
ただし、17／10 atomic checksから6 Security Propertiesへ再配置したため、各mappingは
`migration-review-required`です。これはmappingを削除するより、再review対象を明示するためです。

最初に次を確認します。

- ControlとEngineering Patternが別々に理解できる。
- Relationshipに具体的なrationaleがある。
- ImplementationはControl全体ではなく、対応するPropertyの一部を実現する。
- Mappingの存在をmaturity、adoption、complianceに使わない。
- Mappingの`source_ref`がsource registryのexact versionへ解決する。
