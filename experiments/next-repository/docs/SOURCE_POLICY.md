# Source Policy

## Sourceの役割

| 区分 | 意味 | 書き方 |
|---|---|---|
| Normative | Standardや仕様が直接要求・定義する内容 | versionとimmutable revisionを示す |
| Research | 脅威、例、検証方法を補足する資料 | NormativeなPass条件へ昇格させない |
| Primary source | 製品・protocol・incidentの一次情報 | versionまたは確認日を示す |
| Repository interpretation | 現場の設計判断へ適用する解釈 | Repositoryの判断であると分かるようにする |
| Derived insight | 複数の検討から得た再利用可能な洞察 | Sourceの事実と混ぜない |

Source recordの正本は[`sources/`](../sources/README.md)に置きます。Control側にはsource IDと、
そのPropertyへどう影響したかだけを置きます。Framework relationshipは
[`mappings/`](../mappings/README.md)へ分離します。

## Rules

- Primary sourceを優先し、二次記事だけで製品仕様やincident timelineを確定しない。
- Rolling documentや製品UIは確認日を持ち、古い記述をcurrentとして継承しない。
- 外部Frameworkの文章を大量に複製せず、必要な範囲を要約してlinkする。
- Sourceが特定のtoolを例示しても、それをControlの唯一のImplementationにしない。
- Source間の不一致、不明点、未検証箇所を隠さない。
- Control本文を短くするときも、参照仕様、exact version、採否、除外理由を削除しない。
- Immutable revisionを特定できない製品documentationは、確認日と`re-review-required`を明示する。
- Community compatibility indexで機能を発見しても、製品挙動は公式仕様で確認する。

## Migration pilotのSource state

このPilotは現行リポジトリのcommit
`91fdb7661b38723ce6fb38da93cf3c68b701e521`から知識を再編集しています。
旧Artifactでreview済みだったMappingや製品仕様を、新構造へ移しただけで再review済みとは扱いません。
Provider固有Implementationは採用時に公式sourceを再確認します。
Pilot対象のsource recordと既存framework mappingは省略せず移行しています。旧catalogの非Pilot entryは
対応Artifactを移行するまでlegacy source catalogに残します。
