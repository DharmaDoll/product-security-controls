# Source Protection

Source codeそのものだけでなく、sourceを読み、変更し、releaseやworkflowへ影響できるauthorityを守ります。

| Control | 問うこと | できてはいけないこと |
|---|---|---|
| [PSB-SOURCE-004 Source access credential lifecycle](psb-source-004-source-access-credential-lifecycle/README.md) | 誰が、何の目的で、どのsourceへ、どのoperationを、いつまで行えるかを把握し、不要時に失効できるか | 盗難、異動、退職、用途終了後も、credentialまたはsessionが利用可能なまま残る |

## Learning path

1. Control recordで保証境界を確認する。
2. [Learning note](psb-source-004-source-access-credential-lifecycle/learning.md)で、credential theftがsource authorityへ変わる流れを追う。
3. [Engineering Pattern](../../../engineering/source-protection/source-access-credential-lifecycle/README.md)でidentityの選択とlifecycleを設計する。
4. GitHubを使う場合だけ[GitHub Implementation](../../../engineering/source-protection/source-access-credential-lifecycle/implementations/github/README.md)を読む。
