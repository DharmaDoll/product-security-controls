# 意図的に危険な例: 共有Ownerによる直接変更

> このfileは危険な運用例を説明するためのものです。Providerへ適用する設定や手順ではありません。

## 状況

開発teamはGitHubのdefault branchからpackageを公開している。Release workflowはreview済みのdefault branchへ
mergeされたcodeをbuildし、package registryへpublishできる。

Repositoryのbranch rulesetはpull requestとreviewを必須にしているが、次の運用になっている。

- 複数人が一つの`release-admin` accountを共有している。
- Accountはpasswordと長時間sessionで使用される。
- Ruleset変更を記録するticketや独立承認がない。
- OwnerはGitHubの画面から直接rulesetを変更できる。
- Audit logを定期的に確認する担当者がいない。
- 変更前の設定とrollback手順を保存していない。

ある利用者が急いでreleaseするため、required pull request reviewを外す。共有accountなので、後から個人を特定できない。
その後、未reviewの変更がdefault branchへ入ってrelease workflowが実行される。

## 被害が成立する条件

このruleset変更だけでpackage compromiseが確定するわけではない。次がつながる場合に被害へ進める。

1. Shared Ownerまたはそのsessionを使える人物がrulesetを弱められる。
2. 同じ人物または協力者がdefault branchへ変更を入れられる。
3. Default branchのrelease workflowがその変更を実行する。
4. Release jobがpackage公開に使える実効権限を持つ。
5. Artifact consumerが公開されたreleaseを正規版として受け入れる。

Release jobが存在しない、publish権限がない、別のrelease approvalが止める、またはconsumerが別途exact artifactを
検証する場合、想定したpackage差し替えまで到達しない。ただし、無承認でrulesetを弱められ、誰が何を変更したか
確認できない問題は残る。

## なぜ不十分か

- Actorを一人のcurrent humanへ結び付けられない。
- Exact target、before、after、reasonが実行前にreviewされていない。
- Requester／executorとは別のapproverがいない。
- Provider auditとcurrent settingを独立確認していない。
- 誤変更や不正変更を発見したときのrollbackがない。
- 操作失敗やaudit欠落を`ERROR`として扱う経路がない。

この例にsynthetic evidenceや判定scriptを追加しても、GitHub上の共有account、直接変更、audit未確認は解消しない。
実際のrole、認証、承認手順、audit reviewを変更する必要がある。
