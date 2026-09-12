# 重要な管理設定を変更するときの共通runbook

GitHubの保護ルール、runnerの利用範囲、cloudの信頼ポリシー、registryや署名権限を変更する際に使う手順です。既存の変更管理があれば、足りない部分だけ取り込んでください。独立したsecurity controlや認証制度ではありません。

設定変更だけで製品侵害が確定するわけではありません。例えばreview必須を解除した後、未確認のcodeをmergeでき、公開権限を持つreleaseがそのcodeを実行すると、不正packageの公開につながります。申請では、このように変更後の権限を誰が使えるか、後続の処理にどんな影響があるかを説明します。Digestの確認だけでは、新たに作られた悪意ある成果物の正当性までは判断できません。

独立した公開承認が未確認codeの公開を止める場合、この経路での不正package公開は成立しません。ただし、repository内の改変など他の影響は別に確認します。

## 最短の使い方

1. [変更記録template](change-record-template.md)を既存ticketへ貼り付けます。このrunbookとtemplateを一緒にコピーしても構いません。既存資料は上書きせず、担当者が統合してください。
2. 対象サービスの管理者が、変更する設定と変更前後の値を記入します。開発者は変更理由とbuild／releaseへの影響を説明します。
3. 申請者・実行者とは別の人が対象、変更後の値、影響、戻し方を承認します。承認者に管理権限を与える必要はありません。
4. 記名された管理者が、承認された内容だけを適用します。管理者の認証・権限は対象サービスの既存基準に従います。
5. 実行者以外がproviderの実行記録と変更後設定を確認し、承認内容と照合します。違い・取得不能・未確認は完了扱いにせず、担当者と対応期限を残します。

承認した後に対象や値が変わった場合は、再承認します。元の値へ戻す操作も通常変更または次の緊急経路で記録します。

## 緊急変更

事前承認を待つと被害が拡大する場合に限ります。Incident担当者は理由、対象、実行者、一時変更の期限、戻し方を残し、必要最小限の変更を実施します。実行者以外が期限までに実設定を確認し、継続・復元を判断します。初期の運用例は実行から1時間以内の確認です。サービス事情に応じて期限と当番を事前に決め、期限超過を黙って延長しないでください。復元が障害を再発させる場合は自動で戻さず、incident責任者へ引き継ぎます。

恒久化や例外が必要なら、通常承認または[期限付き例外管理](../../../controls/governance-operations/time-bound-security-exceptions/README.md)へ移します。

## 申請されなかった変更をどう扱うか

申請ticketだけを確認しても、管理画面やAPIからの直接変更は見つかりません。Platform／Security担当者がproviderの変更履歴を起点に、対象期間の変更を承認済みticketへ照合する必要があります。監査の対象範囲、確認頻度、保存先、取得失敗の通知先を決めます。GitHubの管理者と監査設定は[Organization governance](../../../controls/source-protection/github-organization-governance/README.md)を使用します。

対応ticketがない変更は、正規管理者の操作でも理由と後続のbuild、公開、cloud操作を調べます。履歴が欠けていれば「不正変更なし」と判断できません。Providerが事前承認を強制しない場合、攻撃者は監査で見つかる前に変更を悪用できます。この文書はその経路の事前阻止や全providerの網羅的検知を提供しません。

## 手順が使えるか確認する

必要なら、許可された検証用repositoryで既存rulesetのreview数を1件から2件へ増やし、申請、別人の承認、実行、監査記録、変更後設定の一致を確認します。GitHubではrepositoryの `Settings > Rules > Rulesets` を利用します。対象planで利用可能かを先に確認し、productionの保護を弱めて試さないでください。

承認がない申請では実行を止められるかも確認します。監査担当者と合意した検証では、別途許可したsandbox変更を通常ticket未登録として扱い、変更履歴から未照合の変更を発見できるか試せます。これは検証実施の許可を省く指示ではありません。単一の検証結果は、他サービスの設定や監査の完全性を証明しません。

## 記録と運用終了

証跡は組織のticket／監査保管先に残し、public repositoryへcommitしません。取得元、対象、取得時刻、実行者、承認者、変更前後を残します。Token、cookie、秘密鍵は含めません。取得失敗は自己申告で補わず、担当者へ引き継ぎます。

この手順の利用をやめる際は、既存の変更管理へ担当と未完了ticketを引き継ぎ、文書への参照を外します。設定を弱めたり監査記録を削除したりする必要はありません。

## 設定内容の確認先

| 対象 | 安全な設定と検証を所有するcontrol |
|---|---|
| GitHub管理者、認証、権限、監査 | [PSB-SOURCE-006](../../../controls/source-protection/github-organization-governance/README.md) |
| CIのcloud信頼条件 | [PSB-CICD-006](../../../controls/cicd-security/audience-bound-oidc-federation/README.md) |
| Runnerの利用範囲と隔離 | [PSB-CICD-007](../../../controls/cicd-security/runner-hardening/README.md) |
| Registryの権限と保護 | [PSB-CONTAINER-002](../../../controls/container-cloud-iac-security/container-registry-security/README.md) |
| 署名の権限と成果物 | [PSB-REL-005](../../../controls/release-integrity/artifact-signing-generation/README.md) |

## 関連するframework・guidance

以下は手順を理解するための参考です。廃止したcontrolのCPCチェックやformal complianceへのmappingではありません。現行controlのmappingは各control.yamlを参照してください。

- [GitHub: アカウントの保護](https://docs.github.com/en/code-security/tutorials/implement-supply-chain-best-practices/securing-accounts)
- [GitHub: Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub: Organizationの監査ログ確認](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)
- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-AC-01.01](https://baseline.openssf.org/versions/2026-02-19#osps-ac-0101): 重要操作のMFA。
- [OpenSSF OSPS Baseline 2026.02.19 — OSPS-AC-02.01](https://baseline.openssf.org/versions/2026-02-19#osps-ac-0201): 権限の制限。
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)／[T1098](https://attack.mitre.org/techniques/T1098/): 有効accountの悪用とaccount操作という攻撃行動。

旧PSB-CICD-008を共通手順へ移した判断は[ADR-0003](../../adr/0003-privileged-change-runbook.md)に記録しています。
