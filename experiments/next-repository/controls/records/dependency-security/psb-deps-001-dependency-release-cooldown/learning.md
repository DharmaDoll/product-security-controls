# Dependency release cooldown — Learning Note

[Control Record](README.md)

## この文書の目的

Cooldownを「古いpackageなら安全」というruleではなく、公開直後の情報不足を扱う時間境界として理解します。

## 1. 具体Scenario

よく利用されるpackageのmaintainer accountが侵害され、malicious versionが公開されます。Update botは最新versionを
数分後にPRへ追加し、通常CIが最初にfull installを行います。

```text
malicious version published
          |
          v
update bot resolves latest version
          |
          v
CI downloads and runs install-time code
          |
          v
community detects anomaly and registry removes version
```

PRがmergeされなくても、CI secret、source、networkを持つrunner上で既にcodeが実行される場合があります。
「merge前だから安全」ではなく、dependency-controlled codeを実行する前にdecisionを置く必要があります。

## 2. Cooldownが利用するもの

Malicious releaseの検知、maintainerの調査、registryのyank、advisory公開には時間がかかります。
Cooldownは新versionの自動採用を遅らせ、この外部観測が進む時間を確保します。

次は行いません。

- Package内容からmalwareを判定する。
- 一定時間後のpackageを安全と認定する。
- Vulnerability、license、provenance、maintainer reputationを評価する。

## 3. 用語

### Publish timestamp

Versionがregistryで公開された時刻です。PR作成時刻、Git commit時刻、cache時刻、local file mtimeとは異なります。

### Observation window

新versionを通常採用しない期間です。待機時間そのものではなく、その間に外部signalが現れる機会を作ります。

### Resolver

Version rangeやdependency graphから、実際に取得するexact versionを選ぶcomponentです。

### Frozen install

既にreview済みのlockfileを変更せず再現するinstallです。新versionを選ぶupdateとは別のoperationです。

## 4. Lockfileとの違い

```text
dependency update
     |
     v
exact candidateを選ぶ ---- cooldownが守る境界
     |
     v
reviewしてlockfileへ固定
     |
     v
通常buildで再現 --------- lockfileが守る境界
```

Lockfileは選択済みgraphのdriftを防ぎますが、新しく選ぶcandidateの年齢は評価しません。
Cooldownはcandidate選択を遅らせますが、その後のartifact bytesや通常installの再現性は保証しません。

## 5. Security Invariant

> 新しく選ばれるdependency versionは、承認済みsourceからpublish時刻を確認でき、観測期間を満たすまで、
> dependency-controlled codeを実行するauthorityへ到達しない。

Metadataを確認できない場合も、古いと推測せず停止します。

## 6. Enforcement Pointを選ぶ

| Enforcement | 強み | 主なblind spot |
|---|---|---|
| Native resolver gate | Code取得前に候補を除外できる | Version、config precedence、alternate clientによるbypass |
| Trusted CI gate | Teamで共通のmerge boundaryにできる | Full installより後に置くと遅い。PRがpolicyを変更できると弱い |
| Managed proxy | 経路を中央化し、trackingやblockingを追加できる | Minimum-age機能がなければcooldownではない |
| Manual hold | Toolがない環境でも開始できる | Human errorと別経路を防ぎ切れない |

一つを万能とせず、対象repositoryと脅威に応じて組み合わせます。

## 7. よくある誤解

### 「7日経ったから安全」

誤りです。7日はこのControlの旧reference baselineであり、安全になる時刻ではありません。

### 「ScannerがGreenなので待たなくてよい」

Scannerがまだ知らないmalwareや、実行時だけ現れるbehaviorがあります。Scannerとcooldownは別のsignalです。

### 「Proxyを通したのでcooldown済み」

Proxyがpublish ageを強制しない限り、経路制御とcooldownは別のPropertyです。

### 「PRを一週間放置したのでよい」

PR ageとversion publish ageは一致しません。現在のregistry metadataを再評価します。

## 8. 緊急security update

Known vulnerabilityのfixを待つriskが、fresh releaseを採用するriskを上回ることがあります。その場合も、
global floorやpackage-wide exclusionを恒久変更しません。Exact package／version、理由、owner、別approver、
短い期限に限定し、cooldown以外のintegrity、review、execution containmentは維持します。

## 9. 持ち帰る問い

- Age decisionはdependency codeの実行より前にあるか。
- Exact versionとpublish timestampのauthorityを特定できるか。
- Timeoutやmetadata欠落がallowへ変わらないか。
- Developer、bot、AI agentに同じboundaryが適用されるか。
- Cooldown、proxy、scanner、lockfileの異なる保証を混同していないか。

## Related insight

- [Cooldownはtrustではなく観測時間を買う](../../../../docs/insights/cooldown-buys-time-not-trust.md)
- [Security効果はEnforcement Pointに宿る](../../../../docs/insights/security-effects-live-at-enforcement-points.md)

## Sources

- [REF-DEPS-004 compatibility index and official product specifications](../../../../sources/README.md#ref-deps-004)
- [npm package metadata specification state](../../../../sources/README.md#spec-npm-registry-metadata)
- [Incident context retained by the source catalog](../../../../sources/README.md#incident-context-retained-for-learning)
