# ENG-DEPS-001: Dependency release cooldown

対応するControl：[PSB-DEPS-001](../../../controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/README.md)

## Summary

Dependency update時、新versionのpublishから一定期間はcandidateを採用せず、外部の検知・yank・advisoryが
現れるための時間を確保します。Decisionはdependency-controlled codeを実行する前に強制します。

## Use case

- DeveloperまたはAI agentが新しいpackageを追加する。
- Update botがdirect／transitive dependencyを更新する。
- Lockfileを再生成し、新しいexact versionを選ぶ。
- Security fixを通常windowより早く採用する。

## Scope and assumptions

対象は新しく選択するexact package／versionとpublish timestampです。通常buildによるreview済みlockfileの再現、
artifact integrity、install script、vulnerability、license、provenanceは隣接する設計問題です。

Registryまたは承認済みmetadata serviceが、versionとpublish timestampを結び付けて提供できることを前提とします。

## Threat and abuse path

```text
compromised publisher
       |
       v
malicious version published
       |
       v
bot / agent / developer selects newest version
       |
       v
install-time code executes in endpoint or CI
       |
       v
warning, yank, or advisory appears later
```

特に、PRのfull CIがage decisionより先にinstallを行うと、mergeを止めてもrunner上の実行は防げません。

## Security invariants

- Decision対象をexact package、version、registry originへ固定する。
- Publish timestampをPR本文やlocal file時刻から得ない。
- Reviewed minimum ageを満たすまで通常採用しない。
- Decisionをdownload／install／build plugin等のcode実行より前に置く。
- Metadataまたはverifier failureをallowへ変換しない。
- Emergency bypassをexact version、owner、別承認、短いexpiryへ限定する。

## Recommended architecture

```text
dependency change request
          |
          v
trusted candidate enumeration
          |
          v
publish-time lookup + age decision
          |
          +-- too young --------> WAIT / merge blocked
          +-- cannot evaluate --> ERROR / merge blocked
          |
          v
lockfile generation and review
          |
          v
isolated install / test
```

Policyとdecision codeを変更するPRが、その変更後の弱いpolicyだけで自分自身を評価できないようにします。

## Enforcement options

### Native resolver gate

Resolver自身がyoung candidateを除外します。最も早いboundaryですが、supported version、config precedence、
CLI／environment override、alternate clientを確認する必要があります。

### Trusted CI gate

複数ecosystemやteam repositoryで共通のrequired checkを提供します。Candidate列挙、metadata lookup、policyを
untrusted dependency changeから分離し、full installより前に実行します。

### Managed registry proxy

取得経路を中央化し、known-malware blocking、tracking、notificationを追加できます。ただしproviderが
publish ageを強制しない限り、proxy routingはcooldownそのものではありません。

### Operational hold

自動gateがない場合、protected reviewでpublish timestampと最短merge時刻を確認します。
これは開始点にはなりますが、自動enforcementやbypass resistanceを主張しません。

## Choosing a window

長いwindowは公開直後の情報不足を減らしますが、security fixの採用も遅らせます。短いwindowはdeliveryを
速めますが、signalが現れる前に採用する可能性を高めます。

一つの時間をpackage safety thresholdと呼ばず、脅威、更新頻度、緊急例外、運用能力と合わせて決めます。
Pilot Implementationは旧Controlの168時間profileを例示します。

## What to verify

- Boundaryちょうどのold-enough candidateが通常経路へ進む。
- Boundary直前のcandidateがcode実行前に止まる。
- Missing version、missing timestamp、timeout、parse failureがnon-passになる。
- Developer、bot、AI agentが同じdecisionを通る。
- Emergency exceptionが他package、別version、将来のupdateへ残らない。
- 通常buildが新しいversionを暗黙にresolveしない。

Testは選択したImplementationが所有します。Synthetic testの成功はlive CIやresolverへの導入を証明しません。

## Residual risk

Observation window後のmalware、長期潜伏、compromised timestamp authority、artifact substitution、
dependency confusionは残ります。Cooldownをdependency review全体の代替にしません。

## Implementations

- [npm](implementations/npm/README.md)

## Related insights

- [Cooldownはtrustではなく観測時間を買う](../../../docs/insights/cooldown-buys-time-not-trust.md)
- [Security効果はEnforcement Pointに宿る](../../../docs/insights/security-effects-live-at-enforcement-points.md)

## Sources

- [REF-DEPS-004 compatibility index and official client specifications](../../../sources/README.md#ref-deps-004)
- [npm minimum-release-age specification state](../../../sources/README.md#spec-npm-cli-11)
- [npm registry metadata specification state](../../../sources/README.md#spec-npm-registry-metadata)
- [REF-DEPS-001 managed proxy guidance](../../../sources/README.md#ref-deps-001)
