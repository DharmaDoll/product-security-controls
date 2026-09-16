# PSB-DEPS-001: Dependency release cooldown

さらに具体的に学ぶ：[Learning note](learning.md)

設計する：[Engineering Pattern](../../../../engineering/dependency-security/dependency-release-cooldown/README.md)

## 問い

新しく公開されたdependency versionを、定めた観測期間が終わるまで、developerまたはCIのauthorityで
codeを実行する前、かつmergeする前に止められるか。

## できてはいけないこと

Update bot、AI agent、developer、resolverが公開直後のversionを自動採用し、maintainer compromiseや
malicious releaseが発見・削除される前にinstall script、build plugin、dependency codeを実行してはいけません。

Publish時刻を確認できない状態も、古いversionまたは安全なversionとして扱ってはいけません。

## なぜ重要か

Malicious releaseが公開された瞬間に判定情報が揃うとは限りません。利用者、registry、maintainer、
security researcherが異常を検知し、yankやadvisoryへ至るまでの時間差があります。
Cooldownはその時間を防御へ変換します。

Cooldownはmalware detectorではなく、時間経過後の安全も保証しません。

## 適用範囲

新しいdependencyの追加、既存dependencyの更新、lockfile再生成、update botのPRなど、
新しいexact package versionを選択する経路に適用します。

既にreview済みのlockfileをそのまま再現する通常installは、隣接するlockfile／integrity controlの対象です。
Vulnerability、license、provenance、install script、runtime behavior、registry自体の侵害も別の保証です。

## 必要なSecurity Properties

| ID | 成立すべき状態 |
|---|---|
| `DEP-AGE-1` | 新しく選ばれるexact package、version、registry originを特定する |
| `DEP-AGE-2` | Publish timestampを承認済みauthorityから取得し、信頼するUTC時刻でageを評価する |
| `DEP-AGE-3` | Review済みminimum ageを満たすまでcandidateを採用しない |
| `DEP-AGE-4` | 判定をdependency-controlled codeの実行前、かつmerge前に強制する |
| `DEP-AGE-5` | Missing、stale、malformed、unavailableなmetadataとtool failureをnon-passにする |
| `DEP-AGE-6` | 緊急例外をexact package／version、owner、別承認者、期限へ限定する |

## 実装判断の羅針盤

| 状況 | 選択肢 | 注意点 |
|---|---|---|
| Package managerが信頼できるnative age gateを持つ | Resolverで候補から除外 | CLIやenvironmentによる上書き、unsupported versionを確認する |
| Team repositoryまたは複数ecosystem | Trusted CI required check | PRがverifierやpolicyを同じ変更で弱められないようにする |
| 多数のrepositoryとmanaged endpoint | Registry proxyを追加 | Proxy allow判定をcooldownの代替にしない |
| 自動gateを構築できない | Protected branchとmanual hold | Operational fallbackであり、自動強制とは呼ばない |

基準時間はrisk appetiteと更新速度のtrade-offです。Pilotでは旧Controlの168時間baselineを継承していますが、
時間の妥当性とframework mappingは再review対象です。

## 判定のCalibration

| Observation | このControlの判断 |
|---|---|
| PRが7日間openだった | Publish ageの証明にならない |
| Scannerがfindingを出さなかった | Cooldown完了やpackageの安全を証明しない |
| Proxyがdownloadを許可した | Providerがminimum ageを強制すると確認しない限り、cooldownの代替にならない |
| Metadata取得がtimeoutした | `ERROR`相当。採用を進めない |
| 168時間を過ぎたがprovenanceが不明 | CooldownにはPassし得るが、dependency review全体は未完了 |
| Lockfileがある | 通常installのdriftには有効だが、新version選択前のage gateにはならない |

## 保証しない範囲

Cooldownを経過したmalicious package、長期潜伏backdoor、typosquatting、dependency confusion、
artifact substitutionは残ります。Registryが偽のpublish timestampを返す場合も、ageだけでは検出できません。

## Related artifacts

- [Learning note](learning.md)
- [Engineering Pattern](../../../../engineering/dependency-security/dependency-release-cooldown/README.md)
- [Cooldownはtrustではなく観測時間を買う](../../../../docs/insights/cooldown-buys-time-not-trust.md)
- [Security効果はEnforcement Pointに宿る](../../../../docs/insights/security-effects-live-at-enforcement-points.md)
- [Pilot mapping](../../../../mappings/pilot.yaml)
- [Framework mappings](../../../../mappings/frameworks.yaml)
- [Sources and Specifications](../../../../sources/README.md)

## 参照仕様とmapping

| Source | Exact version／ID | Relationship |
|---|---|---|
| MITRE ATT&CK Enterprise | `v19.1`／`T1195.001` | 公開直後のdependency compromise exposureを`mitigates` |
| NIST SSDF | `1.1 (SP 800-218, 2022)`／`PW.4.1` | Third-party componentのcontrolled acquisitionを`supports` |

Package-manager固有仕様はframework mappingではありません。npm、Yarn、uv、pnpm、pipの仕様、
Dependency Cooldowns、managed proxy、incident contextは
[Sources and Specifications](../../../../sources/README.md)に、採用範囲と限界を含めて保持します。
Mappingはpackageの安全性、組織導入、またはformal complianceの主張ではありません。

## Primary references

- [REF-DEPS-004 Dependency Cooldowns and official client specifications](../../../../sources/README.md#ref-deps-004)
- [SPEC-NPM-CLI-11](../../../../sources/README.md#spec-npm-cli-11)
- [npm registry metadata specification](../../../../sources/README.md#spec-npm-registry-metadata)
- [REF-DEPS-001 managed proxy guidance](../../../../sources/README.md#ref-deps-001)
- [npm configuration](https://docs.npmjs.com/cli/v11/using-npm/config/)
- [npm install](https://docs.npmjs.com/cli/install/)
- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- [Yarn security features](https://yarnpkg.com/features/security)
- [uv dependency resolution](https://docs.astral.sh/uv/concepts/resolution/)
- [pnpm dependency resolution settings](https://pnpm.io/settings/dependency-resolution)
