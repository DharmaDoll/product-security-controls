# Migration Ledger

## Purpose

旧リポジトリをそのままコピーせず、Security Property、学習価値、実装価値を選別して再構成します。
旧pathを新treeへ残すredirect directoryは作りません。このledgerとGit historyで追跡します。

Source revision: `91fdb7661b38723ce6fb38da93cf3c68b701e521`

## Dispositions

- `migrated`: 同じSecurity Propertyを保って新Artifactへ移した。
- `split`: 一つの旧packageを複数Artifactへ分けた。
- `deferred`: 有用だがPilotでは移していない。
- `retired`: 形骸化または重複のため移さない。
- `review-required`: Sourceや境界の再確認が必要。

## Pilot records

| Legacy artifact | Disposition | New artifacts | Notes |
|---|---|---|---|
| `controls/source-protection/source-access-credential-lifecycle/README.md` | `split` | Control、Learning、Engineering Pattern、GitHub Implementation、Insight | Credential lifecycleのPropertyを保持し、導入手順をControlから分離 |
| 同packageの`control.yaml` | `split` | concise `control.yaml`、framework mapping | 17 atomic checksをSecurity Propertyへ再編。exact framework version／IDは保持し、新Propertyへのallocationをreview対象にした |
| 同packageの`secure/`、`insecure/`、verifier、expected results | `deferred` | なし | JSON metadataの検査がlive source authorityを強化するか再評価するまで移さない |
| 同packageのGitHub adoption runbook | `split` | GitHub Implementation | 製品固有の導入判断だけを再編集 |
| `REF-AI-004`、`REF-USER-001`、GitHub framework registries | `migrated` | Sources and Specifications、framework mapping | 固定commit、version、採用境界、制約を保持した |
| `controls/dependency-security/release-cooldown/README.md` | `split` | Control、Learning、Engineering Pattern、npm Implementation、Insight | Cooldownの保証とnpm／proxy固有手順を分離 |
| 同packageの`control.yaml` | `split` | concise `control.yaml`、framework mapping | Cooldown、proxy、integrityの境界を再編。MITRE／SSDFのversionとIDは保持した |
| 同packageのpolicy fixture、proxy clients、general verifier | `deferred` | なし | 価値があるImplementation単位を選ぶまで一括copyしない |
| npm project設定 | `migrated` | npm Implementation | 小さな具体例として分離。effective behaviorは採用環境で確認する |
| `REF-DEPS-001`、`REF-DEPS-004`、package-manager仕様、incident資料 | `migrated` | Sources and Specifications | Community indexと公式製品仕様を区別し、mutable sourceを再review対象にした |
| 非Pilotの`REF-*` source records | `deferred` | legacy source catalog | 削除せず、対応Control／Patternの移行時にrecord単位で移す |

## Open design questions

1. Control IDを長期的に`PSB-*`のまま維持するか。
2. Source credential lifecycleを、interactive identity、automation identity、revocationへ分割するか。
3. Dependency cooldownとmanaged proxy routeを別Controlにするか。
4. Atomic adoption checksをControl metadataではなくAssessmentへ移すか。
5. Security Propertyへ暫定再配置したframework mappingsを、どのreview単位で確定するか。

## Source migration rule

Controlを短くすることと、参照仕様を減らすことは別です。仕様、taxonomy、vendor guidance、user input、
incident researchは[`Sources and Specifications`](../sources/README.md)へ移し、Control、Implementation、
Mappingからsource IDで参照します。Sourceを採用しない場合も、重要な除外判断は削除せず理由を残します。
