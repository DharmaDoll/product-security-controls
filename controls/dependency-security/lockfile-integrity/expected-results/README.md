# Native self-test expected results

`make verify-control CONTROL=PSB-DEPS-003`は次を区別する。

- `PASS`: native installerがsafe fixtureをlockfileの変更なしでinstallした、またはnegative fixtureを意図どおり拒否した。
- `NOT_CHECKED pnpm ...`: digest検証済みpnpm `11.25.0` runtimeが指定されていないためpnpm native profileは実行されていない。これはclean resultではない。Missing-runtimeのfail-closed behaviorだけはtestする。
- `ERROR`: test runtime、fixture構築、native install、negative assertionのいずれかが期待どおり動かなかった。

Requiredなnpm、pip、uv profileと、指定されたoptional pnpm profileがすべて期待どおりならexit `0`になる。Required test runtimeの欠落はexit `2`、assertion failureはexit `1`になる。

安定した確認項目は次のとおりである。

1. Directとtransitive dependencyのimmutable install。
2. Successful install前後でnative lockfile digestが不変。
3. Manifest driftとnon-exact requirementの拒否。
4. Missing／weak transitive integrityとmalformed lockの拒否。
5. Valid package形式のままbytesだけ変えたtransitive tarball／wheelの拒否。
6. npm workspaceとplatform-optional lock recordの扱い。
7. uv `--locked`とinsecureな`--frozen`のmanifest freshness差。
8. Missing lock、unsupported schema、runtime absenceのfail-closed behavior。
9. Insecureな通常`npm install`がmanifest driftに合わせてlockfileを書き換える対照動作。

この出力は一時fixtureに対するtest resultであり、採用組織のregistry、CI設定、実artifact、またはorganization adoptionのevidenceではない。
