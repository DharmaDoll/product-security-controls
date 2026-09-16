# Assessments

Assessmentは、Control RecordやImplementation sampleの存在ではなく、特定の組織、system、repository、
environmentでSecurity Propertyが成立しているかを判断するArtifactです。

## Pilot decision

このPilotではAssessment schemaやevidence fixtureを作りません。まずControlとEngineeringの情報設計を評価します。

将来追加するAssessmentは次を満たす必要があります。

- 対象scopeと評価時点を固定する。
- Propertyごとに観測元とauthorityを示す。
- `PASS`、`FAIL`、`NOT_CHECKED`、`INCOMPLETE`、`ERROR`を必要に応じて区別する。
- Sample、文書、synthetic fixtureからorganization adoptionを推論しない。
- Real secret、credential、private source、production payloadをrepositoryへ保存しない。

旧atomic checksとevidence fieldsを移すかどうかは、Control RecordのPilot評価後に決めます。
