# Privileged control-plane change record

このtemplateをapproved ticket／change-management systemへcopyして使用する。Completed recordには実際の
provider情報が含まれるため、public repositoryへcommitしない。

Token、cookie、authorization header、secret value、private key、不要な個人情報は記録しない。

## 1. Classification

- Control: `PSB-CICD-008`
- Change path: [ ] ordinary / [ ] emergency
- Request ID:
- Incident ID（emergencyのみ）:
- Requested at:
- Requester stable identity:
- Product／service owner:

## 2. Exact target

- Provider:
- Organization／account:
- Service class:
  - [ ] SCM
  - [ ] CI
  - [ ] Cloud identity
  - [ ] Artifact registry
  - [ ] Signing service
- Change type:
- Stable target URL／ID:
- Setting name:
- Environment:
- In-scope inventory reference:

`*`、単なる「production設定」、display nameだけなど、別targetへ流用できる記述は使用しない。

## 3. Before and after

### Before

- Human-readable current value:
- Observation source:
- Observed at:
- Attachment／export reference（必要な場合）:
- SHA-256（大きなmachine-readable設定だけ、任意）:

### After

- Human-readable intended value:
- Reviewed attachment／export reference（必要な場合）:
- SHA-256（大きなmachine-readable設定だけ、任意）:

Hashを使用する場合も、approverは内容を読んでから承認する。Hash文字列だけを承認しない。

## 4. Risk and impact conditions

- Security reason for the change:
- 想定する正常な効果:
- 被害が成立し得る条件:
- 利用可能になる、または失われるauthority:
- 影響を受けるworkflow／branch／runner／role／artifact consumer:
- 条件が成立せずimpactが限定される場合:
- User／developerへの副作用:

「危険」「安全」だけで終わらせず、変更後settingと実際に利用可能なauthorityを結ぶ。

## 5. Rollback

- Previous value:
- Rollback owner:
- Rollback decision condition:
- Expected recovery time:
- 変更後に確認するbuild／release behavior:

Rollbackもprivileged changeである。無承認のrollback commandやcredentialをこのrecordへ保存しない。

## 6. Ordinary pre-approval

Emergency changeではこのsectionを`N/A`とし、section 9を使用する。

- Approver stable identity:
- Approver role:
- Requesterと異なる: [ ] yes
- Executorと異なる: [ ] yes
- Exact targetを確認した: [ ] yes
- Before／afterを確認した: [ ] yes
- Risk、side effect、rollbackを確認した: [ ] yes
- Decision: [ ] approved / [ ] rejected
- Approved at:
- Comment:

承認前にprovider変更を開始しない。Genericな「作業を承認」ではなく、section 2と3のtarget／afterへ承認を結び付ける。

## 7. Execution

- Executor stable identity:
- Executor role:
- Authentication／step-up source:
- Sessionまたはreauthentication observation:
- Executed at:
- Provider result:
- Change console／request reference:

Credential valueやsession cookieは記録しない。Providerがsession evidenceを提供しない場合は
`NOT_CHECKED`とする。

## 8. Independent post-change verification

- Reviewer stable identity:
- Executorと異なる: [ ] yes
- Reviewed at:
- Provider audit source:
- Provider event ID／reference:
- Audit actor:
- Audit action:
- Audit target:
- Current-setting source:
- Current-setting captured at:
- Observed current value:
- Approved afterと一致する: [ ] yes / [ ] no / [ ] not checked
- Audit collectionが対象時刻とscopeを覆う: [ ] yes / [ ] no / [ ] unknown

### Check results

| Check | Result | Evidence／reason |
|---|---|---|
| CPC-001 Named current human |  |  |
| CPC-002 Strong bounded session |  |  |
| CPC-003 Exact target and before／after |  |  |
| CPC-004 Independent pre-approval |  |  |
| CPC-005 Provider event and current state |  |  |
| CPC-006 Emergency expiry and review |  |  |
| CPC-007 Scope and evidence completeness |  |  |

Resultは`PASS`、`FAIL`、`NOT_CHECKED`、`ERROR`、review済み`N/A`のいずれかを使用する。
空欄を`PASS`として扱わない。

## 9. Emergency path

Ordinary changeでは`N/A`とする。

- Emergency reason:
- Incident commander:
- Started at:
- Expires at（開始から最大1時間）:
- なぜ事前承認を待てないか:
- 実施した最小変更:
- Provider event／current-state reference:
- Independent reviewer:
- Reviewed at（expiry以前）:
- Decision: [ ] accepted / [ ] reverted
- Revert change reference:
- 通常変更またはtime-bound exceptionへの移行先:

Expiryまでに独立reviewが完了しなければ`FAIL`である。同じrecordを無期限延長しない。

## 10. Closure

- Overall result:
- Open `FAIL`／`NOT_CHECKED`／`ERROR`:
- Failure owner:
- Follow-up due:
- Evidence storage location:
- Record retention owner:
- Closed by:
- Closed at:

一つでもunresolvedな`FAIL`、`NOT_CHECKED`、`ERROR`がある場合、導入済みまたはcleanとしてcloseしない。
