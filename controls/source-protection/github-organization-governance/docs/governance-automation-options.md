# GitHub Organization governance automation options

この文書は、`PSB-SOURCE-006`の案2と案3について、将来採用できるアイデアと現実的な実装境界だけを
示します。Collector、service、workflow、credential、synthetic live evidenceはまだ追加しません。
正式な最小実装は[`github-adoption-runbook.md`](github-adoption-runbook.md)のguidance-first baselineです。

## Decision summary

| Option | Use when | Repository deliverable | Live authority |
|---|---|---|---|
| 案1: guidance-first | 一つまたは少数Organizationを小さく導入する | Policy、verifier、adoption runbook | GitHub／IdP管理者とmanual current-state review |
| 案2: read-only assessment | Daily snapshotの負担を下げる必要がある | Reviewed collectorとnormalized assessment | Read-only GitHub／IdP API |
| 案3: continuous governance | 多数repository／Organizationのdriftとauditを継続監視する | Versioned policy、collector、verifier integration | Security-owned scheduler、evidence store、alert receiver |

案2と案3を採用しても、provider settingの変更は自動化しません。Remediationは`PSB-CICD-008`のrequest、
independent approval、exact target、before／after、audit eventを経た管理者操作にします。

## 案2: optional read-only assessment

### Smallest useful implementation

将来collectorを追加する場合は、一つのsingle-purpose commandに限定します。

```text
GitHub／IdP read-only APIs
          ↓
field allow-list and stable-ID normalization
          ↓
atomic write of organization snapshot
          ↓
existing scripts/verify.py
          ↓
PASS / FAIL / NOT_CHECKED / ERROR
```

Collectorは次だけを行います。

- Exact Organization login、numeric database ID、node IDをresolveする;
- Member、Owner、team、outside collaborator、repository、Appをcomplete paginationで収集する;
- Member privileges、Actions、security configuration、audit healthをcurrent stateとして収集する;
- IdPからassignment、provisioning health、offboarding resultを別authorityとして収集する;
- Secret-free allow-listへnormalizeし、policy SHA-256とobserved timeを付ける;
- 全sourceが成功した場合だけtemporary fileをrenameしてsnapshotを確定する。

Collectorは設定変更、member削除、App停止、ticket承認、exception作成を行いません。GitHubとIdPを一つの
broad credentialで読むのではなく、authorityごとにread-only credentialを分離します。

### Required failure behavior

- Pagination incomplete、count mismatch、rate limit、permission denial、API version mismatch、schema change、
  timeout、stale IdP dataは`ERROR`;
- Provider planで取得不能なstateは、推測せず`NOT_CHECKED`またはorganization-owned evidence;
- Last-known-good snapshotはhistorical evidenceであり、current `PASS`として再利用しない;
- Error outputへtoken、authorization header、repository name、email、App secretを含めない;
- Partial outputをcurrent assessment pathへ残さない。

### Minimum tests before adoption

- Complete multi-page positive response;
- Missing next page and repeated cursor;
- Rate limit、permission denial、timeout;
- Organization ID／policy digest mismatch;
- Count mismatch and duplicate stable ID;
- Secret-bearing provider responseのredaction;
- Unsupported IdP fieldが`PASS`にならないこと;
- Output write failureがprevious snapshotを上書きしないこと。

実adopterのOrganization、plan、必要API、credential custody、IdPが決まるまでは、架空のAPI fixtureだけを
増やしてcollectorを実装済みにしません。

## 案3: continuous governance ideas

案3は一つの製品を導入することではなく、current posture、audit health、drift、alert deliveryを
security-owned boundaryで継続確認する運用です。現実的な候補は次の三つです。

### Idea A: scheduled snapshot evaluation

Security-owned CIまたはjob schedulerが案2のread-only collectorを少なくとも日次実行し、既存verifierへ
渡します。最初に実装するなら、この構成が最小です。

- Daily full inventoryで24時間以内のsnapshotを作る;
- Previous snapshotとの差分ではなく、毎回complete current stateをpolicyへ照合する;
- `FAIL`はowner付きfinding、`ERROR`はcollector incidentとして同じreceiverへ送る;
- SnapshotとresultをGitHub Organization Ownerが削除できないstorageへ保持する;
- Open findingが0でもcollector healthが悪ければclean postureにしない。

これはrepository追加、member変更、App permission変更等を一日以内に発見する用途に適します。Near-real-time
responseは提供しません。

### Idea B: audit stream plus periodic reconciliation

Supported planではaudit log API、stream、またはreview済みwebhookをsecurity-owned receiverへ送り、
membership、application access、visibility、Actions、ruleset、Organization settingのchange signalを
早期検知します。

Event streamだけではcurrent populationの欠落を検出できないため、Idea Aのdaily full reconciliationを
残します。Event receipt、current state、policy decisionをstable Organization／actor／target IDでjoinし、
eventがないことをcleanの根拠にしません。

適する用途は、high-impact setting changeを日次snapshotより早くtriageしたいOrganizationです。Sequence gap、
receiver outage、stream delayは`ERROR`として扱います。

### Idea C: evaluated third-party governance App

OpenSSF Allstar等のOrganization-scale policy Appを候補として比較できます。ただし、本repositoryはAllstarを
install、authorize、executeしておらず、pin済みsource reviewもpublic Appやhosting environmentを承認しません。

採用する場合は次を満たすalert-only pilotから始めます。

- Immutable source／artifact identity、publisher、license、hosting、update pathをreviewする;
- GitHub App permissionをexact read-only targetへ限定し、write permissionを付けない;
- Supported policyが`GHO-*`のどのunique evidence gapを埋めるかをmappingする;
- Missing API access、App outage、aggregate score、issue creationをclean postureにしない;
- Current target、policy revision、observed state、decision、alert receiptを保持する;
- Existing collectorと同じ結果を返すだけなら新しいdependencyを採用しない。

Automatic remediation modeはこのcontrolの実装候補にしません。必要性が将来確認された場合も、別の
security-sensitive design review、least privilege、dry-run、rollback、`PSB-CICD-008`の変更証跡が必要です。

## Realistic reference architecture for 案3

```text
GitHub posture API ── read-only App ──┐
GitHub audit API／stream ─ read-only ─┼─> security-owned collector
IdP／SCIM health ─── read-only ───────┘              │
                                                     v
                                         secret-free normalizer
                                                     │
                             policy digest + stable target + freshness
                                                     │
                                                     v
                                           existing verifier
                                                     │
                        ┌────────────────────────────┼──────────────────┐
                        v                            v                  v
              independent evidence store      alert receiver     review queue
```

### Component boundaries

| Component | Minimum responsibility | Must not do |
|---|---|---|
| Scheduler | Run exact reviewed collector version on a fixed cadence | Silently skip failed runs |
| Posture collector | Complete current inventory and settings | Mutate GitHub settings |
| Audit collector | Preserve required categories, cursor／sequence, freshness | Treat zero events as proof of safety |
| IdP collector | Current assignment、SCIM health、offboarding timing | Copy credential or personal attributes unnecessarily |
| Normalizer | Stable IDs、allow-listed fields、policy digest、source health | Accept self-reported `secure: true` |
| Verifier | Derive `PASS`／`FAIL`／`NOT_CHECKED`／`ERROR` | Apply exceptions as `PASS` |
| Evidence store | Retain immutable or access-controlled sanitized records | Remain deletable only by GitHub Organization Owners |
| Alert receiver | Route finding and collection failure to an accountable owner | Close on delivery acknowledgement alone |

一つのcredentialで全componentを動かしません。Posture、audit、IdP、storage、alertのauthorityを分離し、
collector compromiseのblast radiusを限定します。

### Cadence and completion

現実的なminimum cadenceは次です。

- Full posture collection: at least daily;
- Snapshot and drift decision freshness: at most 24 hours;
- Owner、member、team、outside collaborator、App review: at most 90 days;
- Alert delivery canary: at most 30 days;
- Audit retention in independent storage: at least 180 days。

Continuous governanceの導入完了には、少なくとも二回のconsecutive full collection、意図的に作った無害な
drift signalの検出、collector failure alert、alert canary delivery、manual remediationのbefore／after evidenceを
一つのstable targetでjoinできることが必要です。Repository fixtureやarchitecture diagramはこの完了条件を
満たしません。

## Phased adoption

### Phase 0: manual baseline

Adoption runbookでlive settingsとownerを確定し、current manual evidenceを取得します。これがない状態で
automationを始めると、collectorが何を正しいと判定すべきか決まりません。

### Phase 1: daily read-only snapshot

案2のcollectorを一つのOrganizationで実行し、`FAIL`と`ERROR`のrouting、redaction、complete pagination、
rollback不要のread-only behaviorを確認します。

### Phase 2: independent retention and audit signal

Snapshotとauditをsecurity-owned storageへ保全し、harmless alert canaryとsequence／receiver failureを試します。
この段階でもremediationはmanualです。

### Phase 3: multiple organizations or optional third-party App

Organizationごとにstable target、policy、credential、owner、evidence partitionを分けます。Third-party Appは
unique gap、least privilege、failure semantics、operational ownerが確認できる場合だけalert-onlyでpilotします。

## Information required before implementing 案2 or 案3

実装開始にはadopter固有の次の情報が必要です。

- 対象Organization数、repository数、GitHub plan、enterprise policy;
- SAML／SCIMまたはEMUとIdPの種類;
- Read-only APIで取得可能なsettingと必要permission;
- Credential issuer、custodian、rotation、emergency revocation;
- Independent evidence storage、retention、region、access owner;
- Alert receiver、on-call owner、finding SLA、collector incident SLA;
- Manual remediationのrequest／approval／rollback system;
- Public repositoryとbusiness-required App／Actionsのexception boundary。

これらがない間は、provider-neutral schema、synthetic evidence、常時成功するmonitorを追加せず、案1を正式な
implementationとして運用します。
