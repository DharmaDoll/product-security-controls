# PSB-SOURCE-004 実装計画書

## 1. 計画の目的

`PSB-SOURCE-004`を、自己申告policy JSONの検証を中心とした見え方から、実際のGitHub／IdP設定と
credential lifecycle運用を中心とするguidance-first controlへ整理する。

この計画では次を同時に達成する。

- 開発者が短時間で採用できるGitHub最小baselineを示す。
- Organization owner、repository administrator、securityの作業を分離する。
- Manual live verificationを正式なverificationとして定義する。
- 既存fixture／verifierをreference regression testとして維持する。
- Read-only監査で将来何を確認できるかを紹介するが、collector実装は必須にしない。

## 2. 計画原則

- 新しいpackage、framework、Docker、provider mutation scriptを追加しない。
- 実装効果が生まれるprovider settingと運用をREADMEの早い位置に置く。
- Exact UI名、API version、plan条件は実装時にofficial GitHub documentationで再確認する。
- Production credential、private repository、個人情報をfixture／evidenceへ入れない。
- Documentation文字列だけを確認するtestやno-op testを追加しない。
- Fixture `PASS`とorganization adoptionを分離する。
- Scanner／collector failureをclean resultへ変換しない。

## 2.1 実行結果（2026-08-25）

| Phase | 状態 | 結果 |
|---|---|---|
| 0 | 完了 | Check分類、他controlとの境界、GitHub provider／plan前提を仕様書とrunbookへ記録した。 |
| 1 | 完了 | READMEをguidance-firstへ再構成し、役割、最短導入、live verification、完了条件を先頭近くへ配置した。 |
| 2 | 完了 | GitHub設定、credential移行、棚卸し、失効、test、recovery、rollbackをrunbookへ実装した。 |
| 3 | 完了 | Read-only API、audit log、IdP／endpoint source、将来collectorの安全境界を紹介した。Collector自体は実装していない。 |
| 4 | 完了 | 既存verifierとfixtureをreference regression testとして明示し、live adoptionの証拠と分離した。 |
| 5 | 完了 | `control.yaml`のverification、evidence、limitationsとsecure implementation参照を同期した。 |
| 6 | 完了（注記あり） | Control単体、canonical verification、validation、lint、生成物のcurrent確認は成功。Repository全体のunit test 145件は成功したが、その後、今回の変更範囲外の`PSB-AI-001`が固定digest不一致をexit 2で報告したため、`make test`全体は未成功。 |

この実行結果はrepository上のreference implementationの完成状態であり、GitHub organizationでの
設定変更、current inventory、live drillの完了を示さない。採用組織の状態は、runbookの完了条件を
満たすまで`NOT_CHECKED`である。

## 3. 変更対象

| File | 予定する変更 | 優先度 |
|---|---|---:|
| `README.md` | Guidance-firstの最短導入、役割、live verification、完了条件へ再構成 | P0 |
| `docs/github-adoption-runbook.md` | GitHubの設定・実施順序・drill・recovery・rollbackを新規作成 | P0 |
| `docs/read-only-audit-options.md` | API／audit log／IdP／endpointの確認可能範囲を新規作成 | P1 |
| `secure/*.json` | Baseline sampleとして必要最小限の整合性をreview | P1 |
| `insecure/*.json` | 危険例が実環境導入手順に見えないことをreview | P1 |
| `scripts/verify*.py` | Reference regression testという境界をoutput／docsで明確化 | P1 |
| `tests/test.sh` | 現在の意味あるpositive／negative／error testだけを維持 | P1 |
| `control.yaml` | Verification、evidence、limitationsをguidance-first境界へ同期 | P1 |
| Generated views | Metadata変更後にcanonical targetで再生成 | P2 |

## 4. 実装phase

### Phase 0: Boundary確認

目的は、作業開始前にscopeとprovider条件を固定することである。

作業:

1. `SCL-001..017`を実設定、manual operation、reference fixture、optional auditへ分類する。
2. `PSB-SOURCE-001..003`、`PSB-CICD-006`、`PSB-AI-002／004`、`PSB-GOV-002／004`との分担を再確認する。
3. GitHub Free／Team／Enterprise Cloud、SAML／SCIM、MCP利用の対象profileを記録する。
4. Official GitHub documentationの画面名、影響、API version、必要permissionを確認する。

成果物:

- Reviewed check classification。
- Provider／plan assumption一覧。
- 実装対象外一覧。

完了条件:

- 各checkについてsecurity効果が生まれる実設定または運用とownerを説明できる。
- 他controlのscanner、runtime policy、exception、rotation engineを複製しないことが合意される。

### Phase 1: READMEをguidance-firstへ再構成

目的は、adopterが最初の画面で「何を、誰が、どう設定するか」を理解できる状態にすることである。

作業:

1. Mandatory一枚summaryは維持する。
2. 直後に「セキュリティ向上の効果はどこから生まれるか」を置く。
3. Role別作業表を置く。
4. GitHub最小導入の8 stepとcopy／reference対象を置く。
5. Repository self-testとlive manual verificationを分離する。
6. 導入完了条件、rollback、residual riskを明記する。
7. Policy JSON／verifierの`PASS`がlive adoptionではないことを明記する。

成果物:

- 更新された`README.md`。

完了条件:

- READMEだけで設定対象、担当者、理由、実試験、自動確認不能範囲、導入完了条件が分かる。
- 「組織に合わせて適切に設定する」だけのstepがない。
- Real credentialを扱うcopy-paste commandがない。

### Phase 2: GitHub adoption runbook

目的は、organization ownerとrepository administratorがreviewしながら実設定を変更できる
copy可能な手順を提供することである。

作業:

1. Pre-change inventoryとimpact reviewを定義する。
2. Authentication security、PAT、OAuth App、GitHub Appの設定順序を記載する。
3. Automationをdeveloper tokenからGitHub App等へ移す手順を記載する。
4. Developer storage、SSH、MCP conditional profileを記載する。
5. Quarterly reviewとoffboarding／device loss／exposureのrevocation procedureを記載する。
6. 専用test repositoryでexpected allow、ungranted-permission denial、scope denial、revocation denialを確認する。
7. Common failure、recovery、rollback、break-glass、残余riskを記載する。

安全条件:

- OAuth restrictionや2FAの変更前に影響user／Appを確認する。
- Production credentialを試験で失効しない。
- Policy変更をscriptから自動実行しない。
- Evidenceはcredential値を含まない。

成果物:

- `docs/github-adoption-runbook.md`。

完了条件:

- 各stepにprovider location、設定値、owner、成功状態がある。
- Plan差異は`NOT_CHECKED`または代替措置として表現される。
- Test結果だけでなくcurrent settingとinventory reviewが完了条件に含まれる。

### Phase 3: Read-only audit optionの紹介

目的は、今すぐcollectorを作らず、将来の監査自動化で確認できる範囲をadopterへ伝えることである。

作業:

1. Fine-grained PAT APIで得られるrequest／grant／repository／permission／expiry／last-useを整理する。
2. Installed GitHub Apps API／UIで得られるinstallation、permission、repository selectionを整理する。
3. Organization／Enterprise audit logのevent、plan、retention、API制約を整理する。
4. OAuth App、SAML／SCIM、IdP、IDE／keychain、SSH hardware bindingの別証跡を整理する。
5. Future collectorのidentity、permission、API version、pagination、freshness、sanitization、result stateを定義する。
6. Collectorをadoption prerequisiteにしないことを明記する。

成果物:

- `docs/read-only-audit-options.md`。
- READMEからの短い導線。

完了条件:

- `APIで確認可能`、`別sourceが必要`、`確認不能`を区別している。
- `PASS`、`FAIL`、`NOT_CHECKED`、`ERROR`の意味がある。
- Provider mutationまたはcredential revoke APIを実装計画へ混在させていない。

### Phase 4: 既存reference implementationの再位置付け

目的は、既存の実行可能な価値を維持しながら、自己申告JSONを主実装に見せないことである。

作業:

1. `secure/*.json`がreal credentialやorganization evidenceを含まないことを確認する。
2. `insecure/*.json`を明確な危険例として隔離する。
3. Verifierのdocstring、output、README説明をreference／fixture評価として統一する。
4. `0=accepted`、`1=finding`、`2=error`を維持する。
5. Secure、insecure、malformed、sensitive-value testを維持する。
6. External-evidence checkをfixture `PASS`へ変換する判定を追加しない。

成果物:

- 必要な場合のみ更新されたfixture、verifier、expected result、test。

完了条件:

- Existing regression testが通る。
- Outputを読んでlive organization assessmentと誤解しない。
- 新しい形式的schemaやno-op testがない。

### Phase 5: Metadata同期

目的は、human guidanceとmachine-readable checkの境界を一致させることである。

作業:

1. `verification.expected`をreference testとlive verificationに分けて記述する。
2. 各checkのverification type、method、expected、evidenceを実装仕様と照合する。
3. `SCL-001..017`のcontextと`applies_to`を維持する。
4. Guidance-first化だけを理由にcheck IDをrenumberしない。
5. Mappingのrationaleと`applies_to`をreviewし、compliance claimを追加しない。
6. Limitationsへplan、API、live evidence、fixture境界を反映する。

成果物:

- 更新された`control.yaml`。

完了条件:

- External evidenceが架空のfileを要求しない。
- Fixture successからorganization adoptionを推論するcheckがない。
- `make validate-controls`が成功する。

### Phase 6: Verificationと生成物

実行:

```bash
bash controls/source-protection/source-access-credential-lifecycle/tests/test.sh
make verify-control CONTROL=PSB-SOURCE-004
make validate-controls
make generate-index
make generate-mappings
```

Checklistに影響するmetadataを変更した場合は、repositoryのcanonical checklist生成targetも実行する。

Review対象:

- `PSB-SOURCE-004`由来のindex、mapping、checklist差分。
- Expected resultの意図した差分。
- Secret、個人情報、private organization／repository情報の混入。
- Unrelated generated差分または既存worktree変更との混在。

完了条件:

- Control-local test、canonical verification、validationが成功する。
- Generator実行後にstale outputがない。
- Scanner／generator failureをclean扱いしていない。

## 5. Check実装分類

| Check | 主実装 | Repository verification | Live completion evidence |
|---|---|---|---|
| `SCL-001` | GitHub App／workload identity運用 | Policy fixture | Automation inventory、App grant |
| `SCL-002..005` | PAT organization policy | Policy fixture | Current PAT policy／grant review |
| `SCL-006` | Keychain／secret manager運用 | Sampleの平文禁止 | Endpoint storage確認 |
| `SCL-007` | IdP／GitHub authentication setting | なし | Current 2FA／SSO policy |
| `SCL-008` | Hardware-backed SSH運用 | なし | Key type／enrollment review |
| `SCL-009` | Quarterly inventory review | Metadata shapeのみ | Dated complete review |
| `SCL-010` | Event-driven revocation | Error contractのみ | Revocation drill |
| `SCL-011` | Audit retention／monitoring | なし | Current audit coverage／sample event |
| `SCL-012` | `PSB-GOV-002` exception | Control reference | Current exception decision |
| `SCL-013..017` | OAuth-first MCP profileとcontrol composition | MCP sample verifier | OAuth／IDE／runtime live evidence |

この表の「なし」は欠陥ではない。意味のあるlocal verificationがなく、live authorityが必要なことを示す。

## 6. 実装順序と依存関係

```text
Phase 0 boundary
      ↓
Phase 1 README ──────┐
      ↓              │
Phase 2 runbook      │
      ↓              │
Phase 3 audit guide  │
      ↓              │
Phase 4 fixtures     │
      ↓              │
Phase 5 metadata ◀───┘
      ↓
Phase 6 verify/generate
```

Phase 3はcollector実装をblockしない。Phase 4は既存挙動の変更が不要ならdocumentation境界の更新だけで
完了できる。Phase 5のmetadata変更前にrunbookのverification contractを確定する。

## 7. Review gates

### Gate A: Security design review

- Control essenceと他controlとの分担が明確。
- Provider設定変更によるlockout／revocation impactが扱われている。
- Classic PAT、broad scope、long-lived user tokenがsecure pathにない。

### Gate B: Adoption review

- 最短手順がGitHub provider名、setting、値、owner、順序、成功状態を持つ。
- Developerが追加frameworkを導入しなくても開始できる。
- Rollbackがorganization security policyを黙って弱めない。

### Gate C: Evidence review

- Live evidenceとsynthetic fixtureが分離されている。
- Credential値、private key、authorization header、不要な個人情報を保存しない。
- `NOT_CHECKED`と`ERROR`がclean resultにならない。

### Gate D: Repository review

- Testsとvalidationが成功する。
- Mappingはsupporting relationshipで、formal complianceを主張しない。
- Generated差分が意図したcontrol変更だけである。

## 8. Riskと対処

| Risk | 対処 |
|---|---|
| 2FA／OAuth restrictionでuserやAppをlockoutする | Pre-change inventory、通知、change window、recovery owner |
| RunbookのUI名が陳腐化する | Official source、review date、semantic setting名を併記 |
| Fixture `PASS`が導入済みと誤読される | README、output、metadataでreferenceと明記 |
| Audit APIがplanや権限で使えない | Manual reviewを基本経路とし`NOT_CHECKED`を許容 |
| Collectorがcredentialを漏らす | 今回は実装せず、将来もfield allow-listとsecret-free outputを要求 |
| Credential失効試験がproductionを止める | 専用test identity／repositoryだけを使用 |
| 他controlとrotation／MCP policyが重複する | Exact owning controlへcompositionする |

## 9. Rollback方針

- Documentation変更は通常のpull request revertで戻せる。
- Adopterのprovider settingは一括自動rollbackしない。変更前state、影響対象、security reviewerを
  確認し、runbookの設定単位で戻す。
- Rollbackでclassic PAT、unrestricted OAuth App、broad App installationを黙って再許可しない。
- Emergency accessが必要な場合は`PSB-GOV-002`のnarrow、owned、expiring exceptionを使う。
- Credential migration失敗時もold credentialを無期限に残さず、期限とconsumer ownerを記録する。

## 10. Deferred work

次は本計画の完了条件に含めない。

- GitHub read-only collectorの実装。
- GitLab／Bitbucket／GitHub Enterprise Server adapter。
- IdP／SCIM、MDM、secret manager、SIEMとのlive integration。
- Production credentialの自動revocation／rotation。
- IDE process inheritanceの自動証明。

Read-only collectorは、対象plan、必要field、最小権限identity、retention、consumerが具体化した場合だけ
別計画で開始する。

## 11. Definition of done

- 実装仕様書のSR-1..8がREADME／runbook／metadataへ反映されている。
- GitHub最小導入が具体的で、role、setting、value、sequence、success stateを持つ。
- Expected allow、ungranted-permission denial、scope denial、revocation denialのmanual procedureがある。
- 自動検証できない範囲と必要なlive evidenceが明確である。
- Read-only audit optionの可能性と限界が紹介され、collectorが必須化されていない。
- Existing verifierはreference regression testとして安全／危険／errorを区別する。
- Real secret、production data、架空のadoption evidenceがない。
- `make verify-control CONTROL=PSB-SOURCE-004`と`make validate-controls`が成功する。
- 影響するgenerated viewが再生成され、差分がreviewされる。
