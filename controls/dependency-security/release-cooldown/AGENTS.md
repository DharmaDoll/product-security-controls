# PSB-DEPS-001 implementation instructions

この file は `PSB-DEPS-001`（`dependency-security`）に固有の実装境界を定める。
repository root と `controls/AGENTS.md` を先に読み、共通規約をここへ複製しない。

## Control essence

- この control の本質は、公開直後の dependency version を通常の update から一定時間外し、
  maintainer／registry 侵害の発見、yank、advisory 公開のための観測時間を確保することにある。
- Reference baseline は公開から `168` 時間である。これは package の安全性を保証する時間ではなく、
  review 済みの運用 baseline である。
- 判定対象は dependency update で新たに選ばれる exact package／version と、その authority となる
  registry publish timestamp である。通常の frozen／locked install を毎回再解決させない。
- Security 効果は、実際の resolver／update job／CI gate が若い version を install-time code execution
  より前に拒否し、判定不能時にも停止することから生まれる。Fixture、policy JSON、README を copy
  しただけでは採用組織の dependency acquisition は変わらない。
- Managed registry proxy は、取得経路と metadata authority を固定して direct fallback による
  cooldown bypass を防ぐための supporting boundary である。Proxy の malware blocklist、tracking、
  notification を release age 判定の代替にしない。
- この control を general-purpose dependency scanner、package manager bootstrapper、artifact verifier、
  または endpoint management product にしない。

## Supported profile and assumptions

- Verifier は Python 3.10+ standard library の決定的な実装とし、新しいframeworkやserviceを追加しない。
- PrimaryはmacOS／VS Codeだが、repository-local config と CI 判定は
  platform-neutral に保つ。Windows は具体的な adopter requirement とテストが揃ってから追加する。
- 現在の native sample 対象は npm、pip、uv、pnpm、Yarn である。Go と Composer は native age gate
  があると仮定せず、repository-owned verifier の対象とする。
- Package manager の option 名、単位、default、設定 precedence、対応 version は変わり得る。
  Sample の追加・変更時は current official documentation、対象 major version、fail-closed behavior を
  確認する。Community catalog だけを仕様根拠にしない。
- Reference test は network を使わない synthetic metadata で行う。Production integration は approved
  registry または proxy から publish timestamp を取得する別 adapter／native resolver を必要とする。
- MDM、proxy、egress policy はadopter側のauthorityとし、このpackageから変更しない。

## 実装方式を選ぶ前の判断

変更前に、次を対象 ecosystem ごとに明示する。

1. Security state を変える実設定は native age gate、update workflow、CI required check、proxy route、
   egress deny のどれか。
2. Repository file の copy だけで enforcement が発生するか。発生しない場合は activation と live
   verification を別に示す。
3. 判定する publish timestamp の提供元、version identity、UTC 時刻、metadata 不在時の挙動は何か。
4. 自動化できる config／decision と、MDM 適用、public registry egress、proxy outage 等の live
   environment でしか確認できない状態は何か。
5. Synthetic fixture の `PASS` が organization adoption、live routing、または package の安全性と
   誤解されないか。
6. 既存 control の check を重複実装していないか。

新しい ecosystem／proxy provider を追加するために、公式仕様、対象 version、publish-time authority、
設定 precedence、harmless test 方法のいずれかが不足している場合は、推測した sample を追加しない。
README の unsupported／adopter-tuning 項目として不足情報を列挙する。

## Chosen implementation profile

この control は次の hybrid implementation を採用する。

1. 公式に利用できる場合は、repository-owned または centrally managed な native cooldown config を
   resolver に最も近い第一の guardrail とする。
2. Native behavior がない、ecosystem 間で判定を統一する、または policy floor を regression test
   する場合だけ、小さな repository-owned pre-install verifier を使う。
3. 利用できる組織では managed proxy と public-registry egress deny を適用し、別経路の resolver bypass を
   防ぐ。ProxyなしでもProfile 1／2はofficial registry metadataへ適用できる。
4. CI の dependency-update path で同じ `168` 時間 floor と exception decision を required check にする。
5. Normal install は committed lockfile の frozen／locked mode に保ち、update decision を通過した
   graph を再現する。

三profileを巨大なengineへ統合しない。Native gateもCI verifierも使えない場合だけ、7日のhuman holdと
protected reviewをoperational fallbackとし、機械的enforcementを主張しない。Fake infrastructureや
自己申告evidenceを作らない。

## Profile 2: repository-owned CI verifier

Package manager 非依存の release-age decision と ecosystem-specific metadata adapter を分離し、次を
baseline とする。

- `minimum_release_age_hours: 168` を repository policy と trusted CI configuration で固定する。
- Exact package／version、approved registry origin、publish timestamp、UTC evaluation time を入力とし、PR本文や
  contributor の自己申告 timestamp を信用しない。
- Timestamp は approved HTTPS registry／proxy の read-only API から得る。Missing version、partial response、
  timeout、rate limit、parse failure は `ERROR` にする。
- Dependency update／lockfile regeneration 時だけ、install scriptやbuild pluginより前に実行する。通常の
  frozen install を再resolveしない。
- `0=accepted`、`1=policy finding`、`2=input／metadata／tool error` とし、required check は`0`以外をblockする。
- Verifier、policy、adapter は trusted base／reviewed template から実行し、untrusted PR に floor、allowlist、
  exception、verifier code を同じ decision 内で変更させない。
- 認証が必要なら read-only short-lived credential を runtime injection し、fork PRへ渡さない。Adapter は
  normalized record を出す single-purpose component とし、dynamic pluginやpackage installを行わない。
- Bypass は `PSB-GOV-002` の exact package／version／check に bind された active decision だけとし、CI
  variable や broad allowlist で代用しない。

Blueprintではinput contract、standard-library verifier、3状態fixture、CI wiring、required-check runbookを
提供し、workflow securityは`PSB-CICD-*`へ委譲する。

## Profile 3: managed registry proxy

Proxy service は構築せず、provider-neutral な recommended state、client profile、rollout、live verification
contract を示す。

一般推奨設定は次のとおりである。

- Install endpoint は approved HTTPS proxy だけに固定し、credentialをURLやrepository fileへ埋め込まない。
- npmは単一`registry`、pipは単一`index-url`、Goは単一`GOPROXY`、Composerはcanonical repository＋
  Packagist disableとし、`extra-index-url`、`,direct`、`|direct`、public fallbackを拒否する。
- Developer endpoint、devcontainer、CI templateへ中央配布する。Sampleは明示copy／merge用とし、global設定を
  自動変更しない。Network policyでもpublic registryへのdirect egressをdenyする。
- Proxy／DNS／TLS／authentication／metadata failureは`ERROR`としfallbackしない。Owner、support path、
  復旧手順、availability expectationを事前に決める。
- Install／readとpublishを別endpoint・identity・approvalにし、install credentialへpublish権限を与えない。
  Secretはkeychain、approved secret store、short-lived runtime injectionで配送し、evidenceへ残さない。
- Providerのofficial minimum-ageについてversion、timestamp semantics、missing-metadata、exception scopeを確認
  できる場合だけ168時間を設定する。それ以外はProfile 2を併用する。
- Malware blocking、download tracking、breach notificationは推奨するがrelease-age decisionと分離する。
- Limited pilot、effective-config確認、CI、managed endpoint配布、egress deny、outage drillの順でrolloutし、
  一時的なfail-open pathを作らない。

Blueprintではcredential-free sample、copy手順、役割、provider checklist、live check、outage結果、rollbackを
提供する。実proxy、MDM、firewall、production credential、架空のevidenceは追加しない。

## Security decision semantics

- Release age は `evaluation_time_utc - published_at_utc` で計算し、`168` 時間以上だけを通常許可する。
- Package 名だけでなく exact version と registry origin を timestamp へ bind する。
- Filesystem mtime、Git commit time、lockfile commit time、cache age を publish timestamp の代用にしない。
- Timestamp の欠落、parse failure、unsupported format、registry／proxy failure、clock invalidityは
  `ERROR` とし、old enough または clean と推測しない。
- Test は固定 `--as-of` を使う。Live 判定は信頼できる UTC clock と freshness が分かる registry response
  を使い、取得時刻と source identity を sanitized evidence に残す。
- Native resolver が metadata missing 時に candidate を許可する、若い version へ fallback する、または
  CLI／environment／user-wide config で repository floor を下げられる場合、その状態を secure sample
  として扱わない。
- Persistent package allowlist、wildcard exclusion、package-wide bypass は禁止する。

## Roles and live enforcement

- Product owner: 待機による delivery impact と緊急 security update の優先度を決める。Baseline 短縮を
  自己承認しない。
- Developer: 通常 install では frozen lockfile を使い、dependency update は approved command／bot から
  実行する。既存 project config を上書きせず merge review する。
- Repository administrator: repository-local config、update workflow、required CI check、protected policy
  file を設定し、manifest／lockfile change と cooldown decision を同じ review へ結ぶ。
- Platform／SRE: managed proxy、publish-time metadata access、CI template、trusted UTC、public registry
  egress deny を構築し、proxy outage を direct fallback にしない。
- Security: `168` 時間 baseline、exception、effective client config、live routing、bypass path、evidence
  freshness を独立 review する。

README は fixture 説明より前に、この役割分担と「file copy だけでは live enforcement にならない」ことを
明記する。

## Minimal adoption path

READMEは案1を最小導入、案2を共通CI gate、案3を組織横断のbypass防止として独立提示し、三案すべてを
必須にしない。各profileは一つのsupported ecosystemで完結する最短経路から始める。

1. Package manager と supported major version、approved registry／proxy URL、publish timestamp source、CI owner を
   prerequisites として確認する。
2. 対象ecosystemのfileだけをcopyする。Profile 3では`example.invalid`をapproved proxyへ置換する。
   既存fileは上書きせずmerge reviewする。
3. Repository-local setting で `168` 時間 floor を有効化する。Global shell、Git、IDE、package-manager、
   OS config を暗黙に変更しない。
4. Dependency update command／bot に cooldown 判定を組み込み、package install script または build plugin
   が実行される前に `FAIL`／`ERROR` で停止させる。
5. 同じ判定を CI required check にし、通常 install は frozen／locked mode にする。
6. Offline self-test で old-enough positive、fresh-version negative、metadata unavailable error を確認する。
7. Live environmentでeffective settingを確認し、Profile 3ではproxy-only route、fallback denial、outageを
   read-onlyまたはharmless canaryで確認する。

Expected status は `0=accepted`、`1=security finding`、`2=input／metadata／tool error` とする。Recovery は
時計、metadata authority、proxy、設定 precedence を直して再実行することであり、floor を下げたり direct
fallback を追加したりしない。Rollback はこの導入で copy／参照した repository-local config と CI wiring
だけを review の上で外し、organization proxy や egress control を弱めない。

## Exception boundary

- Urgent known-vulnerability fix では待機自体が risk になるため、cooldown decision に限った例外を許可する。
- Exact package、exact version、control／check target、owner、具体的理由、別 approver、created time、expiry、
  compensating review を必須にする。Reference maximum は `72` 時間である。
- 例外は release age だけを迂回し、approved registry、proxy route、artifact integrity、install execution、
  vulnerability review を迂回しない。
- Existing local exception JSON を新しい横断 schema として拡張しない。New integration は
  `PSB-GOV-002` の `psb-security-exception/v1` decision を消費し、期限切れ・invalid・unavailable register
  を `ERROR` または拒否にする。
- Exception が適用されても underlying cooldown check を `PASS` に書き換えない。Applied exception として
  decision evidence を分離する。

## Relationship to other controls

- `PSB-DEPS-002` は lifecycle script、native build、source build の default deny を所有する。この package
  に install-execution allowlist を追加しない。
- `PSB-DEPS-003` は manifest／frozen lockfile graph、exact version、origin record、artifact digest の一致を
  所有する。この package の integrity fixture は cooldown decision の input binding を示す補助に留め、
  general lockfile／artifact verifier を拡張しない。
- `PSB-DEPS-004` は dependency delta の vulnerability、license、source、provenance、non-author review を
  所有する。Cooldown 経過を risk review または package safety の代替にしない。
- `PSB-DETECT-001` は repository／artifact vulnerability scanning を所有する。公開後 `168` 時間に
  finding がないことを vulnerability-free と主張しない。
- `PSB-SOURCE-001` は endpoint baseline と host authority を所有する。本 control は dependency resolver
  の config と decision semantics だけを所有し、MDM／EDR implementation を複製しない。
- `PSB-GOV-002` は shared security exception lifecycle を所有する。独自の永続 exception register を
  作らない。
- CI workflow の Action pin、permissions、untrusted PR boundary は `PSB-CICD-*` control を composition
  し、この package で再実装しない。

## Verification strategy

- Test は人間が境界を読める最小構成にする。最低限、次を明示的に確認する。
  - `168` 時間以上の exact version は accepted。
  - `168` 時間未満と boundary 直前の version は rejected。
  - Exact かつ有効な緊急例外だけが age check を迂回する。
  - Floor 短縮、persistent exclusion、direct fallback は rejected。
  - Missing／malformed timestamp、unreadable input、proxy／parser failure は exit `2`。
- Native config parser を変更した場合は、safe config、inert unsafe config、malformed config、設定
  precedence による weakening を対象 version ごとに確認する。低価値な組合せ網羅は追加しない。
- External network、real package install、install script、real malware、provider-valid credential を repository
  test で使わない。Proxy block path は provider が公開する harmless canary がある場合だけ live 手順にする。
- Verifier output は package identifier、version、age、check result など必要最小限にし、credential-bearing
  URL、authorization header、private package 名、raw provider response を残さない。
- Secure fixture の成功は reference behavior の regression evidence であり、MDM 適用、live proxy route、
  public egress denial、organization adoption の evidence ではない。
- README の文字列、手書き `secure: true`、synthetic `PASS` だけを検査する test、no-op test は追加しない。

## Live verification and evidence

- Organization adoption は、対象 repository／update job での effective cooldown setting、CI required check、
  managed proxy route、public registry denial、proxy outage failure、current exception inventory を確認して
  初めて判断する。
- Live check を自動化する場合は read-only、explicit provider／API version、complete pagination、field
  allow-list、UTC acquisition time、stable target identity、secret-free output を必須にする。
- Provider setting が取得不能なら `NOT_CHECKED`、collector／permission／provider failure なら `ERROR` とし、
  fixture から `PASS` を補完しない。
- Durable evidence は current provider setting、effective client config、actual CI rejection、harmless canary
  rejection、または収集元・取得時刻・対象・authority が明確な sanitized record に限る。架空の adoption
  evidence を repository に追加しない。

## Metadata and documentation

- `control.yaml` が atomic check の canonical source である。`check_context_version: "1.0"` と各 row 固有の
  threat actor、scenario、target、why required を保持する。
- `COOL-001..010` を不要に renumber しない。新しい check は cooldown 固有の独立した assessable state
  が既存 check／control にない場合だけ追加する。
- README の mandatory one-page summary 直後に prerequisites、copy 対象、activation、positive／negative
  self-test、expected exit、recovery、server-side enforcement、rollback、residual risk を置く。
- `control.yaml` の implementation path と README の supported profile を同期する。Unsupported ecosystem を
  実装済みのように列挙しない。
- Framework mapping は check-specific な reviewed relationship であり、compliance、complete supply-chain
  coverage、または package safety の主張ではない。

## Required verification after changes

Repository root から少なくとも次を実行する。

```bash
bash controls/dependency-security/release-cooldown/tests/test.sh
make verify-control CONTROL=PSB-DEPS-001
make validate-controls
```

`control.yaml` の check、mapping、status、implementation path を変更した場合は canonical generator を実行し、
`PSB-DEPS-001` に由来する index、mapping、checklist 差分だけを review する。Test を通すために cooldown
floor、fail-closed behavior、proxy-only boundary を弱めない。
