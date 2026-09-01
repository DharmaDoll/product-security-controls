# PSB-DEPS-005 implementation instructions

この file は `PSB-DEPS-005`（`dependency-security`）固有の実装境界を定める。
repository root と `controls/AGENTS.md` の共通規約を先に読み、ここへ複製しない。

## Control essence

- この control の本質は、外部から取得した AI model と dataset を一度も load／import／deserialize せず、
  exact bytes、由来、許可、非実行形式、inspection、signer、ML-BOM、staging handoff が同じ bundle を
  指すことを検証してから隔離領域の外へ渡すことにある。
- Security 効果は、実際の model acquisition path が検証前の bundle を quarantine に置き、`0` 以外では
  loader、training、evaluation、serving を開始せず、consumer が exact digest を再照合することから生まれる。
  `secure/`、fixture、README、verifier を copy しただけでは live admission は有効にならない。
- Hash 一致だけで安全としない。Unsafe serialization、remote code、unapproved loader、dataset authorization、
  signed inspection、signer lifecycle、handoff を独立した判断として維持する。
- `ACCEPTED_FOR_STAGING` は staging 評価候補であり、production release 許可、model quality、privacy、
  bias、robustness、semantic poisoning／backdoor 不存在を意味しない。
- この package を model registry、general malware scanner、training pipeline、AI TEVV platform、
  RAG security engine、または production model server にしない。

## 固有前提を変更前に確認する

現在の provider-neutral reference profile には、実装を進めるための前提が揃っている。

- Control ID は `PSB-DEPS-005`、domain は `dependency-security` である。
- Consumer-owned policy と trust root、trusted UTC time、current signer-status source が、model bundle の
  publisher から独立している。
- Model と dataset は exact HTTPS source、full immutable revision、取得後に再計算した SHA-256 で識別できる。
- 検証は credential と network を限定した quarantine で、model／loader code の実行前に行われる。
- Accepted weight profile は Safetensors、inventory profile は CycloneDX 1.7 ML-BOM である。
- Dataset owner が license、approved use、personal-data classification の live evidence を供給する。
- Staging consumer が free-standing な `ACCEPTED` 文字列ではなく、artifact、dataset、ML-BOM、loader の
  exact identity を再照合できる。

Provider adapter、新しい serialization／dtype、別 ML-BOM version、production signer、live scanner を追加する
場合は、実装前に次を確認する。

1. Official specification または API version と immutable source／revision semantics。
2. Artifact size、header、tensor count、dimension、dtype、resource consumption の明示的な上限。
3. Registry、dataset、policy、signer、quarantine、staging consumer の owner と authority boundary。
4. Signer status の完全性、freshness、revocation、scope と trusted clock の取得方法。
5. Dataset license／use／privacy の承認者と、content を複製しない evidence source。
6. Harmless positive／negative test と、provider／tool failure を再現できる fail-closed test。
7. Exact digest-bound handoff を loader より前に enforcement する場所。

これらが不足する場合は provider 名や安全性を推測して実装しない。不足情報と必要な adopter-owned
evidence を README に明記し、既存の provider-neutral contract を維持する。

## Supported reference profile

- Reference verifier は Python 3.10+ standard library と OpenSSL を使う single-purpose implementation とする。
  新しい framework、package manager、dynamic plugin system を追加しない。
- Primary developer environment は macOS／VS Code とし、basic self-test に Docker、sudo、global setting 変更を
  要求しない。Windows は concrete adopter requirement と test が揃ってから追加する。
- Repository test は network-free、credential-free で、synthetic Safetensors と synthetic dataset だけを使う。
  Base64 は fixture transport であり、production model transport の推奨ではない。
- `scripts/verify.py` は quarantine に取得済みの local inputs だけを判定する。Registry download、upload、
  model load、provider-specific authentication を組み込まず、必要な live adapter は別の single-purpose
  acquisition component として扱う。
- Current parser は Safetensors 0.8.0 全体ではなく、policy が許可する bounded structural profile を検証する。
  対応していない dtype や format を黙って許可しない。
- ML-BOM verifier は CycloneDX 1.7 の control-specific subset を検証する。Official schema validator や
  software release SBOM lifecycle の代替と主張しない。
- Production では Python／OpenSSL／scanner／registry client を approved version または artifact digest へ固定し、
  update 時に同じ negative corpus を再実行する。Repository fixture の system OpenSSL 利用を production trust
  model としてコピーしない。

## Trust boundary and data flow

次の区分を変更しない。

- Trusted consumer inputs: `secure/policy.json` を基にした reviewed policy、policy-pinned public key、完全で
  current な signer status、trusted UTC clock、reviewed verifier bytes、approved crypto runtime。
- Untrusted bundle inputs: acquisition manifest、model bytes、dataset bytes、ML-BOM、intake attestation、
  detached signature、deployment handoff。Signed object も検証が完了するまでは untrusted である。
- Verification は raw bytes を直接扱い、model framework、model repository、custom loader、pickle、PyTorch
  artifact を import／execute しない。Negative fixture に実 pickle、malware、executable payload を追加しない。
- Bundle publisher が policy、public key、signer status、evaluation time、verifier path を同じ request から
  上書きできる interface を作らない。
- Output は check ID、decision、必要最小限の identity metadata に限る。Weight bytes、tensor value、dataset row、
  signature、key body、credential-bearing URL、raw provider response を出力しない。

## Implementation and decision semantics

この control は guidance-first ではなく、小さな executable reference と live integration guidance の
組合せを採用する。Repository verifier が実際に検証できる identity、format、structure、signature binding、
handoff は自動検証し、dataset consent、live registry、HSM、scanner coverage、production enforcement は
organization-owned evidence として分離する。

- Exit `0`: 全 check を評価でき、exact bundle が `ACCEPTED_FOR_STAGING`。Production release は許可しない。
- Exit `1`: Untrusted bundle の mutable identity、不一致、unsafe format、finding、revoked／out-of-scope signer、
  handoff 違反を `QUARANTINE`。
- Exit `2`: Trusted policy、signer status、clock、public key、crypto verifier、予期しない verifier failure を
  `ERROR`。Finding zero や accepted に変換しない。
- Missing／malformed untrusted bundle は該当 check の quarantine、missing／malformed trusted input または
  verification infrastructure は error として区別する。
- `--as-of` は deterministic fixture 専用である。Production で bundle publisher や caller が評価時刻を
  選べるようにせず、trusted UTC clock を使う。
- Local exception field、broad allowlist、`skip_validation`、fail-open fallback を追加しない。必要な例外は
  `PSB-GOV-002` の exact control／check／target に bind された current decision を別 record として扱い、
  underlying finding を `PASS` に書き換えない。

## Atomic checks

`control.yaml` が canonical source である。既存 ID を不要に renumber しない。

- `AMS-001`: immutable model source と exact artifact bytes。
- `AMS-002`: application → model → dataset／loader の exact CycloneDX ML-BOM graph。
- `AMS-003`: Safetensors-only、remote code deny、pinned loader。
- `AMS-004`: model を実行しない bounded Safetensors structural inspection。
- `AMS-005`: exact materials、inspector digest、signature、current scoped signer。
- `AMS-006`: exact dataset provenance、license、use authorization、personal-data declaration。
- `AMS-007`: accepted exact bundle だけを staging へ渡す handoff。
- `AMS-008`: trusted verification dependency failure の `ERROR`。
- `AMS-009`: metadata-only evidence と protected content の非複製。

新しい check は、この control 固有の独立した assessable state で、既存 check や他 control が所有しない場合
だけ追加する。追加・変更時は `applies_to`、`responsible_role`、row 固有の threat actor、scenario、
`why_required`、verification、evidence、mapping を一緒に review する。

## Relationship to other controls

- `PSB-DEPS-003` は Safetensors loader package、lockfile、origin、download artifact integrity を所有する。
  この package に general dependency resolver／lockfile verifier を複製しない。
- `PSB-REL-003` は software release の source／build／deployment SBOM lifecycle を所有する。本 control は
  model／dataset／loader semantics を持つ intake ML-BOM と exact handoff だけを所有する。
- `PSB-REL-004` は supplier software SBOM の署名、signer lifecycle、portfolio quarantine を所有する。
  本 control は pre-execution model bytes と AI dependency bundle を扱う。
- `PSB-AI-011` は RAG corpus source authorization、tenant／classification scope、retrieval provenance、
  revocation／deletion、poisoning fixture を所有する。
- `PSB-DETECT-002` は AI TEVV、adversarial evaluation、threshold、release decision を所有する。
- Runtime sandbox、serving egress、application data policy、model behavior monitoring は各 owning control へ
  composition し、この package に取り込まない。
- `PSB-GOV-002` は security exception lifecycle を所有する。独自 exception format を作らない。

## Roles and live enforcement

- Model／data owner: 採用する exact model／dataset、license、approved use、personal-data classification を承認する。
- Platform／build owner: 隔離取得、raw-byte digest、ML-BOM 作成、pre-load gate、network／credential boundary を実装する。
- Security: Consumer policy、inspection profile、trust root、signer scope／status／freshness、exception を review する。
- Release manager: `ACCEPTED_FOR_STAGING` と exact handoff を照合し、production release 判断を
  `PSB-DETECT-002` 等の後続 gate へ渡す。
- Staging consumer: Status 文字列だけを信用せず、model、dataset、ML-BOM、loader digest を load 前に再照合する。

## Minimal adoption path

README を変更するときは mandatory one-page summary の直後に、fixture 解説より先に次の最短経路を置く。

1. Model／dataset owner、approved immutable sources、dataset authorization owner、signer-status owner、
   quarantine owner、staging consumer を決める。
2. `scripts/verify.py` と reviewed policy template を repository-owned path へ copy／reference する。Test public key、
   synthetic identity、`.invalid` URL は production trust root として使わず、既存 adopter config を上書きしない。
3. Quarantine へ exact revision を取得し、model を load する前に raw bytes の digest を計算する。
4. Organization-owned policy、public trust key、current signer status、dataset authorization、ML-BOM、signed
   inspection、handoff を用意し、verifier を pre-load gate として明示的に wiring する。
5. Secure synthetic bundle、inert unsafe bundle、stale／unavailable signer status、missing OpenSSL を self-test し、
   exit `0`／`1`／`2` と expected output を確認する。
6. CI／server-side gate は `0` 以外で停止させ、staging consumer が exact digests を再照合する。Local test の
   成功だけを enforcement にしない。
7. Recovery は policy、evidence、clock、crypto runtime、registry adapter を修復して再実行する。Format や
   trust requirement を緩めない。
8. Rollback は copy／reference した repository-local integration だけを review の上で外す。Quarantine、
   registry protection、dataset governance、production admission を自動で弱めない。

## Verification and fixture rules

- Test は人間が security boundary を読める最小構成にする。Safe bundle、valid signature を保持した unsafe
  bundle、artifact／attestation tampering、malformed untrusted input、sensitive evidence、stale／unavailable
  signer status、missing crypto verifier を維持する。
- Safe fixture の成功、known finding、verification error を別 test と expected result にする。低価値な全組合せ、
  README 文字列 test、手書き `secure: true`、no-op、schema-only test を追加しない。
- Real model、proprietary weights、production dataset、personal data、provider-valid credential、private key、
  malware、実行可能 pickle を repository や test output に追加しない。
- `scripts/verify.py` の bytes は policy と signed attestation の `inspector_sha256` に結ばれている。Script を
  変更する場合は、digest、secure／insecure attestation、policy、fixture signature、expected results を一つの
  review 単位として扱う。Test-only signing key は repository 外の一時領域で生成・使用し、private key を
  commit、log、evidence に残さない。安全な再署名手順を実行できなければ script を変更しない。
- Insecure fixture は policy finding を示しつつ valid signature を保持する。Invalid signature だけで他の
  negative check が隠れないようにする。
- 新しい format／dtype を許可する前に、official pinned specification、bounded parser、resource limits、safe
  fixture、malformed／overlap／truncation test を追加する。Convenience のために unknown input を許可しない。

## Live verification and evidence

- Fixture `PASS` は reference implementation の regression evidence であり、live registry、quarantine、HSM、
  scanner、dataset consent／privacy、staging admission、organization adoption の evidence ではない。
- Live automation を追加する場合は read-only または admission-only、explicit API／provider version、stable
  target identity、complete result、UTC acquisition time、least-privilege credential、secret-free normalized output を
  必須にする。Partial response、permission failure、timeout、schema drift は `ERROR` にする。
- Durable evidence は current provider setting、actual acquisition digest、real inspection job result、current signer
  status、dataset-owner authorization reference、actual staging rejection／admission のように、source、time、target、
  authority boundary が明確な record に限る。Synthetic adoption evidence を作らない。
- Safe read-only API がなければ、exact UI／runbook step、期待値、担当者、確認時刻、必要 evidence を manual
  verification として正式に記述する。自己申告 JSON を検査するだけの adapter を主実装にしない。

## Metadata and documentation

- README、`control.yaml`、policy schema、verifier、fixtures、expected results の identity と decision wording を
  同期する。Supported でない provider、format、dtype、scanner、production gate を実装済みと書かない。
- `check_context_version: "1.0"` と各 check 固有の context を維持する。
- Framework mapping は exact version と check-specific rationale を持つ reviewed relationship であり、AI system、
  CycloneDX、AISVS、SSDF、MITRE ATLAS への compliance や complete coverage の主張ではない。
- この directory 内の変更を基本とする。Shared schema、generator、index の変更が必要なら、先に理由と影響範囲を
  説明し、対象 control に必要な最小差分だけを行う。

## Required verification after changes

Control package から実行する。

```bash
bash tests/test.sh
```

Repository root からも実行する。

```bash
make verify-control CONTROL=PSB-DEPS-005
make validate-controls
```

`control.yaml` の check、mapping、status、implementation path を変更した場合だけ canonical generator を実行し、
`PSB-DEPS-005` に由来する index、mapping、checklist 差分だけを review する。Test を通すために non-executing
inspection、exact identity、signature binding、quarantine、fail-closed behavior を弱めない。
