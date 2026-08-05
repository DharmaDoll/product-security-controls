# Product Security Engineering Blueprint

プロダクト／アプリケーションのセキュリティを高めるための、実行可能なリファレンス実装集です。

このリポジトリは、GitHub設定集やTrivy検証リポジトリだけを目的としません。設計、実装、依存関係、CI/CD、ビルド、コンテナ、クラウド、リリース、AI開発、脆弱性管理までを含むProduct Securityの具体策を、動作するサンプルとして整理します。

## 目標

利用者がREADMEと各control packageを見るだけで、次を素早く把握できることを目指します。

- 何のリスクを下げるのか
- 危険な実装は何か
- 安全な実装は何か
- どう導入するか
- どう検証するか
- どこまで有効か
- どのフレームワーク項目と関係するか

## Product Security domains

| Domain | Examples |
|---|---|
| Secure Design | Threat modeling, trust boundaries, abuse cases |
| Secure Coding | Authentication, authorization, injection, secrets, crypto |
| Source Protection | CODEOWNERS, rulesets, signed commits, protected tags, public-content exposure, developer endpoint hardening |
| Dependency Security | Lockfiles, hashes, cooldown, dependency review |
| CI/CD Security | Action SHA pinning, minimal permissions, OIDC, fork safety |
| Build Security | Isolated builds, reproducibility, provenance |
| Container / Cloud / IaC | Trivy, digest pinning, non-root, IAM, policy-as-code |
| Release Integrity | SBOM, signing, attestation, checksum verification |
| AI Development Security | AGENTS.md, CodeGuard, Skills, MCP, prompt injection |
| Detection / Verification | Trivy, SAST, secret scan, OSV, Scorecard |
| Governance / Operations | Exceptions, metrics, ownership, vulnerability response |

## Control package

```text
controls/<domain>/<control>/
├── README.md
├── control.yaml
├── insecure/
├── secure/
├── tests/
├── expected-results/
└── scripts/
```

各controlの`README.md`は、最初に`このcontrolを一枚で理解する`表を置きます。
表にはセキュリティ上の問題、誰または何から守るか、対象、実施内容、成功状態、
対象外・残余リスクを記載します。詳細な実装・検証説明と、`control.yaml`から生成する
行単位チェックリストの両方を維持します。

## Control catalog

実装済みcontrolは、ドメイン別の
[`controls/README.md`](controls/README.md)から探せます。各controlへ直接移動でき、
security function、atomic check数、成熟度、証跡レベルも一覧できます。

担当、確認方法、証跡、framework mappingを含む行単位の導入判断には、後述する
生成チェックリストを使用してください。

Software supply-chain controlの関係は
[`docs/SUPPLY_CHAIN_PRINCIPLES.md`](docs/SUPPLY_CHAIN_PRINCIPLES.md)を参照してください。
今後実装するcontrolのgoal、既存controlとの境界、実装slice、依存関係、完了条件は
[`docs/PLANNED_CONTROLS.md`](docs/PLANNED_CONTROLS.md)に整理しています。
frameworkではないcheat sheet、vendor hardening guide、ユーザー提供原文などの
設計上の参考情報は、固定source commitまたは保存済み原文、確認日、関連control、
採用範囲とともに
[`docs/SECURITY_GUIDANCE_SOURCES.md`](docs/SECURITY_GUIDANCE_SOURCES.md)へ
記録します。

## Adoption checklist

全controlの原子的な確認項目、想定する脅威主体、行固有の攻撃・失敗scenario、
その確認が必要な理由、担当、対象、確認方法、必要な証跡、行単位のframework
mappingをCSV、Markdown、Excelへ生成します。各行は親READMEを開かなくても、
「誰または何から、何を、なぜ守るか」を判断できる構成です。

```bash
make generate
```

index、framework reverse mapping、checklistをまとめて最新化します。
checklistだけを更新する場合は`make generate-checklists`を使用できます。
生成物は`generated/checklists/`に保存されます。`control.yaml`が正本であり、
生成されたspreadsheetは直接編集しません。組織固有の担当、判定、証跡URL、
期限、例外IDは`product-security-assessment-template.xlsx`へ記録します。
例外そのものの共通field、期限判定、fail-closedな台帳検証は
[`PSB-GOV-002`](controls/governance-operations/time-bound-security-exceptions/README.md)
と[`policies/exceptions/README.md`](policies/exceptions/README.md)を参照してください。

SLSA Build Level 2を目標にする場合は
`profiles/slsa-build-l2.csv`でL1とL2に直接対応する確認項目だけを確認できます。
`profiles/slsa-build-l2-coverage.csv`には未マッピング要件も`gap`として残るため、
対象行があることをLevel 2達成と解釈しません。Excel版では
`SLSA Build L2`と`SLSA L2 Coverage`シートをフィルタできます。

特定のproducer、build platform、consumer、release、source revisionについて、
7つの累積要件を組織所有の証跡で判定する場合:

```bash
make assess-slsa-build-l2 EVIDENCE=/absolute/path/to/live-evidence.json
```

入力契約、11種類の必要証跡、担当分離、判定の意味は
[`docs/SLSA_BUILD_L2_ASSESSMENT.md`](docs/SLSA_BUILD_L2_ASSESSMENT.md)を
参照してください。これは新しいcontrolではなく、既存controlsの証跡を束ねる
assessmentです。マッピング完了とスコープ付きassessmentのPASSは別の状態です。
5担当のdigest固定済みbundleから入力JSONの組立ても行う場合は、次の一段実行を
使用できます。

```bash
make assess-slsa-build-l2-bundles \
  ADAPTER_POLICY=/absolute/path/to/reviewed-adapter-policy.json
```

GitHub Actionsの署名済みprovenanceから`build-platform` bundleを収集する場合:

```bash
make collect-github-actions-build-platform \
  COLLECTOR_POLICY=/absolute/path/to/github-collector-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/build-platform.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/build-record.json \
  GH_CLI=/absolute/path/to/pinned/gh
```

GitHub Releasesからproducer publicationまたは独立storage probeを収集する場合:

```bash
make collect-github-releases-evidence \
  COLLECTOR_POLICY=/absolute/path/to/github-releases-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/issuer-role.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/release-receipt.json \
  GH_CLI=/absolute/path/to/pinned/gh
```

consumer側の`PSB-REL-001`検証証跡を収集する場合:

```bash
make collect-slsa-consumer-evidence \
  COLLECTOR_POLICY=/absolute/path/to/consumer-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/consumer.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/consumer-verification.json \
  OPENSSL=/absolute/path/to/pinned/openssl
```

独立したplatform capability／signer ownership reviewを収集する場合:

```bash
make collect-slsa-security-review-evidence \
  COLLECTOR_POLICY=/absolute/path/to/security-review-policy.json \
  BUNDLE_OUTPUT=/absolute/path/to/bundles/security-review.json \
  RECEIPT_OUTPUT=/absolute/path/to/evidence/security-review.json \
  OPENSSL=/absolute/path/to/pinned/openssl
```

Linux開発端末上で読み取り専用assessmentを実行する場合:

```bash
make assess-control CONTROL=PSB-SOURCE-001
```

結果はGit管理対象外の`generated/assessments/`へJSONとCSVで保存されます。
`NOT_CHECKED`は外部証跡待ち、`ERROR`は検査不能であり、どちらもPASSでは
ありません。

## Framework mapping

Each control is mapped to applicable items from:

- MITRE ATT&CK
- OWASP Top 10
- OWASP ASVS
- SLSA
- NIST SSDF
- NIST SP 800-190 container implementation guidance
- MITRE ATLAS
- OWASP Top 10 for Agentic Applications 2026
- GitHub security guidance
- OpenSSF OSPS Baseline
- CISA Product Security Bad Practices

Mappings are relationships, not automatic claims of compliance.

## Important distinction

```text
MITRE ATT&CK   → what attackers do
OWASP Top 10   → major application risk categories
OWASP ASVS     → concrete application security verification requirements
SLSA           → source and build integrity requirements
NIST SSDF      → secure software development practices
NIST SP 800-190 → application-container countermeasure guidance
MITRE ATLAS    → adversary behavior targeting AI-enabled systems
OWASP Agentic Top 10 → major risk categories for autonomous and tool-using AI systems
OpenSSF OSPS   → open source project security requirements
CISA PSBP      → focused product security bad practices to avoid
This repository→ concrete implementation and verification examples
```

## First implementation candidates

Completed and planned controls are ordered in the
[`Prioritized control backlog`](docs/ROADMAP.md#prioritized-control-backlog).
That backlog is the source of truth for implementation priority; this README
does not maintain a second list.

## Codex usage

Start with:

```text
Read AGENTS.md and all documents under docs/.
Then execute .codex/prompts/00-bootstrap-repository.md.
Do not implement all controls at once.
Complete Phase 0 and Phase 1 only.
```
