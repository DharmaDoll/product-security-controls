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

## Implemented controls

| Control | Outcome | Evidence |
|---|---|---|
| `PSB-CICD-001` | External GitHub Actions and reusable workflows use immutable references | E3 |
| `PSB-CICD-002` | GitHub Actions expressions do not generate runner shell source | E3 |
| `PSB-CICD-003` | pinned zizmorでworkflowをblock判定し、trusted branchのSARIFを記録 | E3 |
| `PSB-DEPS-001` | 依存パッケージの公開直後採用を7日間のcooldownで制御 | E3 |
| `PSB-DEPS-002` | install時のdependency code executionをdefault denyに制御 | E3 |
| `PSB-DEPS-003` | frozen lockfileとartifact integrityを検証 | E3 |
| `PSB-REL-001` | release署名とSLSA provenanceをconsumer expectationへ照合 | E3 |
| `PSB-BUILD-001` | untrusted buildをcredential・deploy権限・broad egressから隔離 | E3 |
| `PSB-BUILD-002` | 一貫したrelease buildを承認済みhosted platformへ限定 | E3 |
| `PSB-BUILD-003` | platformがauthentic SLSA provenanceを自動生成 | E3 |
| `PSB-GOV-001` | SBOMからsupply-chain incidentの影響範囲とdry-run対応planを生成 | E3 |
| `PSB-SOURCE-001` | Developer endpoint policy protects local development trust boundaries | E3 |
| `PSB-SOURCE-002` | リポジトリ所有のGit hooksで開発端末からの情報漏洩を予防 | E3 |
| `PSB-SOURCE-003` | GitHub dorking、全履歴scan、公開面reviewでpublic repository露出を検証 | E3 |

Software supply-chain controlの関係は
[`docs/SUPPLY_CHAIN_PRINCIPLES.md`](docs/SUPPLY_CHAIN_PRINCIPLES.md)を参照してください。

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

SLSA Build Level 2を目標にする場合は
`profiles/slsa-build-l2.csv`でL1とL2に直接対応する確認項目だけを確認できます。
`profiles/slsa-build-l2-coverage.csv`には未マッピング要件も`gap`として残るため、
対象行があることをLevel 2達成と解釈しません。Excel版では
`SLSA Build L2`と`SLSA L2 Coverage`シートをフィルタできます。

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
- MITRE ATLAS
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
MITRE ATLAS    → adversary behavior targeting AI-enabled systems
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
