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
| `PSB-SOURCE-001` | Developer endpoint policy protects local development trust boundaries | E3 |

## Framework mapping

Each control is mapped to applicable items from:

- MITRE ATT&CK
- OWASP Top 10
- OWASP ASVS
- SLSA
- NIST SSDF
- MITRE ATLAS

Mappings are relationships, not automatic claims of compliance.

## Important distinction

```text
MITRE ATT&CK   → what attackers do
OWASP Top 10   → major application risk categories
OWASP ASVS     → concrete application security verification requirements
SLSA           → source and build integrity requirements
NIST SSDF      → secure software development practices
MITRE ATLAS    → adversary behavior targeting AI-enabled systems
This repository→ concrete implementation and verification examples
```

## First implementation candidates

1. GitHub Actions full SHA pinning
2. Minimal workflow permissions
3. Dependency cooldown and lockfile integrity
4. Trivy filesystem, container, IaC, secret, and SBOM examples
5. Secure authorization sample
6. Secure secret handling sample
7. SBOM and artifact attestation
8. CodeGuard and AGENTS.md comparative validation
9. Third-party Skill pinning and review
10. Time-bound vulnerability exceptions
11. GitHub dorking and public repository information exposure
12. Developer endpoint hardening and local trust-boundary protection

## Codex usage

Start with:

```text
Read AGENTS.md and all documents under docs/.
Then execute .codex/prompts/00-bootstrap-repository.md.
Do not implement all controls at once.
Complete Phase 0 and Phase 1 only.
```
