# Control Index

Generated control catalog. Do not edit manually.

| ID | Domain | Title | Checks | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| PSB-AI-004 | ai-development-security | Harden AI coding agent runtime authority | 26 | prototype | E3 |
| PSB-BUILD-001 | build-security | dependency buildを権限・credential・networkから隔離する | 6 | prototype | E3 |
| PSB-BUILD-002 | build-security | 一貫したrelease buildを承認済みhosted platformで実行する | 5 | prototype | E3 |
| PSB-BUILD-003 | build-security | Build platformがauthentic provenanceを自動生成する | 5 | prototype | E3 |
| PSB-CICD-001 | cicd-security | Pin external GitHub Actions and reusable workflows to immutable commits | 6 | prototype | E3 |
| PSB-CICD-002 | cicd-security | Prevent GitHub Actions command injection from direct expression interpolation | 4 | prototype | E3 |
| PSB-CICD-003 | cicd-security | Statically analyze GitHub Actions workflows with a pinned scanner | 5 | adopted | E3 |
| PSB-CICD-004 | cicd-security | Enforce explicit least-privilege GitHub Actions permissions | 6 | prototype | E3 |
| PSB-CICD-005 | cicd-security | Isolate fork and untrusted pull-request workflows from privileged CI | 6 | prototype | E3 |
| PSB-DEPS-001 | dependency-security | 依存パッケージの公開直後採用をrelease cooldownで制御 | 6 | prototype | E3 |
| PSB-DEPS-002 | dependency-security | install時の任意コード実行をdefault denyにする | 5 | prototype | E3 |
| PSB-DEPS-003 | dependency-security | lockfileと取得artifactの完全性を強制する | 5 | prototype | E3 |
| PSB-GOV-001 | governance-operations | supply-chain incidentの影響範囲と対応planを即時生成する | 5 | prototype | E3 |
| PSB-IAC-001 | container-cloud-iac-security | Provide a secure IaC golden path with policy enforcement | 12 | prototype | E3 |
| PSB-REL-001 | release-integrity | release署名とProvenanceを期待値に照合する | 5 | prototype | E3 |
| PSB-REL-002 | release-integrity | Release artifactとprovenanceを一対一で公開・配布する | 5 | prototype | E3 |
| PSB-SOURCE-001 | source-protection | Harden developer endpoints and local trust boundaries | 28 | prototype | E3 |
| PSB-SOURCE-002 | source-protection | リポジトリ所有の開発者向けGit hooksセキュリティベースライン | 14 | prototype | E3 |
| PSB-SOURCE-003 | source-protection | 公開リポジトリ露出とGitHub dorking検証 | 13 | reference | E3 |
| PSB-SOURCE-004 | source-protection | Govern source access credential lifecycle | 12 | prototype | E3 |
