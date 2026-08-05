# Control Index

Generated control catalog. Do not edit manually.

| ID | Domain | Title | Checks | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| [PSB-AI-001](../controls/ai-development-security/repository-owned-ai-security-guidance/README.md) | ai-development-security | Pin and benchmark repository-owned AI security guidance | 7 | prototype | E3 |
| [PSB-AI-002](../controls/ai-development-security/agent-extension-dependency-governance/README.md) | ai-development-security | Govern Skill MCP plugin and external prompt dependencies | 7 | prototype | E3 |
| [PSB-AI-004](../controls/ai-development-security/ai-coding-agent-runtime-hardening/README.md) | ai-development-security | Harden AI coding agent runtime authority | 26 | prototype | E3 |
| [PSB-BUILD-001](../controls/build-security/build-containment/README.md) | build-security | dependency buildを権限・credential・networkから隔離する | 6 | prototype | E3 |
| [PSB-BUILD-002](../controls/build-security/hosted-consistent-build/README.md) | build-security | 一貫したrelease buildを承認済みhosted platformで実行する | 5 | prototype | E3 |
| [PSB-BUILD-003](../controls/build-security/platform-provenance-generation/README.md) | build-security | Build platformがauthentic provenanceを自動生成する | 5 | prototype | E3 |
| [PSB-CICD-001](../controls/cicd-security/action-sha-pinning/README.md) | cicd-security | Pin external GitHub Actions and reusable workflows to immutable commits | 6 | prototype | E3 |
| [PSB-CICD-002](../controls/cicd-security/actions-command-injection/README.md) | cicd-security | Prevent GitHub Actions command injection from direct expression interpolation | 4 | prototype | E3 |
| [PSB-CICD-003](../controls/cicd-security/actions-static-analysis/README.md) | cicd-security | Statically analyze GitHub Actions workflows with a pinned scanner | 5 | adopted | E3 |
| [PSB-CICD-004](../controls/cicd-security/actions-least-privilege/README.md) | cicd-security | Enforce explicit least-privilege GitHub Actions permissions | 6 | prototype | E3 |
| [PSB-CICD-005](../controls/cicd-security/untrusted-pr-boundary/README.md) | cicd-security | Isolate fork and untrusted pull-request workflows from privileged CI | 6 | prototype | E3 |
| [PSB-CICD-006](../controls/cicd-security/audience-bound-oidc-federation/README.md) | cicd-security | Enforce audience-bound cloud OIDC federation | 8 | prototype | E3 |
| [PSB-CONTAINER-001](../controls/container-cloud-iac-security/container-admission-baseline/README.md) | container-cloud-iac-security | Enforce a fail-closed container workload admission baseline | 9 | adopted | E3 |
| [PSB-CONTAINER-002](../controls/container-cloud-iac-security/container-registry-security/README.md) | container-cloud-iac-security | Enforce authenticated immutable and auditable container registries | 7 | prototype | E3 |
| [PSB-CONTAINER-003](../controls/container-cloud-iac-security/container-host-daemon-hardening/README.md) | container-cloud-iac-security | Harden container hosts daemons and node administration | 9 | prototype | E3 |
| [PSB-CONTAINER-004](../controls/container-cloud-iac-security/runtime-threat-detection/README.md) | container-cloud-iac-security | Detect workload-bound container runtime threats without treating telemetry failure as clean | 12 | adopted | E3 |
| [PSB-DEPS-001](../controls/dependency-security/release-cooldown/README.md) | dependency-security | managed registry proxyとrelease cooldownで依存パッケージ採用を制御 | 8 | prototype | E3 |
| [PSB-DEPS-002](../controls/dependency-security/install-script-execution/README.md) | dependency-security | install時の任意コード実行をdefault denyにする | 5 | prototype | E3 |
| [PSB-DEPS-003](../controls/dependency-security/lockfile-integrity/README.md) | dependency-security | lockfileと取得artifactの完全性を強制する | 5 | prototype | E3 |
| [PSB-DEPS-004](../controls/dependency-security/dependency-change-review/README.md) | dependency-security | Review dependency graph changes before merge | 9 | adopted | E3 |
| [PSB-DETECT-001](../controls/detection-verification/integrity-verified-scanner/README.md) | detection-verification | Execute integrity-verified security scanning with fail-closed evidence | 8 | adopted | E3 |
| [PSB-GOV-001](../controls/governance-operations/supply-chain-incident-readiness/README.md) | governance-operations | supply-chain incidentのbuild artifactと稼働deployment影響を即時特定する | 7 | prototype | E3 |
| [PSB-GOV-002](../controls/governance-operations/time-bound-security-exceptions/README.md) | governance-operations | Enforce exact independently approved time-bound security exceptions | 8 | prototype | E3 |
| [PSB-GOV-003](../controls/governance-operations/exploited-vulnerability-prioritization/README.md) | governance-operations | Prioritize exploited product vulnerabilities with accountable PSIRT cases | 8 | prototype | E3 |
| [PSB-IAC-001](../controls/container-cloud-iac-security/secure-iac-golden-path/README.md) | container-cloud-iac-security | Provide a secure IaC golden path with policy enforcement | 12 | prototype | E3 |
| [PSB-REL-001](../controls/release-integrity/signature-provenance-verification/README.md) | release-integrity | release署名とProvenanceを期待値に照合する | 5 | prototype | E3 |
| [PSB-REL-002](../controls/release-integrity/provenance-publication-distribution/README.md) | release-integrity | Release artifactとprovenanceを一対一で公開・配布する | 5 | prototype | E3 |
| [PSB-REL-003](../controls/release-integrity/sbom-binding-publication/README.md) | release-integrity | SBOM lifecycle observationsをrelease artifactへ結び付けて一元管理する | 9 | prototype | E3 |
| [PSB-REL-004](../controls/release-integrity/supplier-sbom-trust/README.md) | release-integrity | supplier SBOMを検証してからportfolioへ受け入れる | 8 | prototype | E3 |
| [PSB-SOURCE-001](../controls/source-protection/developer-endpoint-hardening/README.md) | source-protection | Harden developer endpoints and local trust boundaries | 29 | prototype | E3 |
| [PSB-SOURCE-002](../controls/source-protection/git-hooks-baseline/README.md) | source-protection | リポジトリ所有の開発者向けGit hooksセキュリティベースライン | 14 | prototype | E3 |
| [PSB-SOURCE-003](../controls/source-protection/public-repository-exposure/README.md) | source-protection | 公開リポジトリ露出とGitHub dorking検証 | 13 | reference | E3 |
| [PSB-SOURCE-004](../controls/source-protection/source-access-credential-lifecycle/README.md) | source-protection | Govern source access credential lifecycle | 12 | prototype | E3 |
