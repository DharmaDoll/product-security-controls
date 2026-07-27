# openssf-osps-baseline mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-CICD-002 - Prevent GitHub Actions command injection from direct expression interpolation | 2026.02.19 | OSPS-BR-01.01 | verifies | high | CI/CD pipelineのuntrusted metadataをshell sourceへ直接展開せず、境界を越える前に安全な値として扱う要件をpositive/negative testで検証する。 |
| PSB-BUILD-001 - dependency buildを権限・credential・networkから隔離する | 2026.02.19 | OSPS-BR-01.03 | verifies | high | Untrusted code snapshotを扱うbuildからprivileged CI/CD credentialとdeploy assetを分離する要件をfail-closed policy testで検証する。 |
| PSB-REL-001 - release署名とProvenanceを期待値に照合する | 2026.02.19 | OSPS-BR-06.01 | verifies | high | Release artifactのcryptographic digestを含むsigned provenanceをconsumer expectationへ照合し、署名またはsigned manifest要件を検証する。 |
| PSB-SOURCE-002 - リポジトリ所有の開発者向けGit hooksセキュリティベースライン | 2026.02.19 | OSPS-BR-07.01 | supports | high | Repositoryへcommitされる前にsecret patternと機密ファイルを検出・拒否し、unencrypted sensitive dataの意図しない保存防止を支援する。 |
