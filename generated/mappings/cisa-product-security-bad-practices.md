# cisa-product-security-bad-practices mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-SOURCE-002 - リポジトリ所有の開発者向けGit hooksセキュリティベースライン | 2 (January 2025) | CISA-PSBP-PP-08 | mitigates | medium | Commit前にhardcoded credentialとsecret patternを検出・拒否してsource codeへの混入を減らすが、pattern外のsecretやhook bypassまでは防止できない。 |
