# cisa-product-security-bad-practices mappings

| Control | Checks | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| PSB-SOURCE-002 - リポジトリ所有の開発者向けGit hooksセキュリティベースライン | PSB-SOURCE-002-GHK-007, PSB-SOURCE-002-GHK-009, PSB-SOURCE-002-GHK-010, PSB-SOURCE-002-GHK-011 | 2 (January 2025) | CISA-PSBP-PP-08 | mitigates | medium | Commit前にhardcoded credentialとsecret patternを検出・拒否してsource codeへの混入を減らすが、pattern外のsecretやhook bypassまでは防止できない。 |
| PSB-SOURCE-003 - 公開リポジトリ露出とGitHub dorking検証 | PSB-SOURCE-003-PRE-003, PSB-SOURCE-003-PRE-004, PSB-SOURCE-003-PRE-007, PSB-SOURCE-003-PRE-009 | 2 (January 2025) | CISA-PSBP-PP-08 | detects | medium | Current and historical public-source scanning can detect representative hardcoded credentials and secret patterns but does not prove their complete absence. |
