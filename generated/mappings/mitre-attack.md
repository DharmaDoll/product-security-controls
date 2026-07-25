# mitre-attack mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-CICD-001 - Pin external GitHub Actions and reusable workflows to immutable commits | v19.1 | T1195.001 | mitigates | medium | Immutable references reduce the opportunity to replace a reviewed workflow dependency or development tool through a moved Git reference. |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | v19.1 | T1552.001 | mitigates | medium | Protected credential storage and prohibition of secrets in workspaces reduce exposure to credentials in files. |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | v19.1 | T1555 | mitigates | medium | System-managed credential storage and endpoint access controls reduce exposure of credentials from password stores. |
