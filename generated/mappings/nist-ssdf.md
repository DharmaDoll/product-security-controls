# nist-ssdf mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | 1.1 (SP 800-218, 2022) | PS.3.1 | supports | medium | Least privilege, protected credentials, and endpoint policy checks support protection of code and development environments. |
| PSB-CICD-001 - Pin external GitHub Actions and reusable workflows to immutable commits | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | medium | Pinning reviewed third-party workflow components supports controlled acquisition and maintenance but does not establish that the component is secure. |
