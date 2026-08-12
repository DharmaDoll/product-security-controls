# Software supply-chain integration reconciliation

Generated from the reviewed NIST SP 800-204D integration profile. Do not edit manually.

This view verifies whether identities and decisions stay connected between controls. `SCIR-*` values are repository profile row IDs, not NIST requirement identifiers. `implemented` means the repository has exact executable check evidence for this connection; it does not prove live organization adoption or compliance.

## Disposition summary

| Disposition | Rows | Meaning |
|---|---:|---|
| implemented | 9 | Exact current control checks support the connection. |
| planned | 1 | A named owner and planned control remain necessary. |
| gap | 1 | Partial or absent evidence leaves an owned integration gap. |
| out-of-scope | 1 | The boundary is intentionally assessed elsewhere. |

## Reconciliation rows

| Row | NIST sections | Integration boundary | Disposition | Current check evidence | Planned controls | Owner | Remaining work or boundary |
|---|---|---|---|---|---|---|---|
| SCIR-001 | 3.1.1; 5.1.4 | Developer identity to source revision | implemented | PSB-SOURCE-001-END-013; PSB-SOURCE-004-SCL-007; PSB-SOURCE-004-SCL-008 |  |  |  |
| SCIR-002 | 3.2.2; 5.1.1 | Dependency declaration to acquired artifact | implemented | PSB-DEPS-003-LOCK-001; PSB-DEPS-003-LOCK-002; PSB-DEPS-003-LOCK-003; PSB-DEPS-004-DCR-001; PSB-DEPS-004-DCR-002; PSB-DEPS-004-DCR-003 |  |  |  |
| SCIR-003 | 3.2.2; 5.1.1 | Reviewed source revision to build invocation | implemented | PSB-CICD-005-PRB-003; PSB-CICD-005-PRB-005; PSB-BUILD-002-HCB-002; PSB-BUILD-002-HCB-003; PSB-BUILD-002-HCB-004 |  |  |  |
| SCIR-004 | 4; 5.2 | Pipeline workload identity to deployment authority | implemented | PSB-BUILD-001-BLD-002; PSB-CICD-006-OIDC-002; PSB-CICD-006-OIDC-003; PSB-CICD-006-OIDC-005; PSB-CICD-006-OIDC-007 |  |  |  |
| SCIR-005 | 5.1.1 | Build platform identity to artifact digest and provenance | implemented | PSB-BUILD-003-PPG-001; PSB-BUILD-003-PPG-002; PSB-BUILD-003-PPG-003; PSB-BUILD-003-PPG-004 |  |  |  |
| SCIR-006 | 5.1.2; 5.1.3 | Artifact digest to published release evidence | implemented | PSB-REL-002-RPD-001; PSB-REL-002-RPD-002; PSB-REL-003-SBM-002; PSB-REL-003-SBM-004; PSB-REL-005-ASG-001; PSB-REL-005-ASG-006 |  |  |  |
| SCIR-007 | 5.1.2; 5.2 | Published registry object to deployment admission identity | implemented | PSB-CONTAINER-002-REG-002; PSB-CONTAINER-002-REG-003; PSB-CONTAINER-002-REG-004; PSB-CONTAINER-001-CNT-001; PSB-CONTAINER-001-CNT-002; PSB-CONTAINER-001-CNT-009 |  |  |  |
| SCIR-008 | 5.2; 5.2.1 | Deployment identity to runtime impact inventory | implemented | PSB-IAC-001-IAC-007; PSB-IAC-001-IAC-008; PSB-IAC-001-IAC-009; PSB-REL-003-SBM-008; PSB-REL-003-SBM-009; PSB-GOV-001-INC-007 |  |  |  |
| SCIR-009 | 5.1.4 | Application security results to source revision | planned | PSB-SOURCE-001-DEH-004; PSB-DEPS-004-DCR-001; PSB-DEPS-004-DCR-004 | PSB-CODE-001; PSB-CODE-002; PSB-CODE-003; PSB-CODE-004 | application-security | The application assessment source is still required before executable PSB-CODE controls can provide revision-bound evidence. |
| SCIR-010 | 4; 5 | CI/CD human and control-plane identity to privileged configuration change | gap | PSB-CICD-007-RNR-006; PSB-CICD-007-RNR-008 |  | ci-platform | No cross-provider adapter currently reconciles human administrator sessions and control-plane changes across SCM, CI, cloud federation, registry, and signing services. |
| SCIR-011 | 5.1.4; 5.2 | Running artifact age and vulnerability state to rebuild decision | implemented | PSB-CONTAINER-002-REG-006; PSB-GOV-001-INC-001; PSB-GOV-001-INC-007; PSB-GOV-005-DAR-002; PSB-GOV-005-DAR-003; PSB-GOV-005-DAR-004; PSB-GOV-005-DAR-005; PSB-GOV-005-DAR-006 |  |  |  |
| SCIR-012 | 1.2 | Product-specific secure design and enterprise vulnerability management | out-of-scope |  |  | product-security | This boundary is intentionally excluded from the SP 800-204D integration profile rather than recorded as a CI/CD implementation gap. |
