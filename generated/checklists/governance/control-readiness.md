# Control catalog governance readiness

Generated from repository control metadata. Do not edit manually.

`Control Status` and `Reference Evidence Level` describe the repository implementation. They are not organization adoption or live evidence. Until organization-owned results, evidence timestamps, and a current PSB-GOV-002 exception register are supplied, those fields remain `NOT_CHECKED`.

## Summary

| Metric | Value | Meaning |
|---|---:|---|
| Catalog controls | 52 | Repository control packages; not organization adoption. |
| Atomic checks | 469 | Assessable catalog rows generated from control metadata. |
| Reviewed mapping checks | 413 | Checks with at least one reviewed framework relationship. |
| Provisional mapping checks | 0 | Checks whose framework relationship still needs review. |
| Unmapped checks | 56 | Explicit framework mapping debt; not silently inherited. |
| Assessment adapters | 1 | Controls with a repository read-only assessment interface. |
| Organization adoption | NOT_CHECKED | Organization-owned assessment results are not committed here. |
| Evidence freshness | NOT_CHECKED | No current organization evidence bundle was supplied. |
| Exception debt | NOT_CHECKED | Consume a current PSB-GOV-002 register outside public guidance. |

## Per-control readiness

| Control ID | Domain | Status | Reference Evidence | Checks | Reviewed | Provisional | Unmapped | Assessment Adapter | Organization Adoption | Evidence Freshness | Exception Debt | Governance Result |
|---|---|---|---|---:|---:|---:|---:|---|---|---|---|---|
| PSB-AI-001 | ai-development-security | prototype | E3 | 7 | 2 | 0 | 5 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-002 | ai-development-security | prototype | E3 | 7 | 7 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-003 | ai-development-security | prototype | E3 | 10 | 8 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-004 | ai-development-security | prototype | E3 | 26 | 26 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-005 | ai-development-security | prototype | E3 | 9 | 7 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-006 | ai-development-security | prototype | E3 | 10 | 8 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-007 | ai-development-security | prototype | E3 | 11 | 10 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-008 | ai-development-security | prototype | E3 | 11 | 10 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-009 | ai-development-security | prototype | E3 | 11 | 11 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-010 | ai-development-security | prototype | E3 | 11 | 10 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-AI-011 | ai-development-security | prototype | E3 | 10 | 8 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-BUILD-001 | build-security | prototype | E3 | 6 | 6 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-BUILD-002 | build-security | prototype | E3 | 5 | 4 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-BUILD-003 | build-security | prototype | E3 | 5 | 4 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-001 | cicd-security | prototype | E3 | 6 | 5 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-002 | cicd-security | prototype | E3 | 4 | 2 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-003 | cicd-security | adopted | E3 | 5 | 5 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-004 | cicd-security | prototype | E3 | 6 | 5 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-005 | cicd-security | prototype | E3 | 6 | 5 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-006 | cicd-security | prototype | E3 | 8 | 7 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-007 | cicd-security | prototype | E3 | 9 | 8 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-008 | cicd-security | prototype | E3 | 7 | 6 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CICD-009 | cicd-security | prototype | E3 | 7 | 6 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CODE-005 | secure-coding | prototype | E3 | 6 | 4 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CONTAINER-001 | container-cloud-iac-security | adopted | E3 | 9 | 9 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CONTAINER-002 | container-cloud-iac-security | prototype | E3 | 7 | 6 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CONTAINER-003 | container-cloud-iac-security | prototype | E3 | 9 | 8 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-CONTAINER-004 | container-cloud-iac-security | adopted | E3 | 12 | 10 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DEPS-001 | dependency-security | prototype | E3 | 10 | 9 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DEPS-002 | dependency-security | prototype | E3 | 5 | 4 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DEPS-003 | dependency-security | prototype | E3 | 5 | 4 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DEPS-004 | dependency-security | adopted | E3 | 9 | 9 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DEPS-005 | dependency-security | prototype | E3 | 9 | 8 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DETECT-001 | detection-verification | adopted | E3 | 8 | 8 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-DETECT-002 | detection-verification | prototype | E3 | 10 | 8 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-GOV-001 | governance-operations | prototype | E3 | 7 | 6 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-GOV-002 | governance-operations | prototype | E3 | 8 | 5 | 0 | 3 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-GOV-003 | governance-operations | prototype | E3 | 8 | 8 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-GOV-004 | governance-operations | prototype | E3 | 10 | 8 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-GOV-005 | governance-operations | prototype | E3 | 7 | 7 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-IAC-001 | container-cloud-iac-security | prototype | E3 | 12 | 12 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-REL-001 | release-integrity | prototype | E3 | 5 | 4 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-REL-002 | release-integrity | prototype | E3 | 5 | 4 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-REL-003 | release-integrity | prototype | E3 | 9 | 9 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-REL-004 | release-integrity | prototype | E3 | 8 | 6 | 0 | 2 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-REL-005 | release-integrity | prototype | E3 | 8 | 7 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-SOURCE-001 | source-protection | prototype | E3 | 29 | 27 | 0 | 2 | available | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-SOURCE-002 | source-protection | prototype | E3 | 13 | 12 | 0 | 1 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-SOURCE-003 | source-protection | reference | E3 | 13 | 10 | 0 | 3 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-SOURCE-004 | source-protection | prototype | E3 | 17 | 17 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-SOURCE-005 | source-protection | reference | E1 | 4 | 4 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
| PSB-SOURCE-006 | source-protection | prototype | E3 | 10 | 10 | 0 | 0 | not-provided | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED | NOT_CHECKED |
