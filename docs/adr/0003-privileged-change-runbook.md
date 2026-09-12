# ADR-0003: Privileged changes use a shared runbook

- Status: Accepted
- Date: 2026-09-09

## Context

PSB-CICD-008 repeated administrator identity, authentication, role and audit requirements owned by existing controls. Its unique content was a change-management procedure, without a provider gate or complete detection of unrequested changes. Keeping seven separate checks exaggerated independent coverage.

We considered relying only on secure settings, retaining the manual control, and retaining a shared runbook. Settings alone do not address direct administrator changes. A separate control does not itself close that gap either. A shared procedure preserves useful review and recovery steps without duplicating assurance claims.

## Decision

Retire PSB-CICD-008 and CPC-001 through CPC-007. Do not reuse these IDs. Remove its control.yaml and formal mappings from the catalog source. Keep a migration README at the old URL and place the common procedure and ticket template in [docs/runbooks/privileged-changes](../runbooks/privileged-changes/README.md).

GitHub identity and audit stay with PSB-SOURCE-006. OIDC, runner, registry and signing settings stay with their existing controls. A runbook reference is not atomic-check evidence. Reconciliation rows that relied on the retired checks retain explicit gaps instead of silently inheriting coverage.

## Consequences

The retired ID is no longer selectable as a control. Existing organization checklists must migrate their records using the old IDs without treating them as passing current checks. Historical commits preserve old mappings; regenerated catalogs omit them. Generated outputs may be updated separately under the task's generated-file policy.

Unrequested-change detection across all providers remains an operational gap. A future independent control would need a distinct demonstrated outcome, such as a provider-enforced approval boundary or complete live change reconciliation.
