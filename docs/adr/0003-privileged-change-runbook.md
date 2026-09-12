# ADR-0003: Privileged changes use a shared runbook

- Status: Accepted
- Date: 2026-09-09
- Amended: 2026-09-13

## Context

PSB-CICD-008 repeated administrator identity, authentication, role and audit requirements owned by existing controls. Its unique content was a change-management procedure, without a provider gate or complete detection of unrequested changes. Keeping seven separate checks exaggerated independent coverage.

We considered relying only on secure settings, retaining the manual control, and retaining a shared runbook. Settings alone do not address direct administrator changes. A separate control does not itself close that gap either. A shared procedure preserves useful review and recovery steps without duplicating assurance claims.

The initial retirement left a one-file migration README under `controls/`.
Although it preserved the old URL, the repository tree still presented the
retired name beside active control packages. That made a non-control look like
a control and weakened catalog discoverability.

## Decision

Retire PSB-CICD-008 and CPC-001 through CPC-007. Do not reuse these IDs. Remove
the complete `controls/cicd-security/privileged-control-plane-change/` path,
including its migration README, so `controls/` contains only current control
packages. Preserve the retirement decision in this ADR and place the common
procedure and ticket template in
[docs/runbooks/privileged-changes](../runbooks/privileged-changes/README.md).

GitHub identity and audit stay with PSB-SOURCE-006. OIDC, runner, registry and signing settings stay with their existing controls. A runbook reference is not atomic-check evidence. Reconciliation rows that relied on the retired checks retain explicit gaps instead of silently inheriting coverage.

## Consequences

The retired ID is no longer selectable as a control. Existing organization checklists must migrate their records using the old IDs without treating them as passing current checks. Historical commits preserve the old implementation and mappings; regenerated catalogs omit them. Links to the retired control path are intentionally not preserved. Maintainers must link to this ADR for the retirement decision or to the shared runbook for the current procedure.

Unrequested-change detection across all providers remains an operational gap. A future independent control would need a distinct demonstrated outcome, such as a provider-enforced approval boundary or complete live change reconciliation.
