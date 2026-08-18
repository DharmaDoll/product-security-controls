# Generated adoption checklists

These files are generated from `controls/*/*/control.yaml`. Do not edit them manually.

Regenerate from the repository root:

```bash
make generate-checklists
```

Copy `product-security-assessment-template.xlsx` outside this generated directory before recording organization-owned results. Regeneration replaces the blank template.

`profiles/slsa-build-l2.csv` is the cumulative L1+L2 check view. `profiles/slsa-build-l2-coverage.csv` keeps unmapped requirements visible as gaps; mapped evidence is not a SLSA level claim.

`profiles/application-vulnerability-assessment/status.json` records `INPUT_REQUIRED` until an organization source manifest is supplied; the generator never represents a missing source as an empty checklist.

`governance/control-readiness.csv` and `.md` show repository maturity, mapping debt, and assessment-adapter availability. Organization adoption, evidence freshness, and exception debt remain `NOT_CHECKED` until populated in a copied assessment workbook; repository E3 fixtures are never converted into live adoption.

`profiles/supply-chain-integration/reconciliation.csv` and `.md` connect exact control checks across developer, SCM, dependency, build, release, repository, and deployment boundaries using NIST SP 800-204D as section-level guidance. `SCIR-*` identifiers are repository rows, and every planned, gap, or out-of-scope boundary remains explicit.

`profiles/first-psirt-capability/assessment.csv` and `.md` provide a cumulative Basic, Intermediate, and Advanced organization assessment from integrity-recorded FIRST sources. Repository checks are supporting evidence only; public assessment and freshness values remain `NOT_CHECKED`.

`profiles/sitf/technique-coverage.csv` and `.md` reconcile every technique in the immutable SITF source to exact current checks or an owned gap. `profiles/sitf/attack-flows.csv` and `.md` compose synthetic cross-component review paths. Neither output is a compliance or live organization-adoption claim.
