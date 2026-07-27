# Generated adoption checklists

These files are generated from `controls/*/*/control.yaml`. Do not edit them manually.

Regenerate from the repository root:

```bash
make generate-checklists
```

Copy `product-security-assessment-template.xlsx` outside this generated directory before recording organization-owned results. Regeneration replaces the blank template.

`profiles/slsa-build-l2.csv` is the cumulative L1+L2 check view. `profiles/slsa-build-l2-coverage.csv` keeps unmapped requirements visible as gaps; mapped evidence is not a SLSA level claim.
