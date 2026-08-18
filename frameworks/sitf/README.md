# Supply-chain attack technique framework registry

This registry uses the Wiz Research Supply-chain Attack Technique Framework
(SITF) as a threat taxonomy and attack-flow design aid. It is not a compliance
framework, maturity model, or assertion that every technique is mitigated.

- Content release: upstream `1.0.0`
- Pinned commit: `d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59`
- Pinned artifact: `techniques.json`
- Artifact SHA-256:
  `3f45ca1033e09deab0b66e432969c0b489b35965a4bf2f3299f5a3b24943887e`
- Technique inventory: 81 across endpoint, VCS, CI/CD, registry, and production
- Machine-readable registry: [`registry.json`](registry.json)
- Coverage source:
  [`policies/integration/sitf-coverage.json`](../../policies/integration/sitf-coverage.json)
- Attack-flow source:
  [`policies/integration/sitf-attack-flows.json`](../../policies/integration/sitf-attack-flows.json)

Only the identifiers, names, component, and stage metadata needed for offline
reconciliation are retained here. The upstream descriptions, risks, and
suggested controls remain in the pinned canonical artifact.

## Source and reuse boundary

The upstream `LICENSE` and README at the pinned commit identify CC BY-NC 4.0,
while `CITATION.cff` declares CC-BY-NC-ND-4.0. This metadata inconsistency is
recorded rather than silently resolved. Consumers must review the upstream
terms for their use case; this repository does not relicense SITF content.

The Japanese
[`sitf-technique-library.md`](https://github.com/kyohmizu/seccamp2026-B6/blob/a84ef65bbf7cc83c8c0757ece3c6315abfd2f274/chapter2/sitf-technique-library.md)
is a non-normative reading aid. It is pinned for review traceability but is not
copied, used as the identifier authority, or treated as evidence. The original
Wiz Research artifact is canonical.

## Claim boundary

An `implemented` coverage row means one or more exact repository checks
directly address the technique's primary behavior. It does not prove complete
mitigation, deployment at an organization, or live evidence freshness. A
partial defense stays `gap` with its supporting checks and remaining work
visible. Missing, duplicated, or unknown technique and check identifiers fail
generation.
