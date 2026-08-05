# Framework Registries

Store pinned, reviewed framework identifier metadata used for mapping validation.

Framework registries currently include:

- `cisa-product-security-bad-practices/` — CISA/FBI Product Security Bad
  Practices Version 2 negative baseline.
- `github-security-guidance/` — pinned GitHub security best-practice and
  GitHub Actions security guidance pages.
- `mitre-attack/` — MITRE ATT&CK Enterprise objects.
- `mitre-atlas/` — MITRE ATLAS AI adversary tactics, techniques, mitigations,
  and case studies.
- `nist-sp-800-190/` — NIST application-container countermeasure guidance
  sections used by planned container controls.
- `nist-ssdf/` — NIST SP 800-218 Secure Software Development Framework tasks
  referenced by controls.
- `openssf-osps-baseline/` — OpenSSF OSPS Baseline project security assessment
  requirements.
- `owasp-agentic-top10/` — OWASP Top 10 for Agentic Applications 2026 risk
  categories for autonomous and tool-using AI systems.
- `owasp-asvs/` — OWASP ASVS 5.0.0 application verification requirements.
- `slsa/` — SLSA source and build integrity requirements referenced by
  controls.

Each registry has a `registry.json` containing:

- a role: `requirement-framework`, `threat-taxonomy`,
  `implementation-guidance`, or `negative-baseline`;
- the exact mapping version;
- a reviewed source URL and, where available, immutable commit and artifact
  SHA-256;
- an explicit completeness boundary;
- identifiers accepted in `control.yaml`.

`make validate-controls` rejects mappings whose framework has no registry,
whose version differs from the registry baseline, or whose identifier is not
registered. A registry can deliberately contain a reviewed subset; its
`coverage.completeness` must say so.

## Adoption gate

Do not add a registry only because a publication is well known. A new registry
must:

1. come from an authoritative source that can be versioned or integrity-pinned;
2. add acceptance criteria, threat semantics, negative examples, or
   implementation guidance not already represented;
3. have stable identifiers, or a documented version-scoped local ID rule;
4. have at least one planned or implemented control that can produce evidence;
5. remain verifiable offline after the reviewed source is acquired;
6. document its completeness boundary, limitations, and maintenance owner.

Broad governance rollups and cloud-provider guidance should not become global
control requirements by default. Add them only as secondary mappings or
provider profiles when a corresponding implementation exists.

For ATLAS, pin both values because the upstream data separates them:

- content release, for example `2026.05`;
- data format version, for example `6.0.0`.

GitHub Docs does not publish a framework-style release number. Its registry
therefore pins the upstream `github/docs` commit and records the review date.

CIS Docker Benchmark v1.8.0 is allocated as a future
`requirement-framework`, but no active registry exists until the official PDF
and its applicable reuse terms are supplied and reviewed. Do not reconstruct
its recommendations from third-party mirrors.
