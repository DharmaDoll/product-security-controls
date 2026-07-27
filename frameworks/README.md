# Framework Registries

Store pinned, reviewed framework identifier metadata used for mapping validation.

Framework registries currently include:

- `github-security-guidance/` — pinned GitHub security best-practice and
  GitHub Actions security guidance pages.
- `mitre-attack/` — MITRE ATT&CK Enterprise objects.
- `mitre-atlas/` — MITRE ATLAS AI adversary tactics, techniques, mitigations,
  and case studies.
- `nist-ssdf/` — NIST SP 800-218 Secure Software Development Framework tasks
  referenced by controls.
- `slsa/` — SLSA source and build integrity requirements referenced by
  controls.

Each registry has a `registry.json` containing:

- the exact mapping version;
- a reviewed source URL and, where available, immutable commit and artifact
  SHA-256;
- an explicit completeness boundary;
- identifiers accepted in `control.yaml`.

`make validate-controls` rejects mappings whose framework has no registry,
whose version differs from the registry baseline, or whose identifier is not
registered. A registry can deliberately contain a reviewed subset; its
`coverage.completeness` must say so.

For ATLAS, pin both values because the upstream data separates them:

- content release, for example `2026.05`;
- data format version, for example `6.0.0`.

GitHub Docs does not publish a framework-style release number. Its registry
therefore pins the upstream `github/docs` commit and records the review date.
