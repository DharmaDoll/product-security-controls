# Framework Registries

Store pinned, reviewed framework identifier metadata used for mapping validation.

Framework registries currently include:

- `github-security-guidance/` — pinned GitHub security best-practice and
  GitHub Actions security guidance pages.
- `mitre-attack/` — MITRE ATT&CK enterprise techniques.
- `mitre-atlas/` — MITRE ATLAS AI adversary tactics and techniques.
- `nist-ssdf/` — NIST SP 800-218 Secure Software Development Framework.

For ATLAS, pin both values because the upstream data separates them:

- content release, for example `2026.05`;
- data format version, for example `6.0.0`.

GitHub Docs does not publish a framework-style release number. Its registry
therefore pins the upstream `github/docs` commit and records the review date.
