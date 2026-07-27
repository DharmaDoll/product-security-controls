# Framework Mapping Strategy

## Purpose

Framework mapping helps users understand why a control exists and which external security practices it supports.

It does not automatically prove compliance.

## Framework roles

### GitHub security guidance

Use the pinned GitHub security guidance registry for GitHub-specific
implementation recommendations covering software supply-chain protection and
GitHub Actions security.

Relationship examples:

- supports
- verifies
- related-to

GitHub documentation is vendor guidance, not a formal compliance framework.
Mappings must identify a page-level registry ID and must not imply that use of
a GitHub feature is sufficient to satisfy a broader security outcome. The
registry version is the reviewed `github/docs` commit because the published
documentation does not have a framework-style version number.

### MITRE ATT&CK

Use for relevant attacker behavior and techniques.

For GitHub dorking, describe the behavior precisely rather than treating
“dorking” as an ATT&CK technique itself. Depending on the evidence, relevant
relationships may include `related-to` or `mitigates` for ATT&CK techniques
covering public-information discovery and exposed credentials. The exact
technique identifier must be selected from the pinned ATT&CK registry for the
control and threat scenario under review.

Relationship examples:

- mitigates
- detects
- related-to

Do not describe ATT&CK techniques as requirements.

### MITRE ATLAS

Use for adversary tactics and techniques targeting AI-enabled systems, including
AI models, AI-enabled applications, and their supporting development or
deployment workflows. ATLAS is especially relevant to controls in the
`ai-development-security` domain.

Relationship examples:

- mitigates
- detects
- related-to

Map only when the control's threat scenario involves an AI-specific attack
behavior. Do not treat an ATLAS mapping as proof of AI security or formal
coverage. Record both the ATLAS content release and data format version used
by the registry.

### OWASP Top 10

Use for broad application risk categories.

Relationship examples:

- addresses
- related-to

Top 10 is too coarse to serve as the only implementation requirement.

### OWASP ASVS

Use for detailed application security verification requirements.

The pinned baseline is ASVS `5.0.0`. Mapping identifiers must use the
version-qualified form recommended by OWASP, for example
`v5.0.0-1.2.5`; unqualified identifiers such as `1.2.5` are not accepted.

Relationship examples:

- supports
- verifies
- evidence-for

A secure coding control should map to specific ASVS identifiers where applicable.

### SLSA

Use for source and build integrity controls.

Relationship examples:

- supports
- evidence-for
- verifies

Keep source and build requirements distinct.

### NIST SSDF

Use for secure software development lifecycle practices.

Relationship examples:

- supports
- evidence-for

Pin the exact publication/version and do not mix final and draft identifiers.

## Mapping quality

Every mapping records:

- version;
- identifier;
- relationship;
- confidence;
- rationale;
- reviewer;
- review date.

Confidence levels:

- low: conceptual relationship
- medium: clear support but partial implementation
- high: direct implementation or verification evidence

## Reverse indexes

Generate:

- controls by framework;
- framework items by control;
- unmapped controls;
- mappings awaiting review;
- framework items with no implementation example.

## Important limitation

The repository will not attempt to cover all ATT&CK techniques or every ASVS requirement. Coverage must be explicit and honest.

The same rule applies to ATLAS: mappings identify relevant AI attack behavior,
not complete coverage of the ATLAS knowledge base.
