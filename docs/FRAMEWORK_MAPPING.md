# Framework Mapping Strategy

## Purpose

Framework mapping helps users understand why a control exists and which external security practices it supports.

It does not automatically prove compliance.

## Framework roles

Registries classify their primary role as one of:

- `requirement-framework`: testable or assessable security requirements;
- `threat-taxonomy`: attacker behavior or risk classification, not compliance;
- `implementation-guidance`: product/provider-specific implementation advice;
- `negative-baseline`: focused practices that secure implementations avoid.

This prevents a control from treating a threat taxonomy, vendor guide, and
verification standard as interchangeable evidence.

### CISA Product Security Bad Practices

Use as a focused negative baseline for exceptionally risky product properties,
missing security features, and manufacturer processes. It is especially useful
for defining isolated insecure examples and negative tests.

Relationship examples:

- mitigates
- detects
- supports

The official Version 2 document numbers its 13 practices but does not publish
framework-style stable identifiers. Use the registry's version-scoped local
IDs and review meaning, not numbering alone, when the source is updated.
Do not generalize the guidance's critical-infrastructure scope or treat a
mapping as regulatory compliance or complete Secure by Design coverage.

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

For SLSA Build level filtering, the pinned registry records `track`,
`minimum_level`, `responsibility`, and whether an entry is a level requirement.
Level profiles are cumulative: Build L2 includes L1 and L2 requirements and
excludes L3 requirements. Generated checklist rows expose this metadata, while
the coverage view retains requirements with no mapped control as `gap`.

`mapped-evidence` means that a control check has a reviewed relationship to the
requirement. It does not mean the producer, build platform, or consumer has
passed a complete SLSA assessment, and it must not be presented as achievement
of a SLSA level.

### NIST SSDF

Use for secure software development lifecycle practices.

Relationship examples:

- supports
- evidence-for

Pin the exact publication/version and do not mix final and draft identifiers.

### OpenSSF OSPS Baseline

Use for provider-independent open source project security requirements across
repository access, CI/CD, build and release, documentation, governance,
security assessment, and vulnerability management.

Relationship examples:

- supports
- verifies
- evidence-for

Map only requirements directly implemented or verified by a control. A mapping
does not establish project-wide OSPS conformance or achievement of a maturity
level. Use OpenSSF Scorecard as one possible evidence source, not as a
framework substitute or proof of security. The reviewed reference and
executable-adoption boundary are recorded as
[`REF-GOV-001`](SECURITY_GUIDANCE_SOURCES.md#ref-gov-001); an aggregate score
must never be converted directly into a control pass or OSPS mapping.

## Mapping quality

Every mapping records:

- version;
- identifier;
- relationship;
- confidence;
- rationale;
- reviewer;
- review date.
- the atomic check identifiers to which the rationale applies.

Generated checklist rows show only mappings whose `applies_to` explicitly
references that check. A parent control mapping is never inherited
automatically. Checks without a reviewed relationship are displayed as
`UNMAPPED — framework review required`.

Confidence levels:

- low: conceptual relationship
- medium: clear support but partial implementation
- high: direct implementation or verification evidence

Before adding a new framework, apply the adoption gate in
[`frameworks/README.md`](../frameworks/README.md). Prefer one strong primary
requirement mapping over several overlapping conceptual mappings.

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
