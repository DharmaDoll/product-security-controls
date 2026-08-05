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

### OWASP Top 10 for Agentic Applications

Use the pinned `2026` registry for broad risks created when an AI system can
plan, retain context, invoke tools, inherit identities, delegate, and act across
multiple steps. The stable identifiers are `ASI01` through `ASI10`.

Relationship examples:

- addresses
- mitigates
- detects
- related-to

This is a `threat-taxonomy`, not an atomic verification standard. Map only a
check that directly addresses the named agentic failure scenario, and preserve
unmapped categories as gaps rather than copying a control-level mapping to every
row. A mapping does not prove complete category coverage, Agentic Top 10
compliance, safe model behavior, or effective runtime enforcement.

Keep the source roles separate:

- OWASP Agentic Top 10 classifies the broad agentic risk;
- MITRE ATLAS describes adversary tactics, techniques, mitigations, and case
  studies;
- OWASP AI Agent Security Cheat Sheet is implementation guidance in
  `docs/SECURITY_GUIDANCE_SOURCES.md`;
- a detailed requirement framework such as a future reviewed OWASP AISVS
  registry would supply testable verification requirements.

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

Container images are build artifacts for SLSA purposes. Platform provenance
generation remains `PSB-BUILD-003`, distribution remains `PSB-REL-002`, and
consumer authenticity plus subject-digest verification remains
`PSB-REL-001`. Implemented `PSB-CONTAINER-001` composes that consumer verifier
into admission for the exact OCI manifest digest and maps only its atomic
provenance check to the SLSA consumer requirement. Digest pinning without
authenticated provenance is not a SLSA consumer-authenticity mapping.

Do not map container registry operations, production host or daemon hardening,
or runtime threat detection to SLSA Build levels. They can preserve or consume
SLSA evidence, but the security outcomes belong to `PSB-CONTAINER-002..004`
and are outside the SLSA Build track.

### NIST SSDF

Use for secure software development lifecycle practices.

Relationship examples:

- supports
- evidence-for

Pin the exact publication/version and do not mix final and draft identifiers.

### NIST SP 800-190

Use the September 2017 final publication as product-neutral container
implementation guidance. The registry indexes every Section 4 countermeasure
identifier, but mappings should include only the narrow sections directly
supported by an atomic control check.

Relationship examples:

- supports
- verifies
- evidence-for
- mitigates

Keep image scanning, workload admission, registry protection, host hardening,
application security, and release integrity under separate control owners.
Section 4 guidance is not a container-platform certification or proof of
complete NIST coverage.

The implemented owners are `PSB-DETECT-001` for image and runtime vulnerability
scanning, `PSB-CONTAINER-001` for workload admission,
`PSB-CONTAINER-002` for registry security, `PSB-CONTAINER-003` for host and
daemon hardening, and `PSB-CONTAINER-004` for post-admission runtime behavior.

The duplicate-free source and control boundary is recorded in
[`CONTAINER_SECURITY_SOURCE_ALLOCATION.md`](CONTAINER_SECURITY_SOURCE_ALLOCATION.md).

### CIS Docker Benchmark

Treat CIS Docker Benchmark as a product-specific `requirement-framework`, not
as general reference guidance. Version `1.8.0` is identified, but it remains
`input-required`: no active registry or mapping may be created until an
official authorized PDF, artifact digest, recommendation inventory, and reuse
terms are reviewed. Do not derive content from third-party PDF mirrors.

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
