# Add or Review Framework Mappings

Read:

- `AGENTS.md`
- `docs/FRAMEWORK_MAPPING.md`
- target `control.yaml`
- pinned framework registry data

Control ID: `<CONTROL_ID>`

Frameworks:

- MITRE ATT&CK
- OWASP Top 10
- OWASP ASVS
- SLSA
- NIST SSDF
- MITRE ATLAS

## Task

Add or review mappings for the target control.

## Rules

1. Use only identifiers from the pinned framework version.
2. Record the exact version.
3. Use an allowed relationship type.
4. Add confidence and rationale.
5. Do not force a mapping where none is useful.
6. Do not claim formal compliance.
7. Keep ATT&CK as threat behavior, not a requirement.
8. Keep ATLAS as AI threat behavior, not a requirement.
9. Prefer specific ASVS requirements over only Top 10 categories.
10. Distinguish SLSA source and build requirements.
11. Do not mix NIST SSDF final and draft versions.
12. Record both the ATLAS content release and data format version.

## Output

For each proposed mapping explain:

- identifier;
- relationship;
- confidence;
- rationale;
- evidence in this control;
- limitation.

Update the control metadata only after validating identifiers.
Regenerate mapping indexes and run validation.
