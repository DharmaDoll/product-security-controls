# MITRE ATLAS Registry

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is used here to
describe attacker behavior targeting AI-enabled systems. It complements
MITRE ATT&CK; it does not replace it.

## Pinned registry baseline

- Source: [MITRE ATLAS data](https://github.com/mitre-atlas/atlas-data)
- Content release: `2026.05`
- Data format: `6.0.0`
- Source tag: `v2026.05`
- Machine-readable registry: [`registry.json`](registry.json)
- Identifier forms:
  - tactics: `AML.TA####`
  - techniques: `AML.T####`
  - sub-techniques: `AML.T####.###`
  - mitigations: `AML.M####`
  - case studies: `AML.CS####`

The content release and format version are recorded separately because the
official distribution uses independent versioning for them. Update this file
and review affected control mappings when the baseline changes.

## Mapping boundary

Use ATLAS only when a control addresses an AI-specific threat scenario. A
mapping means the control is related to, detects, or mitigates the referenced
attack behavior; it does not claim complete ATLAS coverage or formal
compliance.
