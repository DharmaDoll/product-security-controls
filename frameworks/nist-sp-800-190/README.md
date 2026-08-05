# NIST SP 800-190 Registry

This registry indexes the container-security countermeasure sections in NIST
SP 800-190. Its role is `implementation-guidance`: a mapping indicates that a
control implements, verifies, or supplies evidence relevant to the cited
countermeasure. It is not a certification or a claim that the complete
publication has been satisfied.

- Publication: NIST SP 800-190, *Application Container Security Guide*
- Release: September 2017 final
- Mapping version: `SP 800-190 (September 2017)`
- Official landing page:
  [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final)
- Official PDF:
  [NIST.SP.800-190.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- Reviewed PDF SHA-256:
  `0ebad52c4a3aba971b3a707b056e57238d1c4ad8f212dffd461ff9f5fed1bdb6`
- Machine-readable registry: [`registry.json`](registry.json)

The registry contains all 24 Section 4 countermeasure identifiers. It does not
turn Section 3 risks, Section 5 scenarios, Appendix B mappings, or lifecycle
discussion into additional requirements.

The publication states that it is not subject to copyright in the United
States and that attribution is appreciated. This repository stores the
reviewed identifiers, titles, source metadata, and digest; it does not
redistribute the PDF.

## Mapping boundary

Prefer the narrowest countermeasure section directly supported by executable
evidence. Do not attach every Section 4 item to one container control:

- `PSB-DETECT-001` implements `4.1.1` and `4.4.1` image and runtime software
  vulnerability detection; `4.1.3` remains allocated to a future
  malware-detection slice and is not mapped by the current control;
- `PSB-CODE-001` owns `4.1.4` secrets excluded from images;
- `PSB-CONTAINER-001` implements mappings for `4.1.5`, `4.3.3`, `4.4.2`,
  `4.4.3`, and `4.4.5`; future workload slices retain `4.1.2`, `4.3.2`, and
  `4.3.4` only when direct evidence exists;
- `PSB-CONTAINER-002` implements `4.2.1` through `4.2.3` registry transport,
  access, audit, and lifecycle mappings through provider-neutral E3 evidence;
- `PSB-CONTAINER-003` implements `4.3.1`, `4.3.5`, `4.5.1` through `4.5.5`,
  and `4.6` host OS, daemon, orchestrator node, and hardware-backed host
  mappings through provider-neutral Linux E3 evidence;
- `PSB-CONTAINER-004` owns `4.4.4` post-admission runtime behavior and alert
  evidence;
- application vulnerability prevention remains in secure-coding controls.

The duplicate-free ownership plan is recorded in
[`CONTAINER_SECURITY_SOURCE_ALLOCATION.md`](../../docs/CONTAINER_SECURITY_SOURCE_ALLOCATION.md).
