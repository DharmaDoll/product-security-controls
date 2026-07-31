# Container Security Source Allocation

## Purpose

This document assigns three container-security sources to distinct repository
roles without registering the same source as both a framework and general
guidance. It also prevents all container outcomes from being absorbed into one
oversized control.

| Source | Repository role | Pinned state | Mapping behavior |
|---|---|---|---|
| NIST SP 800-190 | active `implementation-guidance` framework registry | September 2017 final; official PDF SHA-256 recorded | Section 4 identifiers may be used in reviewed `control.yaml` mappings |
| CIS Docker Benchmark | `requirement-framework` candidate | official site identifies v1.8.0; authorized PDF snapshot not present | no registry and no mapping until the official PDF, hash, recommendation inventory, and reuse terms are reviewed |
| OWASP Docker Security Cheat Sheet | non-framework reference guidance | file commit `cb62ae45198d07302082d4725fc3bdfe24b25dd3` | informs examples and tests; never used as a `control.yaml` framework mapping |

This classification is intentionally exclusive. NIST SP 800-190 and CIS
Docker Benchmark are not duplicated in
`SECURITY_GUIDANCE_SOURCES.md`; the OWASP cheat sheet is not added under
`frameworks/`.

## Source boundaries

### NIST SP 800-190

The
[`nist-sp-800-190` registry](../frameworks/nist-sp-800-190/README.md)
provides the primary product-neutral countermeasure identifiers. Its Section 4
entries define *why* an outcome matters across image, registry, orchestrator,
container, host OS, and hardware boundaries.

### CIS Docker Benchmark

The official
[CIS Docker Benchmark page](https://www.cisecurity.org/benchmark/docker)
identifies Docker `1.8.0` as the recent version. CIS distributes benchmark PDFs
for non-commercial use through a form and applies separate reuse terms. The
repository has not received an authorized PDF snapshot and therefore does not
copy recommendation titles from third-party mirrors, invent identifiers, or
create an active registry.

Activation requires:

1. an official v1.8.0 PDF obtained under applicable terms;
2. its SHA-256 and acquisition date;
3. a reviewed recommendation and profile inventory;
4. confirmation that storing identifiers and titles is permitted;
5. a subset mapped to executable Docker-specific evidence.

Until then, CIS is the planned product-specific benchmark for Docker host,
daemon, image, runtime, and optional Swarm configuration. It is not evidence
that `PSB-CONTAINER-001` meets a CIS profile.

### OWASP Docker Security Cheat Sheet

[`REF-CONTAINER-001`](SECURITY_GUIDANCE_SOURCES.md#ref-container-001)
is the implementation-oriented reference. Its rules help shape insecure and
secure examples, operational notes, and negative tests. They do not supply
formal requirement IDs or compliance evidence.

## Duplicate-free control ownership

Every one of the 24 NIST SP 800-190 Section 4 registry identifiers has one
primary planned owner in this table or the registry README. A second control
may consume the resulting evidence, but it must not create a duplicate
checklist row or claim the same implementation responsibility.

| Security outcome | Primary control owner | NIST SP 800-190 mapping candidates | OWASP reference contribution | CIS role after activation |
|---|---|---|---|---|
| Image and runtime vulnerability detection | `PSB-DETECT-001` | `4.1.1`, `4.4.1`; `4.1.3` remains a future malware-detection slice | Rules 0 and 9 | Docker-specific audit checks |
| Immutable and trusted image admission, including SLSA provenance consumption | `PSB-CONTAINER-001` composed with `PSB-REL-001` | `4.1.5`, `4.4.5` | Rule 13 | exact Docker image and runtime recommendations |
| Non-root and privilege-escalation prevention | `PSB-CONTAINER-001` | `4.4.3`; host-account rights under `4.5.4` remain `PSB-CONTAINER-003` | Rules 2, 3, 4, and 11 | exact workload user, namespace, and capability recommendations |
| Read-only filesystem and constrained runtime | `PSB-CONTAINER-001` | `4.4.3` | Rules 6, 7, and 8 | exact runtime configuration recommendations |
| Network segmentation and bounded exposure | `PSB-CONTAINER-001` | `4.3.3`, `4.3.4`, `4.4.2` | Rules 5 and 5a | exact daemon and container network recommendations |
| Admission fail-closed behavior | `PSB-CONTAINER-001` | `4.1.2`, `4.1.5`, `4.4.5` | Kubernetes admission examples under Rules 2 through 4 | relevant automated and manual runtime checks |
| Secrets excluded from images | `PSB-CODE-001` | `4.1.4` | Rule 12 | image-build secret recommendations |
| Registry transport, authentication, authorization, audit, and stale-image lifecycle | `PSB-CONTAINER-002` | `4.2.1`, `4.2.2`, `4.2.3` | supporting registry and supply-chain examples | registry-specific recommendations |
| Container host, daemon, orchestrator administration, and node trust | `PSB-CONTAINER-003` | `4.3.1`, `4.3.5`, `4.5.1` through `4.5.5`, `4.6` | Rules 0, 1, 10, and 11 | primary Docker-specific benchmark evidence |
| Runtime behavioral monitoring | `PSB-CONTAINER-004` | `4.4.4` | Rule 6 | relevant logging and audit recommendations |
| Application vulnerabilities inside containers | secure-coding controls | use ASVS or another application requirement; NIST `4.4.4` remains allocated to container-aware runtime defense | no duplicate container control | not owned by a container-runtime control |
| Build provenance generation and distribution | `PSB-BUILD-003` and `PSB-REL-002` | none; SLSA is the primary framework | Rule 13 | image trust checks, without replacing SLSA evidence |
| SLSA provenance authenticity and image-subject verification | `PSB-REL-001`; consumed by `PSB-CONTAINER-001` admission | NIST `4.1.5` stays with the admission check; release controls retain SLSA mappings | Rule 13 | image identity checks, without claiming a CIS profile |

Mapping candidates are provisional. They become reviewed mappings only when an
implemented control has an atomic check, runnable verification, negative
fixture, and rationale that directly supports the cited identifier.

`PSB-CONTAINER-004` now meets that implementation threshold for NIST
`4.4.4`. Falco and Sysdig supply representative provider adapters through
[`REF-CONTAINER-003`](SECURITY_GUIDANCE_SOURCES.md#ref-container-003) and
[`REF-CONTAINER-004`](SECURITY_GUIDANCE_SOURCES.md#ref-container-004);
they are tool references, not framework mappings or mandatory products.

## SLSA relationship

SLSA v1.2 treats a container image as a build artifact. The trust flow is:

```text
PSB-BUILD-002  approved hosted build platform
        |
PSB-BUILD-003  platform-generated authentic provenance
        |
PSB-REL-002    provenance distributed with the exact image artifact
        |
PSB-REL-001    consumer verifies provenance and subject digest
        |
PSB-CONTAINER-001 admission binds allow/deny to the exact OCI digest
```

Only the last consumer-verification composition is new container work. The
existing producer, platform, distribution, and consumer controls retain their
SLSA mappings. `PSB-CONTAINER-001` may receive
`build-l2#consumer-validates-authenticity` and `build-provenance` mappings only
for an atomic check that actually reruns or consumes authenticated
`PSB-REL-001` evidence for the exact admitted digest.

`PSB-CONTAINER-002` can protect registry availability, authorization, mutation,
audit, and evidence retention, but those operational states are not themselves
SLSA Build requirements. `PSB-CONTAINER-003` host hardening and
`PSB-CONTAINER-004` runtime detection are outside the SLSA Build track. They
must not be mapped to Build L3 merely because a hardened host or runtime is
used; Build L3 concerns the build system trust boundary, not the production
container host.

## PSB-CONTAINER-001 implemented first-slice boundary

The implemented E3 slice provides Kubernetes workload and admission-policy
verification for:

- exact image digest;
- non-root user;
- privilege escalation disabled;
- all Linux capabilities dropped unless explicitly required;
- no privileged mode, host namespaces, host paths, or runtime socket;
- read-only root filesystem;
- seccomp profile;
- CPU, memory, and process limits where supported;
- admission evaluation errors distinct from an allow decision.

It also reruns `PSB-REL-001` and binds authenticated provenance to the exact
OCI manifest digest before returning allow. Only that atomic provenance check
receives SLSA consumer mappings; the workload hardening rows do not.

Docker host configuration, image scanning, embedded-secret detection, registry
access, runtime behavioral monitoring, application vulnerabilities, and
release signing remain with the owners in the table. `PSB-CONTAINER-002..004`
retain the registry, host or daemon, and post-admission detection boundaries.
This keeps each control executable and prevents overlapping checklist rows.
