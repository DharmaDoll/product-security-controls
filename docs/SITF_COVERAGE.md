# SITF coverage and attack-flow profile

## Purpose and security boundary

The Supply-chain Attack Technique Framework (SITF) is used here as a
cross-component threat taxonomy. The profile answers two questions that an
individual control mapping cannot answer:

1. Which endpoint, VCS, CI/CD, registry, and production attack techniques have
   a direct executable repository control?
2. Which techniques can still connect those components into an attack path?

This is not a new control package, compliance assessment, maturity score, or
claim about live organization adoption. It does not change the meaning of a
passing fixture. `implemented` means exact repository checks directly address
the technique's primary behavior; partial coverage remains `gap` even when
supporting checks exist.

## Source identity and trust decision

The canonical source is Wiz Research
[`techniques.json` at
`d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59`](https://github.com/wiz-sec-public/SITF/blob/d1d1536da5cbc7107fb90ab3f5a4b1f62b21ea59/techniques.json).
The registry records Git blob
`19624258a63cae22a01ab08a9bac442cced3ae83` and SHA-256
`3f45ca1033e09deab0b66e432969c0b489b35965a4bf2f3299f5a3b24943887e`.
All 81 identifiers from that artifact are retained; source descriptions and
recommended controls are not copied.

The upstream `LICENSE` and README identify CC BY-NC 4.0, while its
`CITATION.cff` declares CC-BY-NC-ND-4.0. The registry preserves this conflict
instead of selecting a more permissive interpretation. Consumers must review
the upstream terms for their use case.

The Japanese
[`sitf-technique-library.md` at
`a84ef65bbf7cc83c8c0757ece3c6315abfd2f274`](https://github.com/kyohmizu/seccamp2026-B6/blob/a84ef65bbf7cc83c8c0757ece3c6315abfd2f274/chapter2/sitf-technique-library.md)
is a non-normative reading aid. It is not the identifier authority, is not
copied into generated output, and cannot change a disposition.

## Threat and failure scenario

An attacker can enter through one software-supply-chain component and reuse
credentials, artifacts, workflow authority, or network reachability to cross
several others. A catalog may appear strong when controls are counted
individually while a transition such as endpoint-to-VCS, fork-to-runner, or
registry-to-production remains open. A second failure source is optimistic
mapping: a generic scanner or partial boundary is mistakenly reported as full
coverage.

## Assumptions and acceptance criteria

The initial profile assumes the pinned SITF artifact is the complete source
inventory for this review and that full check identifiers from `control.yaml`
are the only current repository evidence. Live provider settings, telemetry,
adoption, evidence freshness, and active exceptions remain outside the result.

Generation succeeds only when:

- the registry has exactly 81 unique pinned technique identifiers;
- every registry technique occurs exactly once in the reconciliation;
- every current or supporting full check reference resolves;
- an `implemented` row has exact current check evidence and no remaining work;
- every `gap` has a component owner and technique-specific remaining work;
- every synthetic attack flow references known reconciled techniques and
  crosses at least three SITF components;
- missing or malformed input is an error rather than an empty clean result.

## Repository interfaces

Reviewed sources:

- [`frameworks/sitf/registry.json`](../frameworks/sitf/registry.json)
- [`policies/integration/sitf-coverage.json`](../policies/integration/sitf-coverage.json)
- [`policies/integration/sitf-attack-flows.json`](../policies/integration/sitf-attack-flows.json)

Generated views:

- [`generated/checklists/profiles/sitf/technique-coverage.csv`](../generated/checklists/profiles/sitf/technique-coverage.csv)
- [`generated/checklists/profiles/sitf/technique-coverage.md`](../generated/checklists/profiles/sitf/technique-coverage.md)
- [`generated/checklists/profiles/sitf/attack-flows.csv`](../generated/checklists/profiles/sitf/attack-flows.csv)
- [`generated/checklists/profiles/sitf/attack-flows.md`](../generated/checklists/profiles/sitf/attack-flows.md)
- `SITF Coverage` and `SITF Attack Flows` sheets in both generated workbooks.

Run:

```bash
make verify-sitf-coverage
make generate-checklists
make lint
```

`make verify-sitf-coverage` validates the source graph offline. It does not
download or execute SITF content.

## Initial result and priority gaps

The current reconciliation records 44 `implemented` and 37 `gap` techniques.
Counts are inventory signals, not a score. The most important missing outcomes
are:

- endpoint, CI/CD, registry, and production destructive-action recovery;
- source, CI/CD, private-artifact, and production data exfiltration controls;
- endpoint covert-control-channel detection and extension update integrity;
- CI/CD credentialed-job secret enumeration;
- extension publication and update integrity;
- production service-account, metadata, cloud lateral-movement, secret, and
  data-plane protections;
- malicious service provisioning and sensor or agent update poisoning.

The four synthetic flows keep those transitions visible: developer endpoint to
poisoned production image, cross-fork pipeline to production network, malicious
package to deployment, and AI workflow prompt injection to deployment. They
are review scenarios, not incident reports or upstream-authored flows.
