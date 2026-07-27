# ADR-0002: Generate adoption checklists from control metadata

- Status: Accepted
- Date: 2026-07-27

## Context

Control packages explain security outcomes and contain executable positive and
negative examples, but their `verification.expected` entries are often
compound statements. A developer or platform owner cannot reliably use those
statements as an assessment checklist, assign responsibility, attach evidence,
or determine which framework relationship applies to an individual assertion.

Hand-maintained spreadsheets would improve discoverability but would introduce
a second source of truth, weak reviewability, and stale mappings.

## Decision

Each `control.yaml` defines atomic `checks`. Every check has:

- a stable control-local identifier;
- one assessable required state;
- a primary responsible role and target;
- a verification type, method, expected result, and required evidence;
- a mapping status.

Framework mappings declare `applies_to`, containing the check identifiers to
which their rationale applies. A check without a reviewed relationship is
explicitly marked `unmapped`; a framework relationship is never inferred from
the parent control.

Repository tooling generates deterministic user-facing views:

- one consolidated CSV;
- domain-specific CSV files;
- a Markdown preview;
- an XLSX guideline workbook;
- a separate XLSX assessment template with blank organization-owned fields.

The YAML metadata remains canonical. Generated spreadsheets must not contain
organization secrets, production evidence, or completed assessments.

## Consequences

Positive:

- developers can filter the catalog by role, target, or domain;
- every checklist row has an explicit verification and evidence expectation;
- framework relationships are traceable at assertion level;
- spreadsheet views can be regenerated whenever control metadata changes;
- assessment state remains separate from repository-owned guidance.

Negative:

- adding or changing a control requires maintaining atomic check metadata;
- existing control-level mappings require assertion-level review;
- XLSX generation code must be tested without introducing an unreviewed
  spreadsheet dependency;
- external evidence checks still require organization-specific integrations and
  must remain `NOT_CHECKED` until evidence is supplied.
