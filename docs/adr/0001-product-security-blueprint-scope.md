# ADR-0001: Define the repository as a Product Security Engineering Blueprint

- Status: Accepted
- Date: 2026-07-25

## Context

The initial concept mixed Trivy validation, GitHub repository hardening, software supply-chain controls, and AI coding security without a clear hierarchy.

## Decision

The repository is defined as an executable Product Security Engineering Blueprint.

GitHub hardening, Trivy, CodeGuard, SLSA, SBOM, and related technologies are components within broader Product Security domains.

The repository is organized by security outcomes and controls, not by tools.

## Consequences

Positive:

- the project has a stable mission;
- application security and supply-chain security coexist naturally;
- each tool has a clear role;
- framework mappings can be attached to controls;
- users can locate implementation samples quickly.

Negative:

- the scope is broader;
- strict modularity is necessary;
- roadmap discipline is required to avoid becoming a security tool catalog.
