# Refactor Without Scope Drift

Read `AGENTS.md` and all architecture documents.

## Goal

Refactor the repository while preserving the Product Security Engineering Blueprint mission.

## Required checks

- controls remain organized by security outcome, not tool;
- GitHub repository hardening remains one domain, not the whole project;
- application security controls remain first-class;
- AI development security remains one domain;
- framework mappings remain machine-readable;
- control packages remain independently understandable;
- generated indexes remain reproducible;
- no control loses tests or evidence;
- no security invariant is weakened.

## Process

1. Identify current structural problems.
2. Propose the smallest coherent refactor.
3. List moved/renamed files.
4. Identify compatibility impact.
5. Implement in reviewable steps.
6. Run all validation and generation commands.
7. Confirm no orphaned mappings or control IDs.

Do not add new tools or controls during the refactor.
