# Bootstrap the Product Security Engineering Blueprint

Read these files first:

- `AGENTS.md`
- `README.md`
- `docs/PROJECT_CHARTER.md`
- `docs/ARCHITECTURE.md`
- `docs/CONTROL_MODEL.md`
- `docs/REPOSITORY_STRUCTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/FRAMEWORK_MAPPING.md`
- `docs/CODEX_WORKFLOW.md`
- `docs/ROADMAP.md`

## Goal

Implement Phase 0 only.

Create the repository skeleton and foundational automation needed to support modular Product Security controls.

## Required deliverables

1. Directory structure from `docs/REPOSITORY_STRUCTURE.md`
2. `schemas/control.schema.json`
3. One minimal example control metadata file
4. Control metadata validation script
5. Generated control index script
6. Generated framework mapping index script
7. Root `Makefile`
8. Basic lint and test configuration
9. CODEOWNERS placeholder with clear replacement instructions
10. ADR describing the architecture decision

## Constraints

- Do not implement Phase 1 controls.
- Do not add Trivy, Semgrep, CodeGuard, cosign, or other heavy tools yet.
- Minimize dependencies.
- Pin every dependency.
- Do not use floating GitHub Action tags.
- Do not add broad workflow permissions.
- Do not create a monolithic generator script.
- Ensure commands work locally.
- Generated files must be reproducible.

## Required commands

```bash
make lint
make test
make validate-controls
make generate-index
make generate-mappings
```

## Completion report

At the end, report:

- files created;
- commands run;
- test results;
- assumptions;
- deferred work;
- security-sensitive decisions requiring review.

Stop after Phase 0 is complete.
