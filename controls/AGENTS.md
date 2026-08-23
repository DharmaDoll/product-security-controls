# Control implementation instructions

These instructions apply to every package below `controls/`.

## Adoption-first outcome

Each control is a small implementation project, not only a policy description.
An adopter should be able to copy or reference the secure implementation, run
one explicit activation step, execute a safe self-test, understand the expected
result, and remove the integration without changing global developer settings.

Every control README or linked adoption guide should lead with the shortest
supported path and state:

1. prerequisites and trust assumptions;
2. exact files to copy or reference;
3. one explicit local activation procedure;
4. a harmless positive and negative self-test;
5. expected output and exit status;
6. common failure recovery;
7. CI or server-side enforcement still required;
8. rollback steps and residual risk.

## Keep the implementation small

- Prefer repository-owned shell wrappers, standard-library code, and existing
  developer runtimes over a new framework or package manager.
- Do not add an orchestration framework solely to install or invoke one tool.
- Add a dependency only when it closes a documented gap that existing control
  code cannot close simply.
- Keep wrappers single-purpose. Use short named functions and direct data flow;
  avoid plugin systems, hidden discovery, dynamic imports, and configuration
  indirection unless the control requires them.
- Prefer copying a reviewed directory over a long sequence of generated files.
- Put organization-specific tuning after the working minimal path.

## External tools

- Pin a tool to an immutable version and artifact or container digest.
- Verify downloaded artifacts or rely on a digest-pinned approved registry.
- Make network access explicit. Runtime scanning should use network isolation
  when the scanner does not require network access.
- Treat missing runtimes, failed pulls, startup errors, malformed output, and
  scanner failures as errors, never as a clean scan.
- Document the authority of the runtime itself. For example, Docker daemon
  access is privileged and must already be approved on the developer endpoint.

## Safe activation

- Never install hooks silently.
- Never modify global Git, shell, IDE, package-manager, or OS settings.
- Require an explicit repository-local activation command.
- Refuse or clearly stop before overwriting an existing adopter configuration;
  merging remains an adopter-owned review step.
- Never put real credentials or provider-valid tokens in examples or tests.

## Verification

- Ship a self-test beside the copied implementation when feasible.
- Test one safe input, one inert finding, redaction, and fail-closed tool
  unavailability.
- Keep local fixture success separate from live organization adoption.
- Preserve the canonical `make verify-control CONTROL=<id>` interface.

## Nested instructions

Add a control-local `AGENTS.md` only when that control has concrete runtime,
language, evidence, or trust-boundary constraints not shared by other controls.
Do not copy this file into every package.
