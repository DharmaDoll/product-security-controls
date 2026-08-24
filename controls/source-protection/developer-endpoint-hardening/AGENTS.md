# PSB-SOURCE-001 implementation instructions

This package implements the developer-endpoint trust boundary as a small,
portable policy baseline plus sanitized read-only assessment. It is not an MDM,
EDR, identity, network, backup, or developer-platform product.

## Control boundary

- The control ID is `PSB-SOURCE-001` and the domain is `source-protection`.
- Protect source, local credentials, development sessions, and host interfaces
  from device theft, malware, unsafe local execution, excessive privilege,
  exposed services, and accidental configuration drift.
- Own locally observable endpoint and development-runtime state, the distinction
  between local and organization-owned evidence, and fail-closed assessment
  behavior.
- Add a check here only when its primary target is the developer endpoint or
  local development runtime and it changes endpoint exposure even when related
  repository, dependency, identity, and CI controls pass.
- Do not turn this package into a general workstation bootstrapper or a catalog
  of endpoint-security products.

## Supported implementation profile

- Treat Apple Silicon macOS as the primary adopter profile and the existing
  Linux adapter as the secondary profile. Do not add Windows support without a
  concrete adopter requirement and tests.
- Keep Python code compatible with Python 3.10+ and standard-library only unless
  an existing repository dependency closes a documented implementation gap.
- The shortest path must not require Docker. Docker and VS Code Dev Containers
  are optional isolation examples for adopters that already trust and operate
  the Docker daemon.
- Use project-local VS Code, Dev Container, Git, and policy files. Never modify
  global Git, shell, editor, package-manager, Docker Desktop, or OS settings.
- Never require `sudo` for the basic assessment or self-test. Host-changing or
  MDM activation belongs in an explicitly separated, administrator-reviewed
  adoption step and must not run from fixture tests.
- Prefer portable security outcomes over vendor-specific MDM, EDR/XDR, IdP,
  SWG/CASB, secret-manager, or cloud-workstation configuration.

## Minimal adoption experience

- Lead the README, immediately after the mandatory one-page summary, with the
  shortest supported path: prerequisites, exact files to copy or reference, one
  explicit repository-local activation step, self-test, expected status and
  exit code, recovery, rollback, server-side requirements, and residual risk.
- Keep the basic path reviewable as a few files and direct commands. Do not add
  an installer framework, plugin system, or package manager for this control.
- Refuse to overwrite an existing adopter configuration. Merging configuration
  remains an adopter-owned review step.
- Rollback must remove only files and repository-local settings created by the
  activation step. It must not weaken host or organization security policy.
- Keep environment-specific thresholds and vendor wiring in a clearly marked
  adopter-tuning section after the working minimal path.

## Assessment and evidence

- Assess the current execution environment without changing it. When running
  inside a container, cloud workspace, or agent sandbox, state clearly that the
  result does not describe the underlying physical Mac or Linux host.
- macOS collectors must use platform-provided read-only interfaces, require no
  elevation, and emit only normalized states. Linux collectors follow the same
  contract.
- Never emit usernames, home directories, device serial numbers, IP addresses,
  raw listener listings, credential values, secret matches, or unnecessary
  host identifiers.
- Use `PASS` only when a supported read-only observation establishes the
  required local state. Use `FAIL` for an established unsafe state,
  `NOT_CHECKED` for unsupported or organization-owned evidence, and `ERROR` for
  command, parser, permission, malformed-input, or evidence failures.
- Do not infer MDM enrollment, EDR health, IdP lifecycle, egress enforcement,
  backup protection, physical custody, or repository policy from a local
  fixture. Keep those checks as external evidence or `NOT_CHECKED`.
- Live assessment is not organization adoption evidence. Keep host-specific
  output below the ignored `generated/assessments/` path.

## Keep endpoint checks useful

- Prefer a small set of reliable signals over broad but weak detection. A check
  that cannot distinguish secure, insecure, unknown, and execution-failure
  states should remain manual or external evidence.
- Do not hard-code ambiguous slogans such as "latest software" or "high-risk
  development." When an implementation depends on them, define a measurable
  adopter policy such as supported versions, remediation deadlines, workload
  classes, allowed destinations, exact writable paths, or approved services.
- Do not make the entire source workspace read-only for ordinary interactive
  development. For untrusted execution, grant only the minimum required
  writable project path and exclude host credentials, unrelated directories,
  runtime sockets, and broad network access.
- Do not require application allowlisting, EDR, MDM, managed egress, hardware
  keys, or a cloud workspace merely to run the local assessment. These are
  organization guardrails with separately reviewed evidence.

## Relationship to other controls

- Extract the endpoint-specific outcome and compose existing controls instead
  of copying their implementations into this package.
- `PSB-SOURCE-002` owns repository Git-hook installation and local secret or
  sensitive-file blocking. This control may assess or reference its activated
  state but must not implement a second hook framework or scanner.
- `PSB-DEPS-001..003` own dependency cooldown, managed registry routing,
  install-time execution policy, frozen graphs, and artifact integrity.
- `PSB-SOURCE-004` owns source-platform OAuth, PAT, SSH, App credential
  inventory, lifetime, revocation, and audit. This control owns only endpoint
  storage and ambient-use exposure.
- `PSB-AI-002` and `PSB-AI-004` own AI dependency governance and coding-agent
  runtime authorization, sandbox, credential, and network policy. This control
  owns the host boundary those runtimes execute against.
- Repository-side scanning, branch enforcement, CI credentials, and build or
  release isolation remain with their domain controls. A passing endpoint
  assessment must never imply those controls pass.
- Reference exact control/check identities and canonical verification commands
  when composition is needed. Do not duplicate scripts merely to make this
  package appear self-contained.

## Verification strategy

- Keep tests human-readable and proportional to the behavior being claimed.
- For each implemented parser or atomic local behavior, prefer one clear safe
  case, one inert unsafe case, one unresolved case where relevant, and one
  fail-closed execution or malformed-evidence case. Avoid low-value permutation
  tests.
- Test macOS and Linux collectors with sanitized normalized fixtures or captured
  command output; tests must not change the CI host or require the target OS.
- Keep fixture verification separate from the live read-only smoke test. The
  live test may validate schema, sanitization, and supported exit codes, but
  must not require the executing host to be compliant.
- Do not mock MDM, EDR, IdP, network, backup, or physical-security systems solely
  to manufacture a passing test. Document the evidence contract and leave the
  result `NOT_CHECKED` until a real adapter is justified.
- Real secrets, provider-valid tokens, personal data, malware, destructive
  commands, and production endpoint evidence are prohibited. Use inert data and
  verify redaction.
- Scanner or assessment failure must never be interpreted as a clean result.
- If a meaningful automated test is infeasible, document the limitation and the
  required external evidence instead of adding a tautological assertion.

## Metadata and documentation

- `control.yaml` remains canonical for atomic checks. Preserve
  `check_context_version: "1.0"` and control-specific threat actor, scenario,
  target, and necessity context for every check.
- Do not keep a check merely to preserve a large checklist. Narrow, remove, or
  compose duplicated scope through normal repository review, then regenerate
  indexes and mappings.
- An external-evidence check is valid when the security outcome is essential
  but cannot be proven locally. Do not promote it to `PASS` from policy text or
  fixture success.
- Keep literal check counts synchronized or avoid embedding them in prose.
- Treat the control-local Japanese baseline as user-supplied, unverified
  guidance until its publisher, title, version, URL, and integrity metadata are
  supplied. Product names in that input are examples, not dependencies.
- Framework mappings remain check-specific reviewed relationships, not
  compliance or complete endpoint-security claims.

## Required verification after changes

From this package, run:

```bash
bash tests/test.sh
```

From the repository root, also run the canonical commands affected by the
change, normally:

```bash
make verify-control CONTROL=PSB-SOURCE-001
make validate-controls
```

Update sanitized expected results only when a reviewed behavior or evidence
contract intentionally changes. Never weaken a check to make a host-dependent
test pass.
