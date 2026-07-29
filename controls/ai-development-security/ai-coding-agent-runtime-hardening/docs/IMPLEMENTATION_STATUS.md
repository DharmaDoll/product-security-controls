# PSB-AI-004 implementation status

This file is the durable restart point for `PSB-AI-004`. Update it after each
completed phase so implementation can resume without relying on chat history.

Last updated: 2026-07-29

## Current state

Status: `sixth-slice-complete`

Current phase: Phase 24 complete. Select the next remaining scope before
starting Phase 25.

## Phase checklist

- [x] Phase 0: review repository invariants, architecture, control model,
  roadmap, planned control, schema, and existing control patterns.
- [x] Phase 1: define the provider-neutral first-slice policy and isolated
  Claude Code and Codex secure/insecure fixtures.
- [x] Phase 2: implement deterministic offline verification for secure,
  insecure, malformed, unsupported-version, and repository-downgrade cases.
- [x] Phase 3: add expected results, control metadata, row-level framework
  mappings, and operator documentation.
- [x] Phase 4: run control verification, repository validation, generators,
  lint, and the full test suite.
- [x] Phase 5: define second-slice action classes, assumptions, acceptance
  criteria, and deterministic approval evidence.
- [x] Phase 6: implement the read-only approval gate and secure, insecure,
  expired, replay, target-tamper, parameter-tamper, unavailable-validator, and
  malformed fixtures.
- [x] Phase 7: add atomic checklist rows, mappings, expected results, and
  operator documentation for the second slice.
- [x] Phase 8: regenerate indexes and spreadsheets and run control,
  repository, lint, and full-suite verification.
- [x] Phase 9: define third-slice extension identities, capability classes,
  low-frequency HITL policy, assumptions, and acceptance criteria.
- [x] Phase 10: implement Claude Code and Codex MCP adapter fixtures plus
  read-only, bounded-write, high-impact, destructive, unknown-tool,
  target-broadening, malformed, and policy-engine failure tests.
- [x] Phase 11: add atomic checklist rows, mappings, expected results, and
  operator documentation for the third slice.
- [x] Phase 12: regenerate indexes and spreadsheets and run control,
  repository, lint, and full-suite verification.
- [x] Phase 13: define the fourth-slice managed-hook assumptions, acceptance
  criteria, provider compatibility boundary, and fail-closed behavior.
- [x] Phase 14: implement provider input normalization, managed Claude Code
  and Codex hook adapters, and deterministic secure and failure fixtures.
- [x] Phase 15: add an atomic checklist row, mappings, expected results, and
  operator documentation for the fourth slice.
- [x] Phase 16: regenerate indexes and spreadsheets and run control,
  repository, lint, and full-suite verification.
- [x] Phase 17: define the fifth-slice issuer trust, actor identity,
  request-normalization, single-use ledger, failure behavior, and acceptance
  criteria.
- [x] Phase 18: implement reusable approval evaluation, signed evidence
  verification, and atomic single-use consumption.
- [x] Phase 19: connect signed approval to managed `PreToolUse` and add secure,
  tampered, expired, replayed, concurrent, and unavailable-state fixtures.
- [x] Phase 20: add atomic checklist rows, mappings, expected results,
  regenerate artifacts, and run the full verification sequence.
- [x] Phase 21: define the sixth-slice runtime inventory, audit schema,
  redaction, storage, failure behavior, assumptions, and acceptance criteria.
- [x] Phase 22: implement installed extension inventory verification and
  secure, drifted, stale, unavailable, and malformed fixtures.
- [x] Phase 23: integrate a sanitized append-only audit writer with managed
  `PreToolUse` and test allow, deny, error, redaction, and sink failure.
- [x] Phase 24: add atomic checklist rows, mappings, expected results,
  regenerate artifacts, and run the full verification sequence.

## First-slice scope

The first slice verifies the same seven outcomes for Claude Code and Codex:

1. sandbox or permission-profile isolation is enforced and fails closed;
2. writes are limited to the workspace and protected policy paths stay
   read-only;
3. a synthetic credential path cannot be read or written;
4. network access is denied by default;
5. source publication with `git push` requires explicit human approval;
6. dangerous bypass modes are unavailable;
7. repository-local configuration cannot broaden managed policy.

The verifier is read-only. It must not install either product, modify global
settings, contact a model, access a production service, or use a real secret.

## Remaining work after the first slice

- [complete] expand command classes beyond source publication;
- [complete] bind high-impact approval evidence to actor, agent, tool,
  target, normalized parameters, policy version, timestamp, and expiry;
- [partial: MCP, Skill authority, unreviewed plugin installation, installed
  runtime inventory, browser and computer-use defaults complete] add app,
  socket, metadata-service, proxy, and private-network capability checks;
- [partial: managed PreToolUse input, signed issuer authentication, local
  atomic consumption, policy and engine failure, replay, unknown parameters,
  and parameter tampering complete] add product hook process startup and
  timeout assessment, external-side-effect reconciliation, shell indirection,
  and remaining rule-failure fixtures;
- [partial: deterministic inventory and redacted hook audit evidence complete]
  add adopted fleet collector export ingestion alert and live client evidence.

## Third-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: an unapproved or identity-confused extension exposes
tools with broader effects than reviewed, or excessive prompts train the user
to approve high-impact operations without meaningful review.

HITL strategy:

- reviewed read-only tools: no human confirmation;
- narrowly targeted, reversible, idempotent low-risk writes: no human
  confirmation when all machine-checkable constraints pass;
- high-impact side effects: one bound approval at the execution gate;
- destructive, unknown, ambiguous, or policy-invalid calls: deny or `ERROR`
  without asking the human to override the control.

Assumptions:

- `PSB-AI-002` remains responsible for immutable extension source, digest,
  semantic review, and revocation; this slice consumes a synthetic approved
  dependency record but does not replace it;
- provider tool annotations are untrusted input and are checked against the
  repository-owned capability policy;
- fixture server URLs, identities, targets, and data are synthetic and no
  server is contacted;
- Skills are instructional dependencies and receive no direct runtime
  capability; unreviewed plugin installation and browser execution stay
  disabled in this slice.

Acceptance criteria:

- Claude Code and Codex allow only exact managed MCP identities and exact
  reviewed tool sets;
- routine reads and one constrained reversible update complete with zero HITL;
- source publication requires exactly one bound high-impact approval;
- destructive, unknown, effect-mismatched, or target-broadened invocations are
  denied rather than converted into additional prompts;
- missing engine state and malformed input return `ERROR`, never clean;
- console evidence contains extension/tool IDs and reasons but no request
  payload, target value, credential, or private URL.

## Fourth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: a bounded-write tool is configured for native
auto-approval but its target, payload size, or idempotency constraints are
never evaluated at the actual tool-call boundary, or a provider hook failure
is treated as permission to continue.

Assumptions:

- the managed endpoint separately installs the reviewed hook script and
  provider-neutral policy at the absolute sample paths; repository tests do
  not install hooks or change developer settings;
- both products send canonical MCP hook names in the form
  `mcp__<server>__<tool>` and tool arguments as `tool_input`;
- Claude Code supports `permissionDecision: "ask"` for `PreToolUse`; the
  reviewed Codex hook specification does not, so Codex preserves its managed
  native `prompt` decision instead of emitting an unsupported `ask`;
- a command hook exit code of `2` blocks `PreToolUse` in both reviewed
  products, so malformed input, missing policy, and unavailable engine state
  use exit `2` with a sanitized stderr reason;
- product-level hook process startup failure and timeout are not treated as
  equivalent to the gate's explicit exit `2` by this evidence, so bounded
  writes keep a native prompt fallback and become promptless only when the
  hook returns an explicit `allow`;
- this slice established the managed high-impact route; the fifth slice now
  authenticates and atomically consumes bound approval evidence before allow.

Acceptance criteria:

- managed-only hook policy prevents repository, user, and unreviewed plugin
  hooks from replacing or racing the enforcement hook;
- every MCP call, including unknown server and tool names, reaches the
  provider-neutral gate;
- reviewed reads and valid bounded writes are allowed without a new prompt;
- bounded writes with a wrong resource, oversized UTF-8 body, or missing
  idempotency key are denied before the MCP call;
- destructive and unknown MCP calls are denied without an override prompt;
- high-impact calls reach the managed approval route; after the fifth slice,
  both providers allow only valid signed evidence and deny missing or invalid
  evidence without relying on unsupported Codex `ask`;
- malformed hook input and unavailable policy evaluation exit `2`, never
  produce an allow response, and disclose no tool arguments.
- a hook process fault cannot fall through to a native automatic bounded
  write; the provider's normal permission prompt remains the fallback.

## Second-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: a prompt-injected or mistaken agent obtains a broad
approval, changes the target or parameters after review, reuses an old
approval, or continues when approval validation is unavailable.

Assumptions:

- native product prompts remain defense in depth; the provider-neutral gate is
  the final decision point before an adapter executes a classified operation;
- all fixture identities, repositories, timestamps, and digests are synthetic;
- fixture digests demonstrate canonical binding and tamper detection, not
  cryptographic proof that a production approval service issued the decision;
- a production adapter must authenticate approval evidence independently.

Acceptance criteria:

- dependency installation, source commit/publication/history rewrite, package
  publication, database mutation, infrastructure or cloud change, and
  deployment operations are explicitly classified;
- approval is bound to actor, agent, action class, tool, operation, target,
  normalized parameters, policy ID/revision, request digest, issue time, and
  expiry;
- the approver differs from the requesting actor;
- expiry, excessive lifetime, replay, target change, parameter change,
  unclassified operations, malformed evidence, and unavailable validation do
  not produce a clean result;
- output contains only identifiers and decision reasons, never target or
  parameter contents.

## Fifth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: a local process forges an unsigned approval JSON,
changes an approved pull-request target or parameter, or races two agent
invocations so the same approval authorizes multiple high-impact side effects.

Assumptions:

- the approval issuer signs canonical evidence outside this repository; only a
  synthetic public verification key and precomputed signatures are committed;
- managed endpoint tooling owns the actor-identity file, trust manifest,
  approval inbox, and SQLite ledger, and ordinary repository content cannot
  write those paths;
- a signed approval is selected by the SHA-256 digest of the normalized exact
  request rather than by an agent-controlled filename;
- approval consumption commits before the hook returns `allow`; a crash after
  consumption burns the approval and requires a new one rather than risking a
  replay;
- SQLite uniqueness makes consumption atomic among competing hook processes,
  but no local transaction can be atomic with an external MCP side effect;
  production adapters still require idempotency and reconciliation;
- the fixture verifier uses the managed `/usr/bin/openssl` path and treats
  unavailable crypto execution as `ERROR`, not as an invalid-but-clean
  approval.

Acceptance criteria:

- the exact normalized request binds managed actor identity, provider agent
  identity, action class, MCP tool operation, target, parameters, policy
  identity, and request digest;
- the signature verifies against an active exact key ID whose trust record
  binds the expected issuer and algorithm;
- unsigned, malformed, wrong-key, signature-tampered, expired, target-changed,
  parameter-changed, and unavailable-verifier evidence never returns `allow`;
- one valid approval produces one committed ledger row and a second or
  concurrent consumer cannot obtain another allow decision;
- both Claude Code and Codex return `allow` only after signature, binding,
  lifetime, and atomic single-use checks pass;
- missing approval returns a sanitized deny, while trust, crypto, actor-state,
  and ledger evaluation failures return exit `2`;
- output and ledger rows contain identifiers and digests but no target,
  parameter, body, credential, private URL, or signature value.

## Sixth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: a plugin, Skill, or MCP server installed before a
managed deny policy remains active without appearing in the reviewed runtime
set, or an agent invocation cannot be investigated because telemetry is
missing, contains raw prompts and tool arguments, or silently stops recording.

Control boundary:

- `PSB-AI-002` owns immutable dependency source, digest, semantic review,
  capability approval, and revocation;
- this slice consumes each approved `dependency_record_id` and verifies that a
  recent complete endpoint inventory contains exactly the runtime extensions
  expected by `PSB-AI-004`;
- this slice records enforcement decisions at the managed hook boundary; it
  does not claim that product-native telemetry or a workspace Compliance API
  contains every local file, action, or tool call.

Assumptions:

- an MDM or equivalent collector produces provider-specific inventory snapshots
  from outside repository authority and marks incomplete collection as
  unavailable rather than as an empty inventory;
- inventory IDs are not trusted by display name alone; kind, dependency record,
  MCP transport and exact URL, and Skill direct-authority state must match;
- audit files are written below an administrator-owned absolute directory with
  mode `0700`, use a non-symlink regular file with mode `0600`, and are exported
  to an organization-owned retention system before local rotation;
- audit records contain stable policy and tool identifiers plus hashed session,
  request, and approval references, but never prompt text, tool arguments,
  targets, tool output, credential values, signatures, or private URLs;
- failure to write the audit event for a would-be allow or deny prevents the
  hook from returning that decision; an evaluation error attempts a sanitized
  error event but remains exit `2` even when the sink is also unavailable;
- deterministic fixtures do not contact either provider, a model, a plugin
  directory, an MCP server, an OTel collector, or a production SIEM.

Acceptance criteria:

- recent complete Claude Code and Codex snapshots contain exactly the reviewed
  MCP and Skill runtime set and no installed plugin or unknown extension;
- unknown, missing, kind-confused, dependency-record-confused, stale, or
  incomplete inventory cannot produce a clean result;
- managed hook decisions append one fixed-schema record before provider output,
  covering `allow`, `deny`, and `error` without including request content;
- unexpected audit fields, missing decision coverage, excessive retention,
  broad storage permissions, symlinked paths, malformed events, and unavailable
  audit state do not produce a clean result;
- a write failure at the audit boundary returns exit `2` and never emits an
  `allow` provider response;
- console and generated checklist evidence contain only check IDs, provider,
  decision reasons, and reviewed mappings.

## Resume command

```bash
make verify-control CONTROL=PSB-AI-004
```

The 2026-07-29 completion run passed:

- `make verify-control CONTROL=PSB-AI-004`;
- `make validate-controls`;
- `make generate`;
- `make lint`;
- `make test` (42 repository tests and all 17 control packages).

The second-slice completion run on the same date repeated all commands above
after adding four approval checks, nine approval result fixtures, action-class
uniqueness validation, and regenerated checklist artifacts.

The third-slice completion run on the same date repeated all commands after
adding three extension and HITL checks, exact Claude Code and Codex MCP
adapters, zero-confirmation read and bounded-write fixtures, one-confirmation
high-impact routing, and deny/error negative fixtures.

The fourth-slice completion run on the same date repeated all commands after
adding `AAR-015`, managed-only Claude Code and Codex `PreToolUse` definitions,
provider input normalization, runtime target/UTF-8-size/idempotency
enforcement, prompt fallback for hook-process faults, explicit exit-2
fail-closed cases, and regenerated row-level checklist and mapping artifacts.

The fifth-slice completion run on the same date repeated all commands after
adding `AAR-016` and `AAR-017`, exact request normalization, digest-selected
signed evidence, digest-pinned issuer trust, OpenSSL 3 signature verification,
SQLite immediate-transaction uniqueness, sequential and concurrent replay
tests, both-provider hook integration, and malformed, untrusted-key, forged,
expired, target-changed, unknown-parameter, unavailable-verifier,
unavailable-actor, and corrupt-ledger failure cases.

The sixth-slice completion run on the same date repeated all commands after
adding `AAR-018` and `AAR-019`, recent complete provider-versioned runtime
inventory reconciliation, unknown plugin and identity-confusion fixtures,
fixed-schema hashed-reference allow/deny/error audit events, no-follow
permission-bounded append and `fsync`, generated audit verification, and
stale, unavailable, malformed, leakage, excessive-retention, missing-directory,
and symlink-sink failure cases.

For the next slice, start with a selected incomplete outcome under
“Remaining work after the first slice”, update this status to `in-progress`,
and add its secure, insecure, failure, and sanitized-evidence fixtures before
marking another phase complete.
