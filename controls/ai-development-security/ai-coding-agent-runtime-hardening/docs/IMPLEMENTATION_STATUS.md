# PSB-AI-004 implementation status

This file is the durable restart point for `PSB-AI-004`. Update it after each
completed phase so implementation can resume without relying on chat history.

Last updated: 2026-07-29

## Current state

Status: `twelfth-slice-complete`

Current phase: Phase 48 complete. Collector evidence origin authentication,
payload integrity, freshness, and monotonic replay protection are implemented
as deterministic reference evidence.

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
- [x] Phase 25: define seventh-slice network threat, control boundary,
  assumptions, and acceptance criteria.
- [x] Phase 26: implement the provider-neutral network policy and offline
  verifier.
- [x] Phase 27: add exact-destination, DNS rebinding, private/local/metadata,
  proxy, local-listener, Unix socket, malformed, and unavailable fixtures.
- [x] Phase 28: add atomic checklist rows, mappings, documentation, regenerate
  artifacts, and run the full verification sequence.
- [x] Phase 29: define eighth-slice hook-failure threat, official product
  behavior boundary, assumptions, and acceptance criteria.
- [x] Phase 30: implement the provider-neutral downstream hook-permit policy
  and offline verifier.
- [x] Phase 31: add both-provider completed, denied, not-started, timed-out,
  abnormal-exit, invalid-output, bypass, gateway-unavailable, and malformed
  fixtures.
- [x] Phase 32: add atomic checklist rows, mappings, documentation, regenerate
  artifacts, and run the full verification sequence.
- [x] Phase 33: define ninth-slice uncertain-outcome threat, transaction
  boundary, assumptions, and acceptance criteria.
- [x] Phase 34: implement the provider-neutral side-effect reconciliation
  policy and offline state verifier.
- [x] Phase 35: add applied, timeout-after-apply, timeout-before-apply,
  replacement-approval retry, unknown outcome, replay, duplicate-mutation,
  unavailable, and malformed fixtures.
- [x] Phase 36: add atomic checklist rows, mappings, documentation, regenerate
  artifacts, and run the full verification sequence.
- [x] Phase 37: define tenth-slice command-indirection threat, trusted
  normalization boundary, assumptions, and acceptance criteria.
- [x] Phase 38: implement the provider-neutral typed command broker policy and
  offline classifier.
- [x] Phase 39: add direct argv, environment wrapper, shell string, script,
  task runner, Git alias, unknown command, unavailable engine, and malformed
  fixtures.
- [x] Phase 40: add atomic checklist rows, mappings, documentation, regenerate
  artifacts, and run the full verification sequence.
- [x] Phase 41: define eleventh-slice telemetry adoption threat, evidence
  boundary, assumptions, and acceptance criteria.
- [x] Phase 42: implement the fleet telemetry policy and offline verifier.
- [x] Phase 43: add both-provider enrollment, ingestion freshness, sequence
  gap, forbidden content, alert delivery, unavailable collector, and malformed
  fixtures.
- [x] Phase 44: add atomic checklist rows, mappings, documentation, regenerate
  artifacts, and run the full verification sequence.
- [x] Phase 45: define twelfth-slice collector evidence forgery and replay
  threat, trust boundary, assumptions, and acceptance criteria.
- [x] Phase 46: implement the fleet evidence trust policy, signature and
  checkpoint verifier, and isolated synthetic trust root.
- [x] Phase 47: add secure, payload-tampered, signature-tampered, untrusted-key,
  replayed, unavailable-verifier, and malformed fixtures.
- [x] Phase 48: add atomic checklist rows, mappings, documentation, regenerate
  artifacts, and run the full verification sequence.

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
  runtime inventory, browser and computer-use defaults, socket,
  metadata-service, proxy, and private-network command-egress checks complete]
  add remaining app-specific and live provider network-surface checks;
- [partial: managed PreToolUse input, signed issuer authentication, local
  atomic consumption, policy and engine failure, replay, unknown parameters,
  parameter tampering, and synthetic hook startup/timeout/downstream permit
  assessment, synthetic external-side-effect reconciliation, and typed command
  indirection classification complete] add live product/backend/broker failure
  injection and remaining rule-failure fixtures;
- [partial: deterministic inventory, redacted hook audit, and synthetic adopted
  fleet collector, export ingestion, and alert evidence complete] add live
  organization-owned client, collector, SIEM, and receiver evidence.

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

## Seventh-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: a prompt-injected agent or compromised tool uses
temporarily enabled network access to exfiltrate source or credentials, reach a
cloud metadata service or local daemon, pivot through a private network or
upstream proxy, or exploit DNS rebinding between policy evaluation and the
actual connection.

Control boundary:

- `AAR-004` remains the primary default: command network access is off;
- this slice covers only an explicitly selected destination-specific profile
  for tasks whose reviewed MCP endpoint cannot run offline;
- the sample gateway consumes managed policy and resolver evidence without
  performing DNS queries or contacting a destination during repository tests;
- browser, connector, web-search, product control-plane, and MCP server-side
  egress remain separate network surfaces.

Assumptions:

- a managed network proxy or lower-layer egress gateway enforces the same
  exact-host, port, path, resolved-address, and connection-address decision;
- resolver evidence is complete, recent, produced outside repository
  authority, and cannot be replaced by the agent;
- exact synthetic `.invalid` destinations and public IP addresses are fixtures
  only; no network request is made;
- upstream proxies, SOCKS, local listener exposure, private/local addresses,
  metadata endpoints, and Unix sockets are unnecessary for the sample task;
- product-specific network settings are reviewed against the official
  documentation baseline before fleet deployment.

Acceptance criteria:

- network-off remains the ordinary profile and enabling the bounded profile
  without the independent gateway is an error;
- only exact HTTPS hosts, port 443, and reviewed path prefixes are accepted;
  wildcard hosts, IP-literal URLs, userinfo, fragments, unreviewed ports,
  cleartext HTTP, and lookalike subdomains are denied;
- proxy environment use, SOCKS, non-loopback local listeners, Unix sockets,
  localhost, private, loopback, link-local, multicast, reserved, unspecified,
  and known metadata destinations are denied;
- DNS failure, timeout, stale evidence, hostname mismatch, malformed address
  evidence, and an actual connection address not present in the reviewed
  resolution set return `ERROR` or `FAIL`, never allow;
- all resolved and connected addresses must remain globally routable, and the
  transport layer must bind the connection to the classified address to reduce
  DNS rebinding risk;
- outputs contain only scenario IDs, check IDs, and reason classes, never URLs,
  hostnames, addresses, proxy values, or request content.

## Eighth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: a managed `PreToolUse` hook is configured but cannot
start, exceeds its timeout, exits unexpectedly, or returns invalid output, and
the product reports a hook error while continuing a side-effecting MCP call.

Control boundary:

- explicit provider-native deny output and exit `2` remain defense in depth;
- a product hook process is not the sole authorization boundary for remote
  side effects because startup and timeout behavior is not equivalent to a
  verified deny across reviewed providers and versions;
- an independent MCP-side gateway requires a request-bound permit created only
  after the managed hook completes, records its sanitized decision, and returns
  allow;
- this slice verifies synthetic lifecycle and gateway evidence offline; it does
  not start either product or contact an MCP server.

Assumptions:

- the MCP-side gateway and permit state are outside repository, agent, plugin,
  user, and product-hook write authority;
- the production permit issuer authenticates and binds a short-lived,
  single-request permit to the normalized tool call; this slice models the
  state transition but does not commit an issuer private key;
- the side-effecting MCP implementation rejects missing, invalid, replayed, or
  unverifiable permits before mutation;
- provider-native continuation after hook failure is treated as hostile input,
  not as authorization;
- all identities, versions, request references, permits, and outcomes in
  fixtures are synthetic and contain no secret or target value.

Acceptance criteria:

- both reviewed providers pass a completed allow only when managed matching,
  exit `0`, valid allow output, pre-output audit commit, exact request binding,
  trusted permit state, mandatory gateway enforcement, and the gateway allow
  all agree;
- explicit deny, not-started, timed-out, abnormal-exit, and invalid-output
  cases produce no valid permit and no observed external side effect, even when
  the native product would otherwise continue;
- optional or bypassed gateway enforcement with an observed side effect is a
  finding;
- unavailable gateway or permit verification and malformed lifecycle evidence
  return `ERROR`, never allow or a clean result;
- HITL policy is unchanged: routine reviewed operations remain automatic and
  high-impact actions still use the one bound approval from earlier slices;
- output contains provider, scenario ID, check ID, and reason class only, never
  hook input, tool arguments, targets, permit contents, or remote URLs.

## Ninth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: the local gate atomically consumes an approval and
dispatches a remote MCP mutation, but the response is lost or times out, so an
agent retries with a restored approval or new idempotency key and executes the
side effect twice.

Control boundary:

- local SQLite approval consumption remains atomic only on the endpoint;
- the remote side-effect gateway owns an idempotency record bound to the exact
  normalized request digest and exposes an authenticated outcome lookup;
- reconciliation never rolls back or restores the original consumed approval;
- this slice validates synthetic state offline and does not contact or mutate a
  production backend.

Assumptions:

- the backend checks the idempotency key and request digest before mutation and
  returns a conflict when one key is reused for different content;
- gateway outcome evidence is protected from repository, agent, plugin, and
  ordinary developer writes;
- a replacement approval is independently issued only after a complete
  `not-applied` outcome and remains bound to the same exact request and
  idempotency key;
- `unknown`, unavailable, inconsistent, or conflicting outcome state is not
  converted into an automatic retry;
- all request digests, approval IDs, idempotency keys, attempts, and mutation
  references in fixtures are synthetic.

Acceptance criteria:

- original approval consumption is committed before the first dispatch and is
  never restored or reused for a new logical attempt;
- every dispatch carries the same request digest and idempotency key, and the
  backend enforces their one-to-one binding;
- a successful or timeout-after-apply lookup completes without retry and
  observes at most one mutation;
- timeout-before-apply requires a distinct consumed replacement approval before
  retry, while preserving the original idempotency key and exact request;
- unknown outcome blocks, reports no automatic retry, and requires operator
  reconciliation rather than assuming success or failure;
- approval restoration, automatic retry, changed idempotency key or digest,
  more than one mutation, and incomplete outcome evidence are findings;
- unavailable reconciliation or malformed state returns `ERROR`;
- outputs contain only scenario ID, check ID, and reason class, never target,
  parameters, backend URL, credential, approval content, or mutation data.

## Tenth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: action policy recognizes a direct `git push` or
package publication command, but an agent invokes the same operation through
`env`, a shell `-c` string, executable script, task runner, Git alias, or
unknown wrapper and obtains automatic execution.

Control boundary:

- a managed command broker receives provider input before generic command
  execution and produces a typed action class, decision, and HITL route;
- exact direct argv and reviewed environment assignment wrappers may be
  normalized, while shell strings, scripts, task runners, interpreters, and
  unresolved aliases are not considered equivalent to a safe direct command;
- denied indirection is not rescued with repeated human prompts; a reviewed
  typed action must be used when the operation is genuinely required;
- this slice classifies synthetic invocations offline and does not execute any
  command or script.

Assumptions:

- provider adapters preserve argv boundaries or mark input as a shell string;
- executable resolution, Git alias resolution, and broker state are produced
  by managed code outside repository and agent write authority;
- the broker policy covers the high-impact classes already defined by
  `PSB-AI-004`, while unknown or ambiguous operations default deny;
- script and task-runner contents can change after review, so this slice does
  not auto-approve them based on display name;
- all command names, arguments, aliases, paths, and targets are synthetic and
  no real process is launched.

Acceptance criteria:

- reviewed read-only direct argv remains zero-HITL;
- direct high-impact argv and completely resolved reviewed Git aliases map to
  exactly one action class and one bound approval;
- environment assignment wrappers preserve classification only when the final
  executable and argv are unambiguous;
- shell `-c`, interpreter code, scripts, task runners, unknown wrappers,
  unresolved aliases, ambiguous resolution, and unknown operations are denied
  without an override prompt;
- a substring-only broker that automatically allows wrapped high-impact
  commands is a finding;
- unavailable resolution or policy engine and malformed invocation evidence
  return `ERROR`;
- output contains provider, scenario ID, check ID, decision class, and reason
  only, never command arguments, environment values, target, script content, or
  path.

## Eleventh-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: endpoint policy writes local sanitized events, but a
provider is not enrolled, export silently stops, ingestion develops gaps, raw
request content enters the collector, or alert rules never deliver, leaving
the organization unable to detect runtime drift and fail-open activity.

Control boundary:

- `AAR-019` owns local fixed-schema pre-execution audit creation and storage;
- this slice verifies managed fleet enrollment, export receipt, centralized
  ingestion state, content classification, sequence completeness, and tested
  alert delivery for both reviewed providers;
- server-side tool outcomes and backend mutations remain distinct evidence
  joined by hashed references rather than copied request content;
- repository tests use synthetic adoption snapshots and do not contact a SIEM,
  page an operator, or read production logs.

Assumptions:

- collector snapshots are produced by organization-managed inventory and
  logging systems outside repository and agent write authority;
- export transport authenticates endpoints and centralized storage is
  immutable to ordinary developers and agents;
- sequence and lag state reflect every expected endpoint event rather than a
  sampled subset;
- alert tests use synthetic events and an organization-owned delivery receipt;
- no prompt, transcript, tool input, parameter, target, body, output,
  credential, signature, private URL, or permit content is needed for alerts.

Acceptance criteria:

- recent managed snapshots include both Claude Code and Codex endpoint classes
  with enrollment, export, ingestion, and sequence state complete;
- ingestion lag is at most five minutes, no sequence gap exists, rejected or
  quarantined records are explicitly accounted for, and centralized evidence
  is immutable and access-controlled;
- collector field classification remains metadata-only and no forbidden
  content field appears;
- required alerts cover unknown extension, hook failure, audit sink failure,
  gateway bypass, approval replay, reconciliation unknown, and command broker
  bypass;
- every alert is enabled and has a recent synthetic delivery receipt within
  the maximum latency;
- missing provider adoption, stale ingestion, sequence gaps, broad storage,
  content leakage, disabled rule, or failed delivery is a finding;
- unavailable collector or alert verification and malformed evidence return
  `ERROR`;
- output contains provider, check ID, profile, and reason class only, never
  endpoint identity, event content, delivery address, or alert payload.

## Twelfth-slice decision record

Target control: `PSB-AI-004`
Domain: `ai-development-security`

Threat/failure scenario: an agent, developer process, compromised endpoint, or
pipeline intermediary replaces a failing fleet snapshot with fabricated clean
JSON, changes the evidence after collection, or replays an older valid
snapshot so `AAR-025` evaluates attacker-controlled state.

Control boundary:

- `AAR-025` continues to validate the security meaning of the fleet snapshot;
- this slice authenticates an organization collector statement that binds the
  exact canonical snapshot digest, policy identity, collection time, sequence,
  and previous accepted snapshot digest;
- a managed checkpoint records the last accepted sequence and snapshot digest
  outside repository and agent write authority;
- repository tests use a dedicated synthetic public key and precomputed
  signature; no private key is committed or production collector contacted.

Assumptions:

- the production collector signing key is independently protected and never
  delivered to developer endpoints or agents;
- the trust manifest and checkpoint are absolute, non-symlink, managed files
  with integrity and rollback protection supplied by the deployment system;
- one collector stream has a single monotonically increasing sequence and an
  explicit previous-snapshot digest;
- canonical JSON and SHA-256 identify the exact snapshot payload, while an
  asymmetric signature authenticates issuer control;
- OpenSSL 3 is the pinned managed verifier for this executable sample.

Acceptance criteria:

- the active key ID, issuer, algorithm, validity interval, and public-key
  SHA-256 match a dedicated fleet collector trust manifest;
- the RSA PKCS#1 v1.5 SHA-256 signature authenticates the canonical statement;
- the statement subject digest equals the exact canonical fleet snapshot
  digest and binds the expected policy ID and revision;
- statement collection time is recent and agrees with the snapshot capture
  time;
- sequence is exactly the managed checkpoint sequence plus one and
  `previous_snapshot_digest` equals the checkpoint snapshot digest;
- payload or signature tampering and replay are findings;
- missing or untrusted keys, unavailable crypto verifier, malformed trust,
  statement, checkpoint, or snapshot evidence return `ERROR`;
- output contains only check ID, profile, and reason class, never signature,
  endpoint identity, event content, or collector address.

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

The seventh-slice completion run on the same date repeated all commands after
adding `AAR-020` and `AAR-021`, an exact managed HTTPS destination policy,
recent public-unicast DNS classification, connected-address transport binding,
and cleartext, lookalike, userinfo, fragment, port, path, proxy, SOCKS,
listener, Unix socket, local, private, metadata, stale, mismatch, rebinding,
unavailable, and malformed failure cases.

The eighth-slice completion run on the same date repeated all commands after
adding `AAR-022`, a mandatory downstream request-bound permit policy, both
provider lifecycle coverage for completed allow, explicit deny, not-started,
timeout, abnormal exit, invalid output, and invalid permit, plus optional
gateway bypass, gateway unavailable, and malformed evidence failure cases.

The ninth-slice completion run on the same date repeated all commands after
adding `AAR-023`, stable request digest and idempotency policy, applied,
timeout-after-apply, timeout-before-apply, replacement-approved retry, and
unknown-outcome states, plus approval restoration, automatic retry, changed
request identity, duplicate mutation, unavailable reconciliation, and malformed
state failure cases.

The tenth-slice completion run on the same date repeated all commands after
adding `AAR-024`, direct argv and transparent environment normalization,
read-only zero-HITL, high-impact and force-push action classes, resolved and
unresolved Git aliases, and shell, script, task-runner, interpreter, unknown,
auto-allow bypass, unavailable-engine, and malformed failure cases.

The eleventh-slice completion run on the same date repeated all commands after
adding `AAR-025`, both-provider managed enrollment and export, fresh gap-free
ingestion, reject and quarantine accounting, immutable metadata-only central
storage, seven synthetic alert-delivery receipts, and missing-provider, stale,
gap, content-leakage, failed-alert, unavailable-collector, and malformed
failure cases.

The twelfth-slice completion run on the same date repeated all commands after
adding `AAR-026`, a dedicated collector trust root, public-key digest pin,
OpenSSL 3 signature verification, exact snapshot and policy binding, recent
collection time, monotonic sequence and previous-digest checkpoint, and
payload-tamper, signature-tamper, replay, unknown-key, malformed, and
unavailable-verifier failure cases.

For the next slice, start with a selected incomplete outcome under
“Remaining work after the first slice”, update this status to `in-progress`,
and add its secure, insecure, failure, and sanitized-evidence fixtures before
marking another phase complete.
