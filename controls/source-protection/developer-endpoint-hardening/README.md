# PSB-SOURCE-001: Developer endpoint hardening

## Security problem

Developer endpoints hold source code, SSH keys, access tokens, package
caches, local build artifacts, and the execution context for development
tools. Theft, malware, excessive local privilege, or unsafe editor/AI tooling
can turn one endpoint into a path to source or product systems.

開発者はGitHub token、cloud credential、SSH keyなど強い権限を日常的に
利用するため、外部攻撃者、malware、悪意あるdependencyにとって価値の高い
標的です。一人の不注意や一台の侵害を組織全体のsource、build、cloud環境へ
波及させないため、このcontrolは「注意してください」という教育だけに依存せず、
設定の強制、自動block、隔離、検知、証跡を組み合わせた
**engineering guardrail**として端末hardeningを実装します。

This control defines a portable policy baseline. It incorporates the ten
requirements from the supplied Japanese developer endpoint hardening and
operational-control table, with traceability in
`docs/operational-baseline.md`. The included verifier checks policy fixtures
and never changes the host. An organization may connect the same assertions
to MDM, EDR, operating-system compliance APIs, identity and network controls,
CI/CD policy, or developer environment provisioning.

拡張時に提供された日本語ガイドラインの原文は
[`docs/user-supplied-endpoint-hardening-guideline-ja.md`](docs/user-supplied-endpoint-hardening-guideline-ja.md)
で確認できます。原文、実装上の解釈、原子的なchecklistを分離し、背景を残しつつ
`control.yaml`を機械可読な正本として維持しています。

## Threat and trust boundary

The endpoint is a trust boundary between the developer and source/build
systems. Relevant failures include plaintext credential storage, unrestricted
AI-tool network access, exposed container sockets, writable shared workspaces,
disabled encryption or screen locking, unmanaged local debug services,
long-lived credentials, unisolated package installation, data exfiltration,
and bypass of local secret or sensitive-data checks.

## Examples

- `insecure/endpoint-policy.conf` is a deliberately rejected fixture.
- `secure/endpoint-policy.conf` is a declarative secure baseline.
- `docs/operational-baseline.md` maps each imported requirement to a policy
  assertion and its organizational enforcement boundary.

Neither file changes an operating system. They are fixtures for verification
and adaptation to an organization's endpoint-management system.

## Verification

From the repository root:

```bash
make verify-control CONTROL=PSB-SOURCE-001
```

Or run the control-local test directly:

```bash
bash controls/source-protection/developer-endpoint-hardening/tests/test.sh
```

The secure fixture must pass. The insecure fixture must fail validation. A
non-zero validator result means the policy was rejected or verification could
not establish compliance; it must never be treated as a clean result.
The tests compare complete verifier output with the sanitized expected
evidence, so omission of an imported requirement changes the test result.

## Read-only endpoint assessment

The fixture verifier above proves the example policy behavior. To inspect the
current Linux endpoint and repository without changing either, run:

```bash
make assess-control CONTROL=PSB-SOURCE-001
```

The assessment writes sanitized artifacts to:

- `generated/assessments/PSB-SOURCE-001.json`
- `generated/assessments/PSB-SOURCE-001.csv`

These host-specific files are ignored by Git. Results use:

- `PASS` when the supported read-only check establishes the required state;
- `FAIL` when the supported check establishes an insecure state;
- `NOT_CHECKED` when organization evidence or an unsupported integration is
  required;
- `ERROR` when the assessment operation cannot establish a result;
- `N/A` only for an independently reviewed exception.

The underlying runner uses exit codes `0` for complete PASS, `1` for a finding,
`2` for an assessment error, and `3` for incomplete external evidence. GNU
Make reports any failed recipe as its own non-zero status, so automation that
needs the exact code should invoke:

```bash
python3 scripts/run-assessments.py --control PSB-SOURCE-001
```

The initial Linux adapter checks normalized signals for credential storage,
repository-owned hooks, disk encryption, GNOME screen lock, automatic updates,
routine administrator access, common container sockets, known debug listeners,
and container workspace mount mode.

The output deliberately excludes usernames, home paths, IP addresses, raw
listener details, credential-helper paths, and matched secret values. Local
signals do not replace MDM, IdP, repository, network, or backup evidence.
When run inside a container, cloud workspace, or agent sandbox, results describe
that execution environment and may not observe the underlying physical host.

## Adoption guidance

Map each assertion to the organization's endpoint control plane. The baseline
is grouped below by security outcome; the atomic spreadsheet rows remain
canonical in `control.yaml`.

### 1. Endpoint and OS baseline

- keep the OS, browser, editor, package managers, and developer tools on
  supported stable versions through centrally enforced patch management;
- remove unnecessary applications and enforce an approved software inventory
  so extensions and background services do not accumulate by developer choice;
- enroll every in-scope endpoint in healthy EDR or XDR prevention, telemetry,
  and response coverage;
- enforce full-disk encryption, automatic reauthentication, remote loss
  response, and risk-appropriate physical storage and transport controls;
- use MDM or an equivalent control plane to deploy the baseline, detect drift,
  and restrict access from unmanaged or noncompliant endpoints.

### 2. Identity and strong authentication

- require centralized identity lifecycle and phishing-resistant MFA using
  FIDO2 security keys, passkeys, or an equivalent phishing-resistant method
  rather than SMS as the primary strong factor;
- protect SSH and authentication keys with non-exportable hardware and explicit
  user verification, including `-sk` SSH key types where supported;
- enable commit signing in managed Git configuration and enforce verified
  signatures at the protected repository boundary;
- treat signatures as identity evidence, not proof that the code is secure or
  that the authenticated signing session was uncompromised.

OAuth tokens, PATs, SSH keys, and source-platform credential lifecycle are
covered in detail by `PSB-SOURCE-004`; this control covers their endpoint
storage and use.

### 3. Engineered secret management

- prohibit PATs, cloud access keys, and other reusable credentials in
  `.bashrc`, `.zshrc`, `.env`, project files, shell history, or remote URLs;
- use an OS keychain or approved secret manager and inject values only for the
  process and time that requires them;
- prefer short-lived federated or session credentials over static secrets;
- rotate or revoke an exposed credential before history rewriting or cache
  cleanup.

Cloud workload federation in CI/CD remains a separate boundary planned as
`PSB-CICD-006`; endpoint use of cloud credentials still follows this baseline.

### 4. Shift-left workflow controls

- block representative fake secrets and sensitive data before commit with a
  reviewed hook implementation such as the repository's `PSB-SOURCE-002`
  example;
- use independent repository-side secret scanning and required checks because
  local hooks can be bypassed;
- provide approved SAST and SCA feedback in supported IDEs for rapid developer
  feedback while retaining mandatory server-side verification;
- do not install hooks or editor extensions silently; distribute and enforce
  them through the reviewed developer environment or repository onboarding
  process.

Trivy, detect-secrets, Gitleaks, and similar developer-local products are
possible implementations, not the control itself. Organization-operated
full-history and incident-response scanning is owned by `PSB-SOURCE-003`, not
the developer endpoint baseline. A scanner execution failure is an error and
never a clean result.

### 5. Isolation and managed execution

- route package installation, external code builds, and AI-generated code
  execution to disposable restricted containers, VMs, Cloud Workstations,
  Codespaces, or an equivalent managed environment when the operation is
  classified as high risk;
- default host and workspace mounts to read-only and do not expose a host
  container-runtime socket;
- constrain and observe filesystem, process, privilege, socket, and network
  behavior using eBPF telemetry or an equivalent runtime control;
- prevent routine sandbox workloads from reading persistent developer
  credentials or communicating with arbitrary destinations.

The exact choice between a local sandbox and a cloud development environment
depends on source sensitivity, latency, offline requirements, platform support,
and data residency. The required outcome is a centrally reviewable isolation
boundary with disposable state and sanitized evidence.

Additional examples:

- full-disk encryption and automatic screen lock;
- supported OS and developer-tool versions with enforced updates;
- no routine local administrator use;
- short-lived credentials and OS keychain or approved secret-manager use;
- hardware-backed SSH keys or phishing-resistant authenticators;
- no secrets in workspaces, shell history, or dotfiles;
- pre-commit and repository-side secret scanning;
- no broad Docker socket or filesystem mounts;
- isolated package installation and controlled dependency-update timing;
- dependency resolveとupdateに`PSB-DEPS-001`のrepository-owned cooldown
  policyを適用し、通常installではcommitted lockfileを使用する;
- `PSB-DEPS-001`のproxy-only client profileをMDM／CI templateで配布し、
  npm、pip、Go、Composerのdirect registry fallbackとpublic-registry egressを拒否する;
- dependency install時は`PSB-DEPS-002`でlifecycle scriptとsource buildを
  default denyにし、必要な実行だけをreview済みの時限例外に限定する;
- 通常installでは`PSB-DEPS-003`のfrozen graph、registry、artifact integrityを
  検証し、開発端末での暗黙のlockfile再生成を許可しない;
- phishing-resistant MFA and centrally managed identity lifecycle;
- managed developer egress and cloud-storage access;
- sensitive-data file guards before commit;
- allowlisted network access for AI tools and external developer services;
- encrypted backups and controlled local debug services.

Product names from the input table are implementation examples, not required
dependencies. Local hooks are bypassable and must be backed by repository-side
checks. File extension and size rules are only signals for sensitive data and
must not be treated as proof that a file is safe.

## Limitations and operational cost

The fixture verifier cannot prove actual host state, MDM enrollment, EDR
coverage, patch freshness, remote-wipe capability, or resistance to a
privileged local attacker. Organization-specific integrations are required.
It also cannot prove IdP account deprovisioning, SWG/CASB enforcement, CI
scanning, package sandbox containment, or dependency release age.
The baseline may reduce developer convenience through update enforcement,
credential-manager use, application restrictions, phishing-resistant
authentication, signing, network restrictions, managed workspaces, telemetry,
and read-only-by-default mounts. MDM, EDR/XDR, managed development environments,
and runtime monitoring also add licensing, platform-engineering, privacy,
retention, and incident-response costs. Exceptions should follow the
repository's narrow, owned, and time-bound exception policy.

The supplied table identifies its source only as `1`; without bibliographic
details, its provenance and authority cannot be independently verified.

Framework relationships and their confidence are recorded in `control.yaml`.
They are not formal compliance claims. The expanded requirement set needs
framework-mapping review before additional relationships are claimed.
