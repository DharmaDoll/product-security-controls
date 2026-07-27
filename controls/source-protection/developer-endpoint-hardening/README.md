# PSB-SOURCE-001: Developer endpoint hardening

## Security problem

Developer endpoints hold source code, SSH keys, access tokens, package
caches, local build artifacts, and the execution context for development
tools. Theft, malware, excessive local privilege, or unsafe editor/AI tooling
can turn one endpoint into a path to source or product systems.

This control defines a portable policy baseline. It incorporates the ten
requirements from the supplied Japanese developer endpoint hardening and
operational-control table, with traceability in
`docs/operational-baseline.md`. The included verifier checks policy fixtures
and never changes the host. An organization may connect the same assertions
to MDM, EDR, operating-system compliance APIs, identity and network controls,
CI/CD policy, or developer environment provisioning.

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

Map each assertion to the organization's endpoint control plane. Examples:

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
credential-manager use, network restrictions, and read-only-by-default
workspaces. Exceptions should follow the repository's narrow, owned, and
time-bound exception policy.

The supplied table identifies its source only as `1`; without bibliographic
details, its provenance and authority cannot be independently verified.

Framework relationships and their confidence are recorded in `control.yaml`.
They are not formal compliance claims. The expanded requirement set needs
framework-mapping review before additional relationships are claimed.
