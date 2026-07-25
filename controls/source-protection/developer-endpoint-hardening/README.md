# PSB-SOURCE-001: Developer endpoint hardening

## Security problem

Developer endpoints hold source code, SSH keys, access tokens, package
caches, local build artifacts, and the execution context for development
tools. Theft, malware, excessive local privilege, or unsafe editor/AI tooling
can turn one endpoint into a path to source or product systems.

This control defines a small, portable policy baseline. The included verifier
checks policy fixtures and never changes the host. An organization may connect
the same assertions to MDM, EDR, operating-system compliance APIs, or
developer environment provisioning.

## Threat and trust boundary

The endpoint is a trust boundary between the developer and source/build
systems. Relevant failures include plaintext credential storage, unrestricted
AI-tool network access, exposed container sockets, writable shared workspaces,
disabled encryption or screen locking, and unmanaged local debug services.

## Examples

- `insecure/endpoint-policy.conf` is a deliberately rejected fixture.
- `secure/endpoint-policy.conf` is a declarative secure baseline.

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

## Adoption guidance

Map each assertion to the organization's endpoint control plane. Examples:

- full-disk encryption and automatic screen lock;
- supported OS and developer-tool versions with enforced updates;
- no routine local administrator use;
- OS keychain or an approved enterprise secret manager;
- no secrets in workspaces, shell history, or dotfiles;
- no broad Docker socket or filesystem mounts;
- allowlisted network access for AI tools and external developer services;
- encrypted backups and controlled local debug services.

## Limitations and operational cost

The fixture verifier cannot prove actual host state, MDM enrollment, EDR
coverage, patch freshness, remote-wipe capability, or resistance to a
privileged local attacker. Organization-specific integrations are required.
The baseline may reduce developer convenience through update enforcement,
credential-manager use, network restrictions, and read-only-by-default
workspaces. Exceptions should follow the repository's narrow, owned, and
time-bound exception policy.

Framework relationships and their confidence are recorded in `control.yaml`.
They are not formal compliance claims.
