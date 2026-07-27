# Developer endpoint operational baseline

## Purpose and source handling

This document traces the ten rows in the control-local source file
`docs/developer-endpoint-operational-baseline.csv` to executable policy
assertions in this control. The input labels every row as phase 2 and references
only source `1`. Because no title, author, version, or URL is provided, the
source is treated as a user-supplied baseline rather than an independently
verified authority.

Product names below are examples from the input. Adoption depends on security
outcomes and evidence, not on a specific vendor or tool.

## Requirement traceability

| ID | Category | Requirement | Policy assertion | Function | Enforcement boundary and examples |
|---|---|---|---|---|---|
| DEH-001 | Secrets on endpoints | Eliminate static tokens and shorten credential lifetime | `credential_lifetime=short-lived` | prevent | Identity and source platforms; OIDC, short-lived sessions, GitHub Apps, or narrowly scoped fine-grained tokens |
| DEH-002 | Secrets on endpoints | Use an approved secret store | `credential_storage=system-keychain-or-approved-manager` | prevent | OS keychain or approved enterprise secret manager with runtime injection |
| DEH-003 | Secrets on endpoints | Bind keys to hardware and require user verification | `hardware_backed_keys=required` | prevent | Secure Enclave, TPM/security key, FIDO2, passkey, or protected non-exportable keys |
| DEH-004 | Secret leakage | Scan before commit | `pre_commit_secret_scan=required` | prevent | Managed pre-commit policy using a reviewed secret scanner or equivalent detector |
| DEH-005 | Secret leakage | Enforce repository-side layered scanning | `repository_secret_scan=required` | detect, prevent | CI and source platform checks such as secret scanning, Trivy, Semgrep, CodeQL, or reviewed equivalents |
| DEH-006 | Supply-chain attack | Isolate package installation | `package_install_isolation=required` | prevent, detect | Disposable container or cloud workspace, with host isolation and optional behavior monitoring |
| DEH-007 | Supply-chain attack | Control dependency updates | `dependency_update_guard=release-cooldown-and-security-updates` | prevent | Automated updates with a release-age cooldown, review, and an expedited path for known vulnerabilities |
| DEH-008 | Boundary control and identity | Control network and site access | `developer_egress_control=allowlist` | prevent | Managed egress, SWG/CASB, DNS/proxy policy, or equivalent controls for unauthorized storage and repositories |
| DEH-009 | Boundary control and identity | Centralize authentication and require phishing-resistant MFA | `phishing_resistant_mfa=required` | prevent | IdP/SSO lifecycle control with FIDO2/passkey or equivalent phishing-resistant authentication |
| DEH-010 | PII protection | Detect sensitive data files before commit | `sensitive_data_file_guard=required` | detect, prevent | Size, format, extension, and content-aware checks for staged data files |

All requirements are assigned the input phase label "Phase 2: common
guardrails." Prioritization must still be risk-based when an organization
adopts the baseline.

## Extended engineering guardrails

The following requirements capture the additional endpoint-hardening guidance.
They supplement the ten imported rows without changing the provenance of the
control-local source CSV. The user-supplied Japanese text is preserved in
[`user-supplied-endpoint-hardening-guideline-ja.md`](user-supplied-endpoint-hardening-guideline-ja.md);
this table records how that narrative was translated into assessable policy
assertions.

| ID | Category | Requirement | Policy assertion | Enforcement boundary and examples |
|---|---|---|---|---|
| END-011 | Attack-surface reduction | Allow only approved necessary applications | `approved_applications=allowlist-enforced` | MDM, application control, managed extension catalog, and software inventory |
| END-012 | Detection and response | Enforce healthy EDR or XDR coverage | `edr_xdr=required` | Endpoint prevention, behavioral telemetry, isolation, and incident evidence |
| END-013 | Source identity | Sign commits and verify them at the repository boundary | `commit_signing=required` | Managed Git configuration, hardware-protected signing key, and protected-branch rules |
| END-014 | Shift-left feedback | Provide approved SAST and SCA feedback in the IDE | `ide_security_feedback=sast-and-sca` | Managed editor configuration backed by mandatory repository checks |
| END-015 | Execution isolation | Use managed disposable environments for high-risk development | `managed_development_environment=required-for-high-risk` | Cloud workstation, Codespace, restricted container, or VM |
| END-016 | Runtime containment | Restrict and observe sandbox behavior | `sandbox_runtime_monitoring=required` | File, network, process, privilege, and socket policy with eBPF or equivalent telemetry |
| END-017 | Configuration enforcement | Deploy and continuously evaluate the baseline centrally | `endpoint_configuration_management=mdm-enforced` | MDM or equivalent endpoint control plane and conditional access |
| END-018 | Physical protection | Protect device custody, storage, and transport | `physical_device_protection=required` | Hardware lock, controlled storage, travel policy, loss reporting, and remote response |

## Verification and evidence

`scripts/verify.sh` validates the policy values for both fixtures. The secure
fixture must produce 28 passing checks. The insecure fixture must produce 28
failed checks and exit non-zero. `tests/test.sh` compares both complete outputs
with `expected-results/`.

The verifier establishes that a declared policy contains the required values;
it does not inspect a real endpoint or external control plane. Production
evidence should include, as applicable:

- endpoint-management compliance for encryption, lock, updates, and privilege;
- identity-provider policy and timely deprovisioning evidence;
- credential issuance and storage configuration;
- protected-branch evidence for mandatory repository-side scanning;
- sandbox isolation and package-install telemetry;
- dependency update policy, cooldown, and vulnerability exception records;
- managed egress policy and access logs;
- negative test fixtures for secret and sensitive-data detection.
- approved application inventory and EDR or XDR coverage;
- commit-signing configuration and repository-side rejection evidence;
- managed IDE, cloud workspace, sandbox runtime, and MDM compliance evidence;
- physical device and loss-response policy.

The separate read-only Linux assessment can collect a limited set of sanitized
local signals with:

```bash
make assess-control CONTROL=PSB-SOURCE-001
```

It does not replace the organization evidence above. Unsupported or ambiguous
local state remains `NOT_CHECKED`; an assessment execution failure is `ERROR`.

## Residual risk

Local hooks can be bypassed, scanners can miss unknown or encoded data, and
file extensions do not establish content safety. Hardware-backed credentials
can still be misused from a compromised authenticated session. Sandboxes,
network controls, identity systems, and scanners can themselves be
misconfigured or compromised. Scanner execution errors must be reported as
verification failures, never as clean results.
