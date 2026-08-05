# Security Exceptions

Exceptions must be narrow, owned, justified, risk-reviewed, compensated,
independently approved, and time-bound. A valid exception records accepted
risk; it does not turn the underlying failed security condition into `PASS`.

The executable reference and versioned record contract are defined by
[`PSB-GOV-002`](../../controls/governance-operations/time-bound-security-exceptions/README.md).
New controls should consume `psb-security-exception/v1` instead of defining a
new lifecycle schema. Control-specific risk evaluation remains in the owning
control.

Required behavior:

- bind one exact repository `control_id` and `check_id`;
- bind one exact target and environment without wildcard scope;
- keep owner, risk reviewer, and approver independently accountable;
- record justification, risk, compensating controls, approval, remediation,
  creation, and expiry;
- derive expiry from a trusted evaluation time instead of manual cleanup;
- treat expired or invalid records as `FAIL`;
- treat missing, stale, incomplete, malformed, unsafe, or tampered evidence as
  `ERROR`, never as no exception or a clean result;
- store safe identifiers and references, not secrets, source code, production
  payloads, or request/response bodies.

Existing control-local exception formats require explicit adapters during
migration. Do not silently accept both schemas with different semantics.
