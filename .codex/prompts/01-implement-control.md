# Implement One Product Security Control

Read `AGENTS.md` and all relevant project documents first.

## Input

Control ID: `<CONTROL_ID>`

Control title: `<TITLE>`

Domain: `<DOMAIN>`

Security problem: `<PROBLEM>`

## Task

Implement this control as one complete vertical slice.

## Required steps

1. Confirm the control belongs in the specified domain.
2. Describe the threat or failure scenario.
3. Define measurable acceptance criteria.
4. Create the control package.
5. Make `## このcontrolを一枚で理解する` the first README H2 and complete
   all six required rows defined in `docs/CONTROL_MODEL.md`.
6. Add an insecure example where safe and useful.
7. Add a secure example.
8. Add automated verification.
9. Add expected results.
10. Add operational guidance and limitations.
11. Add provisional framework mappings.
12. Regenerate indexes.
13. Run all relevant tests.

## Required package structure

```text
controls/<domain>/<slug>/
├── README.md
├── control.yaml
├── insecure/
├── secure/
├── tests/
├── expected-results/
└── scripts/
```

Omit irrelevant directories, but explain why.

## Security requirements

- Do not use real secrets.
- Do not deploy insecure examples.
- Pin external dependencies and actions.
- Verify downloaded artifacts.
- Keep permissions minimal.
- Distinguish scan failure from clean results.
- Do not suppress findings to obtain a green test.
- Do not claim compliance.
- Include residual risk.

## Completion report

Report:

- behavior implemented;
- insecure versus secure difference;
- verification commands;
- test evidence;
- framework mappings;
- limitations;
- files changed.

Do not implement unrelated controls.
