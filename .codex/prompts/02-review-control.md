# Review a Product Security Control

Read `AGENTS.md`, the target control package, and relevant project documents.

Control ID: `<CONTROL_ID>`

## Review objectives

Review the control for:

1. technical correctness;
2. threat-model alignment;
3. insecure example safety;
4. secure implementation quality;
5. test quality;
6. false confidence;
7. dependency and workflow supply-chain risks;
8. operational feasibility;
9. framework mapping quality;
10. documentation clarity.

## Required findings format

For each finding provide:

- severity: critical/high/medium/low;
- file and location;
- issue;
- security impact;
- recommended correction;
- whether a regression test is required.

## Specific checks

- Are security claims tested?
- Is failure separated from clean status?
- Are actions and downloads immutable?
- Are permissions minimal?
- Can an untrusted PR or fixture trigger privileged behavior?
- Are exceptions narrow and time-bound?
- Are mappings relationships rather than compliance claims?
- Does the control expose limitations?
- Is the sample understandable without reading unrelated controls?
- Is a simpler implementation possible?

## Output

First provide findings only.

Then provide a proposed patch plan.

Do not modify files until the review findings are complete.
