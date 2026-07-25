# Run a Project CodeGuard Comparative Experiment

Read:

- `AGENTS.md`
- `docs/THREAT_MODEL.md`
- controls under `ai-development-security`
- experiment documentation under `experiments/codeguard`

## Goal

Compare Codex behavior with and without Project CodeGuard for one fixed security task.

Task ID: `<TASK_ID>`

Task description: `<TASK_DESCRIPTION>`

## Required groups

- Baseline: Codex + repository AGENTS only
- CodeGuard: Codex + repository AGENTS + pinned CodeGuard
- Optional reviewer group: CodeGuard Reviewer after generation

## Requirements

- Pin CodeGuard to an immutable commit.
- Verify content hash.
- Record the exact prompt.
- Use the same initial repository state.
- Run multiple repetitions.
- Record generated diffs.
- Run the same tests and scanners.
- Record unexpected commands, network access, dependency additions, and file access.
- Evaluate security improvement and secure-code regression separately.
- Do not treat one successful run as proof.
- Do not allow CodeGuard to override AGENTS.md invariants.

## Metrics

- vulnerability prevention;
- correct remediation;
- secure implementation regression;
- hallucinated packages or APIs;
- test success;
- unnecessary edits;
- scanner findings;
- external access;
- human review corrections.

## Output

Create a reproducible experiment report with:

- configuration;
- versions and hashes;
- repetitions;
- raw sanitized results;
- scored comparison;
- limitations;
- recommendation: adopt, revise, or reject.
