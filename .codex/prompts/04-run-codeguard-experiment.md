# Run a Project CodeGuard Comparative Experiment

Read:

- `AGENTS.md`
- `docs/THREAT_MODEL.md`
- controls under `ai-development-security`
- experiment documentation under `experiments/codeguard`
- `controls/ai-development-security/repository-owned-ai-security-guidance/README.md`

## Goal

Compare Codex behavior with and without Project CodeGuard for one fixed security task.

Task ID: `<TASK_ID>`

Task description: `<TASK_DESCRIPTION>`

## Required groups

- Baseline: Codex + repository AGENTS only
- CodeGuard: Codex + repository AGENTS + pinned CodeGuard
- Optional reviewer group: CodeGuard Reviewer after generation

## Requirements

- Register any external CodeGuard dependency through `PSB-AI-002`, pin it to
  an immutable commit, and verify its content hash.
- Bind repository AGENTS, the repository-owned CodeGuard profile, the semantic
  review, and this procedure to the `PSB-AI-001` guidance bundle.
- Record the exact prompt.
- Use the same initial repository state.
- Run multiple repetitions.
- Record generated diffs.
- Run the same tests and scanners.
- Record unexpected commands, network access, dependency additions, and file access.
- Evaluate security improvement and secure-code regression separately.
- Do not treat one successful run as proof.
- Do not allow CodeGuard to override AGENTS.md invariants.
- Treat collector, evaluator, test, or scanner failure as `ERROR`, never as a
  clean run.
- Keep raw prompts, outputs, credentials, and transcripts out of normalized
  benchmark results. Retain sanitized detail in a separately access-controlled
  evidence store and bind it by digest when needed.

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
- recommendation: reject, revise, or pilot;
- explicit `NOT_CHECKED` state for live effectiveness when only synthetic
  fixtures have been evaluated.

Use the schema and thresholds owned by `PSB-AI-001`. A live experiment may
support a later adoption decision only after repeated runs, sanitized diff and
scanner review, operational-cost review, and independent approval. Do not
rewrite historical result files when the model, guidance, task corpus, or
evaluator changes; issue a new experiment identity.
