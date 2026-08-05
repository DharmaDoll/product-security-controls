# CodeGuard Experiments

Comparative experiments for pinned Project CodeGuard usage belong here.

The executable experiment contract, secure synthetic example, negative tests,
and normalized result schema are owned by
[`PSB-AI-001`](../../controls/ai-development-security/repository-owned-ai-security-guidance/README.md).
Use the repository prompt in
[`04-run-codeguard-experiment.md`](../../.codex/prompts/04-run-codeguard-experiment.md)
for live runs.

Do not place credentials, raw prompts, raw model output, private source, or
production data in this directory. Store sanitized live evidence in an
access-controlled system, record immutable digests in the normalized result,
and keep the following states distinct:

- `FAIL`: complete evidence shows a guidance or benchmark finding;
- `NOT_CHECKED`: live model effectiveness has not been evaluated;
- `ERROR`: the run, collector, evaluator, test, or scanner did not produce
  trustworthy complete evidence.

The checked-in synthetic fixture supports only a `pilot` recommendation. It is
an evaluator test, not evidence that a hosted model or agent version is safe.
