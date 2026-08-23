# PSB-SOURCE-002 implementation instructions

This package uses a direct repository-owned Git hooks implementation.

## Loading these instructions in Codex CLI

From the repository root, start a new Codex CLI session with this package as
the working directory:

```bash
codex --cd controls/source-protection/git-hooks-baseline
```

Codex then loads the repository-root `AGENTS.md`, `controls/AGENTS.md`, and this
file in that order. A session started at the repository root does not discover
this deeper file. Instruction discovery happens when the session starts, so
restart the session after changing the working directory or these instructions.

The three files total less than the default 32 KiB project instruction limit.

- The shortest supported adoption path is an explicit
  `scripts/install.sh --target <absolute-repository-path>` invocation. Keep the
  equivalent manual copy, review, repository-local activation, pinned image
  pull, and self-test procedure documented as the transparent fallback.
- The installer must refuse an existing target `.githooks` directory or
  conflicting local settings, must never change global settings, and must roll
  back only files and settings it created when installation or self-test fails.
  Signing remains an explicit opt-in after the adopter prepares its key.
- Do not introduce pre-commit or another hook framework into the minimal path.
- Keep `scan-sensitive.py` Python 3.10+ standard-library only and readable.
- Keep shell hooks POSIX `sh`; do not hide activation or modify global Git
  configuration.
- Invoke Gitleaks through `run-gitleaks.sh` with an immutable container digest,
  read-only mounts, redacted output, no runtime network, and fail-closed exits.
- Keep the Gitleaks wrapper staged-scan only; add another mode only for a
  documented operational requirement.
- `test-detection.sh` must use inert runtime-generated canaries, verify safe and
  finding behavior, and ensure matched values are not printed.
- `tests/test_scan_sensitive.py` must pin the complete filename, suffix, and
  secret-rule inventory and cover file, staged, pre-push, redaction, boundary,
  near-miss, and fail-closed behavior.
- Keep the scanner's reviewed cases in one canonical,
  human-readable `tests/fixtures/scan-sensitive-cases.json` inventory. Fixture
  values must decode to concrete inert, non-issued examples; real or
  provider-valid credentials remain prohibited.
- The raw fixture file itself must scan clean. When a concrete positive value
  would make the fixture self-detect, escape only the minimum detector-critical
  character needed to preserve readable review while decoding to the exact
  value exercised by the test.
- Every supported secret-rule alternative must have a positive fixture, and
  length or syntax boundaries must have safe near-miss fixtures. A rule change
  without the corresponding inventory and boundary updates must fail tests.
- Scanner reporting must suppress every decoded positive fixture value, and
  the redaction test must cover every variant rather than only one example per
  rule.
- Configuration variable references such as npm `${NPM_TOKEN}` are safe
  placeholders, not literal credentials. Keep an explicit near-miss test so
  supported placeholders remain accepted while literal values are rejected.
- Local hooks remain bypassable. Documentation must require independent CI and
  source-platform secret protection.
