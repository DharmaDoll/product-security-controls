# PSB-SOURCE-002 implementation instructions

This package uses a direct repository-owned Git hooks implementation.

- The supported adoption path is: copy `secure/.githooks`, review it, set the
  repository-local `core.hooksPath`, pull the pinned Gitleaks image, and run the
  bundled self-test.
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
- Local hooks remain bypassable. Documentation must require independent CI and
  source-platform secret protection.
