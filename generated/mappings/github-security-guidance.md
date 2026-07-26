# github-security-guidance mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-CICD-002 - Prevent GitHub Actions command injection from direct expression interpolation | github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24) | GHAS-CONCEPT-SCRIPT-INJECTIONS | mitigates | high | The control prevents expression values from being substituted into the temporary shell scripts described by GitHub's script-injection guidance. |
| PSB-CICD-001 - Pin external GitHub Actions and reusable workflows to immutable commits | github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24) | GHAS-REF-SECURE-USE | supports | high | The control directly implements GitHub's recommendation to pin third-party Actions to full-length commit SHAs while retaining separate review and update requirements. |
| PSB-CICD-002 - Prevent GitHub Actions command injection from direct expression interpolation | github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24) | GHAS-REF-SECURE-USE | supports | high | The secure example implements GitHub's recommendation to pass context values through an intermediate environment variable instead of generating shell source from them. |
