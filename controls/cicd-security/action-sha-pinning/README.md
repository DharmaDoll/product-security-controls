# PSB-CICD-001: Immutable GitHub Actions references

## Security problem

GitHub Actions and reusable workflows execute code inside CI jobs that may have
access to source, the `GITHUB_TOKEN`, caches, artifacts, or deployment
credentials. A tag or branch such as `@v6` or `@main` can move after review,
causing the workflow to execute different upstream code without a corresponding
change in this repository.

This control requires external GitHub references to use full 40-character Git
commit SHAs. Docker-based actions must use a `sha256` image digest. Version
comments remain next to pinned references so maintainers can understand and
update them.

## Threat and trust boundary

The trust boundary is between repository-owned workflow code and executable
content obtained from another repository or registry. The primary failure
scenario is `SUPPLY-CHAIN-MUTABLE-ACTION`: an upstream reference changes after
review and introduces credential theft, artifact modification, or unreviewed
build behavior.

Local actions referenced with `./` remain inside the repository trust boundary
and are not required to use a Git SHA by this control.

## Examples

- `insecure/workflow.yml` contains isolated tags, branches, a short SHA, a
  dynamic reference, a mutable Docker tag, and a tagged reusable workflow.
- `secure/workflow.yml` pins official Actions to verified release commits,
  demonstrates a digest-pinned Docker action, preserves version comments, and
  pins a remote reusable workflow syntactically.

The example workflows are outside `.github/workflows` and are never executed by
GitHub. The example organization and reusable workflow are illustrative; this
control verifies immutable syntax, not remote existence or trustworthiness.

## Verification

From the repository root:

```bash
make verify-control CONTROL=PSB-CICD-001
```

To inspect workflow files directly:

```bash
python3 controls/cicd-security/action-sha-pinning/scripts/verify.py \
  .github/workflows
```

Exit status `0` means all discovered `uses:` references satisfy this policy.
Exit status `1` means at least one policy violation was found. Exit status `2`
means verification could not run reliably, for example because an input was
missing or contained no workflow files. A verifier error must never be treated
as a clean result.

## Adoption guidance

1. Resolve a release tag in the Action's canonical repository.
2. Review the release and the exact commit.
3. Replace the tag with its full commit SHA.
4. Keep the human-readable release tag in an inline comment.
5. Set `persist-credentials: false` for checkout unless later Git operations
   require the credential.
6. Configure minimal explicit workflow permissions.
7. Use controlled update automation so pinned dependencies receive reviewed
   security updates.
8. Where available, enable repository, organization, or enterprise policy that
   requires full-length Action SHAs.

## Limitations and operational cost

Immutability is not trust. A fixed commit may be malicious, compromised before
pinning, or contain vulnerable transitive dependencies. This verifier does not
query GitHub, establish repository ownership, inspect nested Action
dependencies, or prove that a commit was reviewed. Remote reusable workflows
can also invoke additional dependencies that require independent verification.

Pinning creates update work and may delay security fixes if update automation
and review ownership are missing. GitHub-hosted and self-hosted runner versions
must also remain compatible with the pinned Action release.

Framework relationships in `control.yaml` describe risk reduction and secure
development support. They are not formal compliance claims. MITRE ATLAS is not
mapped because this threat scenario is not specific to an AI-enabled system.
