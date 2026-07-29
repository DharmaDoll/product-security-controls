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
update them. Because immutable code can still be vulnerable, a second verifier
matches the reviewed Action release inventory against a fresh complete snapshot
of GitHub-reviewed advisories in the `actions` ecosystem.

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
- `secure/advisories.json` and `insecure/advisories.json` are deterministic
  synthetic fixtures. They are not a current export of GitHub Advisory
  Database and must not be used as live adoption evidence.

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

To collect the latest reviewed GitHub Actions advisories and verify a reviewed
Action release inventory:

```bash
make collect-github-action-advisories
make verify-github-action-advisories \
  ACTION_INVENTORY=controls/cicd-security/action-sha-pinning/secure/action-inventory.json \
  ADVISORY_SNAPSHOT=generated/advisories/github-actions.json \
  AS_OF=2026-07-30T12:00:00Z
```

The collector uses the versioned public global-advisories REST API with
`type=reviewed` and `ecosystem=actions`, follows bounded pagination, and writes
the snapshot atomically. Authentication is optional for public data; when
`GITHUB_TOKEN` exists it is read from the environment and never written to the
snapshot. The verifier requires a complete snapshot no older than seven days.

Exit status `0` means all discovered `uses:` references satisfy this policy.
Exit status `1` means at least one policy violation was found. Exit status `2`
means verification could not run reliably, for example because an input was
missing, contained no workflow files, or the advisory snapshot was stale,
incomplete, malformed, or unavailable. A verifier error must never be treated
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
9. Maintain an Action inventory that binds package name and release version to
   the reviewed full commit SHA and upstream release URL.
10. Refresh the GitHub-reviewed `actions` advisory snapshot at least every seven
    days and block affected versions before merge or release.

## Limitations and operational cost

Immutability is not trust. A fixed commit may be malicious, compromised before
pinning, affected by an undisclosed vulnerability, or contain vulnerable
transitive dependencies. The syntax verifier does not query GitHub. The
advisory collector queries only GitHub-reviewed records in the Actions
ecosystem; publication delays, incomplete metadata, unreviewed reports, malware,
and nested dependencies remain residual risk.

GitHub advisories express affected releases as version ranges, not commit SHAs.
The inventory therefore records the separately reviewed upstream release URL,
version, and SHA binding. The verifier does not independently prove that the
SHA belongs to that release or establish repository ownership. Remote reusable
workflows can also invoke additional dependencies that require independent
verification.

Pinning creates update work and may delay security fixes if update automation
and review ownership are missing. GitHub-hosted and self-hosted runner versions
must also remain compatible with the pinned Action release.

Framework relationships in `control.yaml` describe risk reduction and secure
development support. They are not formal compliance claims. MITRE ATLAS is not
mapped because this threat scenario is not specific to an AI-enabled system.

## References

- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Advisory Database — reviewed Actions advisories](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aactions)
- [GitHub global security advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)
