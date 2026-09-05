# Transitive dependency review for pinned GitHub Actions

## Purpose

Full-SHA pinning fixes the direct Git object selected by the caller. It does not recursively freeze executable content that the pinned
Action retrieves or invokes. This review makes that residual boundary visible; it is not a complete dependency resolver or a claim that
the Action is safe.

See [Palo Alto Networks: Unpinnable Actions](https://www.paloaltonetworks.com/blog/cloud-security/unpinnable-actions-github-security/)
for examples of container, package, nested Action, and external-download mutability that can remain behind a pinned Action reference.
Use the article to understand the problem structure, not to treat its historical ecosystem measurements as current adoption evidence.

## Scope and owner

Perform this review for every new third-party Action used by a job with write permission, secrets, OIDC, signing authority, artifact
publication, or deployment authority. Repository administrators identify the exact source commit; an independent security reviewer or
designated reviewer records the outcome in the dependency update PR.

Lower-privilege Actions may be reviewed proportionally, but they remain `NOT_CHECKED` until a review actually occurs. A direct-reference
`PASS` never supplies the transitive result.

## Bounded review procedure

1. Open the canonical Action repository at the exact 40-character commit used by the workflow.
2. Confirm that `action.yml`／`action.yaml`, referenced scripts, `Dockerfile`, and reusable workflow files belong to that commit.
3. Search those files for the following observable mutable execution paths:
   - `FROM` images or runtime containers referenced by tag rather than digest;
   - nested remote `uses:` references using a tag, branch, short SHA, or expression;
   - package installation without a reviewed lockfile or exact integrity metadata;
   - downloaded scripts, binaries, archives, or plugins without checksum or signature verification;
   - URLs, update channels, or runtime selectors that can return different executable content without changing the pinned commit.
4. Record only what was inspected. Do not infer recursive completeness when a script, generated bundle, binary, service, or network
   response cannot be evaluated from source.
5. For a privileged job with observed mutability, select a lower-risk Action, replace it with a small repository-owned script, maintain a
   reviewed fork with locked dependencies, reduce job authority, or use a narrow time-bound exception.

## Result states

| State | Meaning |
|---|---|
| `NO_OBVIOUS_MUTABILITY` | No obvious mutable runtime dependency was found in the stated review scope; this is not proof of safety or completeness |
| `MUTABLE_RUNTIME_OBSERVED` | At least one mutable container, package, nested Action, binary, script, or download was observed |
| `NOT_CHECKED` | The review has not been performed; do not infer a result from SHA pinning |
| `ERROR` | The exact commit or relevant source could not be obtained or evaluated |

## Review record

Keep the record in the dependency update PR or the organization's review system. It should contain:

- workflow and job;
- Action name and exact 40-character commit SHA;
- canonical commit permalink;
- reviewer and review date;
- files and runtime paths inspected;
- one result state from the table above;
- observed mutable dependencies and the selected response;
- a link to any exception, fork, replacement, or least-privilege change.

Do not add a hand-written `secure: true` file or fixture result as evidence. Repository fixtures demonstrate the local verifier only; they
do not prove that an adopting organization reviewed the Action or that all transitive dependencies are immutable.

## Related controls

- [PSB-CICD-003 Actions static analysis](../../actions-static-analysis/README.md)
- [PSB-CICD-004 Actions least privilege](../../actions-least-privilege/README.md)
- [PSB-CICD-005 Untrusted PR boundary](../../untrusted-pr-boundary/README.md)
- [PSB-DEPS-004 Dependency change review](../../../dependency-security/dependency-change-review/README.md)
- [PSB-GOV-002 Time-bound security exceptions](../../../governance-operations/time-bound-security-exceptions/README.md)
