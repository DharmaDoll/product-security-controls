# GitHub Security Guidance Registry

This registry makes GitHub's official security guidance available for
page-level control mappings. It is vendor guidance, not a formal compliance
framework, and a mapping does not prove that a control completely implements a
page or secures a GitHub deployment.

## Pinned registry baseline

- Publisher: GitHub
- Product: GitHub.com documentation
- Source repository: [github/docs](https://github.com/github/docs)
- Source commit:
  [`b17436de8f10c3e7f6a185d6813bf94bc82d22f8`](https://github.com/github/docs/commit/b17436de8f10c3e7f6a185d6813bf94bc82d22f8)
- Source commit date: `2026-07-24`
- Registry review date: `2026-07-27`
- Machine-readable registry: [`registry.json`](registry.json)

GitHub Docs does not publish a framework-style release number. Control
mappings must therefore use:

```text
github/docs@b17436de8f10c3e7f6a185d6813bf94bc82d22f8 (2026-07-24)
```

## Completeness boundary

The registry includes every article exposed by these official security
collections at the pinned baseline:

1. **Implement supply chain best practices** — four articles;
2. **Security in GitHub Actions** — seven concept articles;
3. **Security reference for GitHub Actions** — four reference articles.

Collection landing pages are recorded as collection sources rather than
mapping targets. Workflow syntax, contexts, and event-trigger documentation
are recorded as supporting references because they define how security
guidance is interpreted, but they are not best-practice mapping targets.

“Every article” is deliberately bounded to these collections. It does not mean
every page on `docs.github.com`, every product administration page, or every
page transitively linked from an article.

When GitHub adds, removes, or renames an article in one of these collections,
update `registry.json`, advance the pinned commit and review date, review
affected control mappings, and run `make test`.

## Mapping boundary

Use `github-security-guidance` for GitHub-specific implementation guidance.
Prefer `supports`, `verifies`, or `related-to`, and explain which part of the
page the control implements. Do not use these mappings to claim formal
compliance or complete GitHub security coverage.
