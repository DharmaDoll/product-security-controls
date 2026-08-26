# PSB-SOURCE-003 Public Exposure Monitor PoC Specification

- Specification version: `1.1.0`
- Configuration schema: `1.0`
- Observation schema: `1.0`
- State schema: `1.0`
- Query catalog: `1.1`
- Reference provider: GitHub.com
- Last provider review: 2026-08-26

This is the normative implementation contract for the PoC. An AI agent implementing this control in another environment
MUST preserve the interfaces, trust boundaries, state transitions, redaction rules, and failure semantics below. `MUST`,
`MUST NOT`, `SHOULD`, and `MAY` have their usual normative meanings.

## 1. Objective

The monitor gives Security／AppSec an attacker-view inventory of public material related to organization-owned domains.
An adopter configures stable IDs and domain values. A trusted scheduled job then:

1. builds a fixed, domain-anchored query catalog;
2. collects supported public GitHub results through official REST APIs;
3. emits advanced browser GET searches for human baseline review;
4. normalizes provider data without retaining matched content;
5. compares observations with a dedicated state branch;
6. persists the next state by compare-and-swap; and
7. emits only `NEW` and `REOPENED` events for an external notification adapter.

The security outcome comes from running this process, reviewing findings, and remediating unintended exposure. Copying
files without activation does not improve the live security state.

## 2. Scope and non-goals

### 2.1 Included

- One to 50 owned domains in a strict JSON configuration.
- Public GitHub code, Issue, and Pull Request Search API results.
- New or updated public Gists since a stored cursor.
- Human-review GitHub Code Search, Issue／PR Search, Gist Search, and generic Web queries.
- Stable fingerprinting, deduplication, expiring review, and recurrence detection.
- State read/write through the GitHub Contents API on a fixed branch and path.
- A copyable GitHub Actions workflow with a trusted schedule and manual trigger.
- Sanitized Summary and notifier-ready JSON.
- Small offline unit tests around scanner behavior.

### 2.2 Excluded

- Repository clone, default-branch checkout of a target, or all-history Git scanning.
- Private repository discovery or GitHub Enterprise Server.
- Browser automation, search-result HTML scraping, CAPTCHA handling, or rate-limit evasion.
- SQLite, external database, queue, SIEM, dashboard, or case-management implementation.
- Production Slack App／webhook delivery, retries, acknowledgement, and channel routing.
- Credential validation, login attempts, exploitation, or active probing of third-party assets.
- Automated deletion, visibility changes, credential revocation, or other destructive response.
- Claims that fixture results prove organization adoption or absence of exposure.

The production notification adapter and organization-specific operating model belong in another repository.

## 3. Required decisions and roles

Before activation, humans MUST decide:

- which domains are owned and may be sent to GitHub and Web search providers;
- the private monitor repository and its administrators;
- the public-only search identity and token lifetime;
- scan schedule, finding review SLA, notification route, and escalation threshold;
- review approvers and the maximum retention period; and
- the owner of credential revoke／rotate when exposure is suspected.

Responsibilities:

| Role | Required work |
| --- | --- |
| Security／AppSec | Validate ownership, review queries, triage findings, set disposition and expiry. |
| Repository administrator | Configure the private repository, Actions policy, token, state branch, and branch rules. |
| Development team | Investigate and remediate product-specific exposure. |
| Platform／SRE | Assess exposed endpoints and infrastructure metadata. |
| Incident response | Contain possible credential exposure and investigate misuse. |
| Product owner | Approve intentional publication and residual risk. |

The scanner MUST NOT classify a candidate as a confirmed vulnerability or incident.

## 4. Architecture and identity boundaries

```text
owned domains                         public GitHub
strict config                   Search APIs / public Gist feed
     |                                      |
     v                                      v
query catalog ------> public-only collector ------> sanitized observations
     |                                                |
     +------> browser GET queries                     v
                                               state reconciler
                                                 |          |
                                  Contents API CAS|          +--> Summary/events
                                                 v
                                     psb-source-003-state
                                       state/findings.json
```

Two credentials MUST be separated:

| Identity | Environment variable | Allowed | Forbidden |
| --- | --- | --- | --- |
| Public search identity | `PUBLIC_SEARCH_TOKEN` | Public Search and public Gist read | Private repository read, state write, organization administration |
| Workflow identity | `GITHUB_TOKEN` | Exact monitor repository state file read/write | Search collection, other repository write, organization administration |

The public search identity SHOULD be a dedicated account with no private repository membership. Provider result checks
are defense in depth, not a replacement for this identity separation.

All provider responses, state JSON, and review text are untrusted. The implementation MUST NOT import, evaluate, source,
template-execute, or shell-expand state. Network requests MUST remain on `https://api.github.com`. Output result URLs MUST
use `https://github.com` or `https://gist.github.com` as appropriate.

## 5. Required artifact layout

```text
controls/source-protection/public-repository-exposure/
├── README.md
├── control.yaml
├── AGENTS.md
├── docs/PUBLIC_EXPOSURE_MONITOR_POC_SPEC.md
├── secure/
│   ├── domain-monitor.json
│   ├── state/findings.json
│   └── .github/workflows/public-exposure-monitor.yml
├── insecure/domain-monitor.json
├── scripts/monitor-public-exposure.py
├── tests/test.sh
├── tests/test_monitor_public_exposure.py
└── expected-results/public-exposure-monitor.md
```

The workflow remains under `secure/` in the blueprint so it is not active by default. An adopter explicitly moves it to
`.github/workflows/`. The sample state is initialization data, not synthetic adoption evidence.

The scanner MUST use Python 3.10+ standard library only. It MUST NOT require Docker, a browser driver, a package manager,
or a database.

## 6. Domain configuration

The exact configuration shape is:

```json
{
  "schema_version": "1.0",
  "domains": [
    {
      "id": "ORG-DOMAIN-PRIMARY",
      "value": "corp.example.invalid"
    }
  ]
}
```

Validation requirements:

- The top-level keys MUST be exactly `schema_version` and `domains`.
- `schema_version` MUST equal `1.0`.
- `domains` MUST contain between 1 and 50 objects.
- Each object MUST contain only `id` and `value`.
- `id` MUST match `^ORG-[A-Z0-9][A-Z0-9-]{2,62}$` and be unique.
- `value` MUST be unchanged by trimming, converted through IDNA to lowercase ASCII, and unique after normalization.
- A domain MUST contain at least two valid DNS labels and be no more than 253 ASCII bytes.
- Wildcards, URL schemes, path, port, query, fragment, `@`, IP literal, and `localhost` MUST be rejected.
- The implementation MUST NOT accept an email address, employee name, customer identifier, codename, or secret value.
- Public-suffix-only and ownership checks remain an adoption prerequisite because the standard library has no complete
  Public Suffix List.

The scanner derives `@{domain}`. A private DNS suffix MAY be configured only when its disclosure to providers is approved.

## 7. Query catalog 1.1

Every query MUST contain one configured domain or its derived email suffix. The scanner MUST NOT generate generic global
queries such as `password OR token`, third-party targets, actual secrets, or personal identifiers.

Full query IDs use `{indicator_id}-{suffix}`. Query IDs express catalog provenance; they are not fingerprint inputs.

### 7.1 Automatic REST Search

For each domain, run exactly these six queries:

| Suffix | Endpoint | Query |
| --- | --- | --- |
| `API-CODE-DOMAIN` | `search/code` | `"{domain}" in:file` |
| `API-CODE-EMAIL` | `search/code` | `"@{domain}" in:file` |
| `API-ISSUE-DOMAIN` | `search/issues` | `"{domain}" is:issue` |
| `API-ISSUE-EMAIL` | `search/issues` | `"@{domain}" is:issue` |
| `API-PR-DOMAIN` | `search/issues` | `"{domain}" is:pr` |
| `API-PR-EMAIL` | `search/issues` | `"@{domain}" is:pr` |

The Issue Search syntax does not use an undocumented `is:public` qualifier. Instead, a public-only identity is mandatory,
and every unique Issue／PR `repository_url` MUST be fetched and verified as the same repository with `private: false`.

Search requests use `per_page=100`, follow only validated `https://api.github.com` `rel="next"` links, and stop after ten
pages. `incomplete_results` MUST be exactly `false`; `total_count` MUST remain stable and MUST NOT exceed 1,000. Any
violation is exit `2`, never a clean result. Search requests SHOULD be spaced by at least 6.5 seconds.

Code result requirements:

- `repository.id` is a positive integer;
- `repository.full_name` has `owner/name` form;
- `repository.private` is exactly `false`;
- `path` is non-empty and contains no control character;
- `sha` is a 40-character hexadecimal object identity; and
- `html_url` is HTTPS on `github.com`.

Issue／PR result requirements:

- `id` and `number` are positive integers;
- `updated_at` is second-precision UTC RFC 3339 and is part of object identity;
- Issue and PR response shapes MUST match the requested surface;
- `repository_url` is HTTPS `api.github.com/repos/{owner}/{repo}` and repository visibility is verified; and
- `html_url` is HTTPS on `github.com`.

An Issue／PR update therefore becomes a new occurrence. This catches content added after an earlier review.

### 7.2 Automatic public Gist delta

For each run:

1. Read `github_public_gists_since` from state. On first run use `collected_at - 1 hour`.
2. Call `GET /gists/public?since={cursor}&per_page=100&page=1` and validated next links.
3. Deduplicate Gist IDs; reject more than ten pages or 1,000 unique Gists.
4. Call `GET /gists/{id}` for every listed ID.
5. Require `public: true`, top-level `truncated: false`, no more than 300 files, and a current history version.
6. Require every file to have non-truncated string content.
7. Search description, filename, and content using a case-insensitive DNS suffix boundary for every configured domain.
8. Advance the cursor to the run collection time only after all collection succeeds.

The Gist query ID is `{indicator_id}-API-GIST-DELTA`. The resource identity is
`{gist_id}:{current_revision}:{path}`, where path is a filename or `[description]`. Matched text MUST NOT be retained.

Truncated or over-limit Gist collection is exit `2`. The collector MUST NOT silently skip incomplete content.

### 7.3 Human browser GET catalog

Generate, but do not fetch, these GitHub Code Search queries:

| Suffix | Query |
| --- | --- |
| `WEB-CODE-DOMAIN` | `content:"{domain}" NOT is:generated NOT is:vendored` |
| `WEB-CODE-EMAIL` | `content:"@{domain}" NOT is:generated NOT is:vendored` |
| `WEB-CODE-CREDENTIAL` | `content:"{domain}" AND (password OR token OR secret OR api_key OR client_secret OR credential)` |
| `WEB-CODE-CONFIG` | Domain plus `.env`, YAML, JSON, properties, Terraform, and conf path filters. |
| `WEB-CODE-SERVICE` | Domain plus `admin`, `vpn`, `sso`, `api`, `staging`, `dev`, and `internal`. |
| `WEB-CODE-INFRA` | Domain plus `terraform`, `kubernetes`, `ingress`, `cname`, and `dns`. |
| `WEB-CODE-URL` | Regular expression for HTTP(S) hosts ending in the configured domain. |

Generate GitHub Issue and PR domain searches, Gist domain and email searches, and the following copyable generic text:

```text
site:github.com "{domain}"
site:github.com "@{domain}"
site:gist.github.com "{domain}"
site:raw.githubusercontent.com "{domain}"
site:github.com "{domain}" ("password" OR "token" OR "secret" OR "api_key")
```

GitHub links use `https://github.com/search?q=<encoded>&type=<code|issues|pullrequests>`. Gist links use
`https://gist.github.com/search?q=<encoded>`. Query parameters MUST be produced by a standard URL encoder.

The scanner MUST NOT GET, parse, screenshot, or crawl these HTML result pages. It MUST NOT bypass authentication,
robots policy, CAPTCHA, or rate limits. The Summary MUST say the queries were generated but not executed. Public Gist API
delta collection does not replace a human historical baseline.

## 8. Observation contract

The collection document has exactly:

```json
{
  "schema_version": "1.0",
  "provider": "github",
  "query_catalog_version": "1.1",
  "collected_at": "2026-08-26T00:00:00Z",
  "cursors": {"github_public_gists_since": "2026-08-26T00:00:00Z"},
  "observations": []
}
```

Each observation contains exactly:

```json
{
  "provider": "github",
  "surface": "github-code",
  "resource_id": "123:path/to/file:0123456789abcdef0123456789abcdef01234567",
  "indicator_id": "ORG-DOMAIN-PRIMARY",
  "query_ids": ["ORG-DOMAIN-PRIMARY-API-CODE-DOMAIN"],
  "resource": "outside/example",
  "path": "path/to/file",
  "public_url": "https://github.com/outside/example/blob/0123456789abcdef0123456789abcdef01234567/path/to/file"
}
```

Allowed surfaces are `github-code`, `github-issue`, `github-pull-request`, and `github-gist`. Observations MUST be
deduplicated and sorted by fingerprint. Multiple queries matching one object merge sorted query IDs.

The document and all results MUST omit query text, matched snippet, configured domain value, email local part derived from
content, credential, authorization header, token, and raw provider response.

## 9. Fingerprint and state contract

Fingerprint input is canonical compact JSON with sorted keys containing exactly:

```json
{
  "indicator_id": "ORG-DOMAIN-PRIMARY",
  "provider": "github",
  "resource_id": "provider-stable-object-identity",
  "surface": "github-code"
}
```

The result is lowercase `sha256:<64 hex>`. Display name, query IDs, result order, and collection time MUST NOT affect it.

The initial state is:

```json
{
  "schema_version": "1.0",
  "query_catalog_version": "1.1",
  "updated_at": null,
  "cursors": {"github_public_gists_since": null},
  "findings": []
}
```

Each finding is one observation plus:

```json
{
  "fingerprint": "sha256:<64 hex>",
  "first_seen": "2026-08-26T00:00:00Z",
  "last_seen": "2026-08-26T00:00:00Z",
  "last_notified": "2026-08-26T00:00:00Z",
  "disposition": "open",
  "review": null
}
```

Allowed dispositions are `open`, `accepted-public`, `false-positive`, and `remediated`. `open` and `remediated` require
`review: null`. `accepted-public` and `false-positive` require exactly:

```json
{
  "owner": "security-team",
  "reason": "Intentional public documentation",
  "reviewed_at": "2026-08-26T00:00:00Z",
  "expires_at": "2026-09-25T00:00:00Z"
}
```

Owner is a non-email role or team ID of 1–128 printable characters. Reason is 1–500 printable characters. Neither field
may contain `@`. Expiry MUST be after review time and no more than 180 days later. All timestamps are UTC RFC 3339 at
second precision.

State transitions:

- Unknown fingerprint: create `open`, set first／last seen and last notified, emit `NEW`.
- Known fingerprint: update last seen and merged query IDs; do not re-notify.
- Current `accepted-public`／`false-positive`: suppress notification until expiry.
- Expired review: clear review, set `open`, update last notified, emit `REOPENED`.
- Observed `remediated`: set `open`, update last notified, emit `REOPENED`.
- Changed provider object identity: create a distinct `NEW` occurrence.
- No longer observed: retain finding; do not automatically mark remediated.

State is stored only at branch `psb-source-003-state`, path `state/findings.json`. Read returns the current blob SHA.
Write uses `PUT /repos/{repository}/contents/state/findings.json` with the exact SHA and branch. Conflict, missing branch,
malformed state, permission denial, or write failure is exit `2`. The successful run advances the Gist cursor and therefore
persists state even with no finding event.

## 10. Command-line interface

### 10.1 Generate browser queries

```bash
python3 scripts/monitor-public-exposure.py queries \
  --config secure/domain-monitor.json \
  --output generated/queries.md
```

Requires no token or network. Success prints `WROTE <path>` and returns `0`.

### 10.2 Read state

```bash
GITHUB_TOKEN=... python3 scripts/monitor-public-exposure.py state-read \
  --repository owner/private-monitor \
  --output generated/state-snapshot.json
```

The snapshot contains repository, fixed branch/path, base blob SHA, and parsed state.

### 10.3 Collect observations

```bash
PUBLIC_SEARCH_TOKEN=... python3 scripts/monitor-public-exposure.py collect \
  --config secure/domain-monitor.json \
  --state-snapshot generated/state-snapshot.json \
  --output generated/observations.json
```

Collection MUST finish every configured automatic query and Gist delta before returning `0`.

### 10.4 Reconcile and persist

```bash
GITHUB_TOKEN=... GITHUB_RUN_ID=12345 \
python3 scripts/monitor-public-exposure.py reconcile \
  --state-snapshot generated/state-snapshot.json \
  --observations generated/observations.json \
  --output-dir generated/assessment
```

The command first prepares these local files, then persists state with compare-and-swap, and only after that returns its
final success／finding exit status:

- `new-findings.json`: notifier-ready `NEW`／`REOPENED` events;
- `updated-state.json`: the sanitized state that was persisted; and
- `summary.md`: counts and sanitized public links.

A notification adapter MUST consume the files only when the command has completed with exit `1`. If local output cannot be
prepared, state MUST remain unchanged. If the state update fails, the command returns `2`, the prepared files are not
deliverable, and the unchanged state causes the finding to be emitted again on a later successful run.

Exit statuses are invariant:

| Exit | Meaning |
| --- | --- |
| `0` | The automated scope completed with no `NEW`／`REOPENED`. |
| `1` | State persisted and at least one `NEW`／`REOPENED` was emitted. |
| `2` | Input, provider, pagination, truncation, state read, or state write error. Never clean. |

Unexpected exceptions MUST be redacted to `ERROR <command>: unexpected scanner failure`; traceback and tokens MUST NOT be
printed to CI output.

## 11. GitHub Actions contract

The reference workflow MUST:

- use only `schedule` and `workflow_dispatch`;
- run the privileged job only when the selected ref is the repository default branch;
- use no `pull_request`, `pull_request_target`, or untrusted push-triggered write job;
- declare top-level `permissions: {}` and job-level `contents: write` only;
- use one concurrency group with `cancel-in-progress: false`;
- set a finite job timeout no longer than 60 minutes;
- pin every third-party Action to a full commit SHA;
- checkout reviewed monitor code with `persist-credentials: false`;
- pass tokens through step environment, never command arguments or URLs;
- run queries, state read, collection, reconciliation, Summary, then final outcome enforcement;
- preserve exit `1` as a finding signal and exit `2` as scan error; and
- avoid uploading raw observations, state, domain query catalog, or token-bearing diagnostics as public artifacts.

The actual monitor repository MUST be private because browser queries and public result URLs reveal the organization being
monitored. The state branch MUST NOT be checked out or executed by the workflow.

## 12. Notification boundary

`new-findings.json` MAY contain event type, fingerprint, surface, indicator ID, query IDs, public resource, path, URL,
first seen, and last seen. It MUST NOT contain a domain value, match, snippet, email local part derived from content,
credential, authorization header, or raw response.

Production delivery is outside this PoC. A production adapter MUST define delivery ID, retry, dead-letter behavior,
acknowledgement, access-controlled logging, and the point at which a notification becomes delivered. It MUST NOT treat
state persistence alone as Slack delivery success.

## 13. Verification requirements

Offline tests MUST cover at least:

- valid config creates six domain-anchored REST queries and the browser catalog;
- unsafe domain forms are rejected;
- code results are public-only, normalized, and deduplicated;
- Issue and PR remain distinct and repository visibility is verified;
- Gist description／filename／content matching stores no matched content;
- truncated Gist and collection limits fail closed;
- initial observation is `NEW`, repeated observation is known;
- review expiry and remediated recurrence become `REOPENED`;
- changed object identity becomes a new occurrence;
- Contents API update uses the exact base blob SHA;
- malformed／incomplete provider data and escaped pagination hosts fail closed; and
- workflow triggers, permissions, Action pin, and credential persistence are safe.

Tests MUST be network-free and use synthetic provider responses. They MUST NOT verify README strings, create fake adoption
evidence, or push canary secrets to a public provider. The canonical command is:

```bash
make verify-control CONTROL=PSB-SOURCE-003
```

A live smoke test is optional and MUST explicitly declare network egress and identity. Fixture PASS proves scanner behavior,
not live organization adoption.

## 14. Acceptance criteria

An implementation conforms when all of the following are true:

1. Only a stable ID and owned domain are required to generate the complete catalog.
2. The automatic collector covers code, Issue, PR, and new／updated public Gist through official APIs.
3. Human browser GET queries are advanced, domain-anchored, generated, and clearly marked unexecuted.
4. No target repository is cloned.
5. Search and state credentials are separated and private results are rejected.
6. Result normalization and state contain no matched content or secret-bearing raw responses.
7. `NEW`, known, expiry, remediation recurrence, and object changes follow the state machine.
8. State update is an exact-SHA compare-and-swap on the fixed branch/path.
9. All incomplete or failed collection paths return `2`, never `0`.
10. The copyable workflow is inactive by default in the blueprint and uses trusted triggers and minimum permissions.
11. Offline scanner tests pass.
12. README explains live adoption, browser baseline, notification integration, rollback, and residual risk.

## 15. Versioning

Change the specification and query catalog version before changing a query template, provider object identity, fingerprint,
state transition, output schema, branch/path contract, or failure semantics. A state schema change requires a documented,
fail-closed migration. Implementations MUST reject unsupported versions rather than guessing.

Provider behavior is mutable. Re-review against the official
[REST Search API](https://docs.github.com/en/rest/search/search),
[Gists API](https://docs.github.com/en/rest/gists/gists),
[Contents API](https://docs.github.com/en/rest/repos/contents), and
[Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
before production rollout or after a provider change.
