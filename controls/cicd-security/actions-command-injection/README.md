# PSB-CICD-002: Prevent GitHub Actions command injection

## このcontrolを一枚で理解する

### セキュリティ上の問題

Attacker-influenced GitHub expressionを`run`へ直接展開すると、値がrunner shell sourceとして解釈され任意command injectionになる。

### 誰から、または何から守るか

Fork contributor、悪意あるIssue・PR metadata、変更可能なworkflow input、YAMLまたはshell境界の誤解、parser障害から守る。

### 何が対象か

GitHub Actionsの`run` scalar、event expression、workflow value、environment boundary、workflow verifier。

### 何をするか

`${{ ... }}`の`run`直接補間を禁止し、値をenvironmentまたはstructured argument境界へ移し、shell quotingを適用する。

### 成功状態

`run` scriptに直接expressionがなく、multiline・quoted・unsupported syntaxも検査され、評価不能なworkflowはfail closedとなる。

### 対象外・残余リスク

Environmentへ移した値もshell・subprocessで安全に引用する必要があり、script自身のinjectionや外部Action内部の処理はこの検査だけでは防げない。

## Security problem

GitHub Actions evaluates `${{ ... }}` expressions before an inline `run:` step
is written to a temporary shell script. If an expression contains a pull
request title, branch name, issue body, workflow input, matrix value, or other
attacker-influenced text, shell metacharacters in that value can become
executable commands on the runner.

This control prohibits direct expression interpolation in every `run:` scalar.
Context values needed by a command must cross the expression-to-shell boundary
through `env:` and must be consumed as quoted shell variables. This policy is
intentionally stricter than trying to maintain an incomplete list of
attacker-controlled context properties.

## Threat and trust boundary

The trust boundary is between GitHub's expression evaluator and the command
shell on a workflow runner. The primary failure scenario is
`CI-UNTRUSTED-CONTEXT-COMMAND-INJECTION`: an attacker supplies shell syntax in
event metadata or another workflow value, and direct expression substitution
turns that data into part of the generated script.

An exploit can read the job's files, alter build output, poison caches, or use
credentials available to the job. Minimal workflow permissions and
fork-restricted secrets reduce impact but do not make command injection safe.

## Examples

- `insecure/workflow.yml` directly interpolates a pull request title,
  `github.head_ref`, and a manual workflow input into `run:` commands.
- `secure/workflow.yml` assigns those values under `env:` and accesses them as
  quoted shell variables. It also demonstrates that `${{ github.ref }}` in a
  `concurrency.group` is not shell execution and is outside this control.

The fixtures live outside `.github/workflows` and are never executed by
GitHub.

## Verification

From the repository root:

```bash
make verify-control CONTROL=PSB-CICD-002
```

To inspect repository workflows directly:

```bash
python3 controls/cicd-security/actions-command-injection/scripts/verify.py \
  .github/workflows
```

Exit status `0` means every discovered `run:` scalar is free of direct GitHub
Actions expressions. Exit status `1` means the policy found a vulnerable
interpolation. Exit status `2` means verification could not run reliably, such
as a missing input, unreadable file, unsupported `run:` YAML form, or no
`run:` steps. A verifier error must never be treated as a clean result.

## Adoption guidance

Replace this:

```yaml
run: echo "${{ github.event.pull_request.title }}"
```

with:

```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: printf '%s\n' "$PR_TITLE"
```

For each workflow:

1. Inventory expressions used by `run:` steps.
2. Move required values to step- or job-level `env:`.
3. Quote shell variable expansions and pass values as arguments rather than
   constructing commands.
4. Avoid `eval`, `bash -c` with interpolated data, and dynamically generated
   command strings.
5. Keep `GITHUB_TOKEN` permissions explicit and minimal.
6. Test malicious titles, branch names, inputs, and output values as data.

## Limitations and operational cost

The verifier performs deterministic static analysis of conventional block and
single-line `run:` scalars. It deliberately rejects every direct expression in
`run:`, including values such as `github.sha` that may have a constrained
format, to avoid a brittle allowlist and make the trust boundary reviewable.

Moving a value to `env:` prevents GitHub from inserting it into the generated
script, but unsafe shell code can reintroduce injection. Unquoted variables,
`eval`, `bash -c`, command construction, sourced files, malicious repository
code, and vulnerable third-party Actions require separate analysis. Composite
Actions and scripts invoked by a workflow must be scanned independently.

The verifier is not a full YAML parser and rejects flow-style or aliased
`run:` syntax when it cannot inspect it reliably. The GitHub guidance mappings
in `control.yaml` are vendor-guidance relationships, not compliance claims.
