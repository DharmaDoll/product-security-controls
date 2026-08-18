# PSB-CODE-005: Detect deceptive Unicode controls and identifiers in source code

## このcontrolを一枚で理解する

| 観点 | 内容 |
|---|---|
| セキュリティ上の問題 | Sourceへdirectional control、zero-width character、confusable identifierを混入すると、reviewerが見る表示とparserが解釈するsymbolや順序がずれ、悪意ある処理を正当な変更に見せられる。 |
| 誰から、または何から守るか | 悪意あるcontributor、侵害されたcode generator・editor、不可視文字を含むcopy-and-paste、encoding・parser・policy障害をcleanと扱う運用から守る。 |
| 何が対象か | UTF-8 Python source、全source位置のUnicode format control、identifier token、NFKC normalization、scanner policyとsanitized evidence。 |
| 何をするか | 危険なbidi・zero-width・tag characterを全位置で拒否し、Python identifierをASCIIかつNFKC-stableに限定し、decode・parse・policy障害をERRORにする。 |
| 成功状態 | 通常の日本語string dataを含むsecure fixtureは受理され、bidi・invisible・mixed-script・fullwidth identifier fixtureは位置とcode pointだけを示して拒否される。 |
| 対象外・残余リスク | 初期sliceはPythonのみを対象とし、Unicode domain name、自然言語confusable、dependency・compiler compromise、live repository enforcementやreviewer intentは証明しない。 |

## Security problem

Unicode contains formatting and compatibility mechanisms that do not always
have a visible glyph. Directional override and isolate controls can reorder the
rendered appearance of source. Zero-width and tag characters can hide a byte or
token difference. Cyrillic, Greek, mathematical, and fullwidth characters can
look like ASCII identifiers or normalize to a different spelling.

This creates a review boundary failure: the compiler or interpreter processes
one token sequence while a reviewer, search query, or diff view appears to show
another. The control treats the code-point sequence and the original identifier
token as security evidence rather than trusting one editor's rendering.

## Threat and failure scenarios

The primary actor is a malicious contributor or compromised source generator
that can propose code but should not be able to conceal its behavior from
review. Accidental copy-and-paste is a second failure source. The control also
handles verifier failure: invalid UTF-8, malformed Python, an incomplete policy,
an integrity-mismatched fixture, ambiguous symbolic-link source, existing
materialization target, or an empty input set is `ERROR`, never an accepted scan.

The atomic boundaries are deliberately separate:

- `UNI-001` rejects directional formatting controls at every source position;
- `UNI-002` rejects reviewed invisible formatting and Unicode tag characters;
- `UNI-003` keeps Python identifiers in a deterministic ASCII profile while
  allowing Unicode string and comment data;
- `UNI-004` detects the original token spelling before Python's NFKC identifier
  normalization can hide the difference;
- `UNI-005` separates execution failure from a clean result;
- `UNI-006` keeps evidence free of source lines and identifier values.

## Insecure and secure examples

The insecure example is stored as an escaped, digest-bound
[`unicode-source.json`](insecure/unicode-source.json). Tests materialize it only
inside a temporary directory, producing an inert Python file containing a
right-to-left override, a zero-width space, a mixed Cyrillic identifier, and a
fullwidth normalization-unstable identifier. It is never installed, imported,
or executed.

The secure [`example.py`](secure/example.py) demonstrates that ordinary Unicode
data is allowed in a string while source identifiers remain ASCII. The reviewed
[`unicode-policy.json`](secure/unicode-policy.json) defines the exact code points,
tag range, language, extension, encoding, and identifier profile.

## Verification and expected output

From the repository root:

```bash
make verify-control CONTROL=PSB-CODE-005
```

To inspect Python source directly:

```bash
python3 controls/secure-coding/unicode-source-deception/scripts/verify.py \
  --policy controls/secure-coding/unicode-source-deception/secure/unicode-policy.json \
  path/to/python/source
```

Exit status `0` means every discovered Python source file passed the pinned
policy. Status `1` means policy findings exist. Status `2` means the verifier
could not establish a result. An empty directory is an error rather than an
empty clean scan.

Findings contain only the relative path, line, column, code-point identifiers,
and finding category. They do not echo the source line or identifier:

```text
FAIL example.py:1:22 code-points=U+202E forbidden-right-to-left-override
FAIL example.py:3:1 code-points=U+0430 non-ascii-identifier
```

Complete deterministic outputs are stored under [`expected-results/`](expected-results/).

## Integration

Run the verifier before code review and again in unprivileged CI. Pass explicit
source roots rather than scanning generated, vendored, or binary directories by
accident. A repository that intentionally permits non-Latin identifiers must
design and test a language-specific Unicode Technical Standard #39 profile; it
must not broadly disable `UNI-003`.

The standard-library verifier has no network or downloaded data dependency.
Its policy SHA-256 is emitted with every result so evidence identifies the
reviewed decision input. A pre-commit hook is developer feedback only; protected
CI remains necessary because local hooks can be bypassed.

## Operational cost and limitations

The initial adapter parses Python with the running Python standard library and
supports `.py` only. Other languages require tokenizers that preserve original
identifier spelling and distinguish identifiers from strings and comments.
A naive repository-wide non-ASCII ban is not an acceptable substitute because
it unnecessarily rejects legitimate localized data and encourages bypasses.

ASCII identifiers are intentionally restrictive. Projects needing localized
identifiers should adopt a reviewed script-mixing and confusable profile with
positive and negative fixtures. This control does not inspect Unicode security
in hostnames, user input, natural language, generated binaries, or dependencies.
It also does not prove that the organization runs the verifier in CI or protects
the resulting branch rule.

The SITF `T-E011` relationship is an attacker-behavior mapping, not a compliance
claim or proof that all forms of Unicode deception are mitigated.
