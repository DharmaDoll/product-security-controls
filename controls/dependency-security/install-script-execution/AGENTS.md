# PSB-DEPS-002 implementation instructions

この file は `PSB-DEPS-002`（`dependency-security`）に固有の実装境界を定める。
repository root と `controls/AGENTS.md` を先に読み、共通規約をここへ複製しない。

## Control essence

- この control の本質は、dependency install が単なる file 展開ではなく、developer／CI の権限で
  package-controlled code を実行し得ることを明らかにし、未承認実行を native policy で防ぐことである。
- 現行 package manager では default deny が増えている。独自 policy engine を作らず、supported version の
  native default、明示 approval、危険な override、source-build fallback を正確に説明する。
- Security 効果は、実際の package manager が native policy を適用し、CI が危険な override を拒否する
  ことから生まれる。README、fixture、verifier の copy だけでは live install を保護しない。
- Import、test、compiler plugin、application runtime の実行、package vulnerability、registry trust、
  lockfile／artifact integrity は対象外である。

## Chosen implementation

この control は documentation-led hybrid とする。

1. README を主実装とし、install-time execution point、攻撃経路、version 別 default、override、残余 risk を
   一読できるようにする。
2. `secure/` は package manager 自身が消費できる最小 config を提供する。
3. Python 3.11+ standard-library verifier は危険な全許可、source-build fallback、config corruption の
   regression だけを検出する。
4. Test は network や package install を使わず、inert config fixture で `PASS`、`FAIL`、`ERROR` を
   区別する。
5. Install script approval の組織的 lifecycle は `PSB-GOV-002` に委譲し、この package に独自 approval
   register、期限 engine、自己申告 evidence を置かない。

## Supported versions and assumptions

- Primary developer environment は macOS／VS Code とするが、config と verifier は platform-neutral に保つ。
  Windows 固有手順は concrete requirement と test が揃ってから追加する。
- npm は v12 を primary、v11.16+ の `strict-allow-scripts` を migration path とする。npm v11 と v12 の
  unlisted script behavior を同一視しない。
- pnpm は v11／v12 の `strictDepBuilds`、`allowBuilds`、`dangerouslyAllowAllBuilds` を対象にする。
  pnpm v10 の removed setting を secure profile に混在させない。
- Bun は untrusted dependency script を既定で止めるが、built-in default trusted list と
  `trustedDependencies` が実行経路になることを明記する。Strict profile は `ignoreScripts=true` とする。
- pip は source distribution から PEP 517 build backend が起動する経路を対象とし、
  `--only-binary=:all:` を実装境界とする。
- Manager major、default、setting precedence が変わる変更では current official documentation を確認する。
  確認できない behavior を推測で fixture 化しない。

## README requirements

Mandatory one-page summary の直後に、次を配置する。

1. Supported manager version と trust assumption。
2. 対象 ecosystem の exact copy／merge 対象。
3. Repository-local activation と CI enforcement。
4. Harmless positive／negative self-test と exit status。
5. Recovery、rollback、live verification、residual risk。

`動作原理と悪用手法` section は少なくとも次を説明する。

- npm／pnpm／Bun の `preinstall`、`install`、`postinstall`。
- git／file dependency の `prepare` と `binding.gyp` による implicit native build。
- Direct dependency だけでなく transitive dependency も hook を持てること。
- pip sdist の build requirement 取得、metadata generation、wheel build で backend code が動くこと。
- Developer shell、CI token、SSH agent、source tree、build output、network authority を継承する影響。
- `dangerously-allow-all-scripts`、`dangerouslyAllowAllBuilds`、Bun trust、sdist fallback、古い major、
  config precedence による bypass。

説明は具体的にするが、credential theft、external callback、malware persistence を実行する payload は
repository に置かない。必要な例は temporary marker file 程度の inert pseudo-code に留める。

## Native profiles

### npm

- Repository profile は unreviewed script を non-zero にする `strict-allow-scripts=true` と、
  `dangerously-allow-all-scripts=false` を使用する。
- npm v12 の default deny を説明し、npm v11.16+ では strict mode が migration guard であることを分ける。
- Native `allowScripts` approval を利用する場合は exact installed version を基本とし、name-only／all
  approval の継続 risk を明記する。

### pnpm

- `strictDepBuilds=true`、`dangerouslyAllowAllBuilds=false`、empty または reviewed `allowBuilds` を使う。
- `true` entry は exact version に限定する。`false` entry は reviewed denial として name-only を許容する。
- `pnpm approve-builds --all` を通常導入手順にしない。

### Bun

- Bun の default deny を説明した上で、script が不要な project 向け strict profile として
  `install.ignoreScripts=true` を提供する。
- `trustedDependencies` と built-in default trusted list は trust decision であり、安全性の証明ではない。
- `bun pm untrusted` と `bun pm default-trusted` は read-only review command として案内する。

### pip

- `--only-binary=:all:` を要求し、`--prefer-binary` や source fallback を secure state としない。
- Exact version、hash、origin、lockfile graph は `PSB-DEPS-003` の ownership とし、この verifier で重複する
  general artifact-integrity check を実装しない。

## Verification strategy

- Verifier は `--profile-dir` だけを入力とし、network、clock、registry metadata、package executionを使わない。
- Exit code は `0=accepted`、`1=policy finding`、`2=missing／malformed／unreadable input` とする。
- 最低限、次を test する。
  - Secure native profiles are accepted.
  - npm／pnpm の dangerous all-allow と broad positive selector are rejected.
  - Bun strict mode の解除と explicit trust、pip sdist fallback are rejected.
  - Missing／malformed config is `ERROR`, not a clean result.
- README の文字列、手書き `secure: true`、no-op script、架空の live evidence を test しない。
- Fixture `PASS` は reference behavior の regression evidence であり、organization adoption ではない。

## Exception and live evidence

- Script が必要な dependency は exact package／version、script purpose、owner、independent reviewer、
  artifact identity、expiry、isolated-build requirement を review する。
- New integration は `PSB-GOV-002` の active exact decision を消費する。Valid exception でも underlying
  install-execution check を `PASS` に書き換えない。
- Live adoption は effective manager version／config、CI blocking、current native approval、必要なら
  credential-free least-egress build を確認して初めて判断する。
- Live check unavailable は `NOT_CHECKED`、collector／permission／tool failure は `ERROR` とする。

## Relationship to other controls

- `PSB-DEPS-001`: release cooldown と registry／proxy route。
- `PSB-DEPS-003`: lockfile graph、resolved version、origin、artifact digest。
- `PSB-DEPS-004`: dependency change の vulnerability、license、source、provenance review。
- `PSB-BUILD-001`: build credential、sandbox、egress、telemetry。
- `PSB-GOV-002`: shared exception lifecycle。
- `PSB-DETECT-001`: vulnerability／secret／misconfiguration scanning。

本 package はこれらを再実装せず、README から owning control へ link する。

## Metadata and references

- `control.yaml` の `INS-001..005` と `check_context_version: "1.0"` を維持する。
- Framework mapping は reviewed relationship のある MITRE ATT&CK `T1195.001` と NIST SSDF `PW.4.1`
  を基本とし、guide reference から compliance や complete coverage を推論しない。
- README の package-manager仕様、framework、guide、関連controlはすべて clickable link にする。

## Required verification

Repository root から次を実行する。

```bash
bash controls/dependency-security/install-script-execution/tests/test.sh
make verify-control CONTROL=PSB-DEPS-002
make validate-controls
make lint
```

Metadata を変更した場合は canonical generator を実行し、`PSB-DEPS-002` 由来の差分だけを review する。
