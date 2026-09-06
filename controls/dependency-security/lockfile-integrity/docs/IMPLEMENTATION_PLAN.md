# PSB-DEPS-003 native lockfile integrity implementation plan

## Decision

`PSB-DEPS-003`はpackage-manager非依存の自己申告JSON検査器ではなく、各package managerの
immutable／frozen installとnative artifact integrity検証を主実装にする。

Security stateは、review済みlockfileをcommitし、developerとCIの通常installで次を強制することから変わる。

1. Manifestとlockfileが不一致なら暗黙更新せず停止する。
2. Lockfileに記録されたdirect／transitive resolutionを使用する。
3. 取得artifactのbytesがlockfileのintegrityと一致しなければ停止する。
4. Missing lock、malformed input、unsupported schema、runtime failureをclean resultにしない。
5. Dependency update pathとnormal immutable install pathを分ける。

READMEやfixtureをcopyするだけではorganizationのCI enforcementは変わらない。Adopterはcopyしたwrapperを
repository-localにactivationし、同じcommandをrequired CI checkにする必要がある。

## Control boundary

| 項目 | 本controlが行うこと | 対象外または別control |
| --- | --- | --- |
| Manifestとlockfileのずれ | frozen／immutable installで拒否する | 依存更新を承認する判断 |
| 解決versionの予期しない変化 | committed lockfileの解決結果を使用する | lockfile生成前のresolver操作 |
| 配布物の差し替え | lockfileのintegrityと取得物を照合する | 最初から悪意あるartifactが承認された場合 |
| 推移的依存 | 記録されたtransitive resolutionとartifactを固定・検証する | 脆弱性、license、maintainer侵害、意味的妥当性 |
| Verification failure | lock欠落、不整合、tool failureを非zeroにする | package manager binary自体の侵害 |
| Platform差異 | fixtureでselection boundaryを確認する | 未検証OS、CPU、runtime条件 |

Package managerがdependency graphを解決し、lockfileがその結果を記録する。Lockfileはidentityとbytesの
再現性を支援するが、そのpackageが安全かどうかは判断しない。

## Lockfileの限界

| Lockfileでは防げないこと | 理由 | Required composition |
| --- | --- | --- |
| 固定済みpackage自体の脆弱性・悪意 | Hash一致は安全性ではなく同じbytesであることを示す | [`PSB-DETECT-001`](../../../detection-verification/integrity-verified-scanner/README.md) |
| 危険なtransitive dependencyの採用 | Lockfileはgraphを記録してもriskを評価しない | [`PSB-DEPS-004`](../../dependency-change-review/README.md) |
| Lockfileとhashを同じPRで悪性bytesへ更新 | Committed expectation自体が攻撃者の値になる | CODEOWNER、non-author review、branch protection |
| Publisher／maintainer compromise | 正規versionとして悪性releaseが公開され得る | [`PSB-DEPS-001`](../../release-cooldown/README.md)、[`PSB-REL-001`](../../../release-integrity/signature-provenance-verification/README.md) |
| Lifecycle script／source build execution | Lockfileはinstall時権限を制御しない | [`PSB-DEPS-002`](../../install-script-execution/README.md) |
| Package manager／runtime compromise | 侵害された検証器は結果を偽装できる | Runtime pin、checksum／signature、approved CI image |
| OS／CPU／runtime／marker／peer／optional差 | 同じlockから環境別subsetが選択され得る | Target matrixと実install self-test |
| Mutable Git／directory／editable source | Registry artifactと異なるidentity semanticsを持つ | First profileでは拒否し、別profileでcommitとbytesを検証 |
| Artifact削除やregistry停止 | Integrityはavailabilityを保証しない | Approved mirror、cache、retention |
| Reproducible build全体 | Compiler、system library、flags、時刻等はlockfile外 | Build provenanceとreproducible-build control |
| Organization adoption | Fixture PASSはlive required checkを証明しない | Exact commit／lock digest／runtime／required-check evidence |

追加の残余リスクは次のとおり。

- Lock生成時点でresolver inputやregistry responseが侵害済みなら、その結果を正しく固定する。
- Botのlock更新をreviewなしでmergeすると、悪性transitive changeも正規変更として通る。
- Yanked／deleted artifactや保守停止を必ずしも警告しない。
- Lockfile schemaと意味はpackage-manager versionに依存する。
- Weak／missing hashやartifact全体を覆わないintegrityは安全なprofileとして扱えない。
- Source distributionのbuild dependencyやdynamic metadataはruntime lockだけでは完全に固定できない。

## Implementation profiles

| Profile | Normal secure activation | Claim gate |
| --- | --- | --- |
| npm | `npm ci` | Required runnable positive／negative tests |
| pnpm | `pnpm install --frozen-lockfile` | Required pinned runtime and native tests |
| Modern Yarn | `yarn install --immutable` | Copyable example; implemented only after pinned runtime tests |
| Yarn Zero-Installs | `yarn install --immutable --immutable-cache --check-cache` | Checked-in cache negative test required |
| Bun | `bun ci` | Copyable example; implemented only after pinned runtime tests |
| pip | `python -m pip install --require-hashes --only-binary=:all: -r requirements.lock` | Required runnable positive／negative tests |
| uv project | `uv sync --locked` | Required pinned runtime and native tests |
| uv pip compatibility | `uv pip sync --require-hashes requirements.lock` | Additional hashed-requirements example |

`uv sync --frozen`はlockfile freshnessを確認せず、manifestの未反映変更を無視できるためnormal CI commandにしない。
Wheel-only projectでは`uv sync --locked --no-build`を追加hardeningとして示す。

## Planned package layout

```text
lockfile-integrity/
├── README.md
├── control.yaml
├── secure/
│   ├── javascript/
│   │   ├── npm/
│   │   ├── pnpm/
│   │   ├── yarn/
│   │   └── bun/
│   └── python/
│       ├── pip/
│       └── uv/
├── insecure/
│   ├── javascript/
│   └── python/
├── tests/
│   ├── test.sh
│   └── fixtures/
│       ├── javascript/
│       │   ├── basic/
│       │   ├── transitive-change/
│       │   ├── workspace/
│       │   └── platform-optional/
│       └── python/
│           ├── pip-hashed-requirements/
│           └── uv-project/
├── expected-results/
└── docs/
    └── IMPLEMENTATION_PLAN.md
```

## Atomic checks

1. `LOCK-001`: Manifestとcommitted lockfileのfreshness mismatchを拒否する。
2. `LOCK-002`: Supported profileのdirect／transitive exact resolutionがlockに存在する。
3. `LOCK-003`: 取得artifactのstrong integrity mismatchを拒否する。
4. `LOCK-004`: Normal installがlockfileを変更せず、暗黙再解決しない。
5. `LOCK-005`: Missing／malformed／unsupported inputとtool failureをfail closedにする。

Manifestのcompatible version range自体はfindingにしない。Exact resolutionはlockfile側で確認する。
Registry routeとcooldownは`PSB-DEPS-001`の所有範囲とし、本controlのatomic checkから外す。

## Vertical implementation slices

### Slice 1: npm

- `secure/javascript/npm/install-locked.sh`をsingle-purpose wrapperとして追加する。
- Node standard libraryの小さなread-only preflightでsupported lockfile schemaとstrong SRIを確認する。
- `npm ci`のmanifest drift、missing lock、lock non-mutationをactual commandで検証する。
- Local inert tarballで`application -> parent -> leaf`の二段graphを作る。
- Leaf tarballの1-byte tamperをnative integrity failureにする。
- Basic、transitive、workspace、platform／optional fixtureを分離する。

### Slice 2: pnpm

- Exact pnpm versionをapproved sourceから用意し、normal commandを`--frozen-lockfile`へ固定する。
- `--fix-lockfile`、`--update-checksums`、`--lockfile-only`はreviewed update pathだけで使う。
- npmと同じinert graphでmanifest drift、missing lock、transitive tarball tamperを検証する。
- Pinned runtimeを用意できなければ形式的testを追加せず、implemented claimを保留する。

### Slice 3: pip

- Local inert wheelでdirect／transitive graphを作る。
- Complete `requirements.lock`は全requirementをexact `==`とSHA-256へbindする。
- Correct hash、tampered transitive wheel、missing hash、range、missing toolを検証する。
- Automatic sdist fallbackを許可しない。

### Slice 4: uv

- `pyproject.toml`と`uv.lock`をcommitし、`uv sync --locked`をnormal commandにする。
- uv versionをexact pinし、activation中にdownload／upgradeしない。
- `uv.lock`を独自parserで検証せず、uv native validationをauthorityにする。
- Manifest drift、missing lock、transitive wheel tamper、unsupported schema、tool unavailabilityを検証する。
- `uv sync --frozen`がmanifest driftを検出しないinsecure exampleを示す。
- Markerを含むuniversal resolutionとtarget environmentのinstalled subsetを区別する。

### Slice 5: Yarn and Bun examples

- Modern Yarn、Zero-Installs、Bunのcopy可能なrepository-local commandとconfigを追加する。
- Yarn ClassicとModern Yarnを同じsemanticsとして扱わない。
- Bun auto-installをnormal controlled pathにしない。
- Exact runtimeとnative negative testsが揃うまではreference-onlyと明記する。

### Slice 6: Documentation and metadata

- [`README.md`](../README.md)の最初のH2でmandatory six-label summaryを満たす。
- Security effectの発生源、roles、最短copy path、positive／negative self-test、exit、recovery、rollbackを記載する。
- Lockfile limitsとtransitive risk compositionを早い位置へ置く。
- [`control.yaml`](../control.yaml)をnative implementation、atomic checks、row-specific contextへ更新する。
- Synthetic fixture PASSをorganization adoption evidenceとして扱わない。

## Verification matrix

各required profileで次をhuman-readable test名として実行する。

1. Correct manifest、lock、direct／transitive artifactは成功する。
2. Manifest-only driftは失敗する。
3. Missing lockは失敗する。
4. Transitive artifactの1-byte tamperは失敗する。
5. Missing／weak integrityは失敗する。
6. Install前後でlockfile digestが変わらない。
7. Missing runtime、unsupported schema、malformed inputはclean resultにならない。
8. Workspaceとplatform／optional／peer selection boundaryを確認する。

Fixture executionはreference regression evidenceであり、live registry、CI required check、organization adoptionを証明しない。

Canonical commands:

```bash
bash controls/dependency-security/lockfile-integrity/tests/test.sh
make verify-control CONTROL=PSB-DEPS-003
make validate-controls
make generate-index
make generate-mappings
make generate-checklists
make lint
make test
make verify
```

## Framework relationships

| Framework | Planned disposition |
| --- | --- |
| [MITRE ATT&CK Enterprise v19.1 T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Keep narrow `mitigates` relationship for dependency substitution behavior |
| [NIST SSDF 1.1 / SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Keep `PW.4.1` `supports` relationship |
| [OpenSSF OSPS Baseline 2026.02.19 OSPS-BR-05.01](https://baseline.openssf.org/versions/2026-02-19#osps-br-0501) | Provisional `supports` candidate pending row review |
| [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final) | Integration-profile reference, not a direct compliance claim |
| [SLSA v1.2 Build Provenance](https://slsa.dev/spec/v1.2/build-provenance) | Related boundary only; no direct lockfile mapping |

## Implementation and guidance references

- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- [npm package-lock](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/)
- [pnpm install](https://pnpm.io/cli/install)
- [Yarn install](https://yarnpkg.com/cli/install)
- [Yarn checksum behavior](https://yarnpkg.com/configuration/yarnrc/#checksumBehavior)
- [Bun install](https://bun.com/docs/pm/cli/install)
- [Bun lockfile](https://bun.com/docs/pm/lockfile)
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [uv locking and syncing](https://docs.astral.sh/uv/concepts/projects/sync/)
- [uv resolution](https://docs.astral.sh/uv/concepts/resolution/)
- [uv CLI](https://docs.astral.sh/uv/reference/cli/)
- [PEP 751 pylock.toml](https://peps.python.org/pep-0751/)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
- [OWASP NPM Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)
- [OWASP Dependency Graph and SBOM Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
- [CISA/NSA/ODNI Securing the Software Supply Chain for Developers](https://www.cisa.gov/sites/default/files/2023-12/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.pdf)
- [OpenSSF Concise Guide for Developing More Secure Software](https://best.openssf.org/Concise-Guide-for-Developing-More-Secure-Software.html)

## Cross-control generated references

Changing atomic check meaning or ID may require updating
[`supply-chain-reconciliation.json`](../../../../policies/integration/supply-chain-reconciliation.json) and regenerating its checklist.
These files are outside this control directory. Before modifying them, explain the stale-reference reason and limit edits to exact
reference repair plus canonical generated outputs.

## Definition of done

- npm、pnpm、pip、uvのrequired profiles have native positive and negative tests.
- Yarn／Bun claim level matches their pinned-runtime test status.
- Multiple JavaScript fixtures demonstrate direct、transitive、workspace、platform／optional boundaries.
- README makes guarantees、limits、roles、activation、self-test、CI requirement、rollback clear at first read.
- Tool and evidence failures are distinct from clean results.
- No generic self-report JSON、fictional adoption evidence、no-op test remains as implementation authority.
- Metadata validates and generated views contain only reviewed `PSB-DEPS-003` changes.
