# PSB-CICD-001: Immutable GitHub Actions references

## このcontrolを一枚で理解する

### セキュリティ上の問題

`actions/checkout@v6`の`v6`はversion名に見えますが、同じcommitを指し続ける保証のないtagです。GitHub Actionsは
workflowの実行時に、その時点でtagやbranchが指しているcodeを取得します。そのため、利用側repositoryのworkflowに
差分がなくても、配布元で参照先が変更されると、reviewしていない別のcodeが実行されます。

ただし、tagやbranchを使っただけで直ちに情報漏えいやrepository改ざんが起きるわけではありません。具体的な被害には、
おおむね次の3条件が必要です。

1. Mutableな参照を含むworkflowが実際に実行される。
2. 配布元のaccountやrepositoryが侵害される、tagが意図せず付け替えられる等により、参照先が別のcodeへ変わる。
3. そのjobに、攻撃者にとって価値のあるsecret、書き込み権限、OIDC、成果物、cache、source code、または内部networkへの接続がある。

この条件がそろうと、悪性codeはjobと同じ権限で動きます。たとえばsecretを外部へ送る、build結果やrelease artifactを
差し替える、書き込み可能な`GITHUB_TOKEN`でrepositoryを変更する、といった被害が起こり得ます。逆に、外部Actionが
一度も実行されず、jobがread-onlyで、扱う情報も公開済みで、結果が後続処理から信頼されない場合は、深刻な被害へ至る
経路は限定されます。リスクは参照方法だけでなく、そのjobが持つ権限と扱う情報を合わせて判断します。

### 誰から、または何から守るか

Action配布元のmaintainer accountを奪った攻撃者、書き込み権限を不正取得した攻撃者、repository takeover、悪意のない
tag付け替えやrelease作業の誤り、およびmutableな参照を誤って追加する開発者から守ります。すべての配布元を悪意あるものと
みなすcontrolではなく、配布元の管理境界で起きた変更を、利用側のreviewを経ずに取り込まないためのcontrolです。

### 何が対象か

GitHub Actions workflowから参照する外部Action、外部reusable workflow、`docker://` Actionが対象です。加えて、変更時に
これらの参照を検査するrepository内のCI gateも対象です。`./path/to/action`のようなlocal ActionはGit commit SHAへ固定できない
ため対象外ですが、checkoutしたcode自体を信頼できることが別途必要です。

### 何をするか

外部Git参照をfull 40-character commit SHA、Docker Actionを`sha256` digestへ固定します。これは「同じ名前」ではなく
「reviewした特定のGit objectまたはimage内容」を選ぶためです。Repository-owned verifierをrequired checkにして、tag、branch、
short SHA、dynamic expression、Docker tagが再び入った時にmergeを拒否します。固定commitの内側で使われる依存物は別途reviewし、
直接参照の検査結果と混ぜません。

### 成功状態

採用repositoryの実workflowがverifierでexit `0`になり、その検査がdefault branchのrequired checkとしてmerge前に必ず動く状態です。
利用可能ならGitHub側のfull-length SHA policyも有効です。Secret、write token、OIDC、release、deployment等を扱う高権限jobでは、
固定したcommitの出所と内容がreviewされ、推移的依存の確認結果が直接参照の`PASS`とは別に残っています。

### 対象外・残余リスク

Full SHAが固定するのは、workflowから直接参照したGit objectです。Action内部が実行時に取得するcontainer、package、nested Action、
外部downloadまでは固定しません。また、固定したcommitが無害であること、既知脆弱性がないこと、公式の配布元から取得したことも
自動では証明しません。安全なcommitへ固定していれば後日のtag移動には追随しませんが、悪性または脆弱なcommitを固定した場合は、
明示的に更新するまでその問題が残ります。

## このcontrolで被害経路をどう変えるか

GitHubは、third-party Actionの侵害によってjobで利用可能なsecretや`GITHUB_TOKEN`が悪用され得るため、外部Actionをfull-length
commit SHAへ固定することを推奨しています。詳細は[GitHubのSecure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
を参照してください。

被害が成立する流れは次のように整理できます。

```text
mutableなtag／branchで外部codeを参照してworkflowを実行
        +
配布元で参照先がreview後に別のcodeへ変更される
        +
jobに悪用できる権限・情報・成果物・network接続がある
        =
利用側repositoryに差分を出さず、jobの権限で被害を起こせる
```

本controlは最初の条件を、review済みのexact SHAまたはdigestに置き換えます。配布元が同じtagを別commitへ動かしても、利用側は
自動追随しません。新しいcommitを使うにはworkflowのSHA変更が必要になるため、その変更がpull requestの差分として見え、通常の
reviewを通せます。

一方で、jobへ与える権限の削減や、固定するcommit自体の安全性確認は別の防御です。Pinningだけに依存せず、
[`PSB-CICD-004 Actions least privilege`](../actions-least-privilege/README.md)等と組み合わせます。

## 何が、どの条件で被害になるか

被害の大きさは、そのActionがどのjobで動くかによって変わります。次の表は優先度を判断するための目安であり、すべての
workflowが同じseverityになるという意味ではありません。

| Jobが触れられる対象 | 被害が成立する主な条件 | 起こり得ること | 条件がない場合 |
|---|---|---|---|
| 公開sourceとread-only token | Actionが実行され、その出力やtest結果を人や後続jobが信頼する | Testの偽装、検査結果の改ざん、誤った成果物を後続へ渡す | 出力を利用せず、隔離された一時runnerなら影響は比較的小さい |
| 非公開source code | Checkout後にActionがcodeを読めて、外部通信が可能 | 未公開codeの持ち出し | Sourceをcheckoutしない、または外部通信を強く制限していれば経路は狭まる |
| `GITHUB_TOKEN` | Jobの`permissions`に書き込み権限がある | Tokenの許可範囲内でcontents、issue、pull request、package等を変更 | `permissions: read-all`または必要最小限なら変更可能な範囲は縮小する |
| Repository／organization secret | Secretがそのjobへ渡され、悪性codeから参照でき、外部送信できる | Cloud key、API token、signing material等の漏えいと二次侵害 | Secretがjobへ渡されなければ、そのsecretを直接盗むことはできない |
| OIDC token | `id-token: write`があり、cloud側のtrust条件がそのworkflowを許可 | 一時cloud credentialを取得し、許可範囲でcloud resourceを操作 | OIDC権限がない、またはcloud側のsubject／audience制約で拒否されれば成立しない |
| Build、package、release、deployment | Actionの出力が署名・公開・deploy工程へ渡る、または公開権限を持つ | Artifactのすり替え、汚染packageの公開、意図しないdeployment | 後続で独立検証し、公開権限と分離していれば影響を抑えられる |
| Cache、artifact、shared workspace | 後続の高権限jobが低信頼jobの生成物を検証せず利用 | 後続処理へのcode注入やbuild結果の汚染 | Trust levelごとに保存先を分離し、内容を再検証すれば経路を減らせる |
| Self-hosted runner／内部network | Runnerが使い捨てでなく、host権限や内部serviceへの到達性がある | Credential残留、runnerの永続化、到達可能な内部serviceへの横展開 | Ephemeralで隔離され、内部networkへ到達できなければ影響は限定される |

### 対応優先度の目安

- 最優先: Secret、write token、OIDC、signing、release、deployment、self-hosted runner、内部networkへ到達するjob。
- 高: 生成物、cache、test結果が後続の高権限処理やrelease判断から信頼されるjob。
- 中: 非公開sourceを扱うが、tokenはread-onlyでrunnerが隔離されているjob。
- 相対的に低: 公開sourceだけを扱い、権限のない使い捨てrunnerで動き、出力も信頼されないjob。ただし、参照固定を省略する理由にはしません。

## 実在事例から理解する

2025年3月の[`tj-actions/changed-files`に関するGitHub Advisory（GHSA-mrrh-fwg8-r2c3）](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
では、複数のversion tagが悪性commitを指すように変更され、Actionを実行したrunnerのmemoryから得た情報がworkflow logへ
出力される問題が報告されました。この事例で重要なのは、利用側repositoryのworkflowを変更しなくても、mutableなtagの参照先が
変わることで別のcodeを実行し得た点です。

一方、tagを記載していたすべてのrepositoryが同じ被害を受けたわけではありません。少なくとも、参照先が悪性commitだった期間に
workflowが実行され、そのjob内に露出し得るsecret等があり、出力されたlogを攻撃者または第三者が閲覧できる、といった条件が
影響を左右します。安全なcommitのfull SHAへ事前に固定していたworkflowは、後から動かされたtagには追随しません。ただし、
悪性commitそのものへ固定した場合は防げないため、固定前の配布元確認とcode reviewも必要です。

この事例は「SHA固定ですべて解決する」のではなく、「利用側に差分のないtag移動を止め、次のcommitを取り込む判断を利用側のreviewへ
戻す」という本controlの効果と限界を示しています。

## セキュリティ向上の効果はどこから生まれるか

効果はREADMEやfixtureからではなく、実際の`.github/workflows`をimmutable referenceへ変更し、CI required checkと
利用可能なGitHub policyでmutable referenceを拒否することから生まれます。攻撃者がupstream tagを動かしても、
利用側repositoryのreviewなしに実行codeを差し替えにくくなります。

ただし、固定されるのは直接参照したGit objectだけです。[Palo Alto NetworksのUnpinnable Actions解説](https://www.paloaltonetworks.com/blog/cloud-security/unpinnable-actions-github-security/)
が示すとおり、Action内部のcontainer image、binary、nested Action、外部resourceはmutableな場合があります。本controlは
その問題を隠さずreview対象にしますが、推移的依存を完全に固定したとは主張しません。

### Copyしたものが変える範囲

| 要素 | 実際に変わること | それだけでは変わらないこと |
|---|---|---|
| `scripts/verify.py` | Workflow file内の直接参照がfull SHA／digestかをlocalで判定できる | 実workflowの参照、GitHub setting、job権限は変更しない |
| `secure/verify-action-pinning.yml` | 同じ判定をpull requestごとにCIで実行できる | Required checkにするserver-side設定は自動化しない |
| WorkflowのSHA／digest変更 | 配布元のtag移動へ自動追随しなくなる | 固定commit内部の推移的依存や悪性動作までは止めない |
| GitHub Actions policy | Provider側でもmutableなAction参照を制限できる | Plan、適用範囲、reusable workflowの扱いに差があるためlocal gateを置き換えない |

README、fixture、verifierをcopyしただけでは導入完了ではありません。実workflowの参照を直し、CI workflowを有効化し、
repository administratorがそのcheckをdefault branchのmerge条件に設定した時に継続的な効果が生まれます。

## 最短の導入手順

### 前提条件

- GitHub Actionsを利用しているrepository
- Python 3.10以上
- workflowを変更できるdeveloper
- CI checkをdefault branchへ必須化できるrepository administrator
- GitHub側policyを使う場合だけOrganization ownerと対応plan

VerifierはPython standard libraryだけで、外部通信なしに動きます。[pinact](https://github.com/suzuki-shunsuke/pinact)は
tagやbranchをSHAへ置き換える作業を短くする任意の修正toolです。Pinactが修正を補助し、repository-owned verifierが最終結果を
判定する、という分担です。

### 1. Copyするfile

次の2 fileをcopyします。既存fileがある場合は上書きせず、内容をreviewしてmergeしてください。

- [`scripts/verify.py`](scripts/verify.py) → `scripts/security/verify-action-pinning.py`
- [`secure/verify-action-pinning.yml`](secure/verify-action-pinning.yml) → `.github/workflows/action-sha-pinning.yml`

### 2. Harmless self-test

このrepositoryでは、実行されないfixtureをworkflow textとして検査します。

```bash
python3 controls/cicd-security/action-sha-pinning/scripts/verify.py \
  controls/cicd-security/action-sha-pinning/secure/workflow.yml
echo $?
```

Expected: `PASS`と`ACCEPTED`が表示され、exit `0`。

```bash
python3 controls/cicd-security/action-sha-pinning/scripts/verify.py \
  controls/cicd-security/action-sha-pinning/insecure/workflow.yml
echo $?
```

Expected: mutable Action、Docker tag、tagged reusable workflowが`FAIL`となり、exit `1`。Fixtureは
`.github/workflows`外にあり、GitHubから実行されません。

### 3. 実workflowを直して検査する

```yaml
# insecure: tagは後から移動できる
- uses: actions/checkout@v6

# secure: exact Git objectを固定し、release名はreview用commentに残す
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Reusable workflowにも同じfull SHAを要求します。

```yaml
uses: example-org/ci/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567 # v1.0.0
```

Docker ActionはGit SHAではなくimage digestへ固定します。

```yaml
uses: docker://alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
```

Copy後のlocal activation commandは次です。

```bash
python3 scripts/security/verify-action-pinning.py .github/workflows
```

全対象workflowが`ACCEPTED`となったら、copyしたCI workflowをrequired checkにします。GitHub側でも
[Actions policyのfull-length SHA requirement](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
を有効化してください。Provider policyだけではreusable workflowのtagを防げない場合があるため、local gateは残します。

## pinactで修正を短くする

採用候補は[pinact v4.1.1](https://github.com/suzuki-shunsuke/pinact/releases/tag/v4.1.1)、source commitは
[`b1a554a82ef4f55533237e49c19a24ddf0045100`](https://github.com/suzuki-shunsuke/pinact/commit/b1a554a82ef4f55533237e49c19a24ddf0045100)です。
[公式installation guide](https://github.com/suzuki-shunsuke/pinact/blob/main/INSTALL.md)と、repositoryで固定した
[macOS／Linux release checksums](tools/pinact-v4.1.1-checksums.txt)を使い、downloadしたarchiveを検証してください。
`brew install`や`@latest`は簡便ですが、canonical security gate用のversion固定にはしません。

Apple Silicon Macで一時directoryへ検証済みbinaryを展開する最短例です。

```bash
pinact_tmp="$(mktemp -d)"
pinact_asset="pinact_darwin_arm64.tar.gz"
pinact_checksums="$PWD/controls/cicd-security/action-sha-pinning/tools/pinact-v4.1.1-checksums.txt"
curl --fail --location --silent --show-error \
  --output "$pinact_tmp/$pinact_asset" \
  "https://github.com/suzuki-shunsuke/pinact/releases/download/v4.1.1/$pinact_asset"
(cd "$pinact_tmp" && grep " $pinact_asset$" "$pinact_checksums" | shasum -a 256 -c -)
tar -xzf "$pinact_tmp/$pinact_asset" -C "$pinact_tmp" pinact
"$pinact_tmp/pinact" version
```

Expected versionは`4.1.1`です。Intel Macは`pinact_darwin_amd64.tar.gz`、Linuxは対応する`linux` assetと
`sha256sum -c -`を使います。恒久的な配置先はadopter側のrepository-local tool管理に合わせてください。

Pinactのdefault実行はGitHub APIへ接続して参照先のSHAを調べ、workflow fileを書き換えます。外部通信とfile変更が起きることを
理解した上でrepository rootから明示的に実行し、必ず差分をreviewします。

```bash
"$pinact_tmp/pinact" run -e '^docker://'
git diff -- .github/workflows
python3 scripts/security/verify-action-pinning.py .github/workflows
```

`docker://`だけをpinactの処理から外すのは、pinact v4.1.1がDocker Actionを固定対象として扱わないためです。Docker参照を
無視してよいという意味ではありません。最後にrepository-owned verifierを実行し、image digestへの固定を必ず検査します。
Branch参照などpinactが自動修正できないものは、公式または正規の配布元repositoryでreleaseとSHAを確認して手動で直します。

初期実装ではpinactによるauto-commit、write permission、SARIF、reviewdog、`min-age`を使いません。Cooldownは
[`PSB-DEPS-001`](../../dependency-security/release-cooldown/README.md)の責務です。

## 誰が何をするcontrolなのか

- Developer: 公式または正規の配布元でrelease、exact commit、変更内容を確認し、workflowをSHAまたはdigestへ更新する。
- Repository administrator: Verifierをdefault branchのmergeに必要なcheckへ設定し、verifier自体とworkflowの変更にreviewを要求する。
- Organization owner: 契約planで利用できる場合、許可するActionの範囲とfull-length SHA requirementをGitHub設定で有効化する。
- Security reviewer: Secret、write token、OIDC、release等を扱う高権限jobを優先し、固定commitの内容、推移的依存、例外をreviewする。
- Update automation owner: 人が差分を確認できる小さな更新PRを作り、release名をSHA横のcommentへ残す。Security-sensitiveな更新を自動mergeしない。

## 推移的依存の確認

詳細は[`docs/transitive-dependency-review.md`](docs/transitive-dependency-review.md)を使います。最低限、固定したcommitで
次を確認します。

- Dockerfileのbase imageや実行時containerがdigest固定されているか
- `npm install`、`pip install`等がlockなしで実行されないか
- Composite Action／reusable workflow内部の`uses:`がtagやbranchでないか
- 外部binaryやscriptにchecksum／signature検証があるか

結果は直接参照と分けます。

```text
Direct reference verification: PASS
Transitive dependency review: MUTABLE_RUNTIME_OBSERVED
```

| 状態 | 意味 |
|---|---|
| `NO_OBVIOUS_MUTABILITY` | 確認した範囲では、実行時に参照先が変わる明白な依存は見つからなかった。安全性や確認の完全性を証明する状態ではない |
| `MUTABLE_RUNTIME_OBSERVED` | Container tag、version指定のpackage取得、tag付きnested Action等、実行時に内容が変わり得る依存を確認した |
| `NOT_CHECKED` | 未確認。直接参照が`PASS`でも、この結果を自動的に安全へ読み替えない |
| `ERROR` | Source取得、対象commitの特定、または内容確認に失敗した。未確認のまま扱う |

書き込み可能なtoken、secret、OIDC、署名、deployment権限を持つjobで、実行時に変わり得る依存が見つかった場合は、より小さな
Action、repository-owned script、review済みfork、権限削減、または期限付き例外を選びます。本controlが自動でforkを作ったり、
推移的依存を完全にlockしたりすることはありません。

## Verificationとexpected output

Repository内のcanonical commandは次です。

```bash
make verify-control CONTROL=PSB-CICD-001
```

Exit statusは次のとおりです。

| Exit | 意味 | CIの扱い |
|---:|---|---|
| `0` | 全ての検出済み参照がaccepted | 成功 |
| `1` | Mutable／dynamic referenceを検出 | mergeをblock |
| `2` | Input、parser、tool errorで検査不能 | mergeをblockし、cleanと扱わない |

この自動testが確認するのは、「安全な直接参照を許可し、mutableな直接参照と検査不能状態を拒否する」という判定器の動作です。
Actionが無害であること、推移的依存が固定されていること、採用repositoryでrequired checkが有効なことは確認しません。

### 導入完了の確認

1. 採用repositoryの実際の`.github/workflows`に対してverifierを実行し、exit `0`になる。
2. Mutableな参照を含む安全な検証用PRでcheckがexit `1`となり、required checkによってmergeできないことを確認する。
3. GitHubのbranch protectionまたはruleset画面で、このcheckがdefault branchの必須条件になっていることを確認する。
4. 利用可能なら、GitHub Actions設定でfull-length SHA requirementが有効であることをread-onlyで確認する。
5. 高権限jobについて、固定commitのpermalinkと推移的依存のreview結果をPRまたはticketへ残す。

検証用PRでは、本番処理を動かさずにverifierへ検出させる専用のworkflow fileまたは既存fixtureを使い、検出確認後に削除します。
Fixtureの成功はこのrepositoryのregression確認にすぎません。導入完了のevidenceは、採用repositoryのexact revision、秘密を
除いたverifier output、default branchに適用されたrequired check、確認可能なら現在のprovider設定です。推移的reviewは
固定commit permalinkとPR review記録を使い、架空のevidence JSONは作りません。

## よくある失敗とrollback

- Tag／branch finding: canonical releaseのfull SHAへ変更する。
- Docker finding: image manifestの`sha256` digestへ変更する。
- `ERROR no uses references found`: 対象pathがworkflowを含むか確認する。対象なしを勝手に`PASS`へしない。
- Unsupported YAML: GitHubが解釈する`uses:`を1行のscalarにし、verifierが評価できない状態をskipしない。
- pinact failure: API、rate limit、branch referenceを確認する。pinact失敗をcanonical verifierの成功へ読み替えない。

RollbackではcopyしたCI workflowとverifierだけをreviewの上で外し、既に固定したSHA／digestをtagへ戻しません。
代替のrequired enforcementが有効であることを先に確認します。Global Git、shell、IDE、Python設定は変更しません。

## 限界と運用コスト

- 固定commitが最初から悪性、脆弱、または偽の配布元から取得したものである可能性は残る。
- Verifierは、そのSHAが配布元に実在するか、正規repositoryのものか、意図したreleaseに対応するかを外部へ問い合わせない。
- Action内部の推移的依存、実行時の振る舞い、credentialの受け渡しは自動検証しない。
- Pinningするとtagの更新へ自動追随しなくなる。Security updateを取り込む担当者と、差分を人がreviewする更新手順が必要になる。
- Action releaseの既知脆弱性と一般dependency graphのreviewは[PSB-DEPS-004](../../dependency-security/dependency-change-review/README.md)で扱い、本controlはadvisory databaseを再実装しない。
- Local Actionは呼び出し元repositoryのfileなのでSHAへ固定しない。信頼できないpull requestのcheckoutで差し替えられるriskは別controlで扱う。
- 固定した古いAction releaseが、GitHub-hosted／self-hosted runnerの更新後に動かなくなる場合があるため、互換性確認が必要になる。

## 関連framework

`control.yaml`のmappingは限定的なsupport／mitigation関係であり、formal complianceや完全coverageを意味しません。

- [GitHub Security Guidance registry](../../../frameworks/github-security-guidance/README.md) —
  [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)のfull SHA guidanceを直接support
- [MITRE ATT&CK v19.1 registry](../../../frameworks/mitre-attack/README.md) —
  [T1195.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)を部分的にmitigate
- [NIST SSDF SP 800-218 v1.1 registry](../../../frameworks/nist-ssdf/README.md) —
  [PW.4.1](https://csrc.nist.gov/pubs/sp/800/218/final)のthird-party component acquisition／maintenanceをsupport

関連しますが、本control単独では直接mappingしないguide／frameworkは次です。

- [OpenSSF OSPS Baseline 2026.02.19 registry](../../../frameworks/openssf-osps-baseline/README.md) — dependency remediation policyは本controlより広い
- [SLSA specification](https://slsa.dev/spec/) — SHA pinningだけではbuild provenanceやisolated buildを満たさない
- [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final) — CI/CD supply chain全体の統合guide

## 関連guide・参考資料

- [pinact repository](https://github.com/suzuki-shunsuke/pinact)
- [pinact installation and release verification](https://github.com/suzuki-shunsuke/pinact/blob/main/INSTALL.md)
- [Palo Alto Networks: Unpinnable Actions](https://www.paloaltonetworks.com/blog/cloud-security/unpinnable-actions-github-security/)
- [GitHub Advisory: tj-actions/changed-files tag compromise（GHSA-mrrh-fwg8-r2c3）](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
- [GitHub: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: Reusing workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [GitHub: Managing Actions settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [Repository security guidance sources](../../../docs/SECURITY_GUIDANCE_SOURCES.md)
- [Supply-chain attack control list](../../../docs/SUPPLY_CHAIN_ATTACK_CONTROL_LIST.md)

## 関連control

- [PSB-CICD-003 Actions static analysis](../actions-static-analysis/README.md)
- [PSB-CICD-004 Actions least privilege](../actions-least-privilege/README.md)
- [PSB-CICD-005 Untrusted PR boundary](../untrusted-pr-boundary/README.md)
- [PSB-CICD-006 Audience-bound OIDC](../audience-bound-oidc-federation/README.md)
- [PSB-CICD-007 Runner hardening](../runner-hardening/README.md)
- [PSB-CICD-009 Cache provenance isolation](../cache-provenance-isolation/README.md)
- [PSB-DEPS-001 Release cooldown](../../dependency-security/release-cooldown/README.md)
- [PSB-DEPS-004 Dependency change review](../../dependency-security/dependency-change-review/README.md)
- [PSB-CONTAINER-001 Container admission baseline](../../container-cloud-iac-security/container-admission-baseline/README.md)
- [PSB-SOURCE-006 GitHub Organization governance](../../source-protection/github-organization-governance/README.md)
- [PSB-GOV-002 Time-bound security exceptions](../../governance-operations/time-bound-security-exceptions/README.md)
