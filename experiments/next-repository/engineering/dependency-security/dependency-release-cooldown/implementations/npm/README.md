# npm implementation: Project-local release cooldown

Pattern：[Dependency release cooldown](../../README.md)

Control：[PSB-DEPS-001](../../../../../controls/records/dependency-security/psb-deps-001-dependency-release-cooldown/README.md)

## Status and boundary

Migration Pilotです。npm projectでnative minimum-age settingを使用する小さなImplementation候補です。
旧Projectはnpm `11.10.0`以上と7日をreference profileにしていました。採用時には対象npm majorの公式document、
setting precedence、missing metadata時の挙動を再確認してください。

このImplementationは次を証明しません。

- Teamのすべてのupdate pathで実効設定が使われること。
- CLI、environment、user configで上書きされないこと。
- Packageにmalwareやvulnerabilityがないこと。
- Lockfile、artifact integrity、install scriptが安全であること。

## Files

- [`project.npmrc`](project.npmrc): Projectへmergeする候補設定。

`.npmrc`というhidden fileを直接配布せず、内容をreviewして既存project設定へmergeする前提です。

## Candidate configuration

```ini
registry=https://registry.npmjs.org/
min-release-age=7
save-exact=true
package-lock=true
```

- `min-release-age=7`は旧Pilot baselineの168時間を日単位で表します。
- `save-exact=true`はupdate時のreview対象を明確にします。
- `package-lock=true`は選択したgraphを通常buildで再現するための隣接設定です。

Private registryまたはmanaged proxyを使う場合、URLだけを置換して安全と判断しません。そのendpointが
publish timestampをどう提供し、fallbackやalternate registryをどう扱うかを別に確認します。

## Adoption flow

1. npm versionとofficial config referenceを確認する。
2. Existing `.npmrc`、CLI、environment、user-wide configのprecedenceを確認する。
3. `project.npmrc`の4項目をrepository rootの`.npmrc`へmerge reviewする。
4. Dependency updateを通常buildから分離する。
5. Update時はexact versionを選び、age decision後にmanifestとlockfileを同じPRへ含める。
6. 通常CIとrelease buildはreview済みlockfileを変更しないinstall modeにする。
7. Team repositoryではnative settingに加え、trusted required checkを検討する。

Global npm、shell、IDE、OS設定をこのImplementationから自動変更しません。

## Effective-state checks

対象projectとCIで、少なくとも次の実効値を確認します。

```bash
npm --version
npm config get min-release-age --location=project
npm config get save-exact --location=project
npm config get package-lock --location=project
```

Expected valueはPilot profileでは`7`、`true`、`true`です。ただし表示値だけで実際のresolver behaviorや
上位precedenceからのoverride absenceを証明したとは扱いません。

## Meaningful tests

採用環境で安全なtest scopeを用意できる場合、次を確認します。

- Boundaryを十分に過ぎたtest candidateはresolution対象になる。
- Boundary直前のcandidateはinstall-time code実行前に除外される。
- Publish timestampを取得できないcandidateがallowされない。
- Normal buildがcommitted lockfileを変更しない。
- Team repositoryではyoung candidateがmerge required checkを通過しない。

このPilotには固定のlive packageや形式的なconfig parserを同梱しません。README文字列や
`min-release-age=7`の存在だけを検査するtestは、resolver enforcementを証明しないためです。

## Emergency update

Known vulnerability修正を早く採用する必要がある場合、project-wide floorを恒久的に下げません。
Exact package／version、対象repository、理由、owner、別approver、expiryへ限定したdecisionを使い、
integrity、dependency review、install containmentを維持します。

## Official references

- [SPEC-NPM-CLI-11 source record](../../../../../sources/README.md#spec-npm-cli-11)
- [REF-DEPS-004 and official client specifications](../../../../../sources/README.md#ref-deps-004)
- [npm registry metadata specification state](../../../../../sources/README.md#spec-npm-registry-metadata)
- [npm configuration](https://docs.npmjs.com/cli/v11/using-npm/config/)
- [npm install](https://docs.npmjs.com/cli/install/)
- [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
