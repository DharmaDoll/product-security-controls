# GitHub critical repository recovery runbook

このfileを組織の運用runbookへコピーし、`<...>`を組織固有の値へ置き換えます。

## Scope

- Product: `<product>`
- Product owner: `<owner>`
- Critical repository full name: `<organization/repository>`
- GitHub numeric repository ID: `<id>`
- RPO: `<hours>`
- RTO: `<hours>`
- Required refs: `<default branch, release branches, release tags>`
- Required non-Git data: `<LFS, Issues, PRs, Releases, Packages, other>`

## GitHub configuration

- [ ] Organization **Settings > Member privileges > Repository deletion and transfer**で、memberによる
  削除・移管を無効にした。
- [ ] critical repositoryを対象とするactive rulesetで重要branch／tagの**Restrict deletions**を
  有効にした。
- [ ] 同じrulesetで**Block force pushes**を有効にした。
- [ ] bypass listをreview済みbreak-glass teamに限定した。
- [ ] Organization Ownerとbreak-glass credentialを必要最小限にした。

## Backup boundary

- [ ] GitHub credentialはread-onlyでありadmin／delete権限を持たない。
- [ ] backup先はGitHub Organization Ownerが管理しない別security accountである。
- [ ] backup writerはprotected object versionとretention policyを削除・短縮できない。
- [ ] versioningとretention lockを有効にした。
- [ ] backup間隔がRPO以内である。
- [ ] `git fsck --full`を成功条件に含めた。
- [ ] 全branch／tagと、利用している場合はLFS objectを含めた。
- [ ] 必要なIssues／PR／Release／Package等について別のbackup方法を定義した。

## Restore drill

- [ ] productionと異なるOrganizationまたはGit serverをrestore先にした。
- [ ] 実際のretained backupから全critical repositoryをrestoreした。
- [ ] 必要なbranch、tag、commit、LFS objectを確認した。
- [ ] ruleset、branch protection、default branchを再設定した。
- [ ] development teamがbuildまたはsecurity patchを実行した。
- [ ] 開始から上記確認までがRTO以内だった。
- [ ] 失敗項目にownerと修正期限を設定し、修正後にdrillを再実行した。

## Review cadence

- Critical repository inventory: `<monthly/quarterly>`
- Backup job and RPO review: `<daily/weekly>`
- Restore drill: `<quarterly>`
- Next review date: `<YYYY-MM-DD>`
