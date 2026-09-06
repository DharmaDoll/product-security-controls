# Modern Yarn reference profile

Status: `REFERENCE_ONLY`. Pinned Yarn runtimeによるこのrepositoryのnative negative testは未実施であり、
`PSB-DEPS-003`のimplemented evidenceには数えない。

Copyするのは[`.yarnrc.yml`](.yarnrc.yml)である。既存fileを上書きせず、設定をreviewしてmergeする。
`package.json`の`packageManager`は、adopterがreviewしたexact Yarn 4 releaseへ固定する。

Normal install:

```bash
yarn install --immutable
```

Checked-in cache／Zero-Installs:

```bash
yarn install --immutable --immutable-cache --check-cache
```

`--immutable`はlockfile変更を拒否する。`--immutable-cache`はcache fileの追加・削除を拒否し、
`--check-cache`はcache checksumを再取得結果と照合する。External PRがlockとcacheを同時更新できる場合も、
non-author reviewとdependency graph reviewが必要である。

- [Yarn install](https://yarnpkg.com/cli/install)
- [Yarn checksum behavior](https://yarnpkg.com/configuration/yarnrc/#checksumBehavior)
- [Yarn resolutions](https://yarnpkg.com/configuration/manifest#resolutions)

Yarn Classicはこのprofileのimmutable／cache semanticsとして扱わない。
