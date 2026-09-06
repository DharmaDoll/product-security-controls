# Bun reference profile

Status: `REFERENCE_ONLY`. Pinned Bun runtimeによるこのrepositoryのnative negative testは未実施であり、
`PSB-DEPS-003`のimplemented evidenceには数えない。

Copyするのは[`bunfig.toml`](bunfig.toml)である。既存fileを上書きせず、設定をreviewしてmergeする。
`package.json`の`packageManager`はadopterがreviewしたexact stable Bun releaseへ固定し、text `bun.lock`をcommitする。

Normal install:

```bash
bun ci
```

`bun ci`は`bun install --frozen-lockfile`相当であり、manifest driftを拒否する。Sample configはruntimeの
auto-installを無効化し、normal installがlock外でpackageを取得する経路を残さない。Lifecycle scriptを必要とする場合は
`PSB-DEPS-002`の承認境界へ分離する。

- [Bun install](https://bun.com/docs/pm/cli/install)
- [Bun lockfile](https://bun.com/docs/pm/lockfile)
- [Bun auto-install](https://bun.com/docs/runtime/auto-install)
- [Bun configuration](https://bun.com/docs/runtime/bunfig)
- [Bun overrides and resolutions](https://bun.com/docs/pm/overrides)
