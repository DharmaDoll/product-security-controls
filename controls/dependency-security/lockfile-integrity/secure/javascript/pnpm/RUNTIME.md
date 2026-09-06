# pnpm runtime prerequisite

このprofileはpnpm `11.25.0`だけを検証対象とする。Activation中にruntimeをdownloadまたはupgradeしない。

公式sourceは[pnpm v11.25.0 release](https://github.com/pnpm/pnpm/releases/tag/v11.25.0)である。
Adopterはapproved software distributionまたは次の公式standalone assetを取得し、展開前にSHA-256を照合する。

| Target | Asset | SHA-256 |
| --- | --- | --- |
| macOS arm64 | `pnpm-darwin-arm64.tar.gz` | `cdcf7130ed2e7aa324c7c76ab597de66db0529b6b1e0db9e489bde538fdc0d04` |
| Linux x64 | `pnpm-linux-x64.tar.gz` | `11caeed8b581d460638f836f10f6ead19cbf08d774a5b8e502628b20ebf3ac43` |
| Linux arm64 | `pnpm-linux-arm64.tar.gz` | `6d62b433b7a77b77e814dfaca8032bae57bb79c1a5ad50442e688c4f7fed3c8a` |

macOSでは`shasum -a 256 <asset>`、Linuxでは`sha256sum <asset>`で上表と一致することを確認する。
Mismatch、取得失敗、unsupported platformをclean resultにしない。Global installやshell profile変更は不要で、
`PSB_PNPM=/approved/path/pnpm`としてwrapperまたはself-testへ渡せる。
