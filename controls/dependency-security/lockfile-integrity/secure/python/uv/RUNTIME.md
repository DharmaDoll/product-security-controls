# uv runtime prerequisite

このprofileはuv `0.11.21`だけを検証対象とする。Activation中にruntimeをdownload、upgrade、またはPython runtimeを自動取得しない。

公式sourceは[uv 0.11.21 release](https://github.com/astral-sh/uv/releases/tag/0.11.21)である。Adopterはapproved software distributionまたは次の公式release assetを取得し、展開前にSHA-256を照合する。

| Target | Asset | SHA-256 |
| --- | --- | --- |
| macOS arm64 | `uv-aarch64-apple-darwin.tar.gz` | `1f921d491ba5ffeea774eb04d6681ecee379101341cbb1500394993b541bf3f4` |
| Linux x64 glibc | `uv-x86_64-unknown-linux-gnu.tar.gz` | `8c88519b0ef0af9801fcdee419bbb12116bd9e6b18e162ae093c932d8b264050` |
| Linux arm64 glibc | `uv-aarch64-unknown-linux-gnu.tar.gz` | `88e800834007cc5efd4675f166eb2a51e7e3ad19876d85fa8805a6fb5c922397` |

macOSでは`shasum -a 256 <asset>`、Linuxでは`sha256sum <asset>`で上表と一致することを確認する。加えて、公式releaseが提供する[GitHub artifact attestation verification](https://github.com/astral-sh/uv/releases/tag/0.11.21#verifying-github-artifact-attestations)を利用できる環境では次を実行する。

```bash
gh attestation verify <downloaded-asset> --repo astral-sh/uv
```

Mismatch、attestation failure、取得失敗、unsupported platformをclean resultにしない。`curl | sh`、global shell profile変更、activation時のinstaller実行は不要で、検証済みbinaryを`PSB_UV=/approved/path/uv`としてwrapperへ渡す。
