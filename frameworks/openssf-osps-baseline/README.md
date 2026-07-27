# OpenSSF OSPS Baseline Registry

Open Source Project Security（OSPS）Baselineは、project maturityに応じた
open source projectの最低security requirementsとして使用します。repository、
CI/CD、build、release、documentation、governance、security assessment、
vulnerability managementを横断します。

## 固定ベースライン

- Version: `2026.02.19`
- Source tag: `v2026.02.19`
- Source commit: `e67ae247ebfb2fd758c9d186335e60cad0a74e78`
- Reviewed rendered source SHA-256:
  `54d13befdb1ae4c63b8612acabc1f0d716874be4187d25801d6ba2d6eee98271`
- Machine-readable registry: [`registry.json`](registry.json)

レジストリは固定versionの全assessment requirement IDと親controlの題名を
含みます。requirement本文は公式versioned pageで確認します。

## マッピング境界

OSPS Baseline mappingは、このPJのcontrolが特定assessment requirementを支援、
検証、または証拠化する関係を示します。OSPS maturity levelの達成やproject全体の
conformanceを意味しません。

GitHub固有の設定根拠には`github-security-guidance`を優先し、OSPSは
provider-independentなsecurity outcomeが直接一致するときだけ併記します。
OpenSSF Scorecardの結果はverification evidenceになり得ますが、score自体を
security postureやOSPS達成の証明として扱いません。

## 更新

固定version pageを取得し、tag/commitとSHA-256を確認した後に再生成します。

```bash
python3 scripts/extract-framework-entries.py \
  osps /path/to/versioned-page.html \
  frameworks/openssf-osps-baseline/registry.json
make validate-controls
```
