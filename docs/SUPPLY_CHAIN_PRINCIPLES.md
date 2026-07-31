# Software supply-chain security: 6つの実装原則

このprojectでは、software supply-chain securityを単一scannerではなく、侵害前の予防から
事後対応まで連続する6つのcontrolとして扱います。

| 原則 | Goal | Control |
| --- | --- | --- |
| 1. install時の任意code実行を止める | lifecycle scriptとsource buildをdefault denyにする | `PSB-DEPS-002` |
| 2. 取得経路を固定しrelease後の猶予を置く | managed registry proxyを強制し、公開直後versionの通常採用を独立したcooldownで遅延する | `PSB-DEPS-001` |
| 3. lockfileで完全性を担保する | manifest、frozen graph、registry、artifact hashを一致させる | `PSB-DEPS-003` |
| 4. 信頼signalを検証する | 署名、provenance、builder、source、artifactをconsumer expectationへ照合する | `PSB-REL-001` |
| 5. 権限とnetworkを最小化する | untrusted buildをcredentialとdeploy trust boundaryから隔離する | `PSB-BUILD-001` |
| 6. 事後に即応できる状態を保つ | SBOMから影響範囲を逆引きし、evidence-first response planを生成する | `PSB-GOV-001` |

## Controlの連鎖

```text
release cooldown
      ↓
managed registry proxy (no direct fallback)
      ↓
install execution default deny
      ↓
frozen lockfile + artifact integrity
      ↓
signature + provenance expectations
      ↓
credential-free isolated build
      ↓
SBOM inventory + incident response
```

各controlは独立して検証できますが、単独では十分ではありません。例えば、
cooldownを通過したmalicious packageはinstall script controlやSCAで扱い、正しいhashを
持つartifactも署名・provenanceとmeaningful reviewで検証し、すべてを通過したcodeが
侵害されていた場合はbuild containmentとincident responseでblast radiusを抑えます。

## 共通運用要件

- dependency updateと通常installを分離する
- package-manager client profileを中央配布し、public registryへのdirect fallbackを禁止する
- malicious-package blocklistをrelease cooldownまたはartifact integrityの代替にしない
- package manager、tool、GitHub Actionをimmutable versionへ固定する
- network取得とexternal verifier failureを明示し、cleanへ変換しない
- exceptionはexact target、owner、別承認者、理由、期限を持つ
- buildとdeployを別trust boundaryにする
- SBOM、provenance、build log、artifact digestを同じrelease identityへ関連付ける
- destructive responseはevidence保全後にmanual approvalで実施する

これらのcontrolはformal complianceやSLSA levelを自動的に証明しません。
framework mappingは、実装が各requirementをどのように支援するかを示す関係です。
