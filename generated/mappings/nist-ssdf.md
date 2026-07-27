# nist-ssdf mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-REL-001 - release署名とProvenanceを期待値に照合する | 1.1 (SP 800-218, 2022) | PS.2.1 | supports | high | Software releaseの完全性を暗号署名とprovenance expectationで検証し、改ざん検知を支援する。 |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | 1.1 (SP 800-218, 2022) | PS.3.1 | supports | medium | Least privilege, protected credentials, and endpoint policy checks support protection of code and development environments. |
| PSB-SOURCE-002 - リポジトリ所有の開発者向けGit hooksセキュリティベースライン | 1.1 (SP 800-218, 2022) | PS.3.1 | supports | medium | レビューで保護されたrepository-owned hooksとローカルのcredentialおよびidentity保護は、source codeと開発環境の保護を支援する。 |
| PSB-CICD-001 - Pin external GitHub Actions and reusable workflows to immutable commits | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | medium | Pinning reviewed third-party workflow components supports controlled acquisition and maintenance but does not establish that the component is secure. |
| PSB-DEPS-001 - 依存パッケージの公開直後採用をrelease cooldownで制御 | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | medium | dependencyの取得元、version、公開時刻、integrity、例外を検証することでthird-party componentのcontrolled acquisitionとmaintenanceを支援する。 |
| PSB-DEPS-002 - install時の任意コード実行をdefault denyにする | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | high | third-party component取得時の実行policy、version固定、integrity、例外reviewを検証し、controlled acquisitionとmaintenanceを支援する。 |
| PSB-DEPS-003 - lockfileと取得artifactの完全性を強制する | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | high | Third-party componentの取得元、version、dependency graph、integrityを機械検証しcontrolled acquisitionを支援する。 |
| PSB-BUILD-001 - dependency buildを権限・credential・networkから隔離する | 1.1 (SP 800-218, 2022) | PW.6.1 | supports | high | Build processをleast privilegeと分離された環境で実行し、softwareをsecureにcompile packageするpracticeを支援する。 |
| PSB-GOV-001 - supply-chain incidentの影響範囲と対応planを即時生成する | 1.1 (SP 800-218, 2022) | RV.1.1 | supports | high | Releaseに含まれるcomponentをSBOM inventoryで継続的に識別し、報告された汚染versionとの影響照合を支援する。 |
| PSB-GOV-001 - supply-chain incidentの影響範囲と対応planを即時生成する | 1.1 (SP 800-218, 2022) | RV.2.1 | supports | high | 影響artifactとbuild evidenceを特定し、containment、credential失効、safe rebuildのrisk response planを生成する。 |
