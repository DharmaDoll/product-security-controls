# nist-ssdf mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | 1.1 (SP 800-218, 2022) | PS.3.1 | supports | medium | Least privilege, protected credentials, and endpoint policy checks support protection of code and development environments. |
| PSB-SOURCE-002 - リポジトリ所有の開発者向けGit hooksセキュリティベースライン | 1.1 (SP 800-218, 2022) | PS.3.1 | supports | medium | レビューで保護されたrepository-owned hooksとローカルのcredentialおよびidentity保護は、source codeと開発環境の保護を支援する。 |
| PSB-CICD-001 - Pin external GitHub Actions and reusable workflows to immutable commits | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | medium | Pinning reviewed third-party workflow components supports controlled acquisition and maintenance but does not establish that the component is secure. |
| PSB-DEPS-001 - 依存パッケージの公開直後採用をrelease cooldownで制御 | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | medium | dependencyの取得元、version、公開時刻、integrity、例外を検証することでthird-party componentのcontrolled acquisitionとmaintenanceを支援する。 |
| PSB-DEPS-002 - install時の任意コード実行をdefault denyにする | 1.1 (SP 800-218, 2022) | PW.4.1 | supports | high | third-party component取得時の実行policy、version固定、integrity、例外reviewを検証し、controlled acquisitionとmaintenanceを支援する。 |
