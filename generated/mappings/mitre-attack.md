# mitre-attack mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-CICD-001 - Pin external GitHub Actions and reusable workflows to immutable commits | v19.1 | T1195.001 | mitigates | medium | Immutable references reduce the opportunity to replace a reviewed workflow dependency or development tool through a moved Git reference. |
| PSB-DEPS-001 - 依存パッケージの公開直後採用をrelease cooldownで制御 | v19.1 | T1195.001 | mitigates | medium | 公開直後versionの自動採用を遅らせ、software dependency compromise直後の露出を減らすが、malicious dependency自体を検出するものではない。 |
| PSB-DEPS-002 - install時の任意コード実行をdefault denyにする | v19.1 | T1195.001 | mitigates | high | software dependencyのinstall hookまたはsource buildをdefault denyにし、compromised dependencyが取得直後に実行される経路を減らす。 |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | v19.1 | T1552.001 | mitigates | medium | Protected credential storage and prohibition of secrets in workspaces reduce exposure to credentials in files. |
| PSB-SOURCE-002 - リポジトリ所有の開発者向けGit hooksセキュリティベースライン | v19.1 | T1552.001 | mitigates | medium | ローカルでのsecretおよび機密ファイル検査はファイル内credentialの誤公開を減らすが、回避可能でpatternにも限界がある。 |
| PSB-SOURCE-001 - Harden developer endpoints and local trust boundaries | v19.1 | T1555 | mitigates | medium | System-managed credential storage and endpoint access controls reduce exposure of credentials from password stores. |
