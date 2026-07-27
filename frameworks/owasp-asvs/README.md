# OWASP ASVS Registry

OWASP Application Security Verification Standard（ASVS）は、web applicationと
web serviceの設計・実装・テストに対する具体的なverification requirementとして
使用します。

## 固定ベースライン

- Version: `5.0.0`
- Release tag: `v5.0.0_release`
- Source commit: `5cf9b032440be53ce345ab3c130fda46ba1ce7a2`
- Source asset: official English JSON
- Source SHA-256:
  `bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35`
- Machine-readable registry: [`registry.json`](registry.json)

ASVSのIDはversion間で意味や番号が変わり得るため、mappingではOWASP推奨形式の
`v5.0.0-<chapter>.<section>.<requirement>`を使用します。例:
`v5.0.0-1.2.5`。

レジストリにはrequirement本文を複製せず、ID、verification level、chapter、
sectionを格納します。意味の確認とmapping reviewでは固定releaseの公式本文を
参照してください。

## マッピング境界

ASVS mappingはcontrolが特定requirementを支援または検証することを示します。
application全体のASVS level達成やformal assessmentを意味しません。Top 10の
粗いrisk categoryをASVS requirementの代わりに使用してはいけません。

## 更新

固定した公式JSONを取得してSHA-256を確認した後、次でentriesを再生成します。

```bash
python3 scripts/extract-framework-entries.py \
  asvs /path/to/official-asvs.json frameworks/owasp-asvs/registry.json
make validate-controls
```
