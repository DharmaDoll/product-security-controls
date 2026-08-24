# OWASP AISVS Registry

OWASP Artificial Intelligence Security Verification Standard（AISVS）は、
AI／ML固有のasset、workflow、runtime behaviorに対する具体的で検証可能な
security requirementとして使用します。一般application securityはOWASP ASVS、
攻撃者行動はMITRE ATLAS、広いagentic risk分類はOWASP Agentic Top 10が引き続き
所有します。

## 固定ベースライン

- Version: `1.0`
- Official source commit: `78775233666a2022dcfb82037e5e029116955c00`
- Released source directory: `1.0/`
- English requirements tree: `a8102d4e67cdf92348a32a18bbee2417d633a075`
- Official PDF SHA-256:
  `ff15584843a53d4fd2b52940c98cb15f9ebe1340151d90d54bb74db9cf8468f6`
- License: `CC BY-SA 4.0`
- Machine-readable registry: [`registry.json`](registry.json)

公式repositoryの`1.0/LOCKED.md`は、`1.0/en/`のrequirement本文、level、構造、
identifierを固定対象としています。このregistryはreview時点のfull commitと
requirements treeを追加で固定し、`main`や`1.01-dev`をmapping sourceにしません。

registryにはrequirement本文を複製せず、version付きID、chapter、section、level、
固定source URLだけを格納します。意味の確認とmapping reviewでは固定commitの
公式本文を参照してください。

## Identifierとlevel

mapping IDはAISVS推奨のversion付き形式を使用します。

```text
v1.0-C<chapter>.<section>.<requirement>
```

例: `v1.0-C9.4.3`。

Level 1、2、3はrequirementのassurance depthです。1件のcontrol mappingやfixture
成功を、AISVS level達成、AI system全体の安全性、formal assessment、compliance
claimへ変換してはいけません。AISVS Level Nの評価は、同じLevel NのASVS評価と
組み合わせるという公式前提も維持します。

## Mapping境界

- `supports`: controlがrequirementの一部を具体化するが、完全な検証ではない。
- `verifies`: executableなpositive／negative evidenceがrequirementの中心条件を直接検証する。
- `evidence-for`: broader assessmentで利用できる限定的な証跡を生成する。

mappingはatomic checkへ明示的に結びます。関連が弱いchapter名だけのmapping、
parent controlから全checkへの継承、未実装要件の暗黙のcovered扱いは禁止します。
生成されたAISVS coverage profileは全191要件を保持し、直接mappingがないものを
`gap`として表示します。

## 更新

固定した公式sourceを取得してcommit、tree、PDF SHA-256を確認した後、次でentriesを
再生成します。

```bash
python3 scripts/extract-framework-entries.py \
  aisvs /path/to/AISVS/1.0/en frameworks/owasp-aisvs/registry.json
make validate-controls
make generate
```

version変更時は既存IDを上書きせず、新versionの差分、mapping、coverage gapを
個別にreviewします。
