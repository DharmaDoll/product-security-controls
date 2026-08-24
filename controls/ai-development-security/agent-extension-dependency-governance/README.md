# PSB-AI-002: Skill・MCP・plugin・外部promptの依存関係を統制する

## このcontrolを一枚で理解する

### セキュリティ上の問題

Skill、MCP server、plugin、外部promptはagentへ指示やtool権限を追加するsupply-chain dependencyである。名前だけを信頼すると、review後の差し替え、tool poisoning、credential収集、隠れた副作用を許してしまう。

### 誰から、または何から守るか

悪意ある／侵害されたpublisher、marketplaceの差し替え、lookalike dependency、過剰権限設定、自己承認、期限切れreview、失効情報collectorの障害から守る。

### 何が対象か

Agent Skill、MCP server、plugin、外部prompt packageのcanonical source、commit、artifact、license、owner、semantic review、capability、benchmark、期限、revocation、runtime identity。

### 何をするか

依存物をfull commitとSHA-256へ固定し、publisherと異なるreviewerが意味を確認する。filesystem／network／secret／tool権限をdependency別にallow-list化し、exact identityへbenchmarkとrevocationを結び付ける。

### 成功状態

5件・4種類のfixtureがexact policyを満たし、mutable・自己承認・過剰権限・期限切れ・失効は`FAIL`、改ざん・欠落・stale・collector／evaluator障害は`ERROR`になる。承認identityとruntime dispositionをPSB-AI-004へ引き渡せる。

### 対象外・残余リスク

Offline synthetic fixtureはlive dependencyの安全性、publisherやrevocation sourceの信頼性、endpointでの実効権限を証明しない。実行時強制はPSB-AI-004が担当する。

## セキュリティ上の問題

Agent拡張は通常のlibraryより強い場合があります。MCP serverはtoolを公開し、pluginはcodeを
実行し、Skillとpromptはagentの判断を変えます。したがって「実行ファイルではない」という
理由でSkillやpromptをreview対象外にすると、repository policyを上書きするinstructionを
安全なdependencyとして取り込む経路になります。

このcontrolは、依存物の名前ではなく、次の組を承認単位にします。

```text
dependency ID + kind + canonical source + full commit + artifact SHA-256
+ semantic review + exact capabilities + benchmark + expiry + revocation state
```

## 誰から何を守るか

- Publisherやmarketplaceがreview後にbranch、tag、package内容を差し替える;
- 正しくhashされたtoolにcredential収集、control無効化、hidden side effectが含まれる;
- Read-only用途のMCPがshell、secret、repository write、任意networkを要求する;
- favorableなbenchmarkを別commitや別artifactへ流用する;
- 侵害後にrevokedとなったdependency、または期限切れreviewが残る;
- collectorやevaluator失敗を「問題なし」と誤解する。

守る対象はdeveloper endpoint、repository、credential、接続先system、agentの判断境界、
およびdependency approval自体の信頼性です。

## Control境界

| Control | 所有する境界 |
|---|---|
| `PSB-AI-001` | Repository-owned guidanceとdependency benchmarkの比較・effectiveness claim。 |
| `PSB-AI-002` | 外部Skill、MCP、plugin、promptの導入可否、exact identity、semantic review、capability承認、期限、revocation。 |
| `PSB-AI-003` | Repository文書、issue、Web、tool outputを使ったprompt／document injection scenario。 |
| `PSB-AI-004` | 承認済みdependency identityと実際のinstalled runtime、filesystem、network、secret、tool、side effectの強制。 |

GitHub公式MCPを使う場合もpublisher名だけでは承認しません。`PSB-AI-002`は
[`REF-AI-004`](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-004)のcanonical repository、
review済みcommit／artifact、tool schema、update mechanismをdependency recordへ固定します。
OAuth／PATの選択、PATのscope・保管・期限・失効は`PSB-SOURCE-004`、read-only、tool allow-list、
write approvalは`PSB-AI-004`が所有します。

AI-002の`runtime_handoff`はenforcementそのものではありません。AI-004 inventoryの
`dependency_record_id`が参照する承認元を提供します。Fixtureでは既存AI-004の
`EXT-FIXTURE-DOCS-001`、`EXT-FIXTURE-SOURCE-001`、`EXT-FIXTURE-SKILL-001`と一致させています。
現在AI-004がinventory照合できるのはMCPとSkillです。Pluginと外部promptは
`deny-not-installed`として引き渡し、対応runtime evidenceなしに有効化しません。

## 安全な実装

[`secure/dependency-manifest.json`](secure/dependency-manifest.json) は次の5件を登録します。

| Dependency | 種類 | 許可するcapability |
|---|---|---|
| `EXT-FIXTURE-DOCS-001` | MCP server | 指定docs endpointへのnetworkと`search`／`read`のみ |
| `EXT-FIXTURE-SOURCE-001` | MCP server | 指定source endpointと3つのreview済みtool。Write制約とHITLはAI-004で強制し、`delete_repository`は不許可 |
| `EXT-FIXTURE-SKILL-001` | Skill | 直接tool authorityなし |
| `EXT-FIXTURE-PLUGIN-001` | Plugin | `docs/**`のreadのみ、実行fixtureは無効 |
| `EXT-FIXTURE-PROMPT-001` | External prompt | filesystem、network、secret、tool authorityなし |

すべてsynthetic artifactで、実在serviceへ接続しません。Policyはcapabilityのsubsetではなく
exact matchを要求します。Manifestへ未申告capabilityを追加する変更も、承認済みcapabilityを
勝手に削って挙動を曖昧にする変更もreview対象として`FAIL`にします。

Semantic reviewはintegrity検査と分離し、publisher／owner以外のreviewer、repository policyの
優先、禁止behaviorがないこと、期限内であることを確認します。Benchmarkは
`PSB-AI-001`をownerとし、dependency IDだけでなくfull commitとartifact digestへ結び付けます。

## 危険な実装

[`insecure/dependency-manifest.json`](insecure/dependency-manifest.json) は、次を意図的に含みます。

- `main`と`latest`によるmutable identity;
- publisher、owner、reviewerが同一の自己承認;
- unknown licenseと期限切れreview;
- repository invariant overrideとscanner無効化behavior;
- `/**`、任意network、任意secret、shell、Skillへのdirect authority;
- policyで承認した他dependencyの欠落。

Artifact digestが正しくても13件のpolicy findingで拒否されます。これは「同じbytesか」と
「そのbytesを使ってよいか」が別の問いであることを示します。

## 実行方法

```bash
make verify-control CONTROL=PSB-AI-002
```

直接実行する場合:

```bash
python3 controls/ai-development-security/agent-extension-dependency-governance/scripts/verify.py \
  --control-root controls/ai-development-security/agent-extension-dependency-governance \
  --policy controls/ai-development-security/agent-extension-dependency-governance/secure/policy.json \
  --manifest controls/ai-development-security/agent-extension-dependency-governance/secure/dependency-manifest.json \
  --revocations controls/ai-development-security/agent-extension-dependency-governance/secure/revocations.json \
  --benchmark controls/ai-development-security/agent-extension-dependency-governance/secure/benchmark-results.json
```

終了コードは`0=policyを満たす`、`1=確認済みsecurity finding`、`2=証跡を信頼して判定できない`
です。Artifact改ざん、revocation collection不完全、benchmark evaluator失敗、機微field混入は
clean扱いせず`ERROR`にします。Known revoked stateは証跡が有効なため`FAIL`です。

## 期待する出力

```text
PASS manifest PSB-AI-002-fixture-2026-08-05 contains 5 exact approved dependencies across 4 kinds
PASS canonical HTTPS sources use full immutable commits and every local artifact matches its SHA-256
PASS license owner independent semantic review repository precedence and review expiry satisfy policy
PASS requested filesystem network secret tool and direct-authority capabilities exactly match the allow-list
PASS fresh complete revocation evidence marks every dependency active
PASS PSB-AI-001 benchmark evidence is digest-pinned and bound to each exact commit and artifact
PASS 5 dependency records expose exact PSB-AI-004 runtime dispositions
PASS sanitized evidence contains no raw prompt output transcript token or secret value
```

## 導入手順

1. Canonical publisherとsource repositoryを特定し、releaseではなくfull commitを記録する。
2. 取得artifactを隔離環境でhashし、license、owner、publisherを記録する。
3. Instruction、code、tool schema、install script、update mechanismを独立reviewする。
4. 必要なfilesystem、network、secret、tool、direct authorityを個別にallow-list化する。
5. Exact commit／digestを使い`PSB-AI-001` benchmarkを実施し、normalized結果だけを保持する。
6. Review expiryとrevocation sourceを設定し、collector失敗を`ERROR`としてblockする。
7. 承認record IDとruntime extension ID／kindをPSB-AI-004 inventoryへ配布する。
8. Version、digest、capability、behavior、benchmark、publisher trustの変更時に再reviewする。

## 運用上の注意と制限

- Productionではartifactを内部mirrorへ保持し、source deletionにも対応する。
- MCPのremote endpointはsource commitだけでは実行中server bytesを証明できない。Deployment
  attestationやserver version evidenceを追加し、AI-004のnetwork／tool boundaryと組み合わせる。
- Skill／promptの`direct_tool_authority: false`はmanifest上の契約であり、agent runtimeが
  instructionをどう解釈したかはAI-003／AI-004のlive testで確認する。
- Revocation feedがないdependencyは「active」と推測せず`NOT_CHECKED`または`ERROR`にする。
- Synthetic benchmarkはverifierの動作確認用であり、production adoptionを承認しない。
- Manifest、policy、reviewを同じactorが自由に更新できないようCODEOWNERとbranch protectionを使う。

## Framework mappingと参照資料

- MITRE ATLAS `AML.T0010.005 AI Agent Tool`: agent tool supply-chain compromiseを、immutable
  identity、review、capability、revocationで部分的にmitigateする。
- MITRE ATLAS `AML.T0110 AI Agent Tool Poisoning`: semantic reviewとexact identity-bound
  benchmarkがpoisoned behaviorの導入リスクを下げる。
- OWASP Agentic Top 10 `ASI04 Agentic Supply Chain Vulnerabilities`: dependency provenance、
  integrity、privilege、benchmark、revocationを扱う直接mappingである。
- [OWASP Agentic Top 10 registry](../../../frameworks/owasp-agentic-top10/README.md)
- [MITRE ATLAS registry](../../../frameworks/mitre-atlas/README.md)
- [AI security参考資料](../../../docs/SECURITY_GUIDANCE_SOURCES.md)
- [REF-AI-004 GitHub MCP official authentication guidance](../../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-004)

これらはattack behaviorとrisk categoryのmappingであり、formal complianceやagentic securityの
完全coverageを意味しません。
