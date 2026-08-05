# OWASP Top 10 for Agentic Applications Registry

OWASP Top 10 for Agentic Applicationsは、goal、tool use、identity、memory、
supply chain、multi-agent coordinationなど、agentic AI固有の主要risk categoryを
分類するために使用します。本PJでは`threat-taxonomy`であり、verification standardや
compliance frameworkとしては扱いません。

## 固定ベースライン

- Publication: `OWASP Top 10 for Agentic Applications 2026`
- Publisher: OWASP GenAI Security Project
- Publication date: `2025-12-09`
- Mapping version: `2026`
- Stable identifiers: `ASI01`から`ASI10`
- Official publication:
  [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Official launch article:
  [The Benchmark for Agentic Security in the Age of Autonomous AI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- License: CC BY-SA 4.0
- Machine-readable registry: [`registry.json`](registry.json)

公式publication pageのDownload Monitorはreview時に自動取得を拒否し、返却されたHTMLは
publication artifactではありませんでした。そのため誤ったSHA-256を記録せず、version、
公開日、official URL、全10 identifierを固定しています。OWASPがdirect artifact URL、
release repository、またはchecksumを提供した場合は、そのidentityを追加して全mappingを
再reviewします。

## Mapping境界

使用するrelationshipは主に次です。

- `addresses`: controlがrisk categoryの具体的なfailure scenarioを直接扱う;
- `mitigates`: 実行可能な予防策がriskの成立条件またはblast radiusを縮小する;
- `detects`: controlがriskに対応するbehaviorまたはconfiguration driftを検出する;
- `related-to`: 直接のcoverage主張を避けつつ、riskとの関連を示す。

一つのcheckをTop 10 categoryへmappingしても、category全体の対策完了、Agentic AI
Top 10準拠、agentの安全性、または実運用での有効性を証明しません。具体的なverification
requirementはcontrol自身または将来のOWASP AISVS等のrequirement frameworkから取得し、
Top 10だけをacceptance criteriaにしません。

## ATLAS、Cheat Sheetとの役割分離

| Source | 本PJでの役割 |
|---|---|
| OWASP Agentic Top 10 | Agentic applicationの粗いrisk categoryを分類する。 |
| MITRE ATLAS | Adversaryのtactic、technique、mitigation、case studyを記述する。 |
| OWASP AI Agent Security Cheat Sheet | Control設計と実装例の参考情報として使う。 |

同じcontrolがOWASPとATLASの両方へmappingされる場合も、前者は「どのriskか」、後者は
「攻撃者がどう行動するか」を説明します。Cheat Sheetは
[`REF-AI-002`](../../docs/SECURITY_GUIDANCE_SOURCES.md#ref-ai-002)として管理し、この
framework registryへ重複登録しません。
