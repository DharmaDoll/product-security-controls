# slsa mappings

| Control | Checks | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| PSB-REL-001 - release署名とProvenanceを期待値に照合する | PSB-REL-001-REL-001, PSB-REL-001-REL-002 | 1.2 | build-l2#consumer-validates-authenticity | verifies | high | Consumer-owned trusted keyでprovenance署名とartifact subject bindingを検証し、Build L2のconsumer authenticity validationを直接実装するが、hosted platformとprovenance生成要件は評価しない。 |
| PSB-REL-001 - release署名とProvenanceを期待値に照合する | PSB-REL-001-REL-001, PSB-REL-001-REL-003, PSB-REL-001-REL-004 | 1.2 | build-provenance | verifies | high | SLSA provenance statementのsubject digest、predicate type、builder、build inputを署名とともにconsumer expectationへ照合する。 |
| PSB-BUILD-001 - dependency buildを権限・credential・networkから隔離する | PSB-BUILD-001-BLD-001, PSB-BUILD-001-BLD-002, PSB-BUILD-001-BLD-004 | 1.2 | build-track-basics#build-l3-hardened-builds | supports | medium | Build間の影響を抑えるephemeral isolationとprovenance signing secretをuser-defined buildから分離するSLSA Build L3の方向性を支援するが、platform assessmentは行わない。 |
