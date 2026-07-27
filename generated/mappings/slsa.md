# slsa mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-BUILD-001 - dependency buildを権限・credential・networkから隔離する | 1.2 | Build-L3-Hardened-Builds | supports | medium | Build間の影響を抑えるephemeral isolationとprovenance signing secretをuser-defined buildから分離するSLSA Build L3の方向性を支援するが、platform assessmentは行わない。 |
| PSB-REL-001 - release署名とProvenanceを期待値に照合する | 1.2 | Build-Provenance | verifies | high | SLSA provenance statementのsubject digest、predicate type、builder、build inputを署名とともにconsumer expectationへ照合する。 |
