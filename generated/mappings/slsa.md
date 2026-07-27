# slsa mappings

| Control | Framework version | Identifier | Relationship | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| PSB-REL-001 - release署名とProvenanceを期待値に照合する | 1.2 | build-provenance | verifies | high | SLSA provenance statementのsubject digest、predicate type、builder、build inputを署名とともにconsumer expectationへ照合する。 |
| PSB-BUILD-001 - dependency buildを権限・credential・networkから隔離する | 1.2 | build-track-basics#build-l3-hardened-builds | supports | medium | Build間の影響を抑えるephemeral isolationとprovenance signing secretをuser-defined buildから分離するSLSA Build L3の方向性を支援するが、platform assessmentは行わない。 |
