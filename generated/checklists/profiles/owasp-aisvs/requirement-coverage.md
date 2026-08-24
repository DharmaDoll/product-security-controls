# OWASP AISVS 1.0 requirement coverage

Generated from the complete pinned AISVS 1.0 registry and reviewed atomic control mappings. Do not edit manually.

Source commit: `78775233666a2022dcfb82037e5e029116955c00`; official PDF SHA-256: `ff15584843a53d4fd2b52940c98cb15f9ebe1340151d90d54bb74db9cf8468f6`.

`mapped-evidence` means that at least one exact repository check has a reviewed relationship to the requirement. It does not prove live organization adoption, complete requirement satisfaction, an AISVS level, AI system security, or compliance. Unmapped requirements remain visible as `gap`.

AISVS Level N assumes the corresponding ASVS Level N is assessed in parallel. This repository does not infer either level from this view.

## Inventory

| Verification level | Requirements | Mapped evidence | Gap |
|---:|---:|---:|---:|
| 1 | 51 | 16 | 35 |
| 2 | 95 | 19 | 76 |
| 3 | 45 | 5 | 40 |

## Requirement rows

| Requirement | Level | Area | Status | Mapped checks | Relationships |
|---|---:|---|---|---|---|
| v1.0-C1.1.1 | 1 | Training Data Integrity & Traceability / Training Data Origin & Data Security | gap |  |  |
| v1.0-C1.1.2 | 2 | Training Data Integrity & Traceability / Training Data Origin & Data Security | gap |  |  |
| v1.0-C1.1.3 | 2 | Training Data Integrity & Traceability / Training Data Origin & Data Security | gap |  |  |
| v1.0-C1.1.4 | 2 | Training Data Integrity & Traceability / Training Data Origin & Data Security | gap |  |  |
| v1.0-C1.1.5 | 3 | Training Data Integrity & Traceability / Training Data Origin & Data Security | gap |  |  |
| v1.0-C1.2.1 | 1 | Training Data Integrity & Traceability / Data Labeling and Annotation Security | gap |  |  |
| v1.0-C1.2.2 | 2 | Training Data Integrity & Traceability / Data Labeling and Annotation Security | gap |  |  |
| v1.0-C1.2.3 | 2 | Training Data Integrity & Traceability / Data Labeling and Annotation Security | gap |  |  |
| v1.0-C1.3.1 | 2 | Training Data Integrity & Traceability / Training Data Quality and Security Assurance | gap |  |  |
| v1.0-C1.3.2 | 2 | Training Data Integrity & Traceability / Training Data Quality and Security Assurance | gap |  |  |
| v1.0-C1.3.3 | 2 | Training Data Integrity & Traceability / Training Data Quality and Security Assurance | gap |  |  |
| v1.0-C1.3.4 | 2 | Training Data Integrity & Traceability / Training Data Quality and Security Assurance | gap |  |  |
| v1.0-C1.3.5 | 3 | Training Data Integrity & Traceability / Training Data Quality and Security Assurance | gap |  |  |
| v1.0-C2.1.1 | 1 | Input Validation / Prompt Injection Defenses | gap |  |  |
| v1.0-C2.1.2 | 1 | Input Validation / Prompt Injection Defenses | gap |  |  |
| v1.0-C2.1.3 | 1 | Input Validation / Prompt Injection Defenses | mapped-evidence | PSB-AI-003-AII-001; PSB-AI-003-AII-002; PSB-AI-003-AII-003; PSB-AI-003-AII-004; PSB-AI-003-AII-005; PSB-AI-003-AII-006; PSB-AI-003-AII-007 | verifies |
| v1.0-C2.1.4 | 1 | Input Validation / Prompt Injection Defenses | gap |  |  |
| v1.0-C2.1.5 | 1 | Input Validation / Prompt Injection Defenses | gap |  |  |
| v1.0-C2.1.6 | 2 | Input Validation / Prompt Injection Defenses | mapped-evidence | PSB-AI-003-AII-002; PSB-AI-003-AII-003 | verifies |
| v1.0-C2.1.7 | 2 | Input Validation / Prompt Injection Defenses | gap |  |  |
| v1.0-C2.1.8 | 3 | Input Validation / Prompt Injection Defenses | gap |  |  |
| v1.0-C2.2.1 | 1 | Input Validation / Content & Policy Screening | gap |  |  |
| v1.0-C2.2.2 | 1 | Input Validation / Content & Policy Screening | gap |  |  |
| v1.0-C2.2.3 | 2 | Input Validation / Content & Policy Screening | gap |  |  |
| v1.0-C2.2.4 | 3 | Input Validation / Content & Policy Screening | gap |  |  |
| v1.0-C3.1.1 | 1 | Model Lifecycle Management & Change Control / Model Authorization & Integrity | gap |  |  |
| v1.0-C3.1.2 | 2 | Model Lifecycle Management & Change Control / Model Authorization & Integrity | mapped-evidence | PSB-DEPS-005-AMS-001; PSB-DEPS-005-AMS-005 | supports |
| v1.0-C3.1.3 | 2 | Model Lifecycle Management & Change Control / Model Authorization & Integrity | gap |  |  |
| v1.0-C3.2.1 | 1 | Model Lifecycle Management & Change Control / Model Validation & Testing | mapped-evidence | PSB-DETECT-002-TEV-003; PSB-DETECT-002-TEV-004; PSB-DETECT-002-TEV-005; PSB-DETECT-002-TEV-006 | verifies |
| v1.0-C3.2.2 | 2 | Model Lifecycle Management & Change Control / Model Validation & Testing | gap |  |  |
| v1.0-C3.2.3 | 3 | Model Lifecycle Management & Change Control / Model Validation & Testing | gap |  |  |
| v1.0-C3.3.1 | 2 | Model Lifecycle Management & Change Control / Controlled Deployment & Rollback | gap |  |  |
| v1.0-C3.3.2 | 2 | Model Lifecycle Management & Change Control / Controlled Deployment & Rollback | gap |  |  |
| v1.0-C3.3.3 | 2 | Model Lifecycle Management & Change Control / Controlled Deployment & Rollback | gap |  |  |
| v1.0-C3.4.1 | 1 | Model Lifecycle Management & Change Control / Secure Development Practices | gap |  |  |
| v1.0-C3.4.2 | 2 | Model Lifecycle Management & Change Control / Secure Development Practices | gap |  |  |
| v1.0-C3.5.1 | 2 | Model Lifecycle Management & Change Control / Pipeline Fine-Tuning | gap |  |  |
| v1.0-C3.5.2 | 3 | Model Lifecycle Management & Change Control / Pipeline Fine-Tuning | gap |  |  |
| v1.0-C3.5.3 | 3 | Model Lifecycle Management & Change Control / Pipeline Fine-Tuning | gap |  |  |
| v1.0-C3.5.4 | 3 | Model Lifecycle Management & Change Control / Pipeline Fine-Tuning | gap |  |  |
| v1.0-C4.1.1 | 1 | Infrastructure, Configuration & Deployment Security / AI Workload Sandboxing & Validation | gap |  |  |
| v1.0-C4.1.2 | 1 | Infrastructure, Configuration & Deployment Security / AI Workload Sandboxing & Validation | mapped-evidence | PSB-DEPS-005-AMS-003; PSB-DEPS-005-AMS-004 | verifies |
| v1.0-C4.1.3 | 3 | Infrastructure, Configuration & Deployment Security / AI Workload Sandboxing & Validation | gap |  |  |
| v1.0-C4.1.4 | 3 | Infrastructure, Configuration & Deployment Security / AI Workload Sandboxing & Validation | gap |  |  |
| v1.0-C4.2.1 | 2 | Infrastructure, Configuration & Deployment Security / AI Hardware Security | gap |  |  |
| v1.0-C4.2.2 | 3 | Infrastructure, Configuration & Deployment Security / AI Hardware Security | gap |  |  |
| v1.0-C4.2.3 | 3 | Infrastructure, Configuration & Deployment Security / AI Hardware Security | gap |  |  |
| v1.0-C4.2.4 | 3 | Infrastructure, Configuration & Deployment Security / AI Hardware Security | gap |  |  |
| v1.0-C4.2.5 | 3 | Infrastructure, Configuration & Deployment Security / AI Hardware Security | gap |  |  |
| v1.0-C4.3.1 | 1 | Infrastructure, Configuration & Deployment Security / Edge & Distributed AI Security | gap |  |  |
| v1.0-C4.3.2 | 2 | Infrastructure, Configuration & Deployment Security / Edge & Distributed AI Security | gap |  |  |
| v1.0-C4.3.3 | 3 | Infrastructure, Configuration & Deployment Security / Edge & Distributed AI Security | gap |  |  |
| v1.0-C4.3.4 | 3 | Infrastructure, Configuration & Deployment Security / Edge & Distributed AI Security | gap |  |  |
| v1.0-C4.3.5 | 3 | Infrastructure, Configuration & Deployment Security / Edge & Distributed AI Security | gap |  |  |
| v1.0-C5.1.1 | 3 | Access Control & Identity for AI Components & Users / Authentication | gap |  |  |
| v1.0-C5.1.2 | 3 | Access Control & Identity for AI Components & Users / Authentication | gap |  |  |
| v1.0-C5.2.1 | 2 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | gap |  |  |
| v1.0-C5.2.2 | 2 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | mapped-evidence | PSB-AI-011-RAG-005; PSB-AI-011-RAG-006 | verifies |
| v1.0-C5.2.3 | 2 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | gap |  |  |
| v1.0-C5.2.4 | 2 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | gap |  |  |
| v1.0-C5.2.5 | 2 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | gap |  |  |
| v1.0-C5.2.6 | 3 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | gap |  |  |
| v1.0-C5.2.7 | 3 | Access Control & Identity for AI Components & Users / AI Resource Authorization & Classification | mapped-evidence | PSB-AI-011-RAG-005; PSB-AI-011-RAG-007 | supports |
| v1.0-C5.3.1 | 2 | Access Control & Identity for AI Components & Users / Multi-Tenant Isolation | gap |  |  |
| v1.0-C5.3.2 | 3 | Access Control & Identity for AI Components & Users / Multi-Tenant Isolation | gap |  |  |
| v1.0-C6.1.1 | 1 | Supply Chain Security for Models / Model Artifact Integrity | gap |  |  |
| v1.0-C6.1.2 | 1 | Supply Chain Security for Models / Model Artifact Integrity | mapped-evidence | PSB-DEPS-005-AMS-001; PSB-DEPS-005-AMS-006 | verifies |
| v1.0-C6.1.3 | 2 | Supply Chain Security for Models / Model Artifact Integrity | mapped-evidence | PSB-DEPS-005-AMS-001; PSB-DEPS-005-AMS-005 | verifies |
| v1.0-C6.1.4 | 2 | Supply Chain Security for Models / Model Artifact Integrity | mapped-evidence | PSB-DETECT-002-TEV-001; PSB-DETECT-002-TEV-002; PSB-DETECT-002-TEV-003; PSB-DETECT-002-TEV-008 | verifies |
| v1.0-C6.2.1 | 1 | Supply Chain Security for Models / AI BOM & Supply Chain Monitoring | mapped-evidence | PSB-DEPS-005-AMS-002; PSB-DEPS-005-AMS-006 | verifies |
| v1.0-C6.2.2 | 2 | Supply Chain Security for Models / AI BOM & Supply Chain Monitoring | mapped-evidence | PSB-DEPS-005-AMS-005; PSB-DEPS-005-AMS-007 | verifies |
| v1.0-C6.2.3 | 2 | Supply Chain Security for Models / AI BOM & Supply Chain Monitoring | mapped-evidence | PSB-DEPS-005-AMS-002; PSB-DEPS-005-AMS-008 | verifies |
| v1.0-C7.1.1 | 1 | Model Behavior, Output Control & Safety Assurance / Output Format Enforcement | mapped-evidence | PSB-AI-006-AAI-001; PSB-AI-006-AAI-007 | verifies |
| v1.0-C7.1.2 | 1 | Model Behavior, Output Control & Safety Assurance / Output Format Enforcement | gap |  |  |
| v1.0-C7.2.1 | 2 | Model Behavior, Output Control & Safety Assurance / Hallucination Detection & Mitigation | gap |  |  |
| v1.0-C7.2.2 | 2 | Model Behavior, Output Control & Safety Assurance / Hallucination Detection & Mitigation | gap |  |  |
| v1.0-C7.2.3 | 3 | Model Behavior, Output Control & Safety Assurance / Hallucination Detection & Mitigation | gap |  |  |
| v1.0-C7.3.1 | 1 | Model Behavior, Output Control & Safety Assurance / Output Safety | gap |  |  |
| v1.0-C7.3.2 | 2 | Model Behavior, Output Control & Safety Assurance / Output Safety | gap |  |  |
| v1.0-C7.3.3 | 2 | Model Behavior, Output Control & Safety Assurance / Output Safety | gap |  |  |
| v1.0-C7.3.4 | 3 | Model Behavior, Output Control & Safety Assurance / Output Safety | gap |  |  |
| v1.0-C7.4.1 | 1 | Model Behavior, Output Control & Safety Assurance / Source Attribution & Citation Integrity | gap |  |  |
| v1.0-C7.4.2 | 1 | Model Behavior, Output Control & Safety Assurance / Source Attribution & Citation Integrity | mapped-evidence | PSB-AI-011-RAG-007 | supports |
| v1.0-C7.4.3 | 2 | Model Behavior, Output Control & Safety Assurance / Source Attribution & Citation Integrity | gap |  |  |
| v1.0-C7.4.4 | 3 | Model Behavior, Output Control & Safety Assurance / Source Attribution & Citation Integrity | gap |  |  |
| v1.0-C8.1.1 | 1 | Memory, Embeddings & Vector Database Security / Access Controls on Memory & RAG Indices | gap |  |  |
| v1.0-C8.1.2 | 2 | Memory, Embeddings & Vector Database Security / Access Controls on Memory & RAG Indices | gap |  |  |
| v1.0-C8.1.3 | 2 | Memory, Embeddings & Vector Database Security / Access Controls on Memory & RAG Indices | mapped-evidence | PSB-AI-011-RAG-006 | verifies |
| v1.0-C8.2.1 | 1 | Memory, Embeddings & Vector Database Security / Embedding Sanitization & Validation | gap |  |  |
| v1.0-C8.2.2 | 2 | Memory, Embeddings & Vector Database Security / Embedding Sanitization & Validation | gap |  |  |
| v1.0-C8.2.3 | 2 | Memory, Embeddings & Vector Database Security / Embedding Sanitization & Validation | mapped-evidence | PSB-AI-005-AIM-001; PSB-AI-005-AIM-002 | verifies |
| v1.0-C8.2.4 | 3 | Memory, Embeddings & Vector Database Security / Embedding Sanitization & Validation | mapped-evidence | PSB-AI-011-RAG-003 | verifies |
| v1.0-C8.2.5 | 3 | Memory, Embeddings & Vector Database Security / Embedding Sanitization & Validation | gap |  |  |
| v1.0-C8.3.1 | 2 | Memory, Embeddings & Vector Database Security / Memory Expiry & Revocation | mapped-evidence | PSB-AI-005-AIM-006; PSB-AI-005-AIM-007 | supports |
| v1.0-C8.3.2 | 2 | Memory, Embeddings & Vector Database Security / Memory Expiry & Revocation | gap |  |  |
| v1.0-C8.3.3 | 3 | Memory, Embeddings & Vector Database Security / Memory Expiry & Revocation | gap |  |  |
| v1.0-C9.1.1 | 1 | Orchestration & Agentic Security / Execution Budgets, Loop Control, and Circuit Breakers | gap |  |  |
| v1.0-C9.1.2 | 1 | Orchestration & Agentic Security / Execution Budgets, Loop Control, and Circuit Breakers | mapped-evidence | PSB-AI-007-ARB-002; PSB-AI-007-ARB-003; PSB-AI-007-ARB-004; PSB-AI-007-ARB-005; PSB-AI-007-ARB-006; PSB-AI-007-ARB-007 | verifies |
| v1.0-C9.1.3 | 2 | Orchestration & Agentic Security / Execution Budgets, Loop Control, and Circuit Breakers | gap |  |  |
| v1.0-C9.2.1 | 1 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | mapped-evidence | PSB-AI-004-AAR-005; PSB-AI-004-AAR-008; PSB-AI-004-AAR-009; PSB-AI-004-AAR-010; PSB-AI-004-AAR-011; PSB-AI-004-AAR-014 | verifies |
| v1.0-C9.2.2 | 2 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.3 | 2 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.4 | 2 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.5 | 2 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.6 | 2 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.7 | 2 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.8 | 3 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | mapped-evidence | PSB-AI-004-AAR-009; PSB-AI-004-AAR-010; PSB-AI-004-AAR-011; PSB-AI-004-AAR-016; PSB-AI-004-AAR-017 | verifies |
| v1.0-C9.2.9 | 3 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.2.10 | 3 | Orchestration & Agentic Security / High-Impact Action Approval and Irreversibility Controls | gap |  |  |
| v1.0-C9.3.1 | 1 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | mapped-evidence | PSB-AI-004-AAR-001; PSB-AI-004-AAR-002; PSB-AI-004-AAR-003; PSB-AI-004-AAR-004; PSB-AI-004-AAR-012 | verifies |
| v1.0-C9.3.2 | 1 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | mapped-evidence | PSB-AI-006-AAI-007 | verifies |
| v1.0-C9.3.3 | 2 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | gap |  |  |
| v1.0-C9.3.4 | 2 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | gap |  |  |
| v1.0-C9.3.5 | 2 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | gap |  |  |
| v1.0-C9.3.6 | 2 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | gap |  |  |
| v1.0-C9.3.7 | 2 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | gap |  |  |
| v1.0-C9.3.8 | 3 | Orchestration & Agentic Security / Component Isolation and Tool Authorization | mapped-evidence | PSB-AI-009-RRC-002; PSB-AI-009-RRC-004 | supports |
| v1.0-C9.4.1 | 2 | Orchestration & Agentic Security / Agent and Orchestrator Identity | mapped-evidence | PSB-AI-008-MAD-001; PSB-AI-008-MAD-002 | verifies |
| v1.0-C9.4.2 | 2 | Orchestration & Agentic Security / Agent and Orchestrator Identity | gap |  |  |
| v1.0-C9.4.3 | 3 | Orchestration & Agentic Security / Agent and Orchestrator Identity | gap |  |  |
| v1.0-C9.4.4 | 3 | Orchestration & Agentic Security / Agent and Orchestrator Identity | gap |  |  |
| v1.0-C9.5.1 | 2 | Orchestration & Agentic Security / Agent Authorization, Delegation, and Continuous Enforcement | mapped-evidence | PSB-AI-004-AAR-012; PSB-AI-004-AAR-013; PSB-AI-004-AAR-015; PSB-AI-004-AAR-022; PSB-AI-004-AAR-024; PSB-AI-006-AAI-003; PSB-AI-006-AAI-005 | verifies |
| v1.0-C9.5.2 | 2 | Orchestration & Agentic Security / Agent Authorization, Delegation, and Continuous Enforcement | gap |  |  |
| v1.0-C9.5.3 | 2 | Orchestration & Agentic Security / Agent Authorization, Delegation, and Continuous Enforcement | mapped-evidence | PSB-AI-006-AAI-003; PSB-AI-006-AAI-004; PSB-AI-006-AAI-005 | verifies |
| v1.0-C9.5.4 | 2 | Orchestration & Agentic Security / Agent Authorization, Delegation, and Continuous Enforcement | mapped-evidence | PSB-AI-010-AIG-005; PSB-AI-010-AIG-006; PSB-AI-010-AIG-007 | verifies |
| v1.0-C9.5.5 | 2 | Orchestration & Agentic Security / Agent Authorization, Delegation, and Continuous Enforcement | mapped-evidence | PSB-AI-008-MAD-003; PSB-AI-008-MAD-004; PSB-AI-008-MAD-005; PSB-AI-008-MAD-006; PSB-AI-008-MAD-007; PSB-AI-008-MAD-008 | verifies |
| v1.0-C9.5.6 | 3 | Orchestration & Agentic Security / Agent Authorization, Delegation, and Continuous Enforcement | gap |  |  |
| v1.0-C9.6.1 | 1 | Orchestration & Agentic Security / Shutdown and Graceful Degradation | mapped-evidence | PSB-AI-009-RRC-003; PSB-AI-009-RRC-004 | verifies |
| v1.0-C9.6.2 | 2 | Orchestration & Agentic Security / Shutdown and Graceful Degradation | gap |  |  |
| v1.0-C9.6.3 | 3 | Orchestration & Agentic Security / Shutdown and Graceful Degradation | mapped-evidence | PSB-AI-009-RRC-001; PSB-AI-009-RRC-003 | verifies |
| v1.0-C10.1.1 | 1 | Model Context Protocol (MCP) Security / Component Integrity | mapped-evidence | PSB-AI-002-AID-001; PSB-AI-002-AID-002 | verifies |
| v1.0-C10.1.2 | 2 | Model Context Protocol (MCP) Security / Component Integrity | mapped-evidence | PSB-AI-002-AID-004; PSB-AI-002-AID-007; PSB-AI-004-AAR-012; PSB-AI-004-AAR-018 | verifies |
| v1.0-C10.1.3 | 2 | Model Context Protocol (MCP) Security / Component Integrity | gap |  |  |
| v1.0-C10.2.1 | 1 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.2.2 | 1 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.2.3 | 1 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.2.4 | 2 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.2.5 | 2 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.2.6 | 2 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.2.7 | 2 | Model Context Protocol (MCP) Security / Authentication & Authorization | gap |  |  |
| v1.0-C10.3.1 | 1 | Model Context Protocol (MCP) Security / Secure Transport | gap |  |  |
| v1.0-C10.3.2 | 1 | Model Context Protocol (MCP) Security / Secure Transport | gap |  |  |
| v1.0-C10.3.3 | 2 | Model Context Protocol (MCP) Security / Secure Transport | gap |  |  |
| v1.0-C10.3.4 | 2 | Model Context Protocol (MCP) Security / Secure Transport | gap |  |  |
| v1.0-C10.3.5 | 3 | Model Context Protocol (MCP) Security / Secure Transport | gap |  |  |
| v1.0-C10.4.1 | 1 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.2 | 1 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.3 | 1 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.4 | 2 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.5 | 2 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.6 | 2 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.7 | 2 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C10.4.8 | 3 | Model Context Protocol (MCP) Security / Schema, Message, and Input Validation | gap |  |  |
| v1.0-C11.1.1 | 1 | Adversarial Robustness / Model Alignment, Safety, and Robustness Testing and Training | gap |  |  |
| v1.0-C11.1.2 | 1 | Adversarial Robustness / Model Alignment, Safety, and Robustness Testing and Training | mapped-evidence | PSB-DETECT-002-TEV-001; PSB-DETECT-002-TEV-002; PSB-DETECT-002-TEV-008 | supports |
| v1.0-C11.1.3 | 1 | Adversarial Robustness / Model Alignment, Safety, and Robustness Testing and Training | mapped-evidence | PSB-DETECT-002-TEV-003; PSB-DETECT-002-TEV-004; PSB-DETECT-002-TEV-006 | verifies |
| v1.0-C11.1.4 | 2 | Adversarial Robustness / Model Alignment, Safety, and Robustness Testing and Training | gap |  |  |
| v1.0-C11.1.5 | 3 | Adversarial Robustness / Model Alignment, Safety, and Robustness Testing and Training | gap |  |  |
| v1.0-C11.2.1 | 1 | Adversarial Robustness / Membership-Inference and Model-Inversion Mitigation | gap |  |  |
| v1.0-C11.2.2 | 1 | Adversarial Robustness / Membership-Inference and Model-Inversion Mitigation | gap |  |  |
| v1.0-C11.2.3 | 2 | Adversarial Robustness / Membership-Inference and Model-Inversion Mitigation | gap |  |  |
| v1.0-C11.2.4 | 2 | Adversarial Robustness / Membership-Inference and Model-Inversion Mitigation | gap |  |  |
| v1.0-C11.2.5 | 3 | Adversarial Robustness / Membership-Inference and Model-Inversion Mitigation | gap |  |  |
| v1.0-C11.3.1 | 1 | Adversarial Robustness / Model-Extraction Defense | gap |  |  |
| v1.0-C11.3.2 | 2 | Adversarial Robustness / Model-Extraction Defense | gap |  |  |
| v1.0-C11.3.3 | 3 | Adversarial Robustness / Model-Extraction Defense | gap |  |  |
| v1.0-C11.3.4 | 3 | Adversarial Robustness / Model-Extraction Defense | gap |  |  |
| v1.0-C11.4.1 | 2 | Adversarial Robustness / Model Runtime Anomaly Detection | gap |  |  |
| v1.0-C11.4.2 | 2 | Adversarial Robustness / Model Runtime Anomaly Detection | gap |  |  |
| v1.0-C11.4.3 | 3 | Adversarial Robustness / Model Runtime Anomaly Detection | gap |  |  |
| v1.0-C12.1.1 | 1 | Monitoring, Logging & Anomaly Detection / Request & Response Logging | mapped-evidence | PSB-AI-010-AIG-002; PSB-AI-010-AIG-008 | supports |
| v1.0-C12.1.2 | 2 | Monitoring, Logging & Anomaly Detection / Request & Response Logging | mapped-evidence | PSB-AI-010-AIG-008; PSB-AI-010-AIG-009 | supports |
| v1.0-C12.1.3 | 2 | Monitoring, Logging & Anomaly Detection / Request & Response Logging | gap |  |  |
| v1.0-C12.1.4 | 2 | Monitoring, Logging & Anomaly Detection / Request & Response Logging | gap |  |  |
| v1.0-C12.2.1 | 1 | Monitoring, Logging & Anomaly Detection / Detection and Alerting | gap |  |  |
| v1.0-C12.2.2 | 2 | Monitoring, Logging & Anomaly Detection / Detection and Alerting | mapped-evidence | PSB-AI-007-ARB-006; PSB-AI-007-ARB-008; PSB-AI-007-ARB-009 | supports |
| v1.0-C12.2.3 | 2 | Monitoring, Logging & Anomaly Detection / Detection and Alerting | gap |  |  |
| v1.0-C12.2.4 | 2 | Monitoring, Logging & Anomaly Detection / Detection and Alerting | gap |  |  |
| v1.0-C12.2.5 | 2 | Monitoring, Logging & Anomaly Detection / Detection and Alerting | gap |  |  |
| v1.0-C12.2.6 | 3 | Monitoring, Logging & Anomaly Detection / Detection and Alerting | gap |  |  |
| v1.0-C12.3.1 | 1 | Monitoring, Logging & Anomaly Detection / Model, Data, and Performance Drift Detection | gap |  |  |
| v1.0-C12.3.2 | 2 | Monitoring, Logging & Anomaly Detection / Model, Data, and Performance Drift Detection | gap |  |  |
| v1.0-C12.3.3 | 2 | Monitoring, Logging & Anomaly Detection / Model, Data, and Performance Drift Detection | gap |  |  |
| v1.0-C12.3.4 | 3 | Monitoring, Logging & Anomaly Detection / Model, Data, and Performance Drift Detection | gap |  |  |
| v1.0-C12.4.1 | 2 | Monitoring, Logging & Anomaly Detection / Proactive Security Behavior Monitoring | gap |  |  |
| v1.0-C12.4.2 | 2 | Monitoring, Logging & Anomaly Detection / Proactive Security Behavior Monitoring | gap |  |  |
| v1.0-C12.4.3 | 2 | Monitoring, Logging & Anomaly Detection / Proactive Security Behavior Monitoring | mapped-evidence | PSB-AI-009-RRC-003; PSB-AI-009-RRC-011 | verifies |
| v1.0-C12.5.1 | 1 | Monitoring, Logging & Anomaly Detection / Training Data & Model Lifecycle Audit | gap |  |  |
| v1.0-C12.5.2 | 1 | Monitoring, Logging & Anomaly Detection / Training Data & Model Lifecycle Audit | gap |  |  |
| v1.0-C12.5.3 | 2 | Monitoring, Logging & Anomaly Detection / Training Data & Model Lifecycle Audit | gap |  |  |
| v1.0-C12.5.4 | 2 | Monitoring, Logging & Anomaly Detection / Training Data & Model Lifecycle Audit | gap |  |  |
