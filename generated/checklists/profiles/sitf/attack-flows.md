# Synthetic SITF attack flows

Generated from repository-owned review scenarios. These are not upstream Wiz Research flows or observed incidents. Do not edit manually.

A flow exposes how an unclosed technique can connect otherwise strong controls across endpoint, VCS, CI/CD, registry, and production boundaries.

| Flow | Step | Technique | Component | Coverage | Objective |
|---|---:|---|---|---|---|
| SITF-FLOW-001: Developer endpoint to poisoned production image | 1 | T-E001: Malicious Execution on Endpoint | endpoint | implemented | Execute attacker-controlled code on the developer endpoint. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 2 | T-E003: Harvest Local Secrets / Credentials from Endpoint | endpoint | implemented | Harvest locally available credentials and tokens. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 3 | T-V001: Abuse Credentials for VCS Access | vcs | implemented | Use stolen credentials to access the source platform. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 4 | T-V010: Malicious Code Modification in Repository | vcs | implemented | Modify protected source or workflow content. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 5 | T-C002: Malicious Execution in Workflow Context | cicd | implemented | Run malicious code in the workflow context. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 6 | T-C005: Secret Exfiltration from Workflow | cicd | implemented | Attempt to obtain additional workflow secrets. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 7 | T-R005: Publishing Malicious Container/VM Image | registry | implemented | Publish an attacker-controlled container image. |
| SITF-FLOW-001: Developer endpoint to poisoned production image | 8 | T-P004: Container Image Poisoning to Production | production | implemented | Move the poisoned image into production. |
| SITF-FLOW-002: Cross-fork poisoned pipeline to production network | 1 | T-V012: Cross-Fork Object Reference Abuse | vcs | implemented | Confuse trusted and fork-controlled object identity. |
| SITF-FLOW-002: Cross-fork poisoned pipeline to production network | 2 | T-C003: PWN Request / Poisoned Pipeline Execution | cicd | implemented | Trigger privileged behavior from an untrusted pull request. |
| SITF-FLOW-002: Cross-fork poisoned pipeline to production network | 3 | T-C007: Action Cache Poisoning | cicd | implemented | Poison reusable action or build cache state. |
| SITF-FLOW-002: Cross-fork poisoned pipeline to production network | 4 | T-C013: Persistence on Self-Hosted Runners | cicd | implemented | Persist on a self-hosted runner across jobs. |
| SITF-FLOW-002: Cross-fork poisoned pipeline to production network | 5 | T-P003: Pivot from Self-Hosted Runner to Production Network | production | implemented | Use runner network reachability to approach production. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 1 | T-R010: Typosquatting | registry | implemented | Present a typosquatted package name. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 2 | T-R011: Namespace/Dependency Confusion | registry | implemented | Exploit namespace or resolver confusion. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 3 | T-R012: Package Lifecycle Script Abuse | registry | implemented | Execute code through a package lifecycle script. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 4 | T-C010: Runner Executing Malicious Package | cicd | implemented | Run the malicious package on a CI runner. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 5 | T-C011: Stealing Registry Tokens | cicd | implemented | Steal registry publication credentials. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 6 | T-R005: Publishing Malicious Container/VM Image | registry | implemented | Publish a malicious image under trusted naming. |
| SITF-FLOW-003: Malicious package to release and deployment credentials | 7 | T-P004: Container Image Poisoning to Production | production | implemented | Attempt to admit the malicious image to production. |
| SITF-FLOW-004: Workflow prompt injection to malicious deployment | 1 | T-C021: AI Agent Prompt Injection in Workflow | cicd | implemented | Inject instructions through untrusted workflow input. |
| SITF-FLOW-004: Workflow prompt injection to malicious deployment | 2 | T-C008: Malicious Workflow Performing Code Modification | cicd | implemented | Cause the workflow to modify repository content. |
| SITF-FLOW-004: Workflow prompt injection to malicious deployment | 3 | T-V010: Malicious Code Modification in Repository | vcs | implemented | Persist malicious code in protected source. |
| SITF-FLOW-004: Workflow prompt injection to malicious deployment | 4 | T-C012: PR from Malicious Workflow | cicd | implemented | Create or promote a pull request from the compromised workflow. |
| SITF-FLOW-004: Workflow prompt injection to malicious deployment | 5 | T-P002: Malicious Deployment via Compromised Pipeline | production | implemented | Attempt deployment through the compromised pipeline. |
