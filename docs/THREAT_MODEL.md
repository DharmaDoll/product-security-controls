# Threat Model

## Protected assets

- product source code;
- application data and trust boundaries;
- build and release pipelines;
- dependency graph;
- artifacts and container images;
- signing and cloud identities;
- developer environments;
- security policies and exceptions;
- AI agent execution context;
- customer and consumer trust.

## Threat categories

### Product implementation threats

- injection;
- broken authentication;
- broken authorization;
- insecure cryptography;
- secret exposure;
- unsafe file and command handling;
- insecure defaults;
- missing logging and response capability.

### Software supply-chain threats

- malicious dependencies;
- compromised maintainers;
- typosquatting;
- dependency confusion;
- mutable workflow dependencies;
- compromised build service;
- artifact substitution;
- poisoned scanner database;
- unverified external downloads.

### Public source and information exposure threats

- GitHub dorking against public repositories, code, issues, wikis, and commit
  history to discover internal information;
- accidental exposure of secrets, tokens, internal hostnames, customer data,
  architecture details, or security tooling configuration;
- repository forks, cached copies, and deleted-content remnants preserving
  information after the source repository is corrected;
- over-broad repository visibility, search indexing, or organization
  membership exposing content outside the intended trust boundary.

### Developer endpoint threats

- stolen or unattended developer devices exposing source code, tokens, SSH
  keys, cached credentials, or local build artifacts;
- malware, malicious browser extensions, or untrusted packages executing with
  developer privileges;
- missing OS and tool security updates enabling local privilege escalation or
  credential theft;
- excessive local administrator, container, filesystem, or network access;
- insecure local services, debug ports, copied production data, or weakly
  protected backups crossing the development trust boundary;
- AI agents, Skills, MCP servers, or editor integrations accessing credentials
  and files beyond the task's intended scope.

### CI/CD and release threats

- excessive workflow permissions;
- untrusted PR execution;
- credential exfiltration;
- OIDC trust misconfiguration;
- insecure self-hosted runners;
- unsigned or unverifiable releases;
- missing provenance;
- mutable container tags.

### AI-assisted development threats

- poisoned Skills;
- malicious MCP servers;
- prompt/document injection;
- unsafe dependency recommendations;
- security-control removal;
- credential and filesystem overreach;
- hidden network access;
- hallucinated security APIs or packages.

## Threat-to-control relationship

Threats are documented at the repository level and referenced by controls. Controls should not duplicate the entire threat model.

A control may:

- prevent;
- detect;
- verify;
- reduce impact;
- provide evidence;
- support response.

Residual risk must always be stated.
