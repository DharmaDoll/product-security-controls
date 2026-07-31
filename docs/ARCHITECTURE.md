# Architecture

## Conceptual model

```text
Threats and failure scenarios
            ↓
Product Security controls
            ↓
Concrete secure implementations
            ↓
Automated verification and evidence
            ↓
Framework mappings and adoption guidance
```

## Repository layers

### 1. Control catalog

`controls/` contains individually understandable and testable security controls.
Each package starts with a validated one-page README overview of the problem,
threat source, target, action, success state, and residual boundary, followed by
the executable implementation and machine-readable atomic checks.

### 2. Shared tooling

`tools/`, `scripts/`, and `Makefile` provide common validation and generation functions.

### 3. Framework registry

`frameworks/` stores versioned identifiers and metadata for mapping validation.

### 4. Generated views

`generated/` contains indexes and reverse mappings produced from `control.yaml`.

### 5. Experiments

`experiments/` contains comparative evaluations such as CodeGuard-enabled versus baseline Codex execution.

## Trust model

The following are external or semi-trusted inputs:

- package registries;
- container registries;
- GitHub Actions;
- scanner databases;
- Security Skills;
- MCP servers;
- AI-generated code;
- framework mapping data;
- downloaded tools;
- pull-request content.

Controls must explicitly document which trust boundary they address.

## Prevent, detect, verify, respond

Controls should identify their primary function.

- `prevent`
- `detect`
- `verify`
- `respond`
- `govern`

Example:

- CodeGuard: prevent/support
- secure coding tests: verify
- Trivy: detect/verify
- Dependency Review: detect/prevent
- SBOM: evidence/support
- incident playbook: respond
