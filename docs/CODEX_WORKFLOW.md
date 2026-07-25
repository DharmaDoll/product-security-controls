# Codex Workflow

## Why Codex is suitable

Codex is suitable for this project because most deliverables are repository-native artifacts:

- Markdown;
- YAML;
- GitHub Actions;
- shell scripts;
- policy files;
- sample applications;
- tests;
- generated indexes;
- schema validation.

The project should still be developed control by control. Broad autonomous implementation without review will create inconsistency.

## Recommended iteration

1. Select one control.
2. Ask Codex to analyze the threat and acceptance criteria.
3. Review the proposed file changes.
4. Ask Codex to implement insecure and secure samples.
5. Run verification.
6. Review mappings and limitations.
7. Commit the control.
8. Move to the next control.

## Prompt discipline

Use files under `.codex/prompts/`.

Do not send a broad prompt such as:

> Implement the entire Product Security Blueprint.

Prefer:

> Implement PSB-CICD-001 only. Follow the control package structure and stop after tests and documentation pass.

## Review checkpoints

Human review is mandatory for:

- new dependencies;
- new GitHub Actions;
- workflow permissions;
- OIDC;
- release signing;
- security exceptions;
- Agent Skills;
- MCP servers;
- framework mapping claims;
- changes to AGENTS.md.

## Vibe coding boundary

Vibe coding is effective for rapid iteration on:

- scaffolding;
- documentation;
- test fixtures;
- scripts;
- schema generation;
- sample implementations.

It is not a substitute for explicit acceptance criteria, negative testing, security review, and evidence.
