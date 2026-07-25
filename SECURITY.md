# Security Policy

## Reporting

Do not report sensitive vulnerabilities through a public issue.

Use private vulnerability reporting or the configured security contact when available.

## Intentional insecure examples

This repository contains intentionally insecure examples for education and verification.

They must:

- remain under a control's `insecure/` directory;
- use no real credentials;
- use no production data;
- never deploy by default;
- be clearly labeled;
- avoid malware or destructive payloads.

## Security-sensitive files

Changes to the following require security-owner review:

- `AGENTS.md`
- `.codex/`
- `.github/workflows/`
- `controls/**/control.yaml`
- release/signing configuration
- dependency manifests
- external Skills and MCP configurations
- `policies/exceptions/`
- framework registries and mapping generators
