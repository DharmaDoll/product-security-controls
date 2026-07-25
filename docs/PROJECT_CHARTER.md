# Project Charter

## Vision

Product Securityの考え方を、抽象的なベストプラクティスではなく、再利用可能なコード、設定、テスト、証跡として提供する。

## Problem statement

Product Securityの資料は、次のいずれかに偏りやすい。

- フレームワークや原則だけで具体実装がない
- ツール導入例だけで、何のリスクを下げるか不明
- GitHubやCI/CDだけに閉じている
- アプリケーションコードだけで供給網やリリースを扱わない
- 設定例はあるが自動テストされていない
- 標準マッピングが手作業で陳腐化する

本リポジトリは、Product Security controlを実装単位で整理し、危険例、安全例、検証方法、標準マッピングを統合する。

## Scope

### In scope

- application security design;
- secure coding patterns;
- repository and source protection;
- software dependencies;
- CI/CD and build pipelines;
- containers, cloud, Kubernetes, and IaC;
- release integrity and provenance;
- AI-assisted software development;
- vulnerability detection and response;
- framework mapping and control governance.

### Out of scope

- production SOC platform;
- complete enterprise GRC system;
- exploit development;
- malware execution;
- formal certification;
- exhaustive coverage of every framework;
- replacing product-specific threat modeling.

## Success criteria

- controls are easy to discover;
- examples are runnable;
- insecure and secure behavior are clear;
- verification is automated;
- framework mappings are machine-readable;
- adoption instructions are practical;
- controls expose limitations and trade-offs;
- the repository remains modular rather than becoming a tool dump.

## Core principle

The repository is organized by **security outcome**, not by tool.

Trivy, CodeGuard, Semgrep, Dependabot, cosign, and other tools are implementations or verification mechanisms under a control.
