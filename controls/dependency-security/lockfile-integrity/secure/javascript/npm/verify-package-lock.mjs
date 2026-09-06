#!/usr/bin/env node

import fs from "node:fs";

function inputError(message) {
  console.error(`ERROR ${message}`);
  process.exit(2);
}

function securityFailure(message) {
  console.error(`FAIL ${message}`);
  process.exit(1);
}

if (process.argv.length !== 3) {
  inputError("usage: verify-package-lock.mjs <package-lock.json>");
}

let lock;
try {
  lock = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
} catch {
  inputError("package-lock.json is unreadable or malformed");
}

if (![2, 3].includes(lock.lockfileVersion)) {
  inputError(`unsupported package-lock version: ${String(lock.lockfileVersion)}`);
}
if (!lock.packages || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
  inputError("package-lock.json does not contain the packages map");
}

const root = lock.packages[""];
if (!root || typeof root !== "object") {
  inputError("package-lock.json does not contain a root package record");
}

const workspacePatterns = Array.isArray(root.workspaces) ? root.workspaces : [];

function normalizePath(value) {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/\/$/, "");
}

function matchesWorkspace(packagePath) {
  const normalizedPath = normalizePath(packagePath);
  return workspacePatterns.some((pattern) => {
    const normalizedPattern = normalizePath(pattern);
    if (normalizedPattern.endsWith("/*")) {
      const prefix = normalizedPattern.slice(0, -1);
      const suffix = normalizedPath.slice(prefix.length);
      return normalizedPath.startsWith(prefix) && suffix.length > 0 && !suffix.includes("/");
    }
    return normalizedPattern === normalizedPath;
  });
}

const workspacePaths = new Set(
  Object.keys(lock.packages).filter((packagePath) => packagePath && matchesWorkspace(packagePath)),
);

const strongIntegrity = /(?:^|\s)sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}(?:\?\S+)?(?:$|\s)/;
let verifiedArtifacts = 0;

for (const [packagePath, record] of Object.entries(lock.packages)) {
  if (!packagePath || workspacePaths.has(packagePath)) {
    continue;
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    inputError(`invalid package record: ${packagePath}`);
  }

  if (record.link === true) {
    const target = typeof record.resolved === "string" ? normalizePath(record.resolved) : "";
    if (!workspacePaths.has(target)) {
      securityFailure(`local link is not a declared workspace: ${packagePath}`);
    }
    continue;
  }

  if (typeof record.resolved !== "string" || record.resolved.length === 0) {
    securityFailure(`resolved artifact is missing: ${packagePath}`);
  }
  if (/^(?:git\+|git:|github:|https?:\/\/github\.com\/.*#(?:main|master|head)$)/i.test(record.resolved)) {
    securityFailure(`mutable VCS dependency is unsupported: ${packagePath}`);
  }
  if (record.resolved.startsWith("file:") && !/\.(?:tgz|tar\.gz)(?:$|[?#])/i.test(record.resolved)) {
    securityFailure(`local directory dependency is unsupported: ${packagePath}`);
  }
  if (/^https?:/i.test(record.resolved)) {
    let resolvedUrl;
    try {
      resolvedUrl = new URL(record.resolved);
    } catch {
      inputError(`resolved URL is malformed: ${packagePath}`);
    }
    if (resolvedUrl.username || resolvedUrl.password) {
      securityFailure(`credential-bearing artifact URL is unsupported: ${packagePath}`);
    }
  }
  if (typeof record.integrity !== "string" || !strongIntegrity.test(record.integrity)) {
    securityFailure(`strong artifact integrity is missing: ${packagePath}`);
  }
  verifiedArtifacts += 1;
}

console.log(
  `PASS npm lockfile preflight verified ${verifiedArtifacts} external artifact record(s)`,
);
