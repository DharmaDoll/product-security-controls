#!/usr/bin/env python3
"""Small fail-closed scanner used by the repository-owned Git hooks."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


MAX_FILE_BYTES = 5 * 1024 * 1024
ZERO_OID = re.compile(r"^0+$")

BLOCKED_NAMES = {
    ".ds_store",
    ".netrc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "thumbs.db",
}
BLOCKED_SUFFIXES = {
    ".7z", ".bin", ".class", ".db", ".dll", ".dylib", ".exe", ".gz",
    ".jar", ".jks", ".key", ".keystore", ".mdb", ".msi", ".p12",
    ".pem", ".pfx", ".pyc", ".pyo", ".rar", ".so", ".sqlite",
    ".sqlite3", ".tar", ".war", ".zip",
}
ALLOWED_ENV_ENDINGS = (".example", ".sample", ".template")

SECRET_RULES = {
    "private-key": rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----",
    "github-token": rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "aws-access-key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "aws-secret-access-key": (
        rb"(?im)^\s*(?:aws_)?secret_access_key\s*[:=]\s*['\"]?"
        rb"[A-Za-z0-9/+=]{40}(?=$|[\s'\"])"
    ),
    "google-api-key": rb"\bAIza[0-9A-Za-z_-]{35}\b",
    "jwt": (
        rb"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
        rb"[A-Za-z0-9_-]{5,}\b"
    ),
    "bearer-token": rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}",
    "slack-webhook": (
        rb"https://hooks\.slack\.com/services/[A-Za-z0-9]{8,}/"
        rb"[A-Za-z0-9]{8,}/[A-Za-z0-9]{16,}"
    ),
    "credential-assignment": (
        rb"(?im)^\s*(?:api[_-]?key|client[_-]?secret|password|token)"
        rb"\s*[:=]\s*['\"]?[A-Za-z0-9/+_.-]{12,}"
    ),
}
COMPILED_RULES = {
    name: re.compile(pattern) for name, pattern in SECRET_RULES.items()
}


class ScanError(RuntimeError):
    """The scanner could not produce a trustworthy result."""


def git(*arguments: str) -> bytes:
    """Run Git and return stdout, or fail closed with a short error."""
    try:
        result = subprocess.run(
            ["git", *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ScanError(f"cannot execute git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ScanError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout


def blocked_path(path: str) -> bool:
    """Return True for file types this small text scanner must not accept."""
    name = PurePosixPath(path).name.lower()
    if name == ".env" or name.startswith(".env."):
        return not name.endswith(ALLOWED_ENV_ENDINGS)
    return name in BLOCKED_NAMES or PurePosixPath(name).suffix in BLOCKED_SUFFIXES


def scan(label: str, content: bytes) -> list[tuple[str, str]]:
    """Return rule names and locations without returning matched values."""
    if len(content) > MAX_FILE_BYTES:
        return [("file-too-large", label)]
    if b"\0" in content:
        return [("binary-file", label)]

    findings: list[tuple[str, str]] = []
    if blocked_path(label):
        findings.append(("sensitive-filename", label))
    for name, pattern in COMPILED_RULES.items():
        if pattern.search(content):
            findings.append((name, label))
    return findings


def decode_paths(raw: bytes) -> list[str]:
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0")
        if item
    ]


def scan_staged() -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    paths = decode_paths(
        git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    )
    for path in paths:
        findings.extend(scan(path, git("show", f":{path}")))
    return findings


def scan_commit(commit: str) -> list[tuple[str, str]]:
    findings = scan(
        f"{commit[:12]}:commit-message",
        git("show", "-s", "--format=%B", commit),
    )
    paths = decode_paths(
        git(
            "diff-tree", "--root", "--no-commit-id", "--name-only",
            "--diff-filter=ACMR", "-r", "-z", commit,
        )
    )
    for path in paths:
        findings.extend(scan(f"{commit[:12]}:{path}", git("show", f"{commit}:{path}")))
    return findings


def introduced_commits(remote: str) -> list[str]:
    commits: list[str] = []
    for number, line in enumerate(sys.stdin, start=1):
        fields = line.split()
        if len(fields) != 4:
            raise ScanError(f"invalid pre-push input at line {number}")
        _local_ref, local_oid, _remote_ref, remote_oid = fields
        if ZERO_OID.fullmatch(local_oid):
            continue
        if ZERO_OID.fullmatch(remote_oid):
            if not remote:
                raise ScanError("remote name is required for a new remote ref")
            revision = ("rev-list", local_oid, "--not", f"--remotes={remote}")
        else:
            revision = ("rev-list", f"{remote_oid}..{local_oid}")
        commits.extend(git(*revision).decode("ascii").splitlines())
    return list(dict.fromkeys(commits))


def scan_history(remote: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for commit in introduced_commits(remote):
        findings.extend(scan_commit(commit))
    return findings


def report(findings: list[tuple[str, str]]) -> int:
    for rule, label in findings:
        print(f"BLOCK {rule} {json.dumps(label, ensure_ascii=True)}")
    if findings:
        print(f"REJECTED {len(findings)} finding(s); matched values suppressed")
        return 1
    print("ACCEPTED no sensitive-data findings")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--pre-push", metavar="REMOTE")
    mode.add_argument("--file", type=Path)
    parser.add_argument("--label")
    args = parser.parse_args()

    try:
        if args.staged:
            findings = scan_staged()
        elif args.pre_push is not None:
            findings = scan_history(args.pre_push)
        else:
            if args.file is None or not args.label:
                raise ScanError("--file requires --label")
            findings = scan(args.label, args.file.read_bytes())
    except (OSError, UnicodeError, ScanError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    return report(findings)


if __name__ == "__main__":
    raise SystemExit(main())
