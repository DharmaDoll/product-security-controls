#!/usr/bin/env python3
"""Detect likely sensitive data without printing matched values."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


MAX_FILE_BYTES = 5 * 1024 * 1024
ZERO_OID_RE = re.compile(r"^0+$")
SENSITIVE_NAMES = {
    ".ds_store",
    ".netrc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "thumbs.db",
}
SENSITIVE_SUFFIXES = {
    ".7z",
    ".bin",
    ".class",
    ".db",
    ".dll",
    ".dylib",
    ".exe",
    ".gz",
    ".jar",
    ".jks",
    ".key",
    ".keystore",
    ".mdb",
    ".msi",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".rar",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".war",
    ".zip",
}
ALLOWED_ENV_SUFFIXES = {".example", ".sample", ".template"}
CONTENT_RULES = (
    (
        "private-key",
        re.compile(rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    ),
    (
        "github-token",
        re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "aws-access-key",
        re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "aws-secret-access-key",
        re.compile(
            rb"(?im)^\s*(?:aws_)?secret_access_key\s*[:=]\s*['\"]?"
            rb"[A-Za-z0-9/+=]{40}(?=$|[\s'\"])"
        ),
    ),
    (
        "google-api-key",
        re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "jwt",
        re.compile(
            rb"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
            rb"\.[A-Za-z0-9_-]{5,}\b"
        ),
    ),
    (
        "bearer-token",
        re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    ),
    (
        "slack-webhook",
        re.compile(
            rb"https://hooks\.slack\.com/services/"
            rb"[A-Za-z0-9]{8,}/[A-Za-z0-9]{8,}/[A-Za-z0-9]{16,}"
        ),
    ),
    (
        "credential-assignment",
        re.compile(
            rb"(?im)^\s*(?:api[_-]?key|client[_-]?secret|password|token)"
            rb"\s*[:=]\s*['\"]?[A-Za-z0-9/+_.-]{12,}"
        ),
    ),
)


class ScanError(RuntimeError):
    """Raised when the scanner cannot establish a reliable result."""


def git(*arguments: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise ScanError(f"cannot execute git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ScanError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout


def sensitive_path_rule(path: str) -> str | None:
    name = PurePosixPath(path).name.lower()
    if name == ".env" or name.startswith(".env."):
        if any(name.endswith(suffix) for suffix in ALLOWED_ENV_SUFFIXES):
            return None
        return "sensitive-filename"
    if name in SENSITIVE_NAMES or PurePosixPath(name).suffix in SENSITIVE_SUFFIXES:
        return "sensitive-filename"
    return None


def scan_content(label: str, content: bytes) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if len(content) > MAX_FILE_BYTES:
        return [("file-too-large", label)]
    if b"\x00" in content:
        return [("binary-file", label)]
    for rule, pattern in CONTENT_RULES:
        if pattern.search(content):
            findings.append((rule, label))
    return findings


def scan_blob(label: str, content: bytes) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    path_rule = sensitive_path_rule(label)
    if path_rule:
        findings.append((path_rule, label))
    findings.extend(scan_content(label, content))
    return findings


def staged_findings() -> list[tuple[str, str]]:
    paths = [
        raw.decode("utf-8", errors="surrogateescape")
        for raw in git(
            "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"
        ).split(b"\0")
        if raw
    ]
    findings: list[tuple[str, str]] = []
    for path in paths:
        try:
            content = git("show", f":{path}")
        except ScanError as error:
            raise ScanError(f"cannot inspect staged path {path!r}: {error}") from error
        findings.extend(scan_blob(path, content))
    return findings


def commit_findings(commits: list[str]) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for commit in commits:
        findings.extend(
            scan_content(
                f"{commit[:12]}:commit-message",
                git("show", "-s", "--format=%B", commit),
            )
        )
        paths = [
            raw.decode("utf-8", errors="surrogateescape")
            for raw in git(
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "--diff-filter=ACMR",
                "-r",
                "-z",
                commit,
            ).split(b"\0")
            if raw
        ]
        for path in paths:
            try:
                content = git("show", f"{commit}:{path}")
            except ScanError as error:
                raise ScanError(
                    f"cannot inspect {commit[:12]}:{path!r}: {error}"
                ) from error
            findings.extend(scan_blob(f"{commit[:12]}:{path}", content))
    return findings


def pre_push_commits(remote_name: str) -> list[str]:
    commits: list[str] = []
    for line_number, line in enumerate(sys.stdin, start=1):
        fields = line.split()
        if len(fields) != 4:
            raise ScanError(f"invalid pre-push input at line {line_number}")
        _local_ref, local_oid, _remote_ref, remote_oid = fields
        if ZERO_OID_RE.fullmatch(local_oid):
            continue
        if ZERO_OID_RE.fullmatch(remote_oid):
            if not remote_name:
                raise ScanError("remote name is required for a new remote ref")
            revision_arguments = [
                "rev-list",
                local_oid,
                "--not",
                f"--remotes={remote_name}",
            ]
        else:
            revision_arguments = ["rev-list", f"{remote_oid}..{local_oid}"]
        commits.extend(
            line
            for line in git(*revision_arguments).decode("ascii").splitlines()
            if line
        )
    return list(dict.fromkeys(commits))


def emit(findings: list[tuple[str, str]]) -> int:
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
            findings = staged_findings()
        elif args.pre_push is not None:
            findings = commit_findings(pre_push_commits(args.pre_push))
        else:
            if not args.label:
                raise ScanError("--label is required with --file")
            try:
                content = args.file.read_bytes()
            except OSError as error:
                raise ScanError(f"cannot read input file: {error}") from error
            findings = scan_content(args.label, content)
    except ScanError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2
    return emit(findings)


if __name__ == "__main__":
    raise SystemExit(main())
