#!/usr/bin/env python3
"""Complete behavior tests for the repository-owned sensitive-data scanner."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


CONTROL_ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = CONTROL_ROOT / "secure" / ".githooks" / "scan-sensitive.py"
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "scan-sensitive-cases.json"
FIXTURE_DATA = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

EXPECTED_BLOCKED_NAMES = set(FIXTURE_DATA["blocked_names"])
EXPECTED_BLOCKED_SUFFIXES = set(FIXTURE_DATA["blocked_suffixes"])
EXPECTED_SECRET_RULES = set(FIXTURE_DATA["positive_cases"])


def load_scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("scan_sensitive", SCANNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCANNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load_scanner()


def finding_fixtures() -> dict[str, bytes]:
    """Return the first reviewed inert value for every secret rule."""
    return {
        rule: cases[0]["value"].encode()
        for rule, cases in FIXTURE_DATA["positive_cases"].items()
    }


def safe_near_misses() -> list[tuple[str, bytes]]:
    return [
        (case["name"], case["value"].encode())
        for case in FIXTURE_DATA["near_miss_cases"]
    ]


def rule_variants() -> dict[str, list[tuple[str, bytes]]]:
    """Return every reviewed alternative encoded in the regular expressions."""
    return {
        rule: [(case["name"], case["value"].encode()) for case in cases]
        for rule, cases in FIXTURE_DATA["positive_cases"].items()
    }


class ScannerRuleTests(unittest.TestCase):
    def test_fixture_source_contains_no_raw_finding(self) -> None:
        self.assertEqual(scanner.scan(str(FIXTURE_PATH), FIXTURE_PATH.read_bytes()), [])

    def test_blocked_name_inventory_and_detection(self) -> None:
        self.assertEqual(scanner.BLOCKED_NAMES, EXPECTED_BLOCKED_NAMES)
        for name in sorted(EXPECTED_BLOCKED_NAMES):
            with self.subTest(name=name):
                self.assertEqual(
                    scanner.scan(f"nested/{name.upper()}", b"safe"),
                    [("sensitive-filename", f"nested/{name.upper()}")],
                )

    def test_blocked_suffix_inventory_and_detection(self) -> None:
        self.assertEqual(scanner.BLOCKED_SUFFIXES, EXPECTED_BLOCKED_SUFFIXES)
        for suffix in sorted(EXPECTED_BLOCKED_SUFFIXES):
            label = f"nested/artifact{suffix.upper()}"
            with self.subTest(suffix=suffix):
                self.assertEqual(
                    scanner.scan(label, b"safe"),
                    [("sensitive-filename", label)],
                )

    def test_environment_file_policy(self) -> None:
        for name in (".env", ".env.local", ".ENV.PRODUCTION"):
            with self.subTest(blocked=name):
                self.assertTrue(scanner.blocked_path(name))
        for name in (".env.example", ".env.sample", ".env.template"):
            with self.subTest(allowed=name):
                self.assertFalse(scanner.blocked_path(name))

    def test_all_secret_rules_have_a_detected_fixture(self) -> None:
        fixtures = finding_fixtures()
        self.assertEqual(set(scanner.SECRET_RULES), EXPECTED_SECRET_RULES)
        self.assertEqual(set(fixtures), EXPECTED_SECRET_RULES)
        for rule, content in fixtures.items():
            with self.subTest(rule=rule):
                self.assertEqual(scanner.scan("source.txt", content), [(rule, "source.txt")])

    def test_all_regular_expression_alternatives_are_detected(self) -> None:
        variants = rule_variants()
        self.assertEqual(set(variants), EXPECTED_SECRET_RULES)
        for rule, cases in variants.items():
            for case_name, content in cases:
                with self.subTest(rule=rule, variant=case_name):
                    self.assertEqual(
                        scanner.scan("source.txt", content),
                        [(rule, "source.txt")],
                    )

    def test_near_misses_are_not_detected(self) -> None:
        for case_name, content in safe_near_misses():
            with self.subTest(case=case_name):
                self.assertEqual(scanner.scan("source.txt", content), [])

    def test_allowed_environment_template_still_scans_content(self) -> None:
        content = finding_fixtures()["credential-assignment"]
        self.assertEqual(
            scanner.scan(".env.example", content),
            [("credential-assignment", ".env.example")],
        )

    def test_sensitive_filename_and_content_can_both_be_reported(self) -> None:
        content = finding_fixtures()["credential-assignment"]
        self.assertEqual(
            scanner.scan(".env", content),
            [
                ("sensitive-filename", ".env"),
                ("credential-assignment", ".env"),
            ],
        )

    def test_binary_and_size_boundaries(self) -> None:
        self.assertEqual(scanner.scan("source.txt", b"safe\0content"), [("binary-file", "source.txt")])
        self.assertEqual(scanner.scan("source.txt", b"A" * scanner.MAX_FILE_BYTES), [])
        self.assertEqual(
            scanner.scan("source.txt", b"A" * (scanner.MAX_FILE_BYTES + 1)),
            [("file-too-large", "source.txt")],
        )

    def test_report_redacts_every_fixture_value(self) -> None:
        for rule, cases in rule_variants().items():
            for case_name, content in cases:
                with self.subTest(rule=rule, variant=case_name):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        status = scanner.report(scanner.scan("fixture.txt", content))
                    self.assertEqual(status, 1)
                    self.assertIn(f"BLOCK {rule}", output.getvalue())
                    self.assertNotIn(content.decode(), output.getvalue())

    def test_clean_report_is_distinct_from_finding(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = scanner.report([])
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), "ACCEPTED no sensitive-data findings\n")


class ScannerCommandTests(unittest.TestCase):
    def run_scanner(
        self,
        *arguments: str,
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCANNER_PATH), *arguments],
            cwd=cwd,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def init_repository(self, root: Path) -> Path:
        repository = root / "repository"
        empty_hooks = root / "empty-hooks"
        empty_hooks.mkdir()
        self.git(root, "init", "-q", str(repository))
        self.git(repository, "config", "--local", "user.name", "Scanner Test")
        self.git(
            repository,
            "config",
            "--local",
            "user.email",
            "scanner-test@example.invalid",
        )
        self.git(repository, "config", "--local", "core.hooksPath", str(empty_hooks))
        return repository

    def test_file_mode_clean_finding_redaction_and_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            safe = root / "safe.txt"
            finding = root / "finding.txt"
            safe.write_text("safe content\n", encoding="utf-8")
            secret = finding_fixtures()["credential-assignment"].decode()
            finding.write_text(secret, encoding="utf-8")

            clean = self.run_scanner("--file", str(safe), "--label", "safe")
            blocked = self.run_scanner("--file", str(finding), "--label", "finding")
            missing = self.run_scanner("--file", str(root / "missing"), "--label", "missing")

            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertIn("BLOCK credential-assignment", blocked.stdout)
            self.assertNotIn(secret, blocked.stdout + blocked.stderr)
            self.assertEqual(missing.returncode, 2)
            self.assertIn("ERROR", missing.stderr)

    def test_staged_mode_scans_index_not_unstaged_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            repository = self.init_repository(root)
            source = repository / "source.txt"
            source.write_text("safe staged content\n", encoding="utf-8")
            self.git(repository, "add", "source.txt")

            unstaged_secret = finding_fixtures()["credential-assignment"].decode()
            source.write_text(unstaged_secret, encoding="utf-8")
            clean = self.run_scanner("--staged", cwd=repository)
            self.assertEqual(clean.returncode, 0, clean.stderr)

            self.git(repository, "add", "source.txt")
            blocked = self.run_scanner("--staged", cwd=repository)
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertIn("BLOCK credential-assignment", blocked.stdout)
            self.assertNotIn(unstaged_secret, blocked.stdout + blocked.stderr)

    def test_pre_push_scans_deleted_history_and_commit_messages(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            repository = self.init_repository(root)
            source = repository / "source.txt"
            source.write_text("safe baseline\n", encoding="utf-8")
            self.git(repository, "add", "source.txt")
            self.git(repository, "commit", "-q", "-m", "Safe baseline")
            baseline = self.git(repository, "rev-parse", "HEAD")

            secret = finding_fixtures()["github-token"].decode()
            source.write_text(secret, encoding="utf-8")
            self.git(repository, "add", "source.txt")
            self.git(repository, "commit", "-q", "-m", "Add inert fixture")
            source.write_text("removed from latest tree\n", encoding="utf-8")
            self.git(repository, "add", "source.txt")
            self.git(repository, "commit", "-q", "-m", "Remove inert fixture")

            message_secret = finding_fixtures()["credential-assignment"].decode()
            self.git(repository, "commit", "-q", "--allow-empty", "-m", message_secret)
            head = self.git(repository, "rev-parse", "HEAD")
            push_input = f"refs/heads/main {head} refs/heads/main {baseline}\n"

            blocked = self.run_scanner(
                "--pre-push",
                "origin",
                cwd=repository,
                input_text=push_input,
            )
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertIn("BLOCK github-token", blocked.stdout)
            self.assertIn("BLOCK credential-assignment", blocked.stdout)
            self.assertNotIn(secret, blocked.stdout + blocked.stderr)
            self.assertNotIn(message_secret, blocked.stdout + blocked.stderr)

    def test_new_remote_ref_scans_the_root_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            repository = self.init_repository(root)
            secret = finding_fixtures()["github-token"].decode()
            (repository / "source.txt").write_text(secret, encoding="utf-8")
            self.git(repository, "add", "source.txt")
            self.git(repository, "commit", "-q", "-m", "Root fixture")
            head = self.git(repository, "rev-parse", "HEAD")
            push_input = (
                f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
            )

            blocked = self.run_scanner(
                "--pre-push",
                "origin",
                cwd=repository,
                input_text=push_input,
            )
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertIn("BLOCK github-token", blocked.stdout)
            self.assertNotIn(secret, blocked.stdout + blocked.stderr)

    def test_pre_push_input_and_git_errors_fail_closed(self) -> None:
        malformed = self.run_scanner("--pre-push", "origin", input_text="malformed\n")
        deleted_ref = self.run_scanner(
            "--pre-push",
            "origin",
            input_text=f"refs/heads/main {'0' * 40} refs/heads/main {'1' * 40}\n",
        )
        with tempfile.TemporaryDirectory() as raw_root:
            not_repository = self.run_scanner("--staged", cwd=Path(raw_root))

        self.assertEqual(malformed.returncode, 2)
        self.assertIn("invalid pre-push input", malformed.stderr)
        self.assertEqual(deleted_ref.returncode, 0, deleted_ref.stderr)
        self.assertEqual(not_repository.returncode, 2)
        self.assertIn("ERROR", not_repository.stderr)


if __name__ == "__main__":
    unittest.main()
