from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
SCRIPT = CONTROL / "scripts" / "normalize_github_branch_protection.py"
FIXTURES = CONTROL / "secure" / "github-legacy-branch-scm"
ADMIN_FIXTURES = CONTROL / "secure" / "github-legacy-admin-branch-scm"
CODE_OWNER_FIXTURES = CONTROL / "secure" / "github-legacy-codeowner-branch-scm"
DELETION_FIXTURES = CONTROL / "secure" / "github-legacy-deletion-branch-scm"
SPEC = importlib.util.spec_from_file_location("normalize_github_branch_protection", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def admin_fixture(name: str):
    return json.loads((ADMIN_FIXTURES / name).read_text(encoding="utf-8"))


def code_owner_fixture(name: str):
    return json.loads((CODE_OWNER_FIXTURES / name).read_text(encoding="utf-8"))


def deletion_fixture(name: str):
    return json.loads((DELETION_FIXTURES / name).read_text(encoding="utf-8"))


class GithubBranchProtectionNormalizerTest(unittest.TestCase):
    def sources(self):
        return (
            fixture("audit-events.json"),
            fixture("identity-sessions.json"),
            fixture("change-register.json"),
            fixture("branch-protection-snapshot.json"),
        )

    def admin_sources(self):
        return (
            admin_fixture("audit-events.json"),
            admin_fixture("identity-sessions.json"),
            admin_fixture("change-register.json"),
            admin_fixture("branch-protection-snapshot.json"),
        )

    def code_owner_sources(self):
        return (
            code_owner_fixture("audit-events.json"),
            code_owner_fixture("identity-sessions.json"),
            code_owner_fixture("change-register.json"),
            code_owner_fixture("branch-protection-snapshot.json"),
        )

    def deletion_sources(self):
        return (
            deletion_fixture("audit-events.json"),
            deletion_fixture("identity-sessions.json"),
            deletion_fixture("change-register.json"),
            deletion_fixture("branch-protection-snapshot.json"),
        )

    def test_normalizes_exact_reviewed_force_push_change(self) -> None:
        output = normalizer.normalize(*self.sources())
        change = output["changes"][0]
        self.assertEqual(change["service"], "scm")
        self.assertEqual(change["change_type"], "branch-protection")
        self.assertEqual(change["target"]["type"], "github-legacy-branch-protection")
        self.assertEqual(
            change["request"]["after_digest"],
            "sha256:e103bcfa19e7050dedef1de034933d25c290ceb396980f3c12c513152f0a50ab",
        )
        serialized = json.dumps(output)
        self.assertNotIn("allow_force_pushes", serialized)
        self.assertNotIn("github-request-557", serialized)

    def test_numeric_enabled_levels_are_bound_to_enabled_current_state(self) -> None:
        for level in (1, 2):
            with self.subTest(level=level):
                audit, sessions, register, snapshot = self.sources()
                audit["events"][0]["allow_force_pushes_enforcement_level"] = level
                snapshot["protection"]["allow_force_pushes"] = True
                change = register["changes"][0]
                change["before_allow_force_pushes"] = False
                change["before_digest"] = (
                    "sha256:e103bcfa19e7050dedef1de034933d25c290ceb396980f3c12c513152f0a50ab"
                )
                change["after_digest"] = (
                    "sha256:843c4302bec6591ec443046f7cfb2dfd782be674bf0cf2351aaee7bd3691059e"
                )
                change["approvals"][0]["after_digest"] = change["after_digest"]
                output = normalizer.normalize(audit, sessions, register, snapshot)
                self.assertEqual(
                    output["changes"][0]["request"]["after_digest"],
                    change["after_digest"],
                )

    def test_normalizes_exact_reviewed_admin_enforcement_change(self) -> None:
        output = normalizer.normalize(*self.admin_sources())
        change = output["changes"][0]
        self.assertEqual(change["service"], "scm")
        self.assertEqual(
            change["request"]["after_digest"],
            "sha256:83a2f6dbea6bf9686e15a51b0da5f839399b8ecbf32c2f1d2a2231abae196d2b",
        )
        serialized = json.dumps(output)
        self.assertNotIn("enforce_admins", serialized)
        self.assertNotIn("github-request-559", serialized)

    def test_admin_enforcement_substitution_or_later_update_fails_closed(self) -> None:
        audit, sessions, register, snapshot = self.admin_sources()
        snapshot["protection"]["enforce_admins"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "event target state"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.admin_sources()
        later = copy.deepcopy(audit["events"][0])
        later["_document_id"] = "audit-doc-560"
        later["request_id"] = "github-request-560"
        later["@timestamp"] = "2026-08-12T03:32:30Z"
        later["admin_enforced"] = False
        audit["events"].append(later)
        audit["collection"]["raw_events"] = 2
        audit["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later update"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_normalizes_exact_reviewed_code_owner_review_change(self) -> None:
        output = normalizer.normalize(*self.code_owner_sources())
        change = output["changes"][0]
        self.assertEqual(change["service"], "scm")
        self.assertEqual(
            change["request"]["after_digest"],
            "sha256:b397c3ec49913ace0cedab62a80fafb38eae777671ae835ce0f74e12f1a12ac4",
        )
        serialized = json.dumps(output)
        self.assertNotIn("require_code_owner_reviews", serialized)
        self.assertNotIn("github-request-561", serialized)

    def test_code_owner_review_substitution_or_later_update_fails_closed(self) -> None:
        audit, sessions, register, snapshot = self.code_owner_sources()
        snapshot["protection"]["require_code_owner_reviews"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "event target state"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.code_owner_sources()
        later = copy.deepcopy(audit["events"][0])
        later["_document_id"] = "audit-doc-562"
        later["request_id"] = "github-request-562"
        later["@timestamp"] = "2026-08-12T03:35:30Z"
        later["require_code_owner_review"] = False
        audit["events"].append(later)
        audit["collection"]["raw_events"] = 2
        audit["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later update"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_normalizes_exact_reviewed_branch_deletion_change(self) -> None:
        output = normalizer.normalize(*self.deletion_sources())
        change = output["changes"][0]
        self.assertEqual(change["service"], "scm")
        self.assertEqual(
            change["request"]["after_digest"],
            "sha256:2df853d6179169b889cf899cd0f138342a164f8bda8dae4660bf4a55c01e9a2b",
        )
        serialized = json.dumps(output)
        self.assertNotIn("allow_deletions", serialized)
        self.assertNotIn("github-request-563", serialized)

    def test_branch_deletion_substitution_or_later_update_fails_closed(self) -> None:
        audit, sessions, register, snapshot = self.deletion_sources()
        snapshot["protection"]["allow_deletions"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "event target state"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.deletion_sources()
        later = copy.deepcopy(audit["events"][0])
        later["_document_id"] = "audit-doc-564"
        later["request_id"] = "github-request-564"
        later["@timestamp"] = "2026-08-12T03:38:30Z"
        later["allow_deletions_enforcement_level"] = 0
        audit["events"].append(later)
        audit["collection"]["raw_events"] = 2
        audit["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later update"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_repository_branch_and_current_state_substitution_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.sources()
        snapshot["repository"]["id"] = 19002
        with self.assertRaisesRegex(normalizer.NormalizationError, "event target state"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.sources()
        snapshot["branch"]["name"] = "release"
        snapshot["collection"]["protection_endpoint"] = (
            "https://api.github.com/repos/example-org/product-api/branches/release/protection"
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "event target state"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.sources()
        snapshot["protection"]["allow_force_pushes"] = True
        with self.assertRaisesRegex(normalizer.NormalizationError, "event target state"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_session_and_digest_substitution_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.sources()
        sessions["sessions"][0]["github_actor_id"] = 17022
        with self.assertRaisesRegex(normalizer.NormalizationError, "human session join"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.sources()
        register["changes"][0]["after_digest"] = (
            "sha256:" + "0" * 64
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "setting digests"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_stale_or_later_state_is_ambiguous(self) -> None:
        audit, sessions, register, snapshot = self.sources()
        snapshot["collected_at"] = "2026-08-12T03:36:00Z"
        audit["collection"]["window_end"] = "2026-08-12T03:36:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "snapshot time"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.sources()
        later = copy.deepcopy(audit["events"][0])
        later["_document_id"] = "audit-doc-558"
        later["request_id"] = "github-request-558"
        later["@timestamp"] = "2026-08-12T03:30:30Z"
        later["allow_force_pushes_enforcement_level"] = 1
        audit["events"].append(later)
        audit["collection"]["raw_events"] = 2
        audit["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later update"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_incomplete_or_sensitive_evidence_fails_closed(self) -> None:
        audit, sessions, register, snapshot = self.sources()
        snapshot["complete"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "incomplete"):
            normalizer.normalize(audit, sessions, register, snapshot)

        audit, sessions, register, snapshot = self.sources()
        audit["events"][0]["hashed_token"] = "SYNTHETIC_TEST_VALUE_DO_NOT_USE"
        with self.assertRaisesRegex(normalizer.NormalizationError, "forbidden field"):
            normalizer.normalize(audit, sessions, register, snapshot)

    def test_atomic_writer_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_text("preserve", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(normalizer.NormalizationError, "symlink"):
                normalizer.write_output(link, {"complete": True})
            self.assertEqual(real.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
