from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
SCRIPT = CONTROL / "scripts" / "normalize_github_ruleset.py"
SPEC = importlib.util.spec_from_file_location("normalize_github_ruleset", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def fixture(name: str):
    return json.loads((CONTROL / "secure" / "github-scm" / name).read_text(encoding="utf-8"))


def organization_fixture(name: str):
    return json.loads(
        (CONTROL / "secure" / "github-org-scm" / name).read_text(encoding="utf-8")
    )


def tag_fixture(name: str):
    return json.loads(
        (CONTROL / "secure" / "github-tag-scm" / name).read_text(encoding="utf-8")
    )


def push_fixture(name: str):
    return json.loads(
        (CONTROL / "secure" / "github-push-scm" / name).read_text(encoding="utf-8")
    )


class GithubRulesetNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            fixture("audit-events.json"),
            fixture("identity-sessions.json"),
            fixture("change-register.json"),
            fixture("ruleset-snapshot.json"),
        )

    def test_normalizes_one_secret_free_scm_change(self) -> None:
        output = normalizer.normalize(*self.inputs())
        self.assertEqual(output["collector"]["covered_services"], ["scm"])
        change = output["changes"][0]
        self.assertEqual(change["service"], "scm")
        self.assertEqual(change["change_type"], "branch-protection")
        self.assertEqual(change["target"]["type"], "github-repository-ruleset")
        self.assertEqual(
            change["target"]["id"],
            "github:repository:19001:ruleset:73@RRS_lADOPROTECTMAIN",
        )
        serialized = json.dumps(output)
        for forbidden in (
            "redacted-provider-token-identifier", "hashed_token", "user_agent",
            "bypass_actors", '"conditions"', '"rules"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_repository_session_and_history_actor_substitution_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        wrong_repository = copy.deepcopy(audit)
        wrong_repository["events"][0]["repository_id"] = 19002
        with self.assertRaisesRegex(normalizer.NormalizationError, "event source"):
            normalizer.normalize(wrong_repository, sessions, register, snapshot)

        wrong_session = copy.deepcopy(sessions)
        wrong_session["sessions"][0]["github_actor"] = "other-admin"
        with self.assertRaisesRegex(normalizer.NormalizationError, "identity history"):
            normalizer.normalize(audit, wrong_session, register, snapshot)

        wrong_actor = copy.deepcopy(snapshot)
        wrong_actor["ruleset"]["history"][0]["actor_id"] = 17022
        wrong_actor["ruleset"]["versions"][1]["actor_id"] = 17022
        with self.assertRaisesRegex(normalizer.NormalizationError, "identity history"):
            normalizer.normalize(audit, sessions, register, wrong_actor)

    def test_history_tampering_later_version_and_stale_state_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        tampered = copy.deepcopy(snapshot)
        tampered["ruleset"]["versions"][1]["state"]["rules"][0]["parameters"][
            "required_approving_review_count"
        ] = 1
        with self.assertRaisesRegex(normalizer.NormalizationError, "current state"):
            normalizer.normalize(audit, sessions, register, tampered)

        later = copy.deepcopy(snapshot)
        later["ruleset"]["history"].insert(
            0, {"version_id": 6, "actor_id": 17022, "updated_at": "2026-08-12T03:24:30Z"}
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "later version"):
            normalizer.normalize(audit, sessions, register, later)

        stale = copy.deepcopy(snapshot)
        stale["collected_at"] = "2026-08-12T03:30:00Z"
        covering = copy.deepcopy(audit)
        covering["collection"]["window_end"] = "2026-08-12T03:31:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "snapshot time"):
            normalizer.normalize(covering, sessions, register, stale)

        recreated = copy.deepcopy(snapshot)
        recreated["ruleset"]["versions"][1]["state"]["created_at"] = (
            "2026-08-01T00:00:00Z"
        )
        recreated["ruleset"]["current"]["created_at"] = "2026-08-01T00:00:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "timestamps or generation"):
            normalizer.normalize(audit, sessions, register, recreated)

    def test_register_digest_partial_and_audit_delta_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        wrong_digest = copy.deepcopy(register)
        wrong_digest["changes"][0]["after_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(normalizer.NormalizationError, "history digests"):
            normalizer.normalize(audit, sessions, wrong_digest, snapshot)

        partial = copy.deepcopy(audit)
        partial["collection"]["pagination_complete"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "receipt"):
            normalizer.normalize(partial, sessions, register, snapshot)

        delta = copy.deepcopy(audit)
        delta["events"][0]["ruleset_enforcement"] = "disabled"
        with self.assertRaisesRegex(normalizer.NormalizationError, "audit delta"):
            normalizer.normalize(delta, sessions, register, snapshot)

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


class GithubOrganizationRulesetNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            organization_fixture("audit-events.json"),
            organization_fixture("identity-sessions.json"),
            organization_fixture("change-register.json"),
            organization_fixture("ruleset-snapshot.json"),
        )

    def test_normalizes_one_secret_free_organization_scm_change(self) -> None:
        output = normalizer.normalize(*self.inputs())
        change = output["changes"][0]
        self.assertEqual(change["service"], "scm")
        self.assertEqual(change["target"]["type"], "github-organization-ruleset")
        self.assertEqual(
            change["target"]["id"],
            "github:organization:88001:ruleset:74@RRS_lAOrganizationProtect",
        )
        serialized = json.dumps(output)
        for forbidden in (
            "redacted-provider-token-identifier", "hashed_token", "user_agent",
            "bypass_actors", '"conditions"', '"rules"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_normalizes_organization_tag_update_as_tag_protection(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        changed = copy.deepcopy(snapshot)
        for version in changed["ruleset"]["versions"]:
            version["state"]["target"] = "tag"
        changed["ruleset"]["current"]["target"] = "tag"

        def state_digest(value):
            canonical = json.dumps(
                value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            return "sha256:" + hashlib.sha256(canonical).hexdigest()

        reviewed = copy.deepcopy(register)
        before = state_digest(changed["ruleset"]["versions"][0]["state"])
        after = state_digest(changed["ruleset"]["versions"][1]["state"])
        reviewed["changes"][0]["ruleset_target"] = "tag"
        reviewed["changes"][0]["before_digest"] = before
        reviewed["changes"][0]["after_digest"] = after
        reviewed["changes"][0]["approvals"][0]["after_digest"] = after

        output = normalizer.normalize(audit, sessions, reviewed, changed)
        self.assertEqual(output["changes"][0]["change_type"], "tag-protection")

    def test_org_identity_substitution_and_repository_contamination_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        wrong_org = copy.deepcopy(audit)
        wrong_org["events"][0]["org_id"] = 88002
        with self.assertRaisesRegex(normalizer.NormalizationError, "event source"):
            normalizer.normalize(wrong_org, sessions, register, snapshot)

        contaminated = copy.deepcopy(audit)
        contaminated["events"][0]["repo"] = "example-org/product-api"
        contaminated["events"][0]["repository_id"] = 19001
        with self.assertRaisesRegex(normalizer.NormalizationError, "event source"):
            normalizer.normalize(contaminated, sessions, register, snapshot)

        wrong_register = copy.deepcopy(register)
        wrong_register["changes"][0]["organization_node_id"] = "O_substituted"
        with self.assertRaisesRegex(normalizer.NormalizationError, "organization identity"):
            normalizer.normalize(audit, sessions, wrong_register, snapshot)

    def test_later_version_and_history_actor_substitution_fail_closed(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        later = copy.deepcopy(snapshot)
        later["ruleset"]["history"].insert(
            0, {"version_id": 10, "actor_id": 17023, "updated_at": "2026-08-12T03:27:30Z"}
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "later version"):
            normalizer.normalize(audit, sessions, register, later)

        wrong_actor = copy.deepcopy(snapshot)
        wrong_actor["ruleset"]["history"][0]["actor_id"] = 17023
        wrong_actor["ruleset"]["versions"][1]["actor_id"] = 17023
        with self.assertRaisesRegex(normalizer.NormalizationError, "identity history"):
            normalizer.normalize(audit, sessions, register, wrong_actor)


class GithubTagRulesetNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            tag_fixture("audit-events.json"),
            tag_fixture("identity-sessions.json"),
            tag_fixture("change-register.json"),
            tag_fixture("ruleset-snapshot.json"),
        )

    def test_normalizes_tag_update_as_tag_protection(self) -> None:
        output = normalizer.normalize(*self.inputs())
        change = output["changes"][0]
        self.assertEqual(change["change_type"], "tag-protection")
        self.assertEqual(change["target"]["type"], "github-repository-ruleset")

    def test_reviewed_target_substitution_fails_closed(self) -> None:
        audit, sessions, register, snapshot = self.inputs()
        substituted = copy.deepcopy(register)
        substituted["changes"][0]["ruleset_target"] = "branch"
        with self.assertRaisesRegex(normalizer.NormalizationError, "history digests"):
            normalizer.normalize(audit, sessions, substituted, snapshot)

        unsupported = copy.deepcopy(snapshot)
        for version in unsupported["ruleset"]["versions"]:
            version["state"]["target"] = "push"
        unsupported["ruleset"]["current"]["target"] = "push"
        with self.assertRaisesRegex(normalizer.NormalizationError, "fork-network snapshot"):
            normalizer.normalize(audit, sessions, register, unsupported)

        mixed = copy.deepcopy(snapshot)
        mixed["ruleset"]["versions"][0]["state"]["target"] = "branch"
        with self.assertRaisesRegex(normalizer.NormalizationError, "target changed"):
            normalizer.normalize(audit, sessions, register, mixed)


class GithubPushRulesetNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            push_fixture("audit-events.json"),
            push_fixture("identity-sessions.json"),
            push_fixture("change-register.json"),
            push_fixture("ruleset-snapshot.json"),
            push_fixture("fork-network-snapshot.json"),
        )

    def test_normalizes_push_update_with_exact_network_scope(self) -> None:
        output = normalizer.normalize(*self.inputs())
        change = output["changes"][0]
        self.assertEqual(change["change_type"], "push-protection")
        self.assertIn(":network@sha256:", change["target"]["id"])
        serialized = json.dumps(output)
        self.assertNotIn("partner-org/product-api-review", serialized)
        self.assertNotIn('"forks"', serialized)

    def test_missing_partial_and_wrong_root_network_fail_closed(self) -> None:
        audit, sessions, register, snapshot, network = self.inputs()
        with self.assertRaisesRegex(normalizer.NormalizationError, "lacks a supported"):
            normalizer.normalize(audit, sessions, register, snapshot)

        partial = copy.deepcopy(network)
        partial["complete"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "incomplete"):
            normalizer.normalize(audit, sessions, register, snapshot, partial)

        wrong_root = copy.deepcopy(network)
        wrong_root["root"]["id"] = 19002
        with self.assertRaisesRegex(normalizer.NormalizationError, "root identity"):
            normalizer.normalize(audit, sessions, register, snapshot, wrong_root)

    def test_network_tampering_stale_and_organization_push_fail_closed(self) -> None:
        audit, sessions, register, snapshot, network = self.inputs()
        tampered = copy.deepcopy(network)
        tampered["forks"][0]["node_id"] = "R_substituted"
        with self.assertRaisesRegex(normalizer.NormalizationError, "network identity"):
            normalizer.normalize(audit, sessions, register, snapshot, tampered)

        stale = copy.deepcopy(network)
        stale["collected_at"] = "2026-08-12T03:41:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "snapshot time"):
            normalizer.normalize(audit, sessions, register, snapshot, stale)

        org_audit = organization_fixture("audit-events.json")
        org_sessions = organization_fixture("identity-sessions.json")
        org_register = organization_fixture("change-register.json")
        org_snapshot = organization_fixture("ruleset-snapshot.json")
        for version in org_snapshot["ruleset"]["versions"]:
            version["state"]["target"] = "push"
        org_snapshot["ruleset"]["current"]["target"] = "push"
        with self.assertRaisesRegex(normalizer.NormalizationError, "organization push"):
            normalizer.normalize(org_audit, org_sessions, org_register, org_snapshot, network)


if __name__ == "__main__":
    unittest.main()
