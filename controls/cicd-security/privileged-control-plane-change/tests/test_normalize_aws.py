from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
SCRIPT = CONTROL / "scripts" / "normalize_aws.py"
SPEC = importlib.util.spec_from_file_location("normalize_aws", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def fixture(name: str):
    return json.loads((CONTROL / "secure" / "aws" / name).read_text(encoding="utf-8"))


class AwsTrustPolicyNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            fixture("cloudtrail-events.json"),
            fixture("identity-sessions.json"),
            fixture("change-register.json"),
            fixture("iam-roles.json"),
        )

    def test_normalizes_one_secret_free_cloud_identity_change(self) -> None:
        output = normalizer.normalize(*self.inputs())
        self.assertEqual(output["collector"]["covered_services"], ["cloud-identity"])
        self.assertTrue(output["collector"]["complete"])
        self.assertEqual(len(output["changes"]), 1)
        change = output["changes"][0]
        self.assertEqual(change["service"], "cloud-identity")
        self.assertEqual(change["change_type"], "federated-trust-policy")
        self.assertEqual(
            change["target"]["id"], "111122223333:role:AROARELEASEPROD0001"
        )
        serialized = json.dumps(output)
        for forbidden in (
            "REDACTED-SYNTHETIC-NOT-A-CREDENTIAL",
            "accessKeyId",
            "sourceIPAddress",
            "userAgent",
            "policyDocument",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_identity_substitution_and_missing_session_fail_closed(self) -> None:
        cloudtrail, sessions, register, roles = self.inputs()
        substituted = copy.deepcopy(cloudtrail)
        substituted["events"][0]["userIdentity"]["sessionContext"][
            "sourceIdentity"
        ] = "other-user"
        with self.assertRaisesRegex(normalizer.NormalizationError, "attributed session"):
            normalizer.normalize(substituted, sessions, register, roles)

        missing = copy.deepcopy(sessions)
        missing["sessions"] = []
        with self.assertRaisesRegex(normalizer.NormalizationError, "exact session"):
            normalizer.normalize(cloudtrail, missing, register, roles)

    def test_stable_role_id_and_policy_tampering_fail_closed(self) -> None:
        cloudtrail, sessions, register, roles = self.inputs()
        wrong_role = copy.deepcopy(roles)
        wrong_role["roles"][0]["configuration"]["role_id"] = "AROAOTHERROLE000001"
        with self.assertRaisesRegex(normalizer.NormalizationError, "identity or receipt"):
            normalizer.normalize(cloudtrail, sessions, register, wrong_role)

        tampered = copy.deepcopy(roles)
        tampered["roles"][0]["configuration"]["assume_role_policy_document"][
            "Statement"
        ][0]["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:sub"
        ] = "repo:example-org/*"
        with self.assertRaisesRegex(normalizer.NormalizationError, "digests do not match"):
            normalizer.normalize(cloudtrail, sessions, register, tampered)

    def test_stale_snapshot_and_later_update_fail_closed(self) -> None:
        cloudtrail, sessions, register, roles = self.inputs()
        stale = copy.deepcopy(roles)
        stale["collected_at"] = "2026-08-12T03:50:00Z"
        covering_cloudtrail = copy.deepcopy(cloudtrail)
        covering_cloudtrail["collection"]["window_end"] = "2026-08-12T03:51:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "stale"):
            normalizer.normalize(covering_cloudtrail, sessions, register, stale)

        ambiguous = copy.deepcopy(cloudtrail)
        later = copy.deepcopy(ambiguous["events"][0])
        later["eventID"] = "2ed0ce32-3fcb-48e8-8131-3faf7078f093"
        later["requestID"] = "54dc21ca-d760-4dbc-90a8-d68b40a5f383"
        later["eventTime"] = "2026-08-12T03:44:30Z"
        ambiguous["events"].append(later)
        ambiguous["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later trust update"):
            normalizer.normalize(ambiguous, sessions, register, roles)

    def test_collection_failure_and_error_event_fail_closed(self) -> None:
        cloudtrail, sessions, register, roles = self.inputs()
        partial = copy.deepcopy(cloudtrail)
        partial["collection"]["pagination_complete"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "receipt"):
            normalizer.normalize(partial, sessions, register, roles)

        failed = copy.deepcopy(cloudtrail)
        failed["events"][0]["errorCode"] = "AccessDenied"
        with self.assertRaisesRegex(normalizer.NormalizationError, "unsuccessful"):
            normalizer.normalize(failed, sessions, register, roles)

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
