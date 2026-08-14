from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
SCRIPT = CONTROL / "scripts" / "normalize_aws_ecr.py"
SPEC = importlib.util.spec_from_file_location("normalize_aws_ecr", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def fixture(name: str):
    return json.loads((CONTROL / "secure" / "aws-ecr" / name).read_text(encoding="utf-8"))


class AwsEcrPolicyNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            fixture("cloudtrail-events.json"),
            fixture("identity-sessions.json"),
            fixture("change-register.json"),
            fixture("repositories.json"),
        )

    def test_normalizes_one_secret_free_registry_change(self) -> None:
        output = normalizer.normalize(*self.inputs())
        self.assertEqual(output["collector"]["covered_services"], ["artifact-registry"])
        self.assertEqual(len(output["changes"]), 1)
        change = output["changes"][0]
        self.assertEqual(change["service"], "artifact-registry")
        self.assertEqual(change["change_type"], "registry-protection")
        self.assertEqual(
            change["target"]["id"],
            "arn:aws:ecr:us-east-1:111122223333:repository/product-api@2026-07-01T00:00:00Z",
        )
        serialized = json.dumps(output)
        for forbidden in (
            "REDACTED-SYNTHETIC-NOT-A-CREDENTIAL",
            "accessKeyId",
            "sourceIPAddress",
            "userAgent",
            "policyText",
            "repository_policy",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_identity_and_repository_generation_substitution_fail_closed(self) -> None:
        cloudtrail, sessions, register, repositories = self.inputs()
        substituted = copy.deepcopy(cloudtrail)
        substituted["events"][0]["userIdentity"]["sessionContext"][
            "sourceIdentity"
        ] = "other-user"
        with self.assertRaisesRegex(normalizer.NormalizationError, "attributed session"):
            normalizer.normalize(substituted, sessions, register, repositories)

        recreated = copy.deepcopy(repositories)
        recreated["repositories"][0]["configuration"]["created_at"] = (
            "2026-08-01T00:00:00Z"
        )
        recreated["collection"]["created_at"] = "2026-08-01T00:00:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "one repository generation"):
            normalizer.normalize(cloudtrail, sessions, register, recreated)

    def test_policy_tampering_and_forced_change_fail_closed(self) -> None:
        cloudtrail, sessions, register, repositories = self.inputs()
        tampered = copy.deepcopy(repositories)
        tampered["repositories"][0]["configuration"]["repository_policy"][
            "Statement"
        ][0]["Principal"]["AWS"] = "*"
        with self.assertRaisesRegex(normalizer.NormalizationError, "digests do not match"):
            normalizer.normalize(cloudtrail, sessions, register, tampered)

        forced = copy.deepcopy(cloudtrail)
        forced["events"][0]["requestParameters"]["force"] = True
        forced_register = copy.deepcopy(register)
        forced_register["changes"][0]["force"] = True
        with self.assertRaisesRegex(normalizer.NormalizationError, "separate emergency adapter"):
            normalizer.normalize(forced, sessions, forced_register, repositories)

    def test_stale_snapshot_and_later_update_fail_closed(self) -> None:
        cloudtrail, sessions, register, repositories = self.inputs()
        stale = copy.deepcopy(repositories)
        stale["collected_at"] = "2026-08-12T03:55:00Z"
        covering = copy.deepcopy(cloudtrail)
        covering["collection"]["window_end"] = "2026-08-12T03:56:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "stale"):
            normalizer.normalize(covering, sessions, register, stale)

        ambiguous = copy.deepcopy(cloudtrail)
        later = copy.deepcopy(ambiguous["events"][0])
        later["eventID"] = "4ed0ce32-3fcb-48e8-8131-3faf7078f095"
        later["requestID"] = "74dc21ca-d760-4dbc-90a8-d68b40a5f385"
        later["eventTime"] = "2026-08-12T03:49:30Z"
        ambiguous["events"].append(later)
        ambiguous["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later policy update"):
            normalizer.normalize(ambiguous, sessions, register, repositories)

    def test_partial_collection_failed_event_and_missing_session_fail_closed(self) -> None:
        cloudtrail, sessions, register, repositories = self.inputs()
        partial = copy.deepcopy(cloudtrail)
        partial["collection"]["pagination_complete"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "receipt"):
            normalizer.normalize(partial, sessions, register, repositories)

        failed = copy.deepcopy(cloudtrail)
        failed["events"][0]["errorCode"] = "AccessDeniedException"
        with self.assertRaisesRegex(normalizer.NormalizationError, "unsuccessful"):
            normalizer.normalize(failed, sessions, register, repositories)

        missing = copy.deepcopy(sessions)
        missing["sessions"] = []
        with self.assertRaisesRegex(normalizer.NormalizationError, "exact session"):
            normalizer.normalize(cloudtrail, missing, register, repositories)

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
