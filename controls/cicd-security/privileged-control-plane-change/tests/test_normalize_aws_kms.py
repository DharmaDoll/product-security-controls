from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
SCRIPT = CONTROL / "scripts" / "normalize_aws_kms.py"
SPEC = importlib.util.spec_from_file_location("normalize_aws_kms", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def fixture(name: str):
    return json.loads((CONTROL / "secure" / "aws-kms" / name).read_text(encoding="utf-8"))


class AwsKmsPolicyNormalizerTest(unittest.TestCase):
    def inputs(self):
        return (
            fixture("cloudtrail-events.json"),
            fixture("identity-sessions.json"),
            fixture("change-register.json"),
            fixture("keys.json"),
        )

    def test_normalizes_one_secret_free_signing_change(self) -> None:
        output = normalizer.normalize(*self.inputs())
        self.assertEqual(output["collector"]["covered_services"], ["signing-service"])
        self.assertEqual(len(output["changes"]), 1)
        change = output["changes"][0]
        self.assertEqual(change["service"], "signing-service")
        self.assertEqual(change["change_type"], "signing-policy")
        self.assertEqual(change["target"]["type"], "aws-kms-signing-key-policy")
        self.assertEqual(
            change["target"]["id"],
            "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        )
        serialized = json.dumps(output)
        for forbidden in (
            "REDACTED-SYNTHETIC-NOT-A-CREDENTIAL",
            "accessKeyId",
            "sourceIPAddress",
            "userAgent",
            "key_policy",
            "Statement",
            "Principal",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_identity_and_key_substitution_fail_closed(self) -> None:
        cloudtrail, sessions, register, keys = self.inputs()
        substituted = copy.deepcopy(cloudtrail)
        substituted["events"][0]["userIdentity"]["sessionContext"][
            "sourceIdentity"
        ] = "other-user"
        with self.assertRaisesRegex(normalizer.NormalizationError, "attributed session"):
            normalizer.normalize(substituted, sessions, register, keys)

        wrong_key = copy.deepcopy(register)
        wrong_key["changes"][0]["key_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with self.assertRaisesRegex(normalizer.NormalizationError, "one signing key policy"):
            normalizer.normalize(cloudtrail, sessions, wrong_key, keys)

    def test_policy_tampering_ineffective_policy_and_bypass_fail_closed(self) -> None:
        cloudtrail, sessions, register, keys = self.inputs()
        tampered = copy.deepcopy(keys)
        tampered["keys"][0]["configuration"]["key_policy"]["Statement"][1][
            "Principal"
        ]["AWS"] = "*"
        with self.assertRaisesRegex(normalizer.NormalizationError, "digests do not match"):
            normalizer.normalize(cloudtrail, sessions, register, tampered)

        ineffective = copy.deepcopy(cloudtrail)
        ineffective["events"][0]["requestParameters"]["policy"]["Statement"][1].pop(
            "Resource"
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "ineffective statement"):
            normalizer.normalize(ineffective, sessions, register, keys)

        bypass = copy.deepcopy(cloudtrail)
        bypass["events"][0]["requestParameters"]["bypassPolicyLockoutSafetyCheck"] = True
        bypass_register = copy.deepcopy(register)
        bypass_register["changes"][0]["bypass_policy_lockout_safety_check"] = True
        with self.assertRaisesRegex(normalizer.NormalizationError, "separate emergency adapter"):
            normalizer.normalize(bypass, sessions, bypass_register, keys)

    def test_wrong_key_purpose_stale_snapshot_and_later_update_fail_closed(self) -> None:
        cloudtrail, sessions, register, keys = self.inputs()
        encrypt_key = copy.deepcopy(keys)
        encrypt_key["keys"][0]["configuration"]["key_usage"] = "ENCRYPT_DECRYPT"
        with self.assertRaisesRegex(normalizer.NormalizationError, "identity state"):
            normalizer.normalize(cloudtrail, sessions, register, encrypt_key)

        stale = copy.deepcopy(keys)
        stale["collected_at"] = "2026-08-12T04:00:00Z"
        covering = copy.deepcopy(cloudtrail)
        covering["collection"]["window_end"] = "2026-08-12T04:01:00Z"
        with self.assertRaisesRegex(normalizer.NormalizationError, "stale"):
            normalizer.normalize(covering, sessions, register, stale)

        ambiguous = copy.deepcopy(cloudtrail)
        later = copy.deepcopy(ambiguous["events"][0])
        later["eventID"] = "6ed0ce32-3fcb-48e8-8131-3faf7078f097"
        later["requestID"] = "c5dc21ca-d760-4dbc-90a8-d68b40a5f390"
        later["eventTime"] = "2026-08-12T03:54:30Z"
        ambiguous["events"].append(later)
        ambiguous["collection"]["selected_events"] = 2
        with self.assertRaisesRegex(normalizer.NormalizationError, "later policy update"):
            normalizer.normalize(ambiguous, sessions, register, keys)

    def test_partial_failed_event_and_missing_session_fail_closed(self) -> None:
        cloudtrail, sessions, register, keys = self.inputs()
        partial = copy.deepcopy(cloudtrail)
        partial["collection"]["pagination_complete"] = False
        with self.assertRaisesRegex(normalizer.NormalizationError, "receipt"):
            normalizer.normalize(partial, sessions, register, keys)

        failed = copy.deepcopy(cloudtrail)
        failed["events"][0]["errorCode"] = "AccessDeniedException"
        with self.assertRaisesRegex(normalizer.NormalizationError, "unsuccessful"):
            normalizer.normalize(failed, sessions, register, keys)

        missing = copy.deepcopy(sessions)
        missing["sessions"] = []
        with self.assertRaisesRegex(normalizer.NormalizationError, "exact session"):
            normalizer.normalize(cloudtrail, missing, register, keys)

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
