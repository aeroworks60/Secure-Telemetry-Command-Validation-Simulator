"""HMAC authentication tests: tag generation/verification, serialization, key handling,
and proof that authentication stays separate from authorization, freshness and replay checks."""
import hmac
import json
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from unittest import mock

import auth
from auth import (
    DEV_KEY, MALFORMED_TAG, MISSING_TAG, NOT_CHECKED, SIGNED_FIELDS, TAG_FIELD, TAG_MISMATCH, VALID,
    HmacAuthenticator, canonical_bytes, load_authenticator_from_env,
)
from runtime import SentinelRuntime
from validator import REQUIRED_FIELDS, SentinelValidator

KEY = b"unit-test-shared-secret-0001"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
STAMP = "2026-10-16T12:00:00Z"


def telemetry(message_id="T-1", seq=10, battery=80, stamp=STAMP):
    return {
        "message_id": message_id, "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": seq, "message_type": "TELEMETRY", "sender_role": "satellite",
        "payload": {"battery_pct": battery, "temperature_c": 21, "altitude_km": 550},
    }


class SerializationTests(unittest.TestCase):
    def test_signed_fields_are_exactly_the_required_fields_and_exclude_the_tag(self):
        self.assertEqual(set(SIGNED_FIELDS), set(REQUIRED_FIELDS))
        self.assertNotIn(TAG_FIELD, SIGNED_FIELDS)

    def test_tag_field_never_changes_the_signed_bytes(self):
        message = telemetry()
        self.assertEqual(canonical_bytes(message), canonical_bytes({**message, TAG_FIELD: "anything"}))

    def test_key_order_and_whitespace_do_not_change_the_signed_bytes(self):
        message = telemetry()
        reordered = dict(reversed(list(message.items())))
        reparsed = json.loads(json.dumps(message, indent=4))
        self.assertEqual(canonical_bytes(message), canonical_bytes(reordered))
        self.assertEqual(canonical_bytes(message), canonical_bytes(reparsed))

    def test_bytes_are_ascii_and_domain_separated(self):
        data = canonical_bytes(telemetry())
        self.assertTrue(data.startswith(auth.DOMAIN_PREFIX))
        data.decode("ascii")


class AuthenticatorTests(unittest.TestCase):
    def setUp(self):
        self.auth = HmacAuthenticator(KEY)
        self.signed = self.auth.sign(telemetry())

    def test_valid_tag_verifies(self):
        result = self.auth.verify(self.signed)
        self.assertTrue(result.ok)
        self.assertEqual(result.status, VALID)

    def test_tag_is_64_lowercase_hex_and_deterministic(self):
        tag = self.signed[TAG_FIELD]
        self.assertRegex(tag, r"^[0-9a-f]{64}$")
        self.assertEqual(tag, self.auth.generate_tag(telemetry()))

    def test_sign_does_not_mutate_input_and_replaces_old_tag(self):
        original = telemetry()
        original[TAG_FIELD] = "0" * 64
        copy = deepcopy(original)
        signed = self.auth.sign(original)
        self.assertEqual(original, copy)
        self.assertNotEqual(signed[TAG_FIELD], "0" * 64)
        self.assertTrue(self.auth.verify(signed).ok)

    def test_changing_any_signed_field_invalidates_the_original_tag(self):
        changes = {
            "message_id": "T-2", "satellite_id": "SAT-BETA", "timestamp": "2026-10-16T12:00:01Z",
            "sequence_number": 11, "message_type": "COMMAND", "sender_role": "viewer",
            "payload": {"battery_pct": 81, "temperature_c": 21, "altitude_km": 550},
        }
        self.assertEqual(set(changes), set(SIGNED_FIELDS))
        for field, new_value in changes.items():
            with self.subTest(field=field):
                tampered = deepcopy(self.signed)
                tampered[field] = new_value
                result = self.auth.verify(tampered)
                self.assertFalse(result.ok)
                self.assertEqual(result.status, TAG_MISMATCH)

    def test_removing_a_signed_field_invalidates_the_tag(self):
        tampered = deepcopy(self.signed)
        del tampered["payload"]
        self.assertEqual(self.auth.verify(tampered).status, TAG_MISMATCH)

    def test_nested_payload_change_invalidates_the_tag(self):
        tampered = deepcopy(self.signed)
        tampered["payload"]["altitude_km"] = 551
        self.assertEqual(self.auth.verify(tampered).status, TAG_MISMATCH)

    def test_incorrect_key_is_rejected(self):
        other = HmacAuthenticator(b"a-completely-different-key-99")
        self.assertEqual(other.verify(self.signed).status, TAG_MISMATCH)
        self.assertNotEqual(other.generate_tag(telemetry()), self.signed[TAG_FIELD])

    def test_mismatch_message_admits_it_cannot_tell_tampering_from_wrong_key(self):
        detail = self.auth.verify({**self.signed, "message_id": "X"}).detail
        self.assertIn("changed after signing", detail)
        self.assertIn("different key", detail)

    def test_missing_tag(self):
        result = self.auth.verify(telemetry())
        self.assertEqual((result.status, result.ok), (MISSING_TAG, False))

    def test_malformed_tags(self):
        valid = self.signed[TAG_FIELD]
        bad_values = ["", "abc", valid[:-1], valid + "0", valid.upper(), "g" * 64, valid[:63] + "\n",
                      valid + "\n", 12345, None, ["a"], {"x": 1}, True]
        for value in bad_values:
            with self.subTest(value=value):
                result = self.auth.verify({**telemetry(), TAG_FIELD: value})
                self.assertEqual((result.status, result.ok), (MALFORMED_TAG, False))

    def test_non_ascii_tag_is_malformed_not_a_crash(self):
        self.assertEqual(self.auth.verify({**telemetry(), TAG_FIELD: "é" * 64}).status, MALFORMED_TAG)

    def test_compare_digest_is_used_for_tag_comparison(self):
        with mock.patch("auth.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            self.assertTrue(self.auth.verify(self.signed).ok)
            spy.assert_called_once()
            self.assertEqual(spy.call_args[0][1], self.signed[TAG_FIELD])

    def test_no_single_character_change_to_the_tag_verifies(self):
        tag = self.signed[TAG_FIELD]
        for i in range(len(tag)):
            replacement = "0" if tag[i] != "0" else "1"
            forged = {**self.signed, TAG_FIELD: tag[:i] + replacement + tag[i + 1:]}
            self.assertFalse(self.auth.verify(forged).ok, i)

    def test_repr_never_reveals_the_key(self):
        self.assertNotIn(KEY.decode(), repr(self.auth))
        self.assertNotIn(KEY.decode(), str(self.auth.verify(self.signed)))

    def test_weak_or_wrong_type_keys_are_refused(self):
        for bad in (b"short", "not-bytes-but-a-long-string", None):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    HmacAuthenticator(bad)


class KeyLoadingTests(unittest.TestCase):
    def test_environment_key_is_used_when_set(self):
        loaded = load_authenticator_from_env({auth.KEY_ENV_VAR: KEY.decode()})
        self.assertFalse(loaded.is_dev_key)
        self.assertEqual(loaded.key_source, auth.ENV_KEY_SOURCE)
        self.assertEqual(loaded.generate_tag(telemetry()), HmacAuthenticator(KEY).generate_tag(telemetry()))

    def test_missing_or_empty_env_falls_back_to_clearly_labelled_dev_key(self):
        for env in ({}, {auth.KEY_ENV_VAR: ""}):
            loaded = load_authenticator_from_env(env)
            self.assertTrue(loaded.is_dev_key)
            self.assertEqual(loaded.key_source, "development-demo")
            self.assertEqual(loaded.generate_tag(telemetry()), HmacAuthenticator(DEV_KEY).generate_tag(telemetry()))

    def test_weak_env_key_fails_closed_instead_of_falling_back(self):
        with self.assertRaises(ValueError):
            load_authenticator_from_env({auth.KEY_ENV_VAR: "tooshort"})


class SeparationFromOtherChecksTests(unittest.TestCase):
    """Authentication must not be conflated with authorization, freshness or replay checks."""

    def setUp(self):
        self.auth = HmacAuthenticator(KEY)
        self.validator = SentinelValidator(authenticator=self.auth, require_auth=True)

    def check(self, message):
        return self.validator.validate(message, now=NOW)

    def test_valid_signed_message_is_accepted_with_valid_authentication(self):
        result = self.check(self.auth.sign(telemetry()))
        self.assertTrue(result.accepted, result.reasons)
        self.assertEqual(result.authentication, VALID)

    def test_tampered_message_is_rejected_for_authentication_only(self):
        signed = self.auth.sign(telemetry())
        signed["payload"]["battery_pct"] = 81
        result = self.check(signed)
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, TAG_MISMATCH)
        self.assertEqual(len(result.reasons), 1)
        self.assertIn("Authentication failed", result.reasons[0])

    def test_unsigned_message_rejected_when_required(self):
        result = self.check(telemetry())
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, MISSING_TAG)

    def test_unsigned_message_allowed_when_optional_but_marked_not_checked(self):
        self.validator.require_auth = False
        result = self.check(telemetry())
        self.assertTrue(result.accepted, result.reasons)
        self.assertEqual(result.authentication, NOT_CHECKED)

    def test_bad_tag_is_rejected_even_when_authentication_is_optional(self):
        self.validator.require_auth = False
        for tag in ("not-hex", "0" * 64):
            with self.subTest(tag=tag):
                result = self.check({**telemetry(message_id=f"B-{tag[:3]}"), TAG_FIELD: tag})
                self.assertFalse(result.accepted)
                self.assertIn(result.authentication, (MALFORMED_TAG, TAG_MISMATCH))

    def test_wrong_key_signature_is_rejected(self):
        forged = HmacAuthenticator(b"attacker-wrong-key-123456").sign(telemetry())
        result = self.check(forged)
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, TAG_MISMATCH)

    def test_failed_authentication_does_not_consume_message_id_or_sequence(self):
        forged = {**telemetry("VICTIM-1", seq=500), TAG_FIELD: "0" * 64}
        self.assertFalse(self.check(forged).accepted)
        self.assertNotIn("VICTIM-1", self.validator.seen_message_ids)
        self.assertEqual(self.validator.last_accepted_sequence, {})
        legit = self.check(self.auth.sign(telemetry("VICTIM-1", seq=500)))
        self.assertTrue(legit.accepted, legit.reasons)

    def test_authentic_but_unauthorized_command_is_rejected_by_authorization_not_auth(self):
        message = self.auth.sign({
            "message_id": "C-1", "satellite_id": "SAT-ALPHA", "timestamp": STAMP, "sequence_number": 20,
            "message_type": "COMMAND", "sender_role": "viewer", "payload": {"command": "REBOOT_SENSOR"},
        })
        result = self.check(message)
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, VALID)
        self.assertTrue(any("not authorized" in r.lower() for r in result.reasons))

    def test_authentic_but_stale_message_is_rejected_by_freshness_not_auth(self):
        result = self.check(self.auth.sign(telemetry("S-1", stamp="2026-10-16T11:00:00Z")))
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, VALID)
        self.assertTrue(any("stale" in r.lower() for r in result.reasons))

    def test_authentic_but_future_message_is_rejected_by_freshness_not_auth(self):
        result = self.check(self.auth.sign(telemetry("F-1", stamp="2026-10-16T13:00:00Z")))
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, VALID)

    def test_authentic_replay_is_rejected_by_replay_checks_not_auth(self):
        signed = self.auth.sign(telemetry("R-1", seq=30))
        self.assertTrue(self.check(signed).accepted)
        replay = self.check(deepcopy(signed))
        self.assertFalse(replay.accepted)
        self.assertEqual(replay.authentication, VALID)
        self.assertTrue(any("Duplicate message_id" in r for r in replay.reasons))

    def test_authentic_out_of_range_telemetry_is_rejected_by_range_rule_not_auth(self):
        result = self.check(self.auth.sign(telemetry("O-1", battery=140)))
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, VALID)
        self.assertTrue(any("outside the allowed range" in r for r in result.reasons))

    def test_unsigned_extra_field_cannot_ride_along_with_a_valid_tag(self):
        message = self.auth.sign(telemetry("X-1"))
        message["debug_override"] = True  # not covered by the tag; schema check must still reject it
        result = self.check(message)
        self.assertFalse(result.accepted)
        self.assertEqual(result.authentication, VALID)
        self.assertTrue(any("Unexpected field" in r for r in result.reasons))

    def test_validator_without_an_authenticator_behaves_as_before(self):
        plain = SentinelValidator()
        result = plain.validate(telemetry(), now=NOW)
        self.assertTrue(result.accepted, result.reasons)
        self.assertEqual(result.authentication, NOT_CHECKED)


class RuntimeAuthDemoTests(unittest.TestCase):
    def test_auth_demo_batch_results(self):
        runtime = SentinelRuntime(HmacAuthenticator(KEY), require_auth=False)
        results = runtime.run_auth_demo()
        self.assertTrue(runtime.require_auth)
        self.assertEqual([r["decision"] for r in results], ["ACCEPTED", "REJECTED", "REJECTED", "REJECTED", "REJECTED", "ACCEPTED", "REJECTED"])
        self.assertEqual([r["authentication"] for r in results],
                         [VALID, TAG_MISMATCH, MISSING_TAG, TAG_MISMATCH, MALFORMED_TAG, VALID, VALID])
        self.assertEqual(runtime.summary()["accepted"], 2)
        self.assertEqual(runtime.summary()["rejected"], 5)

    def test_mode_survives_reset_and_audit_never_stores_tags_or_keys(self):
        runtime = SentinelRuntime(HmacAuthenticator(KEY), require_auth=True)
        runtime.run_auth_demo()
        dump = json.dumps(runtime.snapshot())
        self.assertNotIn(KEY.decode(), dump)
        self.assertNotRegex(dump, r"[0-9a-f]{64}")
        runtime.reset()
        self.assertTrue(runtime.require_auth)

    def test_auth_status_never_contains_key_material(self):
        status = SentinelRuntime(HmacAuthenticator(KEY, "environment")).auth_status()
        self.assertNotIn(KEY.decode(), json.dumps(status))


if __name__ == "__main__":
    unittest.main(verbosity=2)
