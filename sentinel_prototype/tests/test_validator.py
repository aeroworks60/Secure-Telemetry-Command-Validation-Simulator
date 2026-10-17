import unittest
from datetime import datetime, timezone, timedelta
from copy import deepcopy

from samples import build_demo_messages
from validator import SentinelValidator


class SentinelValidatorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
        self.validator = SentinelValidator()
        self.valid = build_demo_messages(self.now)[0]

    def test_accepts_valid_telemetry(self):
        result = self.validator.validate(deepcopy(self.valid), now=self.now)
        self.assertTrue(result.accepted, result.reasons)

    def test_rejects_missing_required_payload(self):
        message = build_demo_messages(self.now)[2]
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("Missing required field" in reason for reason in result.reasons))

    def test_rejects_stale_timestamp(self):
        message = build_demo_messages(self.now)[3]
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("stale" in reason.lower() for reason in result.reasons))

    def test_rejects_unauthorized_command(self):
        message = build_demo_messages(self.now)[4]
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("not authorized" in reason.lower() for reason in result.reasons))

    def test_rejects_out_of_range_battery(self):
        message = build_demo_messages(self.now)[5]
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("outside the allowed range" in reason for reason in result.reasons))

    def test_rejects_duplicate_message_id(self):
        first = deepcopy(self.valid)
        second = deepcopy(self.valid)
        second["sequence_number"] = 101
        self.assertTrue(self.validator.validate(first, now=self.now).accepted)
        result = self.validator.validate(second, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("Duplicate message_id" in reason for reason in result.reasons))

    def test_rejects_non_increasing_sequence_number(self):
        first = deepcopy(self.valid)
        second = deepcopy(self.valid)
        second["message_id"] = "SYN-DIFFERENT"
        second["sequence_number"] = 99
        self.assertTrue(self.validator.validate(first, now=self.now).accepted)
        result = self.validator.validate(second, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("Stale sequence_number" in reason for reason in result.reasons))

    def test_rejects_naive_timestamp(self):
        message = deepcopy(self.valid)
        message["timestamp"] = "2026-10-16T12:00:00"
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("with a timezone" in reason for reason in result.reasons))

    def test_rejects_boolean_sequence_number(self):
        message = deepcopy(self.valid)
        message["sequence_number"] = True
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("positive integer" in reason for reason in result.reasons))

    def test_malformed_field_types_are_rejected_without_crashing(self):
        message = deepcopy(self.valid)
        message["message_type"] = ["TELEMETRY"]
        message["sender_role"] = ["satellite"]
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("message_type must be" in reason for reason in result.reasons))
        self.assertTrue(any("sender_role is not" in reason for reason in result.reasons))

    def test_rejects_unexpected_field(self):
        message = deepcopy(self.valid)
        message["unreviewed_extra"] = "unexpected"
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("Unexpected field" in reason for reason in result.reasons))


    def test_rejects_unexpected_nested_telemetry_field(self):
        message = deepcopy(self.valid)
        message["payload"]["debug_mode"] = True
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("Unexpected telemetry payload field" in reason for reason in result.reasons))

    def test_rejects_unexpected_nested_command_field(self):
        message = deepcopy(build_demo_messages(self.now)[1])
        message["payload"]["override"] = True
        result = self.validator.validate(message, now=self.now)
        self.assertFalse(result.accepted)
        self.assertTrue(any("Unexpected payload field" in reason for reason in result.reasons))

    def test_does_not_advance_sequence_for_rejected_message(self):
        first = deepcopy(self.valid)
        self.assertTrue(self.validator.validate(first, now=self.now).accepted)
        bad = deepcopy(first)
        bad["message_id"] = "SYN-BAD"
        bad["sequence_number"] = 102
        bad["payload"]["battery_pct"] = 150
        self.assertFalse(self.validator.validate(bad, now=self.now).accepted)
        next_good = deepcopy(first)
        next_good["message_id"] = "SYN-NEXT"
        next_good["sequence_number"] = 101
        self.assertTrue(self.validator.validate(next_good, now=self.now).accepted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
