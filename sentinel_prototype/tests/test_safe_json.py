import unittest

from safe_json import MAX_JSON_BYTES, parse_json_message


class SafeJSONTests(unittest.TestCase):
    def test_parses_valid_standard_json(self):
        self.assertEqual(parse_json_message('{"ok": true, "n": 3}'), {"ok": True, "n": 3})

    def test_rejects_oversized_json_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_json_message(' ' * (MAX_JSON_BYTES + 1))

    def test_rejects_nonstandard_nan(self):
        with self.assertRaisesRegex(ValueError, "Non-standard JSON"):
            parse_json_message('{"value": NaN}')

    def test_rejects_nonstandard_infinity(self):
        with self.assertRaisesRegex(ValueError, "Non-standard JSON"):
            parse_json_message('{"value": Infinity}')

    def test_rejects_excessively_deep_json_without_crashing_app(self):
        raw = '[' * 10000 + '0' + ']' * 10000
        with self.assertRaisesRegex(ValueError, "nesting is too deep"):
            parse_json_message(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
