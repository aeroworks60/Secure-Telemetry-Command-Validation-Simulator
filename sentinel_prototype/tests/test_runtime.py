import unittest

from runtime import SentinelRuntime


class SentinelRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.runtime = SentinelRuntime()

    def test_demo_batch_summary(self):
        results = self.runtime.run_demo_batch()
        self.assertEqual(len(results), 8)
        self.assertEqual(self.runtime.summary()["accepted"], 2)
        self.assertEqual(self.runtime.summary()["rejected"], 6)

    def test_reset_clears_audit_and_validator_state(self):
        self.runtime.run_demo_batch()
        self.runtime.reset()
        self.assertEqual(self.runtime.summary()["total"], 0)
        self.assertEqual(self.runtime.snapshot(), [])

    def test_audit_snapshot_does_not_expose_internal_reason_list(self):
        self.runtime.run_demo_batch()
        snapshot = self.runtime.snapshot()
        snapshot[0]["reasons"].append("mutation from caller")
        self.assertNotIn("mutation from caller", self.runtime.snapshot()[0]["reasons"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
