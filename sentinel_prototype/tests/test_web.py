import json
import unittest

from app import create_app
from samples import build_demo_messages


class SentinelWebTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(testing=True)
        self.client = self.app.test_client()
        self.runtime = self.app.extensions["sentinel_runtime"]

    def test_all_primary_pages_load(self):
        for path in ("/", "/validate", "/schema", "/audit"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn(b"SENTINEL", response.data)

    def test_message_lab_has_visual_builder_and_raw_json_customization(self):
        response = self.client.get("/validate")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Customize this message", html)
        self.assertIn("Apply fields to JSON", html)
        self.assertIn('id="b-message-id"', html)
        self.assertIn('id="b-battery"', html)
        self.assertIn('id="raw_json" name="raw_json"', html)
        self.assertIn("RAW JSON EDITOR — FULL CONTROL", html)

    def test_demo_batch_has_two_accepts_and_six_rejects(self):
        response = self.client.post("/demo", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        summary = self.runtime.summary()
        self.assertEqual(summary["total"], 8)
        self.assertEqual(summary["accepted"], 2)
        self.assertEqual(summary["rejected"], 6)
        self.assertIn(b"Demo complete: 2 accepted, 6 rejected", response.data)

    def test_repeat_submission_rejects_duplicate_id(self):
        message = build_demo_messages()[0]
        raw = json.dumps(message)
        first = self.client.post("/validate", data={"raw_json": raw, "example": "Custom JSON"}, follow_redirects=True)
        second = self.client.post("/validate", data={"raw_json": raw, "example": "Custom JSON"}, follow_redirects=True)
        self.assertEqual(first.status_code, 200)
        self.assertIn(b"ACCEPTED", first.data)
        self.assertEqual(second.status_code, 200)
        self.assertIn(b"Duplicate message_id", second.data)
        self.assertEqual(self.runtime.summary()["accepted"], 1)
        self.assertEqual(self.runtime.summary()["rejected"], 1)

    def test_invalid_json_does_not_enter_audit(self):
        response = self.client.post(
            "/validate", data={"raw_json": '{"message_id":', "example": "Custom JSON"}, follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid JSON syntax", response.data)
        self.assertEqual(self.runtime.summary()["total"], 0)

    def test_out_of_range_message_is_rejected(self):
        message = build_demo_messages()[0]
        message["message_id"] = "WEB-OUT-OF-RANGE"
        message["payload"]["battery_pct"] = 140
        response = self.client.post(
            "/validate", data={"raw_json": json.dumps(message), "example": "Custom JSON"}, follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"REJECTED", response.data)
        self.assertIn(b"outside the allowed range", response.data)

    def test_audit_export_routes(self):
        self.client.post("/demo")
        json_response = self.client.get("/audit/export.json")
        csv_response = self.client.get("/audit/export.csv")
        self.assertEqual(json_response.status_code, 200)
        self.assertIn(b"application/json", json_response.content_type.encode())
        self.assertEqual(len(json.loads(json_response.get_data(as_text=True))), 8)
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn("message_id", csv_response.get_data(as_text=True))

    def test_only_loopback_server_config_is_documented(self):
        response = self.client.get("/")
        self.assertIn(b"NO LIVE LINK", response.data)
        self.assertIn(b"No satellite or operational command connection", response.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
