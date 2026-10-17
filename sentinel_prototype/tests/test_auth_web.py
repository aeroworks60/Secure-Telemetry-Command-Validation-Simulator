"""Web-level HMAC tests: signing endpoint, mode switch, end-to-end valid/tampered demo,
and checks that the secret key is never sent to the browser."""
import json
import pathlib
import unittest

from app import create_app
from auth import DEV_KEY, HmacAuthenticator
from samples import build_demo_messages

KEY = b"web-test-shared-secret-0001"
ROOT = pathlib.Path(__file__).resolve().parent.parent


class AuthWebTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(testing=True, authenticator=HmacAuthenticator(KEY), require_auth=True)
        self.client = self.app.test_client()
        self.runtime = self.app.extensions["sentinel_runtime"]

    def sign(self, message):
        response = self.client.post("/auth/sign", json={"raw_json": json.dumps(message)})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()["signed_json"]

    def validate(self, raw_json):
        return self.client.post("/validate", data={"raw_json": raw_json, "example": "Custom JSON"}, follow_redirects=True)

    def fresh(self, message_id):
        message = build_demo_messages()[0]
        message["message_id"] = message_id
        message["sequence_number"] = 900
        return message

    def test_signed_message_is_accepted_end_to_end(self):
        response = self.validate(self.sign(self.fresh("WEB-AUTH-OK")))
        html = response.get_data(as_text=True)
        self.assertIn("ACCEPTED", html)
        self.assertIn("auth_tag verified", html)
        self.assertEqual(self.runtime.summary()["accepted"], 1)

    def test_tampered_message_is_rejected_end_to_end(self):
        signed = json.loads(self.sign(self.fresh("WEB-AUTH-TAMPER")))
        signed["payload"]["battery_pct"] = 81
        html = self.validate(json.dumps(signed)).get_data(as_text=True)
        self.assertIn("REJECTED", html)
        self.assertIn("TAG MISMATCH", html)
        self.assertIn("Message rejected: authentication failed.", html)
        self.assertEqual(self.runtime.summary()["accepted"], 0)

    def test_unsigned_message_is_rejected_when_authentication_required(self):
        html = self.validate(json.dumps(self.fresh("WEB-AUTH-NONE"))).get_data(as_text=True)
        self.assertIn("REJECTED", html)
        self.assertIn("MISSING TAG", html)

    def test_malformed_tag_is_rejected(self):
        message = self.fresh("WEB-AUTH-BAD")
        message["auth_tag"] = "nope"
        html = self.validate(json.dumps(message)).get_data(as_text=True)
        self.assertIn("MALFORMED TAG", html)

    def test_sign_endpoint_requires_json_and_rejects_bad_input(self):
        self.assertEqual(self.client.post("/auth/sign", data={"raw_json": "{}"}).status_code, 415)
        self.assertEqual(self.client.post("/auth/sign", json={"raw_json": "{not json"}).status_code, 400)
        self.assertEqual(self.client.post("/auth/sign", json={"raw_json": "[1,2]"}).status_code, 400)
        self.assertEqual(self.client.post("/auth/sign", json={"raw_json": 5}).status_code, 400)
        self.assertEqual(self.client.post("/auth/sign", json={"raw_json": '{"a": NaN}'}).status_code, 400)

    def test_mode_endpoint_json_and_form(self):
        response = self.client.post("/auth/mode", json={"require": False})
        self.assertEqual(response.get_json(), {"ok": True, "required": False})
        self.assertFalse(self.runtime.require_auth)
        self.assertEqual(self.client.post("/auth/mode", json={"require": "yes"}).status_code, 400)
        self.client.post("/auth/mode", data={"require": "1", "next": "validate"})
        self.assertTrue(self.runtime.require_auth)

    def test_optional_mode_lets_unsigned_through_but_not_bad_tags(self):
        self.runtime.set_require_auth(False)
        self.assertIn("ACCEPTED", self.validate(json.dumps(self.fresh("WEB-OPT-1"))).get_data(as_text=True))
        bad = self.fresh("WEB-OPT-2")
        bad["sequence_number"] = 901
        bad["auth_tag"] = "0" * 64
        self.assertIn("TAG MISMATCH", self.validate(json.dumps(bad)).get_data(as_text=True))

    def test_auth_demo_route_runs_seven_messages(self):
        response = self.client.post("/auth/demo", follow_redirects=True)
        self.assertIn(b"Authentication demo complete: 2 accepted, 5 rejected", response.data)
        self.assertEqual(self.runtime.summary()["total"], 7)
        self.assertIn(b"TAG MISMATCH", response.data)

    def test_existing_demo_batch_is_unchanged(self):
        self.client.post("/demo")
        self.assertEqual(self.runtime.summary()["accepted"], 0)  # auth required: unsigned seeds rejected
        optional = create_app(testing=True, authenticator=HmacAuthenticator(KEY), require_auth=False)
        optional.test_client().post("/demo")
        summary = optional.extensions["sentinel_runtime"].summary()
        self.assertEqual((summary["accepted"], summary["rejected"]), (2, 6))

    def test_lab_page_offers_sign_tamper_and_signed_examples(self):
        html = self.client.get("/validate").get_data(as_text=True)
        for needle in ('id="sign-message"', 'id="tamper-message"', "HMAC: signed valid telemetry",
                       "HMAC: tampered after signing", "does <strong>not</strong> encrypt"):
            self.assertIn(needle, html)

    def test_audit_page_and_csv_show_authentication_status(self):
        self.client.post("/auth/demo")
        self.assertIn(b"MALFORMED TAG", self.client.get("/audit").data)
        csv_text = self.client.get("/audit/export.csv").get_data(as_text=True)
        self.assertIn("authentication", csv_text.splitlines()[0])
        self.assertIn("TAG_MISMATCH", csv_text)

    def test_secret_key_never_reaches_the_browser(self):
        self.client.post("/auth/demo")
        self.sign(self.fresh("WEB-LEAK-CHECK"))
        pages = ["/", "/validate", "/schema", "/audit", "/audit/export.json", "/audit/export.csv", "/static/console.js", "/static/console.css"]
        for path in pages:
            with self.client.get(path) as response:
                body = response.data
            self.assertNotIn(KEY, body, path)
            self.assertNotIn(DEV_KEY, body, path)
        signed = self.client.post("/auth/sign", json={"raw_json": json.dumps(self.fresh("WEB-LEAK-2"))}).data
        self.assertNotIn(KEY, signed)

    def test_key_is_not_in_any_template_or_static_file(self):
        for folder in ("templates", "static"):
            for path in (ROOT / folder).rglob("*"):
                if path.is_file():
                    self.assertNotIn(DEV_KEY, path.read_bytes(), str(path))
                    self.assertNotIn(KEY, path.read_bytes(), str(path))

    def test_dev_key_warning_is_shown_only_for_the_development_key(self):
        self.assertNotIn(b"Development key in use", self.client.get("/").data)
        dev_app = create_app(testing=True)
        self.assertIn(b"Development key in use", dev_app.test_client().get("/").data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
