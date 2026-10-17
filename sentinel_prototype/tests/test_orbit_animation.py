"""The Earth/satellite animation must reflect REAL validation results and never show a fake success."""
import json
import pathlib
import re
import unittest

from app import create_app
from auth import HmacAuthenticator
from samples import build_demo_messages

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKMARK_PATH = 'd="M-9 1L-3 8L10-8"'  # the green check drawn on the gate ONLY for an accepted state


def state_of(html):
    return re.search(r'data-link-state="(\w+)"', html).group(1)


class OrbitAnimationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(testing=True, authenticator=HmacAuthenticator(b"orbit-test-key-0123456"), require_auth=False)
        self.client = self.app.test_client()
        self.runtime = self.app.extensions["sentinel_runtime"]

    def message(self, message_id, **payload_changes):
        message = build_demo_messages()[0]
        message["message_id"] = message_id
        message["payload"].update(payload_changes)
        return message

    def lab(self, message):
        return self.client.post("/validate", data={"raw_json": json.dumps(message), "example": "Custom JSON"}, follow_redirects=True).get_data(as_text=True)

    def test_idle_scene_shows_no_packets_and_no_success(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertEqual(state_of(html), "idle")
        self.assertNotIn('class="sx-pkt', html)
        self.assertIn("AWAITING MESSAGE", html)
        self.assertIn("sx-rx-dark", html)
        self.assertNotIn("sx-rx-live", html)
        self.assertNotIn(CHECKMARK_PATH, html)

    def test_mixed_demo_batch_draws_exactly_the_real_outcomes(self):
        self.client.post("/demo")
        html = self.client.get("/").get_data(as_text=True)
        self.assertEqual(state_of(html), "mixed")
        self.assertEqual(html.count('class="sx-pkt sx-pkt-ok"'), 2)
        self.assertEqual(html.count('class="sx-pkt sx-pkt-no"'), 6)
        self.assertIn("LAST RUN: 2 ACCEPTED", html)
        self.assertIn("6 REJECTED", html)
        self.assertIn("RECEIVED 2", html)

    def test_rejected_message_is_blocked_and_nothing_is_delivered(self):
        html = self.lab(self.message("ORB-BAD", battery_pct=140))
        self.assertEqual(state_of(html), "rejected")
        self.assertEqual(html.count('class="sx-pkt sx-pkt-no"'), 1)
        self.assertNotIn('class="sx-pkt sx-pkt-ok"', html)
        self.assertIn("BLOCKED", html)
        self.assertIn("NOTHING RECEIVED", html)
        self.assertIn("sx-rx-dark", html)
        self.assertNotIn("sx-rx-live", html)
        self.assertNotIn(CHECKMARK_PATH, html)

    def test_accepted_message_passes_the_gate(self):
        html = self.lab(self.message("ORB-GOOD"))
        self.assertEqual(state_of(html), "accepted")
        self.assertEqual(html.count('class="sx-pkt sx-pkt-ok"'), 1)
        self.assertNotIn('class="sx-pkt sx-pkt-no"', html)
        self.assertIn("sx-rx-live", html)
        self.assertIn("Passed all configured checks", html)
        self.assertIn(CHECKMARK_PATH, html)

    def test_tampered_signed_message_is_shown_as_blocked(self):
        self.runtime.set_require_auth(True)
        signed = self.runtime.authenticator.sign(self.message("ORB-TAMPER"))
        signed["payload"]["battery_pct"] = 81
        html = self.lab(signed)
        self.assertEqual(state_of(html), "rejected")
        self.assertIn("TAG MISMATCH", html)
        self.assertNotIn(CHECKMARK_PATH, html)

    def test_unsigned_message_is_blocked_when_authentication_required(self):
        self.runtime.set_require_auth(True)
        html = self.lab(self.message("ORB-UNSIGNED"))
        self.assertEqual(state_of(html), "rejected")
        self.assertNotIn("sx-rx-live", html)

    def test_dashboard_follows_the_latest_real_result_not_a_canned_one(self):
        self.lab(self.message("ORB-A"))
        self.assertEqual(state_of(self.client.get("/").get_data(as_text=True)), "accepted")
        self.lab(self.message("ORB-B", battery_pct=-5))
        self.assertEqual(state_of(self.client.get("/").get_data(as_text=True)), "rejected")
        self.client.post("/reset")
        self.assertEqual(state_of(self.client.get("/").get_data(as_text=True)), "idle")

    def test_lab_starts_idle_before_any_validation(self):
        self.assertEqual(state_of(self.client.get("/validate").get_data(as_text=True)), "idle")

    def test_scene_is_pure_css_svg_with_no_scripts_or_external_assets(self):
        partial = (ROOT / "templates" / "_orbit.html").read_text(encoding="utf-8")
        self.assertNotIn("<script", partial)
        self.assertNotIn("http://", partial)
        self.assertNotIn("https://", partial)
        self.assertEqual((ROOT / "requirements.txt").read_text().split("\n")[0].split(">")[0].lower(), "flask")
        css = (ROOT / "static" / "console.css").read_text(encoding="utf-8")
        for name in ("sx-fly-ok", "sx-fly-no", "sx-rot", "sx-land"):
            self.assertIn("@keyframes " + name, css)

    def test_packets_stay_hidden_without_animation_for_reduced_motion(self):
        css = (ROOT / "static" / "console.css").read_text(encoding="utf-8")
        self.assertRegex(css, r"\.sx-pkt\{opacity:0;")
        self.assertIn("prefers-reduced-motion:reduce", css)


if __name__ == "__main__":
    unittest.main(verbosity=2)
