"""In-memory runtime state for the local Sentinel demo.

The state is intentionally ephemeral: it resets when the app process restarts or
when the operator presses Reset. This is a classroom prototype, not a persistent
or tamper-resistant audit service.
"""
from __future__ import annotations

import os
from threading import RLock
from typing import Any

from auth import HmacAuthenticator, load_authenticator_from_env
from samples import build_auth_demo_messages, build_demo_messages
from validator import SentinelValidator


class SentinelRuntime:
    def __init__(self, authenticator: HmacAuthenticator | None = None, require_auth: bool | None = None) -> None:
        self._lock = RLock()
        # The key lives only here, server side. It is never passed to templates or JavaScript.
        self.authenticator = authenticator or load_authenticator_from_env()
        self.require_auth = (os.environ.get("SENTINEL_REQUIRE_AUTH") == "1") if require_auth is None else bool(require_auth)
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", RLock()):
            self.validator = SentinelValidator(authenticator=self.authenticator, require_auth=self.require_auth)
            self.audit: list[dict[str, Any]] = []
            self.latest_results: list[dict[str, Any]] = []

    def set_require_auth(self, required: bool) -> None:
        with self._lock:
            self.require_auth = bool(required)
            self.validator.require_auth = self.require_auth

    def auth_status(self) -> dict[str, Any]:
        """Safe-to-display authentication settings. Never includes key material."""
        dev = self.authenticator.is_dev_key
        return {
            "required": self.require_auth,
            "key_source": self.authenticator.key_source,
            "dev_key": dev,
            "key_label": "development-only demonstration key (public, not a secret)" if dev else "SENTINEL_HMAC_KEY environment variable",
        }

    def evaluate(self, message: Any) -> dict[str, Any]:
        with self._lock:
            result = self.validator.validate(message).to_dict()
            record = {
                "event_number": len(self.audit) + 1,
                "message_id": result["message_id"],
                "satellite_id": result["satellite_id"],
                "message_type": result["message_type"],
                "sequence_number": result["sequence_number"],
                "decision": "ACCEPTED" if result["accepted"] else "REJECTED",
                "authentication": result["authentication"],
                "authentication_detail": result["authentication_detail"],
                "reasons": result["reasons"],
                "reason": " ".join(result["reasons"]),
                "evaluated_at": result["evaluated_at"],
            }
            self.audit.append(record)
            self.latest_results = [record]
            return record

    def run_demo_batch(self) -> list[dict[str, Any]]:
        with self._lock:
            self.reset()
            results = [self.evaluate(message) for message in build_demo_messages()]
            self.latest_results = results
            return results

    def run_auth_demo(self) -> list[dict[str, Any]]:
        """Reset, require authentication, then run signed/tampered/unsigned/wrong-key messages."""
        with self._lock:
            self.reset()
            self.set_require_auth(True)
            results = [self.evaluate(message) for _label, message in build_auth_demo_messages(self.authenticator)]
            self.latest_results = results
            return results

    def summary(self) -> dict[str, int | str]:
        with self._lock:
            total = len(self.audit)
            accepted = sum(row["decision"] == "ACCEPTED" for row in self.audit)
            rejected = total - accepted
            return {
                "total": total,
                "accepted": accepted,
                "rejected": rejected,
                "acceptance_rate": round((accepted / total) * 100) if total else 0,
            }

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            # Copy records so callers can't mutate the runtime's audit entries.
            return [dict(row, reasons=list(row["reasons"])) for row in self.audit]
