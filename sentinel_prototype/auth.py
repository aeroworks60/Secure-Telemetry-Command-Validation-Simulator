"""HMAC-SHA256 message authentication for Sentinel's synthetic messages.

Authentication answers ONE question: "Was this exact message produced by a holder of the
shared secret key, and is it unchanged since signing?"

It is deliberately separate from authorization (sender roles/command allowlist), timestamp
freshness and replay/sequence checks, which live in validator.py. HMAC does NOT encrypt the
message, does not hide its contents, and does not make this prototype production-secure.

Serialization (what is signed) -- exactly these fields, in this canonical form:
  fields : message_id, satellite_id, timestamp, sequence_number, message_type, sender_role, payload
  excluded: auth_tag (the tag cannot sign itself)
  bytes   : DOMAIN_PREFIX + JSON(fields only, sorted keys, no whitespace, ASCII-escaped, UTF-8)
Values are serialized as parsed (45 and 45.0 are different JSON numbers and sign differently).

Key handling: the key lives only in server memory. Set SENTINEL_HMAC_KEY (>= 16 bytes) in the
server's environment. If it is unset, a clearly labelled DEVELOPMENT-ONLY demonstration key is
used so the demo runs out of the box; that key is public in this source file and provides no secrecy.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

TAG_FIELD = "auth_tag"
SIGNED_FIELDS = (
    "message_id", "satellite_id", "timestamp", "sequence_number",
    "message_type", "sender_role", "payload",
)
DOMAIN_PREFIX = b"SENTINEL-HMAC-SHA256-v1\n"
KEY_ENV_VAR = "SENTINEL_HMAC_KEY"
MIN_KEY_BYTES = 16
DEV_KEY = b"sentinel-DEV-ONLY-demo-key-not-a-secret"  # public; demonstration only
DEV_KEY_SOURCE = "development-demo"
ENV_KEY_SOURCE = "environment"

_TAG_RE = re.compile(r"[0-9a-f]{64}")  # lowercase hex SHA-256 digest, ASCII only

VALID = "VALID"
MISSING_TAG = "MISSING_TAG"
MALFORMED_TAG = "MALFORMED_TAG"
TAG_MISMATCH = "TAG_MISMATCH"
NOT_CHECKED = "NOT_CHECKED"


@dataclass(frozen=True)
class AuthResult:
    status: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_bytes(message: Mapping[str, Any]) -> bytes:
    """Deterministic bytes covered by the tag. Never includes the auth_tag field."""
    signed = {name: message[name] for name in SIGNED_FIELDS if name in message}
    text = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return DOMAIN_PREFIX + text.encode("ascii")


class HmacAuthenticator:
    """Generates and verifies HMAC-SHA256 tags using a shared secret key (server side only)."""

    def __init__(self, key: bytes, key_source: str = ENV_KEY_SOURCE):
        if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
            raise ValueError(f"HMAC key must be at least {MIN_KEY_BYTES} bytes.")
        self._key = bytes(key)
        self.key_source = key_source

    def __repr__(self) -> str:  # never reveal key material in logs or tracebacks
        return f"HmacAuthenticator(key_source={self.key_source!r})"

    @property
    def is_dev_key(self) -> bool:
        return self.key_source == DEV_KEY_SOURCE

    def generate_tag(self, message: Mapping[str, Any]) -> str:
        return hmac.new(self._key, canonical_bytes(message), hashlib.sha256).hexdigest()

    def sign(self, message: Mapping[str, Any]) -> dict[str, Any]:
        """Return a copy of the message with a fresh auth_tag (any old tag is discarded)."""
        signed = {k: v for k, v in message.items() if k != TAG_FIELD}
        signed[TAG_FIELD] = self.generate_tag(signed)
        return signed

    def verify(self, message: Mapping[str, Any]) -> AuthResult:
        """Check the tag only. Says nothing about roles, freshness or replay."""
        if TAG_FIELD not in message:
            return AuthResult(MISSING_TAG, False, "No auth_tag was supplied.")
        tag = message[TAG_FIELD]
        if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
            return AuthResult(MALFORMED_TAG, False, "auth_tag must be 64 lowercase hexadecimal characters.")
        try:
            expected = self.generate_tag(message)
        except (TypeError, ValueError):
            return AuthResult(TAG_MISMATCH, False, "Message could not be serialized for verification.")
        if hmac.compare_digest(expected, tag):
            return AuthResult(VALID, True, "auth_tag verified: signed fields are unchanged since signing with this key.")
        # HMAC cannot tell these two causes apart; saying so is more honest than guessing.
        return AuthResult(
            TAG_MISMATCH, False,
            "auth_tag does not match: a signed field was changed after signing, or a different key was used.",
        )


def load_authenticator_from_env(environ: Mapping[str, str] | None = None) -> HmacAuthenticator:
    """Use SENTINEL_HMAC_KEY if set (fail closed if too short); otherwise the labelled dev key."""
    env = os.environ if environ is None else environ
    value = env.get(KEY_ENV_VAR, "")
    if not value:
        return HmacAuthenticator(DEV_KEY, DEV_KEY_SOURCE)
    key = value.encode("utf-8")
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"{KEY_ENV_VAR} must be at least {MIN_KEY_BYTES} bytes; refusing to start with a weak key.")
    return HmacAuthenticator(key, ENV_KEY_SOURCE)
