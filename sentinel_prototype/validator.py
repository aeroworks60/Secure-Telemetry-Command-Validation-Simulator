"""Local-only validation engine for the Sentinel satellite-message simulator.

This is an educational prototype. It processes synthetic JSON-like dictionaries
and never sends commands to a real satellite or operational system.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Any

from auth import NOT_CHECKED, TAG_FIELD

REQUIRED_FIELDS = {
    "message_id", "satellite_id", "timestamp", "sequence_number",
    "message_type", "sender_role", "payload",
}
OPTIONAL_FIELDS = {TAG_FIELD}  # HMAC tag; verified by auth.py, never part of the signed bytes
ALLOWED_MESSAGE_TYPES = {"TELEMETRY", "COMMAND"}
ALLOWED_ROLES = {"satellite", "ground_operator", "mission_analyst", "viewer"}
ALLOWED_COMMANDS = {
    "REQUEST_STATUS": {"ground_operator", "mission_analyst"},
    "SET_ORIENTATION": {"ground_operator"},
    "CAPTURE_IMAGE": {"ground_operator"},
    "REBOOT_SENSOR": {"ground_operator"},
}
TELEMETRY_RANGES = {
    "battery_pct": (0, 100),
    "temperature_c": (-80, 100),
    "altitude_km": (300, 2000),
}
TELEMETRY_PAYLOAD_FIELDS = set(TELEMETRY_RANGES)
COMMAND_PAYLOAD_FIELDS = {
    "REQUEST_STATUS": {"command"},
    "SET_ORIENTATION": {"command", "angle_deg"},
    "CAPTURE_IMAGE": {"command", "target"},
    "REBOOT_SENSOR": {"command"},
}
MAX_MESSAGE_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 30


@dataclass
class ValidationResult:
    accepted: bool
    reasons: list[str]
    message_id: str
    satellite_id: str
    message_type: str
    sequence_number: int | str
    evaluated_at: str
    authentication: str = NOT_CHECKED
    authentication_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _display(value: Any) -> str:
    return value[:80] if isinstance(value, str) and value.strip() else "(missing/invalid)"


def _display_seq(value: Any) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return "(missing)" if value is None else str(value)[:40]


class SentinelValidator:
    """Stateful validator with message-ID and per-satellite sequence checks."""

    def __init__(self, max_age_seconds: int = MAX_MESSAGE_AGE_SECONDS, authenticator: Any = None, require_auth: bool = False):
        self.max_age_seconds = max_age_seconds
        self.authenticator = authenticator  # HmacAuthenticator or None (authentication off)
        self.require_auth = require_auth
        self.seen_message_ids: set[str] = set()
        self.last_accepted_sequence: dict[str, int] = {}

    def reset(self) -> None:
        self.seen_message_ids.clear()
        self.last_accepted_sequence.clear()

    @staticmethod
    def _is_number(value: Any) -> bool:
        # bool is a subclass of int in Python, but should not count as numeric here.
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            normalized = value.strip()
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                return None
            return parsed.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return None

    def validate(self, message: Any, now: datetime | None = None) -> ValidationResult:
        evaluated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        issues: list[str] = []

        if not isinstance(message, dict):
            return ValidationResult(
                accepted=False,
                reasons=["Message must be a JSON object."],
                message_id="(unavailable)",
                satellite_id="(unknown)",
                message_type="(unknown)",
                sequence_number="(unknown)",
                evaluated_at=evaluated.isoformat(timespec="seconds").replace("+00:00", "Z"),
            )

        # --- Authentication gate: independent of every rule below ----------------------
        # Runs first so an unauthenticated message can never consume a message ID or advance a
        # sequence number. Authorization, freshness and replay rules are unchanged further down.
        auth_status, auth_detail = NOT_CHECKED, "Authentication was not performed."
        if self.authenticator is not None:
            auth = self.authenticator.verify(message)
            if not auth.ok and (self.require_auth or TAG_FIELD in message):
                return ValidationResult(
                    accepted=False,
                    reasons=[f"Authentication failed ({auth.status}): {auth.detail}"],
                    message_id=_display(message.get("message_id")),
                    satellite_id=_display(message.get("satellite_id")),
                    message_type=_display(message.get("message_type")),
                    sequence_number=_display_seq(message.get("sequence_number")),
                    evaluated_at=evaluated.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    authentication=auth.status,
                    authentication_detail=auth.detail,
                )
            if auth.ok:
                auth_status, auth_detail = auth.status, auth.detail
            else:
                auth_status, auth_detail = NOT_CHECKED, "No auth_tag supplied; authentication is optional in the current mode."

        # Human-readable values for the audit table, even when fields are missing.
        msg_id = message.get("message_id") if isinstance(message.get("message_id"), str) else "(missing/invalid)"
        sat_id = message.get("satellite_id") if isinstance(message.get("satellite_id"), str) else "(missing/invalid)"
        msg_type = message.get("message_type") if isinstance(message.get("message_type"), str) else "(missing/invalid)"
        seq_for_log = message.get("sequence_number", "(missing)")
        if not isinstance(seq_for_log, (int, str)) or isinstance(seq_for_log, bool):
            seq_for_log = str(seq_for_log)

        missing = sorted(REQUIRED_FIELDS - set(message.keys()))
        if missing:
            issues.append("Missing required field(s): " + ", ".join(missing) + ".")
        extra = sorted(str(key) for key in set(message.keys()) - REQUIRED_FIELDS - OPTIONAL_FIELDS)
        if extra:
            issues.append("Unexpected field(s): " + ", ".join(extra) + ".")

        # Validate message ID and remember first-seen IDs, including rejected messages.
        # This prevents an identical ID from later being reused to mask a retry.
        if not isinstance(message.get("message_id"), str) or not message.get("message_id", "").strip():
            issues.append("message_id must be a non-empty string.")
        else:
            normalized_id = message["message_id"].strip()
            if normalized_id in self.seen_message_ids:
                issues.append(f"Duplicate message_id '{normalized_id}' (possible replay).")
            else:
                self.seen_message_ids.add(normalized_id)
                msg_id = normalized_id

        if not isinstance(message.get("satellite_id"), str) or not message.get("satellite_id", "").strip():
            issues.append("satellite_id must be a non-empty string.")
        else:
            sat_id = message["satellite_id"].strip()

        # Sequence numbers are integers (never booleans) and must move forward.
        seq = message.get("sequence_number")
        sequence_is_valid = isinstance(seq, int) and not isinstance(seq, bool) and seq >= 1
        if not sequence_is_valid:
            issues.append("sequence_number must be a positive integer.")
        elif isinstance(sat_id, str) and sat_id not in {"(unknown)", "(missing/invalid)"}:
            previous = self.last_accepted_sequence.get(sat_id)
            if previous is not None and seq <= previous:
                issues.append(
                    f"Stale sequence_number {seq}; the last accepted sequence for {sat_id} is {previous}."
                )

        parsed_timestamp = self._parse_timestamp(message.get("timestamp"))
        if parsed_timestamp is None:
            issues.append("timestamp must be a valid ISO-8601 timestamp with a timezone (UTC 'Z' is recommended).")
        else:
            age_seconds = (evaluated - parsed_timestamp).total_seconds()
            if age_seconds > self.max_age_seconds:
                issues.append(f"Message is stale ({int(age_seconds)} seconds old; limit is {self.max_age_seconds}).")
            elif age_seconds < -MAX_FUTURE_SKEW_SECONDS:
                issues.append(f"Timestamp is too far in the future (more than {MAX_FUTURE_SKEW_SECONDS} seconds).")

        msg_type_value = message.get("message_type")
        if not isinstance(msg_type_value, str) or msg_type_value not in ALLOWED_MESSAGE_TYPES:
            issues.append("message_type must be TELEMETRY or COMMAND.")

        role = message.get("sender_role")
        if not isinstance(role, str) or role not in ALLOWED_ROLES:
            issues.append("sender_role is not in the configured role allowlist.")

        payload = message.get("payload")
        if not isinstance(payload, dict):
            issues.append("payload must be a JSON object.")
        elif msg_type_value == "TELEMETRY":
            if role != "satellite":
                issues.append("TELEMETRY messages must identify the sender_role as satellite.")
            unexpected_payload = sorted(set(payload.keys()) - TELEMETRY_PAYLOAD_FIELDS)
            if unexpected_payload:
                issues.append("Unexpected telemetry payload field(s): " + ", ".join(unexpected_payload) + ".")
            for field, (minimum, maximum) in TELEMETRY_RANGES.items():
                if field not in payload:
                    issues.append(f"Telemetry payload is missing '{field}'.")
                elif not self._is_number(payload[field]):
                    issues.append(f"Telemetry field '{field}' must be numeric.")
                elif not minimum <= payload[field] <= maximum:
                    issues.append(f"Telemetry field '{field}' is outside the allowed range [{minimum}, {maximum}].")
        elif msg_type_value == "COMMAND":
            if role == "satellite":
                issues.append("A satellite sender cannot issue ground commands.")
            command = payload.get("command")
            if not isinstance(command, str) or command not in ALLOWED_COMMANDS:
                issues.append("Command is not in the permitted command allowlist.")
            else:
                unexpected_payload = sorted(set(payload.keys()) - COMMAND_PAYLOAD_FIELDS[command])
                if unexpected_payload:
                    issues.append(
                        "Unexpected payload field(s) for command " + command + ": "
                        + ", ".join(unexpected_payload) + "."
                    )
                permitted_roles = ALLOWED_COMMANDS[command]
                if not isinstance(role, str) or role not in permitted_roles:
                    issues.append(
                        f"Role '{role}' is not authorized for command '{command}'. Allowed role(s): "
                        + ", ".join(sorted(permitted_roles)) + "."
                    )
                if command == "SET_ORIENTATION":
                    angle = payload.get("angle_deg")
                    if not self._is_number(angle):
                        issues.append("SET_ORIENTATION requires a numeric angle_deg.")
                    elif not -180 <= angle <= 180:
                        issues.append("angle_deg must be between -180 and 180 degrees.")
                if command == "CAPTURE_IMAGE":
                    target = payload.get("target")
                    if not isinstance(target, str) or not target.strip():
                        issues.append("CAPTURE_IMAGE requires a non-empty target string.")

        accepted = len(issues) == 0
        if accepted and isinstance(sat_id, str) and isinstance(seq, int):
            self.last_accepted_sequence[sat_id] = seq

        return ValidationResult(
            accepted=accepted,
            reasons=issues if issues else ["All configured validation checks passed."],
            message_id=str(msg_id),
            satellite_id=str(sat_id),
            message_type=str(msg_type),
            sequence_number=seq_for_log,
            evaluated_at=evaluated.isoformat(timespec="seconds").replace("+00:00", "Z"),
            authentication=auth_status,
            authentication_detail=auth_detail,
        )


def example_schema() -> dict[str, Any]:
    """A compact schema summary shown in the UI and README."""
    return {
        "message_id": "string, unique per simulator session",
        "satellite_id": "non-empty string",
        "timestamp": "ISO-8601 datetime with timezone",
        "sequence_number": "positive integer, increasing per satellite",
        "message_type": "TELEMETRY | COMMAND",
        "sender_role": "satellite | ground_operator | mission_analyst | viewer",
        "payload": "object; fields depend on message_type",
        "auth_tag": "optional string: HMAC-SHA256 hex tag (64 lowercase hex chars); required when authentication is required",
    }
