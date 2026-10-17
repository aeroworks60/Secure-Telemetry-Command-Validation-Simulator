"""Deterministic-shaped synthetic examples for local demonstration only."""
from datetime import datetime, timezone, timedelta
from copy import deepcopy


def build_demo_messages(now: datetime | None = None) -> list[dict]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    stamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    stale_stamp = (now - timedelta(minutes=10)).isoformat(timespec="seconds").replace("+00:00", "Z")

    valid_telemetry = {
        "message_id": "SYN-100", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 100, "message_type": "TELEMETRY", "sender_role": "satellite",
        "payload": {"battery_pct": 86.4, "temperature_c": 22.5, "altitude_km": 547.2},
    }
    valid_command = {
        "message_id": "SYN-101", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 101, "message_type": "COMMAND", "sender_role": "ground_operator",
        "payload": {"command": "SET_ORIENTATION", "angle_deg": 45},
    }
    missing_field = {
        "message_id": "SYN-102", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 102, "message_type": "TELEMETRY", "sender_role": "satellite",
        # payload intentionally missing
    }
    stale_message = {
        "message_id": "SYN-103", "satellite_id": "SAT-ALPHA", "timestamp": stale_stamp,
        "sequence_number": 102, "message_type": "TELEMETRY", "sender_role": "satellite",
        "payload": {"battery_pct": 86, "temperature_c": 21, "altitude_km": 550},
    }
    unauthorized_command = {
        "message_id": "SYN-104", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 102, "message_type": "COMMAND", "sender_role": "mission_analyst",
        "payload": {"command": "REBOOT_SENSOR"},
    }
    out_of_range = {
        "message_id": "SYN-105", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 102, "message_type": "TELEMETRY", "sender_role": "satellite",
        "payload": {"battery_pct": 140, "temperature_c": 21, "altitude_km": 550},
    }
    out_of_order = {
        "message_id": "SYN-106", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 99, "message_type": "TELEMETRY", "sender_role": "satellite",
        "payload": {"battery_pct": 86, "temperature_c": 21, "altitude_km": 550},
    }
    replay = deepcopy(valid_telemetry)
    replay["sequence_number"] = 103

    return [
        valid_telemetry,
        valid_command,
        missing_field,
        stale_message,
        unauthorized_command,
        out_of_range,
        out_of_order,
        replay,
    ]


# --- HMAC authentication demo messages (synthetic) -------------------------------------------
def _stamp(now: datetime) -> str:
    return now.isoformat(timespec="seconds").replace("+00:00", "Z")


def _telemetry(message_id: str, seq: int, stamp: str, battery: float = 80) -> dict:
    return {
        "message_id": message_id, "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": seq, "message_type": "TELEMETRY", "sender_role": "satellite",
        "payload": {"battery_pct": battery, "temperature_c": 21, "altitude_km": 550},
    }


def _attacker_authenticator():
    from auth import HmacAuthenticator
    return HmacAuthenticator(b"attacker-simulation-wrong-key", "attacker-simulation")


def build_auth_lab_examples(authenticator, now: datetime | None = None) -> dict[str, dict]:
    """Seeded examples for the Message Lab dropdown. Tags are computed server-side per page load."""
    stamp = _stamp((now or datetime.now(timezone.utc)).astimezone(timezone.utc))
    tampered = authenticator.sign(_telemetry("AUTH-LAB-2", 301, stamp, 80))
    tampered["payload"]["battery_pct"] = 81  # changed AFTER signing; tag left as-is
    bad_tag = _telemetry("AUTH-LAB-5", 304, stamp)
    bad_tag["auth_tag"] = "XYZ-not-a-hex-tag"
    return {
        "HMAC: signed valid telemetry": authenticator.sign(_telemetry("AUTH-LAB-1", 300, stamp)),
        "HMAC: tampered after signing": tampered,
        "HMAC: unsigned (no auth_tag)": _telemetry("AUTH-LAB-3", 302, stamp),
        "HMAC: signed with wrong key": _attacker_authenticator().sign(_telemetry("AUTH-LAB-4", 303, stamp)),
        "HMAC: malformed auth_tag": bad_tag,
    }


def build_auth_demo_messages(authenticator, now: datetime | None = None) -> list[tuple[str, dict]]:
    """Seven messages for the dashboard demo. Expected: 2 accepted, 5 rejected (run with auth required)."""
    stamp = _stamp((now or datetime.now(timezone.utc)).astimezone(timezone.utc))
    attacker = _attacker_authenticator()
    tampered = authenticator.sign(_telemetry("AUTH-TAMPERED-201", 201, stamp, 80))
    tampered["payload"]["battery_pct"] = 81  # modified in transit; tag no longer matches
    bad_tag = _telemetry("AUTH-BADTAG-201", 201, stamp)
    bad_tag["auth_tag"] = "not-a-real-tag"
    good_command = authenticator.sign({
        "message_id": "AUTH-CMD-OK-201", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 201, "message_type": "COMMAND", "sender_role": "ground_operator",
        "payload": {"command": "SET_ORIENTATION", "angle_deg": 45},
    })
    viewer_command = authenticator.sign({  # authentic, but the role is NOT authorized: auth != authz
        "message_id": "AUTH-VIEWER-202", "satellite_id": "SAT-ALPHA", "timestamp": stamp,
        "sequence_number": 202, "message_type": "COMMAND", "sender_role": "viewer",
        "payload": {"command": "REBOOT_SENSOR"},
    })
    return [
        ("Valid signed telemetry", authenticator.sign(_telemetry("AUTH-VALID-200", 200, stamp))),
        ("Tampered after signing", tampered),
        ("Unsigned message", _telemetry("AUTH-UNSIGNED-201", 201, stamp)),
        ("Signed with wrong key", attacker.sign(_telemetry("AUTH-WRONGKEY-201", 201, stamp))),
        ("Malformed tag", bad_tag),
        ("Valid signed command", good_command),
        ("Authentic but unauthorized role", viewer_command),
    ]
