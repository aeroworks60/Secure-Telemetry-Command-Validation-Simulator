"""Size-limited, strict JSON parsing for Sentinel's local demo input."""
from __future__ import annotations

import json
from typing import Any

MAX_JSON_BYTES = 64 * 1024  # 64 KiB: sufficient for the synthetic demo schema.


def _reject_nonstandard_constant(value: str) -> None:
    """Python's decoder accepts NaN/Infinity by default; strict JSON does not."""
    raise ValueError(f"Non-standard JSON numeric value {value!r} is not permitted.")


def parse_json_message(raw: str, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse a JSON message after enforcing a byte cap and standard JSON numbers."""
    if not isinstance(raw, str):
        raise ValueError("Input must be text containing one JSON document.")
    if len(raw.encode("utf-8")) > max_bytes:
        raise ValueError(f"JSON input exceeds the {max_bytes}-byte size limit.")
    try:
        return json.loads(raw, parse_constant=_reject_nonstandard_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep for this simulator.") from exc
