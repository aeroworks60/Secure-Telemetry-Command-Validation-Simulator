# Sentinel: review of the suggested resources

This document records the guidance checked against the local educational prototype.

## Python `json`
Reference: https://docs.python.org/3/library/json.html

- Uses `json.loads` for local manual-message parsing and `json.dumps` for exports.
- Manual JSON input is capped at 64 KiB before parsing.
- Non-standard `NaN`, `Infinity`, and `-Infinity` constants are rejected.
- Excessive nesting that triggers Python's recursion limit is reported as a controlled input error.
- This cap is a practical demo safeguard, not a complete production parser resource policy.

## Python `hmac`
Reference: https://docs.python.org/3/library/hmac.html

- HMAC-SHA256 is implemented in `auth.py` using the standard library (`hmac`, `hashlib`); tags are compared with `hmac.compare_digest()`, as the Python documentation recommends over `==`.
- The shared key is supplied through the server-side `SENTINEL_HMAC_KEY` environment variable; a clearly labelled development-only key is used otherwise.
- Do not state that HMAC encrypts messages or makes the prototype production-secure. It authenticates the signed fields with a shared key only.

## NIST Cybersecurity Framework
Reference: https://www.nist.gov/cyberframework

- Used as high-level cybersecurity risk-management context only.
- Sentinel is a small educational project and does not claim certification, formal assessment, or full CSF compliance.

## OWASP Input Validation Cheat Sheet
Reference: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

- Explicit required fields and rejection of unexpected top-level fields.
- Allowlists for message types, sender roles, and command types.
- Type, range, timestamp, freshness, sequence, and authorization checks.
- Unexpected fields inside telemetry and command payloads are rejected.
- Parse failures, overly large input, non-standard JSON numeric constants, and excessive nesting are rejected before message validation.

## OWASP Logging Cheat Sheet
Reference: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

- Decision records include evaluation time, message identifiers, decision, sequence number, and reason.
- Audit data lives in the running Flask process and can be reset; it is not persistent or tamper-proof.
- Do not claim production-grade logging, integrity protection, or incident response capabilities.
- Authentication keys and tags are never written to the audit log (tests check this).
