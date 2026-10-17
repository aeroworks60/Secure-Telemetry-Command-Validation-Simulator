# SENTINEL — Custom Flask Console

**Secure Telemetry/Command Validation Simulator**

Sentinel is a local educational prototype inspired by satellite telemetry and command validation. It processes synthetic JSON messages and demonstrates how configured rules can accept or reject them with a readable reason. It does not connect to a real satellite, spacecraft network, or operational command channel.

## What this version includes

- A custom HTML/CSS/JavaScript mission-console interface served by Flask (not Streamlit).
- **Customizable Message Lab:** edit common fields in a visual builder (message ID, satellite ID, timestamp, sequence number, type, sender role, telemetry values or command arguments) and apply them to the JSON editor; or edit the JSON directly for full control, missing fields, extra fields and malformed-input tests.
- A synthetic eight-message scenario with valid and intentionally invalid messages.
- Required-field, type, unexpected-field and telemetry-range checks.
- Timestamp freshness checks, duplicate-message-ID detection and per-satellite increasing sequence checks.
- A simple command allowlist tied to sender roles.
- Explainable accept/reject decisions and a downloadable in-memory JSON/CSV audit log.
- Size-limited strict JSON parsing that rejects non-standard `NaN`/`Infinity` constants and handles excessive nesting.
- **HMAC-SHA256 message authentication** (Python `hmac` + `hashlib`): server-side signing, verification with `hmac.compare_digest()`, a Message Lab "Sign / Simulate tampering" control, an authentication mode switch, and a seven-message authentication demo on the Overview page.
- **Navy / orange / white / green theme** and an **animated, simulated Earth** with orbiting satellite icons and communication packets (pure CSS/SVG, no 3D library, no scripts). Each packet is one real validation result: accepted packets pass the gate, rejected packets burst at the gate and never reach the receiving satellite, and with no messages the scene is idle and shows no success.
- Unit tests for the validation engine, HMAC authentication, the animation's honesty and web routes.

## Not implemented / limitations

- HMAC is a **shared-key** integrity/authenticity check only. It does **not encrypt** messages, does not hide their contents, and does not make this prototype production-secure. Anyone holding the key can sign; there is no key rotation, per-sender keys or key management.
- The built-in signing key is a **development-only demonstration key** (public in `auth.py`). Set `SENTINEL_HMAC_KEY` on the server for anything else. The `/auth/sign` route is a demo convenience: a real system would never expose a signing oracle.
- A valid tag does not mean the message is authorized, fresh or non-replayed; those checks are separate (see below).
- The configured message IDs, sender roles and ranges are synthetic demo policy, not satellite operational standards.
- A timestamp does not authenticate the sender, and duplicate-ID detection alone is not complete replay protection.
- Audit records live in process memory. They disappear when the app restarts and are not tamper-proof or production-grade.
- The development server binds to `127.0.0.1` only; it is intended for a local demo, not internet deployment.

## Orbit view (animation)

The Overview hero and the Message Lab result panel show a stylized Earth, two decorative orbiting satellite icons, a ground marker, the SENTINEL gate and a receiving satellite. The orbits and Earth are decorative: they are **not** real positions, and nothing connects to any real satellite.

What is real: the packets, gate state and captions are generated on the server from the actual validation records (`templates/_orbit.html`). `ACCEPTED` results are drawn as green packets that pass the gate; `REJECTED` results (including failed authentication) are red packets that burst at the gate, and the receiving satellite stays dark with "NOTHING RECEIVED". With no results the scene is idle ("AWAITING MESSAGE"). The Overview shows the latest run (up to 8 packets); the Message Lab shows the message just validated. The animation honours the operating system's reduced-motion setting (packets stay hidden and the text/gate status still show the result).

## HMAC message authentication

**What is signed.** Exactly these seven fields: `message_id`, `satellite_id`, `timestamp`, `sequence_number`, `message_type`, `sender_role`, `payload`. The `auth_tag` field is excluded so the tag never signs itself. Serialization is canonical (sorted keys, no whitespace, ASCII-escaped JSON, with a `SENTINEL-HMAC-SHA256-v1` domain prefix), so key order and spacing in the editor do not matter. Numbers are signed as parsed (`45` and `45.0` differ). A field outside this list is not covered by the tag, so the validator still rejects unexpected fields.

**Tag format.** `auth_tag` = 64 lowercase hex characters (HMAC-SHA256). Verification uses `hmac.compare_digest()`.

**Results.** `VALID`, `TAG_MISMATCH`, `MISSING_TAG`, `MALFORMED_TAG` (or `NOT_CHECKED` when authentication is optional and no tag was sent). `TAG_MISMATCH` covers both "a signed field changed after signing" and "signed with a different key": HMAC cannot tell those apart, and the UI says so.

**Modes.** *Optional* (default; keeps the original behaviour): unsigned messages skip the HMAC check, but a supplied bad tag is always rejected. *Required*: unsigned messages are rejected. Toggle it on the Overview page or in the Message Lab, or start with `SENTINEL_REQUIRE_AUTH=1`.

**Separation of concerns.** Authentication runs first and is implemented in `auth.py`, apart from authorization (roles/commands), timestamp freshness, duplicate-ID and sequence checks in `validator.py`. A message that fails authentication is rejected immediately and **does not consume its message ID or advance a sequence number**, so a forged message cannot burn a legitimate one. A message that passes authentication can still be rejected by the other rules, and the result shows both outcomes separately.

**Key handling.** The key exists only in server memory and is never put in a template, JavaScript or response. Windows (Command Prompt) before starting:

```bat
set SENTINEL_HMAC_KEY=replace-with-a-long-random-secret
.venv\Scripts\python.exe app.py
```

The key must be at least 16 bytes; a shorter value stops the app from starting rather than silently falling back. If the variable is unset, a development-only demonstration key is used and the Overview page shows a warning. Never commit a real key.

## Windows launch (exact steps)

**Easiest:** extract the ZIP to a normal folder (not inside the ZIP viewer), make sure Python 3.10+ is installed, then double-click `run_sentinel.bat`. The first run needs internet to install Flask. Leave the window open and use the browser page at `http://127.0.0.1:8765`.

**Command Prompt (manual):**

```bat
cd /d C:\path\to\sentinel_prototype
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
set SENTINEL_HMAC_KEY=replace-with-a-long-random-secret
.venv\Scripts\python.exe app.py
```

(`SENTINEL_HMAC_KEY` is optional: without it a development-only demonstration key is used and a warning is shown. If `py` is not found, use `python -m venv .venv`.)

**PowerShell:** `$env:SENTINEL_HMAC_KEY="replace-with-a-long-random-secret"` then `.\.venv\Scripts\python.exe app.py`.

**Run the tests:** `.venv\Scripts\python.exe -m unittest discover -s tests -v`

Stop the server with `Ctrl+C`. The server listens on `127.0.0.1` only. These steps were written for Windows but the Windows launch itself was **not** executed by the author; the same server and tests were run on Linux (see `TEST_RESULTS.txt`).

## Windows quick start

1. Extract the ZIP to a normal folder.
2. Make sure Python 3.10 or newer is installed.
3. Double-click `run_sentinel.bat`.
4. On the first run, an internet connection is needed to install Flask.
5. A browser should open at `http://127.0.0.1:8765`. Leave the terminal window open while using the app.
6. Click **Run 8-message scenario**. This resets the current in-memory state, then processes the eight seeded examples.

If the browser does not open, manually visit `http://127.0.0.1:8765` after the terminal says the server is running.

## Manual start

From Command Prompt in this folder:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

Stop the server by focusing the terminal window and pressing `Ctrl+C`.

## Automated tests

Install requirements, then run:

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover validator rules, safe JSON input, the demo batch, duplicate submission, malformed JSON, range rejection, audit exports, and HMAC authentication (valid tags, modified messages, wrong keys, missing/malformed tags, every signed field, `compare_digest` use, key loading, separation from other checks, and the web flow).

## Suggested demo flow

1. On **Overview**, click **Run 8-message scenario**. The seeded set is expected to produce two accepted and six rejected decisions.
2. Open **Message Lab**. The visual builder loads the current sample automatically. Change `message_id` and `battery_pct`, click **Apply fields to JSON**, review the generated JSON, then click **Validate message**.
3. To make a fully custom case, click inside the **RAW JSON EDITOR** and change any value or add/remove fields. The editor is intentionally editable. To demonstrate duplicate detection, submit a valid message and submit the exact same JSON again; the second attempt should be rejected for a duplicate message ID.
4. To test a range violation, use a new unique `message_id`, set `battery_pct` to `140` in the visual builder, apply to JSON, and validate.
4. **Authentication:** on **Overview**, click **Run authentication demo (7 messages)** (expected: 2 accepted, 5 rejected). In **Message Lab**, turn on *Require authentication*, load `HMAC: signed valid telemetry` and validate (accepted), then load `HMAC: tampered after signing` (rejected: tag mismatch). Or sign any message with **Sign with server key** and use **Simulate tampering**.
5. Open **Rules** to explain the schema and policy.
6. Open **Audit Trail** and export JSON or CSV to show the recorded decisions.

## Folder map

- `app.py` — Flask web routes and app configuration.
- `templates/` — four HTML screens plus `_orbit.html`, the data-driven satellite-link animation.
- `static/console.css` — custom responsive orange-on-midnight console theme.
- `static/console.js` — seeded example selector, editable visual message builder, JSON synchronization and byte counter.
- `validator.py` — existing validation engine (plus an authentication gate that calls `auth.py`).
- `auth.py` — HMAC-SHA256 signing/verification, canonical serialization, key loading.
- `safe_json.py` — bounded strict JSON parser.
- `samples.py` — synthetic demo messages.
- `runtime.py` — per-process in-memory validator and audit state.
- `tests/` — automated tests.
- `RESOURCE_REVIEW.md` — resource review and project limitations.

## Technology note

Flask renders the HTML templates, while CSS and JavaScript provide the custom interface. The security rules remain in Python modules, separate from the UI, so presentation changes do not need to rewrite the validator.
